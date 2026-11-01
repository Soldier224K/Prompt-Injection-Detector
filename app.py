"""
Prompt Injection Detector -- Web UI
====================================
Architecture:
  PRIMARY  → Gemini analyses every chunk directly (when API key present)
  FALLBACK → Local rule engine (L1 regex + L2 structural) when Gemini is
             unavailable, over quota, or returns an error for a chunk.

Run:  python app.py
Open: http://localhost:5001
"""

import os
import sys
import tempfile
from pathlib import Path
from flask import Flask, render_template, request, jsonify

# ── Load .env ──────────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ── Import detector primitives ─────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))
from prompt_injection_detector import (
    load_segments, chunk_segment,
    rule_scan, gemini_judge, level_of,
)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024   # 50 MB

ALLOWED_EXTENSIONS = {".pdf", ".docx", ".txt", ".md", ".markdown", ".text"}
DEFAULT_MODEL       = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash-lite")


# ══════════════════════════════════════════════════════════════════════
# Scoring helpers
# ══════════════════════════════════════════════════════════════════════
def _score_from_gemini(verdict_data: dict, structural: int = 0) -> float | None:
    """
    Convert a Gemini verdict dict into a 0-100 risk score.
    Returns None if the verdict is an error/quota/parse failure
    so the caller knows to fall back to the rule engine.
    """
    v = verdict_data.get("verdict", "")
    c = float(verdict_data.get("confidence", 0.5))

    if v == "injection":
        base = c * 100          # 0.9 conf → 90
    elif v == "suspicious":
        base = c * 60           # 0.8 conf → 48
    elif v == "benign":
        base = (1.0 - c) * 15  # 0.9 conf → 1.5
    else:
        return None             # error / quota_exceeded / parse_error → fallback

    return min(100.0, round(base + structural, 1))


# ══════════════════════════════════════════════════════════════════════
# Core scan
# ══════════════════════════════════════════════════════════════════════
def _scan(target_path: str,
          use_gemini: bool = True,
          max_judges: int = 50,
          model: str = DEFAULT_MODEL) -> dict:
    """
    For every chunk:
      1. Try Gemini first  → primary score + rich verdict
      2. On any failure    → fall back to local rule engine score
    Structural signals (hidden text, annotations, metadata) always
    add bonus weight regardless of which layer scored the chunk.
    """
    api_key = os.environ.get("GEMINI_API_KEY") if use_gemini else None

    segments = load_segments(target_path)
    chunks   = [c for seg in segments for c in chunk_segment(seg)]

    results      = []
    judge_used   = 0   # successful Gemini calls
    fallback_cnt = 0   # chunks that fell back to rules

    for chunk in chunks:
        structural = chunk["structural"]
        text       = chunk["text"]
        used_gemini_for_chunk = False
        judge_result          = None

        # ── PRIMARY: Gemini ──────────────────────────────────────────
        if api_key and judge_used < max_judges:
            try:
                verdict      = gemini_judge(text, api_key, model)
                gemini_score = _score_from_gemini(verdict, structural)

                if gemini_score is not None:
                    # Gemini gave a usable answer
                    score               = gemini_score
                    matched             = []   # Gemini replaces pattern list
                    judge_result        = verdict
                    used_gemini_for_chunk = True
                    judge_used          += 1
                else:
                    # Gemini returned quota/error → fall through to rules
                    judge_result = verdict  # keep for UI transparency
            except Exception as e:
                judge_result = {"verdict": "error", "reason": str(e)[:200]}

        # ── FALLBACK: local rule engine ──────────────────────────────
        if not used_gemini_for_chunk:
            score, matched = rule_scan(chunk)
            fallback_cnt  += 1
        else:
            # Still run rules for metadata (categories/snippets shown in UI)
            _, matched = rule_scan(chunk)

        rec = {
            "source":           chunk["source"],
            "text":             text[:300],
            "score":            round(score, 1),
            "level":            level_of(score),
            "structural":       structural,
            "matched":          matched,
            "judge":            judge_result,
            "scored_by":        "gemini" if used_gemini_for_chunk else "rules",
        }
        results.append(rec)

    # ── Document-level aggregation ───────────────────────────────────
    flagged = [r for r in results if r["level"] != "CLEAN"]
    if flagged:
        maxc = max(r["score"] for r in flagged)
        avg  = sum(r["score"] for r in flagged) / len(flagged)
        structural_bonus = 10 if any(
            r["score"] >= 30 and
            r["source"].split(":")[0].endswith(("metadata", "annotation", "comment"))
            for r in flagged
        ) else 0
        doc_score = min(100, round(0.65 * maxc + 0.35 * avg + structural_bonus))
    else:
        doc_score = min(12, max((r["score"] for r in results), default=0))

    return {
        "doc_score":      doc_score,
        "verdict":        level_of(doc_score),
        "n_chunks":       len(results),
        "n_flagged":      len(flagged),
        "judge_calls":    judge_used,
        "fallback_chunks": fallback_cnt,
        "gemini_enabled": bool(api_key),
        "model":          model if api_key else None,
        "chunks":         results,
    }


# ══════════════════════════════════════════════════════════════════════
# Routes
# ══════════════════════════════════════════════════════════════════════
@app.route("/")
def index():
    gemini_ready = bool(os.environ.get("GEMINI_API_KEY"))
    return render_template("index.html", gemini_ready=gemini_ready)


@app.route("/scan/text", methods=["POST"])
def scan_text():
    data = request.get_json(force=True)
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"error": "No text provided"}), 400

    use_gemini = bool(data.get("use_gemini", True))
    with tempfile.NamedTemporaryFile("w", suffix=".txt",
                                     delete=False, encoding="utf-8") as f:
        f.write(text)
        tmp = f.name
    try:
        result = _scan(tmp, use_gemini=use_gemini)
        result["source_name"] = "Pasted text"
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        os.unlink(tmp)


@app.route("/scan/file", methods=["POST"])
def scan_file():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400

    ext = Path(f.filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        return jsonify({
            "error": f"Unsupported file type '{ext}'. "
                     f"Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
        }), 400

    use_gemini = request.form.get("use_gemini", "true").lower() == "true"

    with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
        f.save(tmp.name)
        tmp_path = tmp.name

    try:
        result = _scan(tmp_path, use_gemini=use_gemini)
        result["source_name"] = f.filename
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        os.unlink(tmp_path)


# ══════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    print(f"\n🛡️  Prompt Injection Detector UI")
    print(f"   Primary  : Gemini ({DEFAULT_MODEL})")
    print(f"   Fallback : Local rule engine")
    print(f"   Open     : http://localhost:{port}\n")
    app.run(debug=True, port=port)
