"""
Prompt Injection Detector -- Web UI
====================================
Detection policy:
  AUTO    -> Gemini primary (if configured)
             -> offline rules/structural evidence as fallback
             -> Ollama Cloud as the last-resort semantic judge

Local Ollama is intentionally not part of Auto. It remains available only when
explicitly selected from the CLI (`--provider ollama`) for backwards
compatibility. Offline detection always runs and never needs a key or network.

Run:  python app.py
Open: http://localhost:5001
"""

import argparse
import os
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from flask import Flask, jsonify, render_template, request, send_from_directory

# -- Load .env ---------------------------------------------------------
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# -- Import detector primitives ---------------------------------------
sys.path.insert(0, str(Path(__file__).parent))
from prompt_injection_detector import (  # noqa: E402
    DEFAULT_MODEL,
    DEFAULT_OLLAMA_BASE_URL,
    DEFAULT_OLLAMA_CLOUD_MODEL,
    DEFAULT_OLLAMA_HOST,
    DEFAULT_OLLAMA_MODEL,
    DEFAULT_OLLAMA_TIMEOUT,
    DEFAULT_NUM_CTX,
    OPENAI_PROVIDERS,
    ollama_status,
    scan_file as run_detector_scan,
)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB


@app.errorhandler(413)
def request_too_large(_error):
    return jsonify({"error": "The request exceeds the 50 MB file limit."}), 413

APP_VERSION = os.environ.get("APP_VERSION", "1.0.0")
ALLOWED_EXTENSIONS = {".pdf", ".docx", ".txt", ".md", ".markdown", ".text"}
MAX_JUDGES = max(0, min(50, int(os.environ.get("MAX_JUDGES", "8"))))

_ENGINE_CACHE = {"ts": 0.0, "data": None}
_ENGINE_TTL = 10.0

AUTO_CHAIN = ["gemini", "offline", "ollama_cloud"]


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _redact(value, secret):
    if not value:
        return value
    text = str(value)
    if secret:
        text = text.replace(secret, "[redacted]")
    return text[:240]


def _connectivity_state(configured, reachable, disabled=False):
    if disabled:
        return "disabled"
    if not configured:
        return "not_configured"
    if reachable is True:
        return "reachable"
    if reachable is False:
        return "unreachable"
    return "not_tested"


def _probe_gemini(key):
    """Check connectivity only. Never return the API key or request headers."""
    if not key:
        return {"reachable": None, "models": [], "error": None}
    try:
        response = requests.get(
            "https://generativelanguage.googleapis.com/v1beta/models",
            headers={"x-goog-api-key": key},
            params={"pageSize": 20},
            timeout=6,
        )
        if response.status_code == 200:
            models = [
                str(item.get("name", "")).replace("models/", "", 1)
                for item in response.json().get("models", [])
            ]
            return {"reachable": True, "models": models, "error": None}
        return {
            "reachable": False,
            "models": [],
            "error": f"HTTP {response.status_code}",
        }
    except requests.RequestException as exc:
        return {
            "reachable": False,
            "models": [],
            "error": _redact(exc, key),
        }
    except Exception as exc:  # malformed provider response
        return {
            "reachable": False,
            "models": [],
            "error": _redact(exc, key),
        }


def _probe_ollama_cloud(key):
    """Probe the configured Ollama Cloud endpoint with a short timeout."""
    if not key:
        return {"reachable": None, "models": [], "error": None}
    base = (os.environ.get("OLLAMA_BASE_URL") or DEFAULT_OLLAMA_BASE_URL).rstrip("/")
    status = ollama_status(base, api_key=key, timeout=5)
    return {
        "reachable": bool(status.get("available")),
        "models": status.get("models", []),
        "error": _redact(status.get("error"), key),
    }


def _engines(probe=False):
    """Return engine configuration and, optionally, tested connectivity.

    `configured` only means credentials/implementation are present. `reachable`
    stays None until an explicit probe, so the UI never presents a configured
    API key as proof of a working connection.
    """
    now = time.monotonic()
    if (not probe and _ENGINE_CACHE["data"] is not None
            and now - _ENGINE_CACHE["ts"] < _ENGINE_TTL):
        return _ENGINE_CACHE["data"]

    gemini_key = os.environ.get("GEMINI_API_KEY", "")
    cloud_key = os.environ.get("OLLAMA_API_KEY", "")
    gemini_model = os.environ.get("GEMINI_MODEL") or DEFAULT_MODEL
    cloud_model = os.environ.get("OLLAMA_CLOUD_MODEL") or DEFAULT_OLLAMA_CLOUD_MODEL
    local_host = os.environ.get("OLLAMA_HOST", DEFAULT_OLLAMA_HOST)
    local_model = os.environ.get("OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL)

    gemini_probe = _probe_gemini(gemini_key) if probe else {
        "reachable": None, "models": [], "error": None}
    cloud_probe = _probe_ollama_cloud(cloud_key) if probe else {
        "reachable": None, "models": [], "error": None}

    gemini_configured = bool(gemini_key)
    cloud_configured = bool(cloud_key)

    if not gemini_configured:
        gemini_details = ("No Gemini credential is configured. Auto falls back "
                          "to the offline detector.")
    elif not probe:
        gemini_details = ("Configured as the primary semantic judge. "
                          "Connectivity is checked only when requested.")
    elif gemini_probe["reachable"] is True:
        gemini_details = ("Reachable during the last connectivity check. "
                          "Auto tries Gemini before the offline fallback.")
    else:
        gemini_details = ("Configured, but the last connectivity check failed. "
                          "Auto falls back to offline evidence.")

    if not cloud_configured:
        cloud_details = ("No Ollama Cloud credential is configured. This "
                         "fallback is skipped.")
    elif not probe:
        cloud_details = ("Configured as the last-resort judge when Gemini is "
                         "missing or fails. Connectivity is checked on request.")
    elif cloud_probe["reachable"] is True:
        cloud_details = ("Reachable during the last connectivity check. Used "
                         "only when Gemini is missing or fails.")
    else:
        cloud_details = ("Configured, but the last connectivity check failed. "
                         "Offline evidence remains the fallback.")

    providers = [
        {
            "id": "gemini",
            "name": "Gemini",
            "kind": "cloud",
            "role": "primary",
            "role_label": "Primary judge",
            "configured": gemini_configured,
            "reachable": gemini_probe["reachable"],
            "connectivity": _connectivity_state(
                gemini_configured, gemini_probe["reachable"]),
            "model": gemini_model,
            "models": gemini_probe["models"],
            "details": gemini_details,
            "error": gemini_probe["error"],
        },
        {
            "id": "offline",
            "name": "Offline detector",
            "kind": "offline",
            "role": "fallback",
            "role_label": "Always active",
            "configured": True,
            "reachable": True,
            "connectivity": "active",
            "model": "Rules + structural + decode + entropy",
            "models": [],
            "details": "Runs on every scan. No key, daemon, or network access.",
            "error": None,
        },
        {
            "id": "ollama_cloud",
            "name": "Ollama Cloud",
            "kind": "cloud",
            "role": "last_resort",
            "role_label": "Last-resort judge",
            "configured": cloud_configured,
            "reachable": cloud_probe["reachable"],
            "connectivity": _connectivity_state(
                cloud_configured, cloud_probe["reachable"]),
            "model": cloud_model,
            "models": cloud_probe["models"],
            "details": cloud_details,
            "error": cloud_probe["error"],
        },
        {
            "id": "ollama_local",
            "name": "Ollama local",
            "kind": "local",
            "role": "disabled",
            "role_label": "Disabled by policy",
            "configured": False,
            "reachable": None,
            "connectivity": "disabled",
            "model": local_model,
            "models": [],
            "details": (f"Local inference at {local_host} is not used by Auto. "
                        "Explicit CLI --provider ollama remains available."),
            "error": None,
        },
    ]

    for provider_id, cfg in OPENAI_PROVIDERS.items():
        configured = bool(os.environ.get(cfg["env"], ""))
        providers.append({
            "id": provider_id,
            "name": provider_id.capitalize(),
            "kind": "cloud",
            "role": "optional",
            "role_label": "Optional",
            "configured": configured,
            "reachable": None,
            "connectivity": _connectivity_state(configured, None),
            "model": cfg["model"],
            "models": [],
            "details": ("Supported by the detector but outside the Auto chain."
                        if configured else "No credential configured."),
            "error": None,
        })

    data = {
        "policy": {
            "primary": "gemini",
            "fallback": "offline",
            "last_resort": "ollama_cloud",
            "auto_chain": AUTO_CHAIN,
            "offline_always": True,
            "local_ollama": "disabled",
            "description": (
                "Offline detection always runs. Auto uses Gemini first; if it is "
                "unavailable or fails, offline evidence decides the verdict. "
                "Ollama Cloud is the last-resort semantic judge."
            ),
        },
        "providers": providers,
        "scanner_providers": [
            {"id": "auto", "label": "Auto", "configured": True},
            {"id": "gemini", "label": "Gemini", "configured": gemini_configured},
            {"id": "offline", "label": "Offline only", "configured": True},
            {"id": "ollama-cloud", "label": "Ollama Cloud",
             "configured": cloud_configured},
        ],
        "default_provider": "auto",
        "max_judges": MAX_JUDGES,
        "app_version": APP_VERSION,
        "probe": bool(probe),
        "tested_at": _now_iso() if probe else None,
        "generated_at": _now_iso(),
        # Backwards-compatible summary keys. No credential values are exposed.
        "gemini": {
            "available": gemini_configured,
            "configured": gemini_configured,
            "reachable": gemini_probe["reachable"],
            "default_model": gemini_model,
        },
        "ollama_cloud": {
            "available": cloud_configured,
            "configured": cloud_configured,
            "reachable": cloud_probe["reachable"],
            "default_model": cloud_model,
        },
        "ollama": {
            "available": False,
            "configured": False,
            "disabled": True,
            "host": local_host,
            "models": [],
            "default_model": local_model,
            "error": None,
        },
    }
    _ENGINE_CACHE.update({"ts": now, "data": data})
    return data


# ======================================================================
# Core scan
# ======================================================================
def _scan(target_path, provider="auto", model=None,
          max_judges=None, judge_all=False, source_name=None):
    requested_provider = (provider or "auto").strip().lower()
    ollama_cloud = requested_provider in ("ollama-cloud", "ollama_cloud", "cloud")
    internal_provider = "ollama" if ollama_cloud else requested_provider

    max_judges = MAX_JUDGES if max_judges is None else max(0, min(50, int(max_judges)))

    args = argparse.Namespace(
        offline=(requested_provider == "offline"),
        provider=internal_provider,
        model=(model or "").strip() or None,
        judge_all=bool(judge_all),
        max_judges=max_judges,
        ollama_host=os.environ.get("OLLAMA_HOST"),
        ollama_cloud=ollama_cloud,
        ollama_timeout=float(os.environ.get("OLLAMA_TIMEOUT", DEFAULT_OLLAMA_TIMEOUT)),
        num_ctx=int(os.environ.get("OLLAMA_NUM_CTX", DEFAULT_NUM_CTX)),
    )

    started_at = _now_iso()
    started = time.perf_counter()
    result = run_detector_scan(target_path, args)
    result["scan_started_at"] = started_at
    result["scan_duration_ms"] = round((time.perf_counter() - started) * 1000)
    result["source_name"] = source_name or Path(target_path).name
    result["requested_provider"] = requested_provider
    result["provider"] = requested_provider
    result["engine_label"] = result.get("judge_label") or (
        "offline" if requested_provider == "offline" else requested_provider
    )
    result["app_version"] = APP_VERSION
    return result


# ======================================================================
# Routes
# ======================================================================
@app.route("/")
def index():
    engines = _engines()
    return render_template(
        "index.html",
        engines=engines,
        app_version=APP_VERSION,
        default_provider=engines["default_provider"],
    )


@app.route("/favicon.ico")
def favicon():
    """Browsers request /favicon.ico even when an SVG icon is linked."""
    return send_from_directory(
        app.static_folder, "favicon.svg", mimetype="image/svg+xml")


@app.route("/engines")
def engines_route():
    probe = request.args.get("probe", "").lower() in ("1", "true", "yes")
    return jsonify(_engines(probe=probe))


@app.route("/scan/text", methods=["POST"])
def scan_text_route():
    data = request.get_json(force=True, silent=True) or {}
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"error": "No text provided"}), 400

    # Backwards compatibility: old clients sent use_gemini=true/false.
    provider = data.get("provider")
    if provider is None:
        provider = "gemini" if data.get("use_gemini") else "auto"
    model = data.get("model")
    max_judges = data.get("max_judges", MAX_JUDGES)
    judge_all = bool(data.get("judge_all", False))

    with tempfile.NamedTemporaryFile("w", suffix=".txt",
                                     delete=False, encoding="utf-8") as f:
        f.write(text)
        tmp = f.name
    try:
        result = _scan(tmp, provider=provider, model=model,
                       max_judges=max_judges, judge_all=judge_all,
                       source_name="Pasted text")
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


@app.route("/scan/file", methods=["POST"])
def scan_file_route():
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

    provider = request.form.get("provider")
    if provider is None:
        provider = "gemini" if request.form.get("use_gemini", "").lower() == "true" else "auto"
    model = request.form.get("model")
    try:
        max_judges = int(request.form.get("max_judges", MAX_JUDGES))
    except (TypeError, ValueError):
        max_judges = MAX_JUDGES
    judge_all = request.form.get("judge_all", "").lower() in ("1", "true", "yes", "on")

    with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
        f.save(tmp.name)
        tmp_path = tmp.name

    try:
        result = _scan(tmp_path, provider=provider, model=model,
                       max_judges=max_judges, judge_all=judge_all,
                       source_name=f.filename)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


# ======================================================================
if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 5001))
    engines = _engines()
    print("\nPrompt Injection Detector UI")
    print("   Policy  : Gemini primary -> offline fallback -> Ollama Cloud last")
    print("   Offline : L1 rules + L2 structural (always available)")
    print(f"   Gemini  : {'configured' if engines['gemini']['configured'] else 'not configured (offline fallback)'}")
    print(f"   Cloud   : {'configured (last resort)' if engines['ollama_cloud']['configured'] else 'not configured (optional)'}")
    print("   Local   : disabled for Auto; explicit CLI --provider ollama only")
    print(f"   Open    : http://{'localhost' if host == '0.0.0.0' else host}:{port}\n")
    app.run(host=host, debug=os.environ.get("FLASK_DEBUG") == "1", port=port)
