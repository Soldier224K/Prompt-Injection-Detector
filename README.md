# Prompt Warden

<p align="center">
  <img src="static/img/logo-mark.png" alt="Prompt Warden Logo" width="140" />
</p>

> **Zero-trust document firewall against direct and indirect prompt injection for RAG systems, LLM summarizers, and autonomous agents.**

Aligned with [OWASP Top 10 for LLM Applications 2025: LLM01 Prompt Injection](docs/OWASP_LLM01_2025.md).

Live Preview : https://prompt-injection-detector-tvue.onrender.com

Scans **PDF, DOCX, TXT, and MD** files before their text reaches an LLM. Offline
detection requires **no API key, daemon, or network access**. When a semantic
judge is enabled, the default policy is:

1. **Gemini** is the primary semantic judge when `GEMINI_API_KEY` is set.
2. **Offline evidence** is always the fallback. Rules, structural forensics,
   decoding, and entropy signals run on every scan.
3. **Ollama Cloud** is the last-resort judge only when Gemini is missing or
   fails and `OLLAMA_API_KEY` is configured.

Local Ollama is **not** part of Auto detection or the web UI. It remains
available only through the explicit CLI flag `--provider ollama` for backwards
compatibility and local experiments.

The frontend is a dark, keyboard-accessible security workspace served by the
existing Flask app. Engine status reports configuration and connectivity as
separate facts, and the UI renders only fields returned by the backend.

---

## Why this exists

Indirect prompt injection hides instructions in documents that look ordinary:
white-on-white PDF text, DOCX hidden runs, PDF annotations, comments, metadata,
Unicode tag characters, or a Base64 appendix. A plain regex pass over the visible
text misses most of them.

This detector combines:

1. **Structural forensics** that recover text a normal parser drops.
2. **Deterministic rules** for known attack language, including non-English.
3. **In-memory decoding** of obfuscated streams, with provenance.
4. **Entropy/lexical signals** for adversarial suffixes and unnatural text.
5. **A bounded semantic judge** for ambiguous chunks.

The LLM never replaces the offline layer. Rules and structural evidence always
run, and high-confidence rule hits do not depend on a key or a service.

---

## Detection policy

| Mode | Semantic judge | Network | Text leaves the machine |
|---|---|---|---|
| **Auto** | Gemini when configured; offline evidence always; Ollama Cloud when Gemini is missing or fails | Yes, when a judge is configured | Yes, to Gemini or Ollama Cloud when that judge is attempted |
| **Offline only** | None | No | No |
| **Gemini** (explicit) | Gemini | Yes | Yes, to Google |
| **Ollama Cloud** (explicit, UI) | Ollama Cloud | Yes | Yes, to Ollama Cloud |
| **Ollama local** (explicit CLI) | Local Ollama | Localhost | No |

In Auto, chunks are sent to Gemini only when a Gemini key is configured and the
judge gating rules select the chunk. If Gemini is missing or returns an error,
offline evidence remains the fallback and Ollama Cloud is tried when
`OLLAMA_API_KEY` is configured. Without either key, the scan completes entirely
offline.

The web UI defaults to **Auto**. **Offline only** is the local mode and makes no
external requests.

---

## Architecture

```
                 +-------------------------------------+
                 | Document: PDF / DOCX / TXT / MD     |
                 +------------------+------------------+
                                    |
                                    v
                 +-------------------------------------+
                 | L2  Structural extraction           |
                 |  PDF: off-canvas, alpha=0,          |
                 |       white-on-white, annotations,  |
                 |       links, embedded files, XMP    |
                 |  DOCX: hidden runs/styles, deleted  |
                 |       text, comments, footnotes,    |
                 |       custom XML                    |
                 |  TXT/MD: HTML comments/scripts      |
                 |  Unicode: zero-width, bidi, tags    |
                 +------------------+------------------+
                                    |
                                    v
                 +-------------------------------------+
                 | L1  Rules + lexical + entropy       |
                 |  instruction override, role hijack, |
                 |  prompt leak, exfiltration, tool    |
                 |  abuse, delimiter spoofing,         |
                 |  ES/FR/DE/PT/RU/ZH/HI/AR patterns   |
                 +------------------+------------------+
                                    |
                                    v
                 +-------------------------------------+
                 | L2.5 In-memory unpacker             |
                 |  Base64 / Base64URL / hex / URL /   |
                 |  HTML entities / ROT13              |
                 |  provenance: decoded_from + kind    |
                 +------------------+------------------+
                                    |
                     score 15-64, decoded, or anomaly
                                    |
                                    v
                 +-------------------------------------+
                 | L3  Bounded semantic judge          |
                 |  Auto: Gemini primary               |
                 |        offline evidence fallback    |
                 |        Ollama Cloud last resort     |
                 |  Explicit CLI: local Ollama or      |
                 |        Groq / OpenRouter / Cerebras  |
                 +------------------+------------------+
                                    |
                                    v
                 +-------------------------------------+
                 | Aggregate verdict: 0-100            |
                 | CLEAN | LOW | MEDIUM | HIGH | CRITICAL |
                 +-------------------------------------+
```

### Severity thresholds

| Score | Verdict |
|---:|---|
| 0-14 | CLEAN |
| 15-29 | LOW |
| 30-54 | MEDIUM |
| 55-79 | HIGH |
| 80-100 | CRITICAL |

The judge is called for short documents (chunks at or below the judge-call
budget), borderline scores (`15-64`), decoded streams, and token anomalies. On
longer documents, scores of 65+ are treated as definite rule hits. Use
`--judge-all`, or the UI's **Judge every chunk** control, to assess every chunk
(useful for security documentation that quotes attack strings). `max_judges`
caps the number of actual model calls per document.

---

## Installation

**Prerequisites:** Python 3.10+ and, for PDF/DOCX support, the packages in
`requirements.txt`.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Configure a judge only if you want semantic assessment:

```bash
cp .env.example .env
# Add GEMINI_API_KEY for the primary judge.
# Add OLLAMA_API_KEY only if you want the last-resort cloud fallback.
```

No `.env` is required for offline detection. If no key is configured, Auto stays
offline and returns a complete result from the deterministic layers.

---

## Usage

### Fully offline (no keys, no network)

```bash
python prompt_injection_detector.py document.pdf --offline
python prompt_injection_detector.py --text "Ignore all previous instructions" --offline
```

`--offline` always wins over configured keys.

### Auto: Gemini first, offline fallback

```bash
export GEMINI_API_KEY="..."
python prompt_injection_detector.py document.pdf
```

The CLI default is `--provider auto`. It uses Gemini when the key is present,
then offline evidence, and finally Ollama Cloud when `OLLAMA_API_KEY` is set.
Local Ollama is never selected by Auto.

### Explicit Gemini

```bash
python prompt_injection_detector.py document.pdf --provider gemini
```

### Ollama Cloud

```bash
export OLLAMA_API_KEY="..."
python prompt_injection_detector.py document.pdf \
  --provider ollama --ollama-cloud --model gemma4:31b
```

Ollama Cloud is a last-resort judge in Auto and an explicit choice in the UI.

### Local Ollama (explicit CLI only)

```bash
ollama pull gemma4:12b
ollama serve
python prompt_injection_detector.py document.pdf --provider ollama --model gemma4:12b
```

This path is retained for backwards compatibility. It is not used by Auto and
is disabled in the web UI by policy.

### Web dashboard

```bash
python app.py
# http://localhost:5001
```

The workspace includes:

- **Scanner** with text and document modes, provider selection, model override,
  judge-call cap, and a per-chunk judge option.
- **Results** with verdict and score, layer breakdown, findings table, evidence
  inspector, and the raw backend JSON.
- **Engine status** with the Auto policy chain, a provider matrix that separates
  configuration from tested connectivity, and an on-demand connection probe.

The provider selector offers **Auto**, **Gemini**, **Offline only**, and
**Ollama Cloud** when configured. Unconfigured providers are disabled in the UI,
and no credential values are returned by `/engines`.

### JSON report

```bash
python prompt_injection_detector.py document.pdf --offline --json report.json
```

### Exit codes

- `0`: CLEAN or LOW
- `1`: MEDIUM or HIGH
- `2`: CRITICAL
- `3`: processing error

---

## What the layers detect

### L1: Rules, lexical, and entropy

- Instruction overrides: `ignore previous instructions`, `disregard all rules`,
  `new directive:`, `do not follow`.
- Role/system hijacks: `you are now`, `pretend to be`, `[SYSTEM]`, `<|im_start|>`,
  `<<SYS>>`, fake system/assistant turns, "no content policies".
- Prompt leaks: reveal/print/repeat the system prompt or instructions above.
- Exfiltration: markdown image payloads, URL parameters (`?data=`, `?token=`),
  webhook/paste/discord endpoints, credentials sent to a URL, `POST` of
  conversation history.
- Action/tool abuse: `<tool_call>`, function calls, destructive file/database
  commands, email/payment actions, shell execution phrases.
- Obfuscation: Unicode tag plane, zero-width characters, bidi controls, Base64
  blobs, cipher/decode cues.
- Context/delimiter spoofing: fake `</document_context>`, `=== END OF SYSTEM ===`,
  "end of document, now begin".
- Multilingual rules for Spanish, French, German, Portuguese, Russian, Chinese,
  Hindi, and Arabic.
- Lexical density: imperative sentence starts, second-person pronouns, and
  high-entropy low-vowel tokens (GCG-style suffixes).
- A per-category cap prevents a single noisy category from saturating the score.

### L2: Structural forensics

**PDF**
- Off-canvas text using `pymupdf.INFINITE_RECT()` (normal extraction drops it).
- Invisible text via `span["alpha"] == 0` (render mode 3).
- White text only when there is no dark fill or image behind it.
- Microscopic fonts (< 2 pt).
- Annotations, link URIs, DocInfo metadata, XMP metadata.
- Embedded files (names always; small text attachments scanned).
- A low-weight active-content flag for `/JavaScript`, `/OpenAction`, `/Launch`.

**DOCX**
- Runs with `w:vanish` / `w:specVanish`, including style-inherited hiding.
- `w:delText` (tracked-change deletions).
- Comments, footnotes, endnotes, custom XML parts, custom document properties.
- Headers, footers, tables, and core properties.

**TXT / MD**
- Inline HTML comments, `<script>` and `<style>` blocks.
- Zero-width, bidi, and Unicode tag characters.

### L2.5: Decode layer

Decoded content is scanned as a separate segment with `decoded=True`,
`decode_kind`, and `derived_from` provenance:

- Base64 and Base64URL (JWT-shaped payloads are skipped to avoid false positives).
- `\xNN` / `0xNN` / long continuous hex byte streams.
- URL percent-encoding.
- HTML entities.
- ROT13 only when the text explicitly cues it.

Caps on depth, decoded character count, and derived segment count prevent decode
bombs. Nothing is written to disk during decoding.

### L3: Bounded semantic judge

The judge receives the chunk wrapped as untrusted data with a JSON schema
constraint. Results are cached in memory by `model + prompt version + text`.
Ollama requests use `num_ctx=4096`, `think=false`, a fixed seed,
`temperature=0`, and `keep_alive=10m` to keep latency predictable.

Auto policy:

1. Try Gemini when `GEMINI_API_KEY` is configured.
2. If Gemini is unavailable or returns an unusable response, keep the offline
   score and continue. Offline evidence is always present.
3. If `OLLAMA_API_KEY` is configured, try Ollama Cloud as the final judge.
4. If no judge is available, the result is fully offline.

Local Ollama is reachable only through `--provider ollama`. The UI never selects
it, and `/engines` reports it as disabled by policy.

---

## API

The existing Flask routes and request contracts are preserved.

| Route | Purpose |
|---|---|
| `GET /` | Web workspace |
| `GET /engines` | Provider policy, configuration, and sanitized connectivity state |
| `GET /engines?probe=1` | Same response plus an on-demand Gemini and Ollama Cloud connectivity probe |
| `POST /scan/text` | JSON body with `text`, optional `provider`, `model`, `max_judges`, `judge_all` |
| `POST /scan/file` | Multipart upload with `file`, optional `provider`, `model`, `max_judges`, `judge_all` |

A scan response includes the existing detector fields plus real request data:
`source_name`, `requested_provider`, `provider`, `engine_label`,
`scan_started_at`, `scan_duration_ms`, and `app_version`. Evidence text is
retained up to 4,000 characters per chunk, with `text_length` and
`text_truncated` describing the original content.

`/engines` returns `policy`, `providers`, and `scanner_providers`. Each provider
exposes whether it is configured and its separately tested connectivity state
(`not_configured`, `not_tested`, `reachable`, `unreachable`, `active`, or
`disabled`). Credential values and environment contents are never returned.

---

## Evaluation corpus

`Data/` contains 18 malicious fixtures and 18 malicious prompts. `Data/benign/`
contains 15 benign controls covering business prose, FAQs, code READMEs, JSON
with hashes/JWTs, legitimate campaign URLs, multilingual text, legal text, news,
a changelog, a CSV inventory, meeting notes, a white-on-dark PDF, a normal DOCX
table, and an inline binary Base64 image.

Run the scorecard:

```bash
# Fully offline
python Data/run_corpus.py --offline

# Gemini judge (requires GEMINI_API_KEY)
python Data/run_corpus.py --provider gemini

# Explicit local Ollama CLI path
python Data/run_corpus.py --provider ollama --model gemma4:12b
```

Current offline results:

- **Malicious files:** 18/18 at or above the expected severity.
- **Benign controls:** 0/15 false positives.
- **Malicious prompts:** 4/18 caught by rules alone; the remaining prompts are
  designed to require a semantic judge.

The previously recorded explicit local Ollama run (`gemma4:12b`) caught 18/18
malicious files and 18/18 malicious prompts, with 0/15 benign false positives.
Those numbers are for the explicit CLI path, not the Auto policy. Re-run the
scorecard if you change the judge or model.

A document that *quotes* attack strings (a security tutorial, this README, a
red-team report) can trip the rules offline. That is intentional conservatism;
use an explicitly selected judge with **Judge every chunk** to distinguish
discussion from intent.

---

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q   # 49 tests
```

The suite covers:

- Base64 / Base64URL / hex / URL / HTML-entity / ROT13 decoding and JWT skipping.
- Binary Base64 rejection and decode provenance.
- PDF off-canvas, alpha-zero, white-on-white, and white-on-dark visibility.
- DOCX hidden runs and normal tables.
- Chunk provenance and pattern de-duplication.
- Malicious corpus severity and benign-corpus precision.
- Offline mode making zero network requests.
- Judge gating, score blending, and high-score fast paths.
- Auto fallback from Gemini to offline and then Ollama Cloud.
- `/engines` policy metadata, connectivity probes, and secret redaction.
- Scan timing, evidence, and provider metadata in both scan routes.
- CLI exit codes and JSON reports.

---

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `GEMINI_API_KEY` | unset | Primary semantic judge for Auto |
| `GEMINI_MODEL` | `gemini-2.5-flash-lite` | Gemini model |
| `OLLAMA_API_KEY` | unset | Ollama Cloud key; last-resort judge |
| `OLLAMA_CLOUD_MODEL` | `gemma4:31b` | Ollama Cloud model |
| `OLLAMA_BASE_URL` | `https://ollama.com` | Ollama Cloud base URL |
| `MAX_JUDGES` | `8` | Max judge calls per document |
| `OLLAMA_HOST` | `http://localhost:11434` | Local daemon for explicit CLI only |
| `OLLAMA_MODEL` | `gemma4:12b` | Local model for explicit CLI only |
| `OLLAMA_NUM_CTX` | `4096` | Context window; keeps a local model on GPU |
| `OLLAMA_TIMEOUT` | `120` | Judge request timeout in seconds |
| `GROQ_API_KEY` | unset | Optional explicit CLI provider outside Auto |
| `OPENROUTER_API_KEY` | unset | Optional explicit CLI provider outside Auto |
| `CEREBRAS_API_KEY` | unset | Optional explicit CLI provider outside Auto |
| `PORT` | `5001` | Flask port |
| `FLASK_DEBUG` | `0` | Set to `1` for the Flask debug server |
| `APP_VERSION` | `1.0.0` | Version shown in the UI and API responses |

---

## Limitations

- Regex rules cannot understand intent. Quoted attack text, red-team reports, and
  security documentation may be flagged offline; the semantic judge is the
  disambiguation layer.
- PDF extraction depends on PyMuPDF. Encrypted PDFs and scanned image-only PDFs
  are not OCR'd.
- DOCX support covers the common WordprocessingML structures listed above; exotic
  or malformed packages degrade gracefully.
- The judge is a classifier, not a guarantee. Keep human approval for destructive
  or outbound actions, and enforce least privilege on tool-using agents.
- Auto sends selected chunk text to Gemini when configured. Ollama Cloud may
  receive chunk text as the last-resort judge. Use **Offline only** or
  `--offline` when content must not leave the machine.
- Connectivity probes are deliberately manual. A configured key is not proof of
  a working connection; press **Test connections** in Engine status to check it.

---

## License

MIT. See [LICENSE](LICENSE).
