#!/usr/bin/env python3
"""
Scorecard runner: scans the test corpus with the detector and reports
detection rate per item. Works offline (rules+structural only) or with
any LLM judge (gemini/groq/openrouter/cerebras) when a key is in env.

Usage:
    python run_corpus.py                 # auto: judge ON if any API key in env
    python run_corpus.py --offline       # rules + structural only
    python run_corpus.py --provider groq # force a provider
"""
import argparse
import importlib.util
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
if not os.path.exists(os.path.join(HERE, "manifest.json")):      # run from scripts/ but corpus lives in download/
    HERE = "/home/z/my-project/download/prompt-injection-test-corpus"
CANDIDATES = [
    os.path.join(os.path.dirname(HERE), "prompt_injection_detector.py"),
    os.path.join(HERE, "prompt_injection_detector.py"),
    os.path.join(HERE, "..", "scripts", "prompt_injection_detector.py"),
    os.path.join(os.path.dirname(HERE), "prompt-injection-detector", "prompt_injection_detector.py"),
    "/home/z/my-project/scripts/prompt_injection_detector.py",
]
det_path = next((p for p in CANDIDATES if os.path.exists(p)), None)
if not det_path:
    sys.exit("prompt_injection_detector.py not found next to run_corpus.py")
spec = importlib.util.spec_from_file_location("pid", det_path)
pid = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pid)

LEVELS = {"CLEAN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--provider", default="gemini",
                    choices=["gemini", "groq", "openrouter", "cerebras"])
    ap.add_argument("--model", default=pid.DEFAULT_MODEL)
    ap.add_argument("--out", default=os.path.join(HERE, "scorecard.json"))
    args = ap.parse_args()

    have_key = any(os.environ.get(k) for k in
                   ("GEMINI_API_KEY", "GROQ_API_KEY", "OPENROUTER_API_KEY", "CEREBRAS_API_KEY"))
    args.offline = args.offline or not have_key
    args.judge_all = not args.offline     # judge everything in corpus mode
    args.max_judges = 500

    manifest = json.load(open(os.path.join(HERE, "manifest.json")))
    prompts = json.load(open(os.path.join(HERE, "prompts.json")))

    def scan_text(text):
        tf = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        tf.write(text); tf.close()
        try:
            return pid.scan_file(tf.name, args)
        finally:
            os.unlink(tf.name)

    mode = f"OFFLINE (rules+structural)" if args.offline else f"WITH JUDGE: {args.provider}"
    print(f"\n{'='*74}\n CORPUS SCORECARD -- {mode}\n{'='*74}")

    results = {"mode": mode, "files": [], "prompts": []}
    det = miss = weak = 0
    print(f"\n--- MALICIOUS FILES ({len(manifest)}) " + "-" * 44)
    print(f" {'ID':<4}{'EXPECTED':<10}{'GOT':<10}{'SC':<6}STATUS   ATTACK / JUDGE-NEEDED")
    for m in manifest:
        file_path = os.path.join(HERE, m["file"])
        if not os.path.exists(file_path):
            file_path = os.path.join(HERE, os.path.basename(m["file"]))
        rep = pid.scan_file(file_path, args)
        got, exp = rep["verdict"], m["expected_level"]
        if LEVELS[got] >= LEVELS[exp]:
            status, det = "DETECTED", det + 1
        elif rep["doc_score"] >= 15:
            status, weak = "FLAGGED-WEAK", weak + 1
        else:
            status, miss = "MISS", miss + 1
        if m["judge_needed"] and args.offline and status == "MISS":
            status = "MISS* (judge needed)"
        print(f" {m['id']:<4}{exp:<10}{got:<10}{rep['doc_score']:<6.0f}{status:<18}"
              f"{m['attack_type']}" + (" [judge]" if m["judge_needed"] else ""))
        results["files"].append({"id": m["id"], "expected": exp, "got": got,
                                 "score": rep["doc_score"], "status": status,
                                 "attack": m["attack_type"]})
    print(f"   -> detected {det} | flagged-weak {weak} | missed {miss} of {len(manifest)}")

    pdet = pmiss = 0
    print(f"\n--- MALICIOUS PROMPTS ({len(prompts)}) " + "-" * 42)
    print(f" {'ID':<5}{'SCORE':<7}{'OFFLINE':<16}{'JUDGE WOULD CATCH?'}TECHNIQUE")
    for p in prompts:
        rep = scan_text(p["text"])
        caught_offline = rep["doc_score"] >= 15
        if caught_offline:
            pdet += 1
        else:
            pmiss += 1
        print(f" {p['id']:<5}{rep['doc_score']:<7.0f}"
              f"{'RULES-CAUGHT' if caught_offline else 'JUDGE-REQUIRED':<16}"
              f"{'' if caught_offline else 'yes (needs LLM judge)':<20}{p['technique']}")
        results["prompts"].append({"id": p["id"], "score": rep["doc_score"],
                                   "caught_offline": caught_offline, "technique": p["technique"]})
    total_items = len(manifest) + len(prompts)
    print(f"   -> prompts: rules caught {pdet} | judge-required {pmiss} of {len(prompts)}")
    print(f"\n SUMMARY: {mode}")
    print(f"   files  : {det}/{len(manifest)} at expected level "
          f"(+{weak} weakly flagged)")
    print(f"   prompts: {pdet}/{len(prompts)} caught by rules alone -> "
          f"the other {pmiss} REQUIRE the Gemini/LLM judge layer")
    print(f"   combined offline ceiling: {det + pdet}/{total_items} | "
          f"with judge: up to {total_items}/{total_items}")
    json.dump(results, open(args.out, "w"), indent=2)
    print(f" scorecard -> {args.out}\n")

if __name__ == "__main__":
    main()
