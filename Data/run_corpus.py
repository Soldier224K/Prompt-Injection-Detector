#!/usr/bin/env python3
"""
Scorecard runner: scans the malicious and benign corpora with the detector.

Works fully offline (rules + structural + unpacker + entropy) or with an
LLM judge:
    python run_corpus.py --offline
    python run_corpus.py --provider gemini
    python run_corpus.py --provider ollama --model gemma4:12b

With `--provider auto`, Gemini is tried first when GEMINI_API_KEY is set, then
offline evidence decides, and Ollama Cloud is the last resort when configured.
Local Ollama is used only through an explicit `--provider ollama`.
"""
import argparse
import importlib.util
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
if not os.path.exists(os.path.join(HERE, "manifest.json")):
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
    ap.add_argument("--offline", action="store_true",
                    help="rules + structural + unpacker + entropy only")
    ap.add_argument("--provider", default="auto",
                    choices=["auto", "offline", "ollama", "gemini",
                             "groq", "openrouter", "cerebras"])
    ap.add_argument("--model", default=None,
                    help="judge model (default: provider-specific)")
    ap.add_argument("--ollama-host", default=None)
    ap.add_argument("--ollama-cloud", action="store_true")
    ap.add_argument("--judge-all", action="store_true",
                    help="judge every chunk instead of only borderline ones")
    ap.add_argument("--max-judges", type=int, default=8,
                    help="max judge calls per file (default: 8)")
    ap.add_argument("--out", default=os.path.join(HERE, "scorecard.json"))
    args = ap.parse_args()

    if args.offline:
        args.provider = "offline"
    args.ollama_timeout = pid.DEFAULT_OLLAMA_TIMEOUT
    args.num_ctx = pid.DEFAULT_NUM_CTX

    # A rules-only copy of the args is used to report the offline score even
    # when a judge is active. It never touches the network.
    offline_args = argparse.Namespace(**vars(args))
    offline_args.offline = True
    offline_args.provider = "offline"
    offline_args.judge_all = False
    offline_args.max_judges = 0

    manifest = json.load(open(os.path.join(HERE, "manifest.json")))
    prompts = json.load(open(os.path.join(HERE, "prompts.json")))

    benign_manifest = []
    benign_path = os.path.join(HERE, "benign", "manifest.json")
    if os.path.exists(benign_path):
        benign_manifest = json.load(open(benign_path))

    # Resolve once so the scorecard label matches what scan_file will use.
    judge_fn, judge_label = pid.resolve_judge(args)
    mode = "OFFLINE (rules+structural+unpacker)" if judge_fn is None else f"WITH JUDGE: {judge_label}"
    print(f"\n{'='*74}\n CORPUS SCORECARD -- {mode}\n{'='*74}")

    def scan_text(text, scan_args=None):
        tf = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        tf.write(text)
        tf.close()
        try:
            return pid.scan_file(tf.name, scan_args or args)
        finally:
            os.unlink(tf.name)

    results = {"mode": mode, "files": [], "prompts": [], "benign": []}
    det = miss = weak = 0
    print(f"\n--- MALICIOUS FILES ({len(manifest)}) " + "-" * 44)
    print(f" {'ID':<4}{'EXPECTED':<10}{'GOT':<10}{'SC':<6}STATUS   ATTACK")
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
        print(f" {m['id']:<4}{exp:<10}{got:<10}{rep['doc_score']:<6.0f}{status:<18}"
              f"{m['attack_type']}")
        results["files"].append({"id": m["id"], "expected": exp, "got": got,
                                 "score": rep["doc_score"], "status": status,
                                 "attack": m["attack_type"]})
    print(f"   -> detected {det} | flagged-weak {weak} | missed {miss} of {len(manifest)}")

    pdet = pmiss = poff = 0
    score_col = "JUDGED" if judge_fn is not None else "SCORE"
    print(f"\n--- MALICIOUS PROMPTS ({len(prompts)}) " + "-" * 42)
    print(f" {'ID':<5}{score_col:<7}{'OFFLINE':<10}TECHNIQUE")
    for p in prompts:
        rep = scan_text(p["text"])
        off = rep if judge_fn is None else scan_text(p["text"], offline_args)
        caught = rep["doc_score"] >= 15
        caught_offline = off["doc_score"] >= 15
        if caught:
            pdet += 1
        else:
            pmiss += 1
        if caught_offline:
            poff += 1
        print(f" {p['id']:<5}{rep['doc_score']:<7.0f}"
              f"{off['doc_score']:<10.0f}{p['technique']}")
        results["prompts"].append({"id": p["id"], "score": rep["doc_score"],
                                   "offline_score": off["doc_score"],
                                   "caught": caught,
                                   "caught_offline": caught_offline,
                                   "technique": p["technique"]})
    print(f"   -> prompts: caught {pdet} | missed {pmiss} "
          f"({poff}/{len(prompts)} by rules alone)")

    fp = 0
    if benign_manifest:
        print(f"\n--- BENIGN CONTROLS ({len(benign_manifest)}) " + "-" * 40)
        print(f" {'ID':<4}{'EXPECTED':<10}{'GOT':<10}{'SC':<6}STATUS   KIND")
        for b in benign_manifest:
            file_path = os.path.join(HERE, "benign", b["file"])
            rep = pid.scan_file(file_path, args)
            got = rep["verdict"]
            expected_max = b.get("expected_max", "CLEAN")
            is_fp = LEVELS[got] > LEVELS[expected_max]
            if is_fp:
                fp += 1
            print(f" {b['id']:<4}{expected_max:<10}{got:<10}{rep['doc_score']:<6.0f}"
                  f"{'FALSE-POSITIVE' if is_fp else 'ok':<18}{b['kind']}")
            results["benign"].append({"id": b["id"], "expected_max": expected_max,
                                      "got": got, "score": rep["doc_score"],
                                      "false_positive": is_fp,
                                      "kind": b["kind"]})
        print(f"   -> false positives: {fp} of {len(benign_manifest)}")

    total_items = len(manifest) + len(prompts)
    print(f"\n SUMMARY: {mode}")
    print(f"   files  : {det}/{len(manifest)} at expected level "
          f"(+{weak} weakly flagged)")
    print(f"   prompts: {pdet}/{len(prompts)} caught "
          f"({poff}/{len(prompts)} by rules alone)")
    if benign_manifest:
        print(f"   benign : {fp}/{len(benign_manifest)} false positives")
    print(f"   combined: {det + pdet}/{total_items} caught")
    json.dump(results, open(args.out, "w"), indent=2)
    print(f" scorecard -> {args.out}\n")


if __name__ == "__main__":
    main()
