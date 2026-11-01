import argparse
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import prompt_injection_detector as detector  # noqa: E402


@pytest.fixture(scope="session")
def pid():
    return detector


@pytest.fixture
def offline_args():
    return argparse.Namespace(
        offline=True,
        provider="offline",
        model=None,
        judge_all=False,
        max_judges=0,
        ollama_host=None,
        ollama_cloud=False,
        ollama_timeout=120,
        num_ctx=4096,
    )


@pytest.fixture(scope="session")
def corpus_path():
    manifest = json.loads((ROOT / "Data" / "manifest.json").read_text(encoding="utf-8"))

    def _get(fid):
        entry = next(m for m in manifest if m["id"] == fid)
        path = ROOT / "Data" / entry["file"]
        if not path.exists():
            path = ROOT / "Data" / Path(entry["file"]).name
        return path

    return _get


@pytest.fixture(scope="session")
def benign_path():
    manifest = json.loads((ROOT / "Data" / "benign" / "manifest.json").read_text(encoding="utf-8"))

    def _get(bid):
        entry = next(m for m in manifest if m["id"] == bid)
        return ROOT / "Data" / "benign" / entry["file"]

    return _get
