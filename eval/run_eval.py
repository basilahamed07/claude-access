#!/usr/bin/env python
"""Measure the injection firewall on the labelled sets in eval/datasets.

    agentshield/.venv/bin/python eval/run_eval.py --stack rules --split test --out eval/results/run.json

Rules of the house: TPR is never reported without FPR; the split is deterministic by group id so no variant of
a tuned-on sample reaches the test split; a stack that needs a model that is not available is reported as
"not measured", never estimated.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import statistics
import sys
import time
from collections import defaultdict
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
DATASETS = [HERE / "datasets" / "attacks.jsonl", HERE / "datasets" / "clean.jsonl"]
FIELDS = ("id", "group_id", "text", "label", "category", "source", "licence")
DEV_BUCKETS = 4          # of 10: groups hashing to 0-3 are the dev (tuning) split, 4-9 are the held-out test split
STACKS = ("rules", "rules+classifier", "full")
Row = dict[str, str]
ScanFn = Callable[[Row], Awaitable[tuple[str, float]]]


# ── data ──────────────────────────────────────────────────────────────────────────────────────────────
def validate_row(row: dict[str, Any]) -> Row:
    missing = [f for f in FIELDS if f not in row]
    if missing:
        raise ValueError(f"row {row.get('id', '?')} is missing {', '.join(missing)}")
    if row["label"] not in {"attack", "clean"}:
        raise ValueError(f"row {row['id']} has an invalid label {row['label']!r}")
    if not str(row["text"]).strip():
        raise ValueError(f"row {row['id']} has empty text")
    return {k: str(row[k]) for k in FIELDS}


def load_rows(path: Path) -> list[Row]:
    rows = [validate_row(json.loads(line)) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len({r["id"] for r in rows}) != len(rows):
        raise ValueError(f"duplicate ids in {path.name}")
    return rows


def bucket(group_id: str) -> int:
    return int(hashlib.sha256(group_id.encode()).hexdigest()[:8], 16) % 10


def split_rows(rows: list[Row], split: str) -> list[Row]:
    if split == "all":
        return list(rows)
    if split not in {"dev", "test"}:
        raise ValueError("split must be dev, test or all")
    return [r for r in rows if (bucket(r["group_id"]) < DEV_BUCKETS) == (split == "dev")]


def dataset_sha256(paths: list[Path]) -> str:
    h = hashlib.sha256()
    for p in paths:
        h.update(p.read_bytes())
    return h.hexdigest()


# ── metrics ───────────────────────────────────────────────────────────────────────────────────────────
def _pct(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    return s[min(len(s) - 1, int(q * len(s)))]


async def evaluate(rows: list[Row], scan: ScanFn) -> dict[str, Any]:
    """`scan(row) -> (verdict, seconds)`. A sample counts as detected when the verdict is "malicious"; the
    "flagged" rates also count "suspicious". Both are reported."""
    outcome: list[tuple[Row, str]] = []
    times: list[float] = []
    for r in rows:
        verdict, seconds = await scan(r)
        outcome.append((r, verdict))
        times.append(seconds * 1000)
    atk = [(r, v) for r, v in outcome if r["label"] == "attack"]
    cln = [(r, v) for r, v in outcome if r["label"] == "clean"]
    tp = sum(1 for _, v in atk if v == "malicious")
    fp = sum(1 for _, v in cln if v == "malicious")
    tp_f = sum(1 for _, v in atk if v != "clean")
    fp_f = sum(1 for _, v in cln if v != "clean")
    per_cat: dict[str, list[int]] = defaultdict(list)
    for r, v in atk:
        per_cat[r["category"]].append(1 if v == "malicious" else 0)
    misses = [{"id": r["id"], "category": r["category"], "verdict": v} for r, v in atk if v != "malicious"]
    false_alarms = [{"id": r["id"], "category": r["category"], "verdict": v} for r, v in cln if v != "clean"]
    return {
        "n_attack": len(atk), "n_clean": len(cln),
        "tpr": tp / len(atk) if atk else None, "fpr": fp / len(cln) if cln else None,
        "tpr_flagged": tp_f / len(atk) if atk else None, "fpr_flagged": fp_f / len(cln) if cln else None,
        "confusion": {"tp": tp, "fn": len(atk) - tp, "fp": fp, "tn": len(cln) - fp},
        "per_category_recall": {c: sum(v) / len(v) for c, v in sorted(per_cat.items())},
        "missed_attacks": misses, "flagged_clean": false_alarms,
        "latency_ms": {"scan": {"p50": round(statistics.median(times), 3) if times else 0.0, "p95": round(_pct(times, 0.95), 3)}},
    }


def render_report(m: dict[str, Any], *, stack: str = "", split: str = "", thresholds: dict[str, float] | None = None) -> str:
    """Markdown. Refuses to show a detection rate that has no false positive rate next to it."""
    if m.get("fpr") is None or not m.get("n_clean"):
        raise ValueError("refusing to report a detection rate without a false positive rate (no clean samples)")
    if m.get("tpr") is None:
        raise ValueError("refusing to report a false positive rate without a detection rate (no attack samples)")
    lines = [f"**{stack or 'stack'}** on the **{split or 'selected'}** split: {m['n_attack']} attacks, {m['n_clean']} clean.", "",
             "| Measure | Malicious only | Malicious or suspicious |", "|---|---|---|",
             f"| TPR (attacks caught) | {m['tpr']:.3f} | {m['tpr_flagged']:.3f} |",
             f"| FPR (clean wrongly flagged) | {m['fpr']:.3f} | {m['fpr_flagged']:.3f} |"]
    if thresholds:
        lines += ["", "Thresholds: " + ", ".join(f"{k} {v}" for k, v in thresholds.items()) + "."]
    if m.get("per_category_recall"):
        lines += ["", "| Attack category | Recall (malicious) |", "|---|---|"] + [f"| {c} | {r:.2f} |" for c, r in m["per_category_recall"].items()]
    lat = m.get("latency_ms", {}).get("scan")
    if lat:
        lines += ["", f"Scan latency per sample: p50 {lat['p50']} ms, p95 {lat['p95']} ms (in-process, single thread)."]
    return "\n".join(lines)


# ── stacks ────────────────────────────────────────────────────────────────────────────────────────────
def stack_unavailable(stack: str, *, classifier_dir: str, judge: bool) -> str | None:
    if stack not in STACKS:
        return f"unknown stack {stack!r}; use one of {', '.join(STACKS)}"
    if stack in {"rules+classifier", "full"} and not classifier_dir:
        return "no classifier model available (pass --classifier-dir with an exported ONNX model; see docs/classifier.md)"
    if stack == "full" and not judge:
        return "no judge model available (the judge needs an LLM upstream, not configured for offline runs)"
    return None


async def run_stack(rows: list[Row], stack: str, *, classifier_dir: str = "", classifier_kind: str = "onnx") -> dict[str, Any]:
    from agentshield.scan.classifier import ClassifierHandle, NullClassifier, load_classifier
    from agentshield.scan.pipeline import ScanConfig, scan
    from agentshield.scan.rules import default_ruleset

    clf = load_classifier(classifier_kind, classifier_dir) if stack != "rules" else ClassifierHandle(NullClassifier(), "disabled", "rules only")
    if stack != "rules" and clf.status != "ok":
        raise RuntimeError(f"classifier did not load: {clf.reason}")
    cfg = ScanConfig(ruleset=default_ruleset(), classifier=clf, judge=None, on_malicious="sanitize")

    async def one(row: Row) -> tuple[str, float]:
        t = time.perf_counter()
        res = await scan(row["text"], source="eval", cfg=cfg)
        return res.verdict, time.perf_counter() - t

    m = await evaluate(rows, one)
    m["classifier"] = clf.reason
    m["ruleset"] = default_ruleset().version
    return m


def thresholds() -> dict[str, float]:
    from agentshield.scan import pipeline
    return {"clean_below": pipeline.CLEAN_BELOW, "malicious_at": pipeline.MALICIOUS_AT}


# ── cli ───────────────────────────────────────────────────────────────────────────────────────────────
START, END = "<!-- results:start -->", "<!-- results:end -->"


def write_readme(block: str, readme: Path) -> None:
    text = readme.read_text(encoding="utf-8")
    if START not in text or END not in text:
        raise ValueError("eval/README.md has no results markers")
    head, rest = text.split(START, 1)
    _, tail = rest.split(END, 1)
    readme.write_text(f"{head}{START}\n{block}\n{END}{tail}", encoding="utf-8")


def latest_results(results_dir: Path) -> dict[tuple[str, str], dict[str, Any]]:
    """The newest result file per (stack, split)."""
    latest: dict[tuple[str, str], dict[str, Any]] = {}
    for p in sorted(results_dir.glob("*.json")):
        d = json.loads(p.read_text(encoding="utf-8"))
        key = (d["stack"], d["split"])
        if key not in latest or d["generated_at"] >= latest[key]["generated_at"]:
            latest[key] = d
    return latest


def render_all(results_dir: Path) -> str:
    out: list[str] = []
    for (stack, split), d in sorted(latest_results(results_dir).items(), key=lambda kv: (kv[0][1] != "test", kv[0])):
        if d["status"] != "measured":
            out.append(f"### {stack} ({split})\n\nNot measured. {d['reason']}.")
            continue
        out.append(f"### {stack} ({split})\n\n" + render_report(d, stack=stack, split=split, thresholds=d.get("thresholds")) +
                   f"\n\nDataset sha256 `{d['dataset']['sha256'][:16]}…`, ruleset `{d.get('ruleset')}`, generated {d['generated_at']}.")
    return "\n\n".join(out) if out else "Not run yet."


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stack", choices=STACKS, default="rules")
    ap.add_argument("--split", choices=["dev", "test", "all"], default="dev")
    ap.add_argument("--classifier-dir", default="")
    ap.add_argument("--classifier", default="onnx", choices=["onnx", "protectai_v2", "prompt_guard_2_22m"])
    ap.add_argument("--out", type=Path)
    ap.add_argument("--write-readme", action="store_true", help="re-render the results block of eval/README.md from eval/results/*.json")
    a = ap.parse_args(argv)

    reason = stack_unavailable(a.stack, classifier_dir=a.classifier_dir, judge=False)
    rows = [r for p in DATASETS for r in load_rows(p)]
    result: dict[str, Any] = {"generated_at": datetime.now(UTC).isoformat(timespec="seconds"), "stack": a.stack, "split": a.split,
                              "dataset": {"files": [p.name for p in DATASETS], "sha256": dataset_sha256(DATASETS)}}
    if reason:
        result["status"] = "not measured"
        result["reason"] = reason
        block = f"**{a.stack}**: not measured. {reason}."
    else:
        chosen = split_rows(rows, a.split)
        m = asyncio.run(run_stack(chosen, a.stack, classifier_dir=a.classifier_dir, classifier_kind=a.classifier))
        result.update({"status": "measured", "thresholds": thresholds(), **m})
        block = render_report(m, stack=a.stack, split=a.split, thresholds=thresholds())
    print(block)
    if a.out:
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if a.write_readme:
        write_readme(render_all(HERE / "results"), HERE / "README.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
