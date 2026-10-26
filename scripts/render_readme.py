#!/usr/bin/env python
"""Render README.md from README.template.md, taking every measured number from a result file.

    python scripts/render_readme.py            # write README.md
    python scripts/render_readme.py --check    # exit 1 if README.md differs from the render, or the template types a measured-looking number by hand

Placeholders:  {{eval:<stack>:<split>:<field>}}  from the newest eval/results/*.json  (n_attack n_clean tpr fpr tpr_flagged fpr_flagged p50 p95)
               {{perf:<section>:<field>}}        from docs/measured/perf.json
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "eval"))
import run_eval  # noqa: E402

TEMPLATE, README = ROOT / "README.template.md", ROOT / "README.md"
PLACEHOLDER = re.compile(r"\{\{(eval|perf):([^}]+)\}\}")
# Numbers that look like measurements. They must come from a placeholder, never from the template text.
HAND_TYPED = re.compile(r"(?<![\w./-])(?:0\.\d{2,}\b|\d+(?:\.\d+)?\s?%|\d+(?:\.\d+)?\s?ms\b)")


def eval_value(stack: str, split: str, field: str) -> str:
    d = run_eval.latest_results(ROOT / "eval" / "results").get((stack, split))
    if d is None or d.get("status") != "measured":
        raise SystemExit(f"no measured result for {stack}/{split} in eval/results")
    if field in {"n_attack", "n_clean"}:
        return str(d[field])
    if field in {"p50", "p95"}:
        return f"{d['latency_ms']['scan'][field]:.3f}"
    if field in {"tpr", "fpr", "tpr_flagged", "fpr_flagged"}:
        return f"{d[field]:.3f}"
    raise SystemExit(f"unknown eval field {field!r}")


def perf_value(section: str, field: str) -> str:
    d = json.loads((ROOT / "docs" / "measured" / "perf.json").read_text())[section]
    v = d[field]
    return str(v)


def render(template: str) -> str:
    def sub(m: re.Match[str]) -> str:
        kind, rest = m.group(1), m.group(2).split(":")
        return eval_value(*rest) if kind == "eval" else perf_value(*rest)
    return PLACEHOLDER.sub(sub, template)


def hand_typed(template: str) -> list[str]:
    stripped = PLACEHOLDER.sub("", template)
    stripped = re.sub(r"```.*?```", "", stripped, flags=re.S)         # code samples may contain version numbers and thresholds
    return HAND_TYPED.findall(stripped)


def main(argv: list[str]) -> int:
    template = TEMPLATE.read_text(encoding="utf-8")
    bad = hand_typed(template)
    if bad:
        print(f"README.template.md contains measured-looking numbers typed by hand: {bad}. Use a placeholder.", file=sys.stderr)
        return 1
    out = render(template)
    if "--check" in argv:
        if not README.exists() or README.read_text(encoding="utf-8") != out:
            print("README.md is out of date: run `python scripts/render_readme.py`", file=sys.stderr)
            return 1
        return 0
    README.write_text(out, encoding="utf-8")
    print(f"wrote {README}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
