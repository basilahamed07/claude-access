import asyncio
import json
from collections import Counter
from pathlib import Path

import pytest
import run_eval as ev

ROOT = Path(__file__).resolve().parents[1]


def R(id_, label, group=None, category="x", text="t"):
    return {"id": id_, "group_id": group or f"g-{id_}", "text": text, "label": label, "category": category, "source": "s", "licence": "l"}


FIXTURE = [R("a1", "attack", category="direct"), R("a2", "attack", category="direct"), R("a3", "attack", category="base64"),
           R("c1", "clean"), R("c2", "clean"), R("c3", "clean", category="hard-negative")]


def fake_scan(verdicts):
    async def scan(row):
        return verdicts[row["id"]], 0.001
    return scan


def test_exact_tpr_and_fpr_on_a_six_sample_fixture():
    verdicts = {"a1": "malicious", "a2": "malicious", "a3": "clean", "c1": "clean", "c2": "suspicious", "c3": "malicious"}
    m = asyncio.run(ev.evaluate(FIXTURE, fake_scan(verdicts)))
    assert (m["n_attack"], m["n_clean"]) == (3, 3)
    assert m["tpr"] == pytest.approx(2 / 3) and m["fpr"] == pytest.approx(1 / 3)           # malicious only
    assert m["tpr_flagged"] == pytest.approx(2 / 3) and m["fpr_flagged"] == pytest.approx(2 / 3)   # suspicious counts too
    assert m["per_category_recall"] == {"direct": 1.0, "base64": 0.0}
    assert m["confusion"] == {"tp": 2, "fn": 1, "fp": 1, "tn": 2}


def test_report_refuses_a_detection_rate_without_its_false_positive_rate():
    with pytest.raises(ValueError, match="false positive"):
        ev.render_report({"tpr": 0.9, "n_attack": 10, "n_clean": 0, "fpr": None, "per_category_recall": {}})
    with pytest.raises(ValueError, match="false positive"):
        ev.render_report({"tpr": 0.9, "n_attack": 10, "n_clean": 5, "per_category_recall": {}})


def test_report_shows_both_rates_and_the_composition():
    m = asyncio.run(ev.evaluate(FIXTURE, fake_scan({r["id"]: "clean" for r in FIXTURE})))
    text = ev.render_report(m, stack="rules", split="test", thresholds={"clean_below": 0.35, "malicious_at": 0.8})
    assert "TPR" in text and "FPR" in text and "3 attacks" in text and "3 clean" in text and "0.35" in text


def test_split_is_deterministic_and_disjoint():
    rows = ev.load_rows(ROOT / "datasets" / "attacks.jsonl") + ev.load_rows(ROOT / "datasets" / "clean.jsonl")
    dev1, test1 = ev.split_rows(rows, "dev"), ev.split_rows(rows, "test")
    assert [r["id"] for r in dev1] == [r["id"] for r in ev.split_rows(rows, "dev")]
    assert not {r["id"] for r in dev1} & {r["id"] for r in test1}
    assert len(dev1) + len(test1) == len(rows) and len(dev1) > 20 and len(test1) > 20
    assert {r["id"] for r in ev.split_rows(rows, "all")} == {r["id"] for r in rows}


def test_groups_never_straddle_the_split():
    rows = ev.load_rows(ROOT / "datasets" / "attacks.jsonl") + ev.load_rows(ROOT / "datasets" / "clean.jsonl")
    where = {}
    for name in ("dev", "test"):
        for r in ev.split_rows(rows, name):
            where.setdefault(r["group_id"], set()).add(name)
    assert all(len(v) == 1 for v in where.values())
    assert len(rows) > len(where)                            # groups really do hold several variants


def test_every_row_validates_and_ids_are_unique():
    rows = ev.load_rows(ROOT / "datasets" / "attacks.jsonl") + ev.load_rows(ROOT / "datasets" / "clean.jsonl")
    assert len({r["id"] for r in rows}) == len(rows)
    with pytest.raises(ValueError, match="label"):
        ev.validate_row({**R("x", "attack"), "label": "maybe"})
    with pytest.raises(ValueError, match="missing"):
        ev.validate_row({"id": "x"})
    with pytest.raises(ValueError, match="empty"):
        ev.validate_row(R("x", "attack", text="  "))


def test_dataset_meets_the_agreed_size_and_composition():
    atk = ev.load_rows(ROOT / "datasets" / "attacks.jsonl")
    cln = ev.load_rows(ROOT / "datasets" / "clean.jsonl")
    cats = Counter(r["category"] for r in atk)
    assert len(atk) >= 60 and len(cln) >= 200
    assert sum(1 for r in cln if r["category"] == "hard-negative") >= 40
    assert {"direct", "indirect-email", "indirect-web", "indirect-pdf-text", "zero-width", "base64", "html-comment", "css-hidden", "homoglyph",
            "multilingual", "exfil-url", "tool-description"} <= set(cats)
    assert all(r["licence"] for r in atk + cln)


def test_dataset_fingerprint_changes_when_a_file_changes(tmp_path):
    a = tmp_path / "a.jsonl"; b = tmp_path / "b.jsonl"
    a.write_text(json.dumps(R("1", "attack")) + "\n"); b.write_text(json.dumps(R("2", "clean")) + "\n")
    f1 = ev.dataset_sha256([a, b])
    b.write_text(json.dumps(R("3", "clean")) + "\n")
    assert f1 != ev.dataset_sha256([a, b])


def test_stacks_that_need_a_model_say_so_instead_of_inventing_numbers():
    assert ev.stack_unavailable("rules", classifier_dir="", judge=False) is None
    assert "classifier" in ev.stack_unavailable("rules+classifier", classifier_dir="", judge=False)
    assert "judge" in ev.stack_unavailable("full", classifier_dir="/x", judge=False)
    assert ev.stack_unavailable("bogus", classifier_dir="", judge=False).startswith("unknown stack")


def test_the_real_rules_run_on_the_real_dataset_without_crashing():
    rows = ev.load_rows(ROOT / "datasets" / "attacks.jsonl")[:5] + ev.load_rows(ROOT / "datasets" / "clean.jsonl")[:5]
    m = asyncio.run(ev.run_stack(rows, "rules", classifier_dir="", classifier_kind="onnx"))
    assert m["n_attack"] == 5 and m["n_clean"] == 5 and set(m["latency_ms"]) == {"scan"} and m["latency_ms"]["scan"]["p95"] >= 0


def test_readme_block_is_rendered_from_result_files_only(tmp_path):
    base = {"stack": "rules", "split": "test", "status": "measured", "generated_at": "2026-10-26T10:00:00+00:00", "dataset": {"sha256": "ab" * 32},
            "n_attack": 3, "n_clean": 3, "tpr": 0.5, "fpr": 0.0, "tpr_flagged": 1.0, "fpr_flagged": 0.0, "per_category_recall": {"direct": 0.5},
            "latency_ms": {"scan": {"p50": 1.0, "p95": 2.0}}, "thresholds": {"clean_below": 0.35}}
    (tmp_path / "a.json").write_text(json.dumps(base))
    (tmp_path / "b.json").write_text(json.dumps({**base, "stack": "rules+classifier", "status": "not measured", "reason": "no classifier model available"}))
    older = {**base, "generated_at": "2025-01-01T00:00:00+00:00", "tpr": 0.99}
    (tmp_path / "c.json").write_text(json.dumps(older))
    text = ev.render_all(tmp_path)
    assert "0.500" in text and "0.990" not in text and "Not measured. no classifier model available" in text
    readme = tmp_path / "README.md"
    readme.write_text("x\n<!-- results:start -->\nold\n<!-- results:end -->\ny")
    ev.write_readme(text, readme)
    assert readme.read_text().startswith("x\n<!-- results:start -->") and "\nold\n" not in readme.read_text() and readme.read_text().endswith("y")


def test_readme_renderer_refuses_hand_typed_measurements_and_matches_the_committed_readme():
    import sys
    sys.path.insert(0, str(ROOT.parent / "scripts"))
    import render_readme as rr
    assert rr.hand_typed("We catch 93% of attacks, TPR 0.912, in 3 ms.") == ["93%", "0.912", "3 ms"]
    assert rr.hand_typed("{{eval:rules:test:tpr}} and `code 0.5 here`\n```\nthreshold 0.8\n```") == []
    assert rr.hand_typed((ROOT.parent / "README.template.md").read_text()) == []
    assert rr.main(["--check"]) == 0
