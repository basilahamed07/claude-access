# Injection firewall evaluation

How well does the scanner separate attacks from ordinary content? This folder measures it and reports the answer
with its limits. **Nothing here is estimated: a stack that cannot run on this machine says "not measured".**

## Method
- `datasets/attacks.jsonl` and `datasets/clean.jsonl`, rebuilt by `datasets/build_datasets.py`.
  Every base text was written by hand for this repository; obfuscation variants (zero-width, base64, HTML comment, CSS-hidden,
  homoglyph) are mechanical transformations of a hand-written attack and clean texts are repeated in a few realistic
  wrappers. They share a `group_id`, and the **split is by group id** (`sha256(group_id) % 10`; 0-3 = dev, 4-9 = test), so a
  variant can never be tuned on in dev and scored in test. No public dataset is included (none could be downloaded here).
- **dev** is for tuning rule weights and thresholds. **test** is run once at the end; if a result there leads to a rule change, the
  new numbers are no longer held-out and the README says so.
- A sample counts as *detected* when the verdict is `malicious`. A second column also counts `suspicious` ("flagged").
- Always read TPR together with FPR: `run_eval.py` refuses to print one without the other.

## Run
```
agentshield/.venv/bin/python eval/run_eval.py --stack rules --split dev
agentshield/.venv/bin/python eval/run_eval.py --stack rules --split test --out eval/results/rules-test.json --write-readme
# with an exported model (docs/classifier.md):
agentshield/.venv/bin/python eval/run_eval.py --stack rules+classifier --classifier-dir /path/to/model --classifier protectai_v2 --split test
```

## Results
<!-- results:start -->
### full (test)

Not measured. no classifier model available (pass --classifier-dir with an exported ONNX model; see docs/classifier.md).

### rules (test)

**rules** on the **test** split: 29 attacks, 162 clean.

| Measure | Malicious only | Malicious or suspicious |
|---|---|---|
| TPR (attacks caught) | 0.621 | 0.793 |
| FPR (clean wrongly flagged) | 0.006 | 0.031 |

Thresholds: clean_below 0.35, malicious_at 0.8.

| Attack category | Recall (malicious) |
|---|---|
| base64 | 1.00 |
| css-hidden | 1.00 |
| direct | 0.43 |
| exfil-url | 0.50 |
| homoglyph | 1.00 |
| html-comment | 1.00 |
| indirect-email | 0.67 |
| indirect-pdf-text | 0.00 |
| indirect-web | 0.33 |
| multilingual | 1.00 |
| tool-description | 1.00 |
| zero-width | 1.00 |

Scan latency per sample: p50 0.325 ms, p95 0.755 ms (in-process, single thread).

Dataset sha256 `8451169a27eb4d1b…`, ruleset `default-b878955b`, generated 2026-10-26T16:29:01+00:00.

### rules+classifier (test)

Not measured. no classifier model available (pass --classifier-dir with an exported ONNX model; see docs/classifier.md).

### rules (dev)

**rules** on the **dev** split: 39 attacks, 63 clean.

| Measure | Malicious only | Malicious or suspicious |
|---|---|---|
| TPR (attacks caught) | 0.872 | 1.000 |
| FPR (clean wrongly flagged) | 0.000 | 0.016 |

Thresholds: clean_below 0.35, malicious_at 0.8.

| Attack category | Recall (malicious) |
|---|---|
| base64 | 1.00 |
| css-hidden | 1.00 |
| direct | 1.00 |
| exfil-url | 1.00 |
| homoglyph | 1.00 |
| html-comment | 1.00 |
| indirect-email | 0.50 |
| indirect-pdf-text | 0.50 |
| indirect-web | 0.50 |
| multilingual | 1.00 |
| tool-description | 0.33 |
| zero-width | 1.00 |

Scan latency per sample: p50 0.379 ms, p95 0.892 ms (in-process, single thread).

Dataset sha256 `8451169a27eb4d1b…`, ruleset `default-b878955b`, generated 2026-10-26T16:29:00+00:00.
<!-- results:end -->

## Limits (read before quoting a number)
- The labelled set is small and written by the people who built the rules, so it flatters the rules layer. Treat the numbers as a
  regression baseline, not as a claim about attacks in the wild.
- The classifier and judge stacks are **not measured** unless you supply a model; the environment this was built in could not
  download one.
- Latency is in-process on one thread and excludes network and the model call.
