# Installing a prompt-injection classifier

AgentShield's injection firewall works without a classifier (rules + optional LLM judge). A classifier adds a
fast learned layer. **No model is bundled**, because bundling one would pull its licence and several hundred MB
into the image. Pick one, export it to ONNX once, and point AgentShield at the directory.

| Model | Licence | Notes |
|---|---|---|
| [`protectai/deberta-v3-base-prompt-injection-v2`](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) (recommended default) | Apache-2.0 | Detects injection (not jailbreaks). ~184M parameters; INT8 export is roughly 230 MB (third-party figure, measure it yourself) |
| `meta-llama/Llama-Prompt-Guard-2-22M` | Llama 4 Community Licence, **gated** download | Lightest (~22M, DeBERTa-xsmall), English only. You must accept Meta's terms on Hugging Face and download it yourself |

## Export and quantize (once, on any machine with internet)

```bash
pip install "optimum[onnxruntime]" transformers
optimum-cli export onnx --model protectai/deberta-v3-base-prompt-injection-v2 --task text-classification ./pi-v2
python - <<'PY'
from onnxruntime.quantization import quantize_dynamic, QuantType
quantize_dynamic("pi-v2/model.onnx", "pi-v2/model_quantized.onnx", weight_type=QuantType.QInt8)
PY
ls pi-v2        # must contain: tokenizer.json, config.json, model_quantized.onnx (or model.onnx)
```

## Use it

```bash
export AGENTSHIELD_CLASSIFIER=protectai_v2          # or prompt_guard_2_22m, or onnx for any other directory
export AGENTSHIELD_CLASSIFIER_DIR=/models/pi-v2
```

`GET /readyz` reports `classifier: ok | disabled | degraded`. If the model cannot be loaded AgentShield keeps
running **rules-only and says `degraded`**; it never treats a missing model as "clean".

## Measure it on your hardware

```bash
AGENTSHIELD_TEST_CLASSIFIER_DIR=/models/pi-v2 pytest agentshield/tests/perf/test_classifier_latency.py -s
AGENTSHIELD_TEST_CLASSIFIER_DIR=/models/pi-v2 python eval/run_eval.py --stack rules+classifier
```

The design targets (p95 < 120 ms for a 2 KB input on 4 vCPU; detection and false-alarm rates) are **targets, not
results** until you run these. The numbers published in the README come only from such runs.

## Honest limits
Classifiers are bypassable (a 2026 paper reports a 100 % bypass of Prompt Guard 2 86M with one fragmentation
attack class), so AgentShield treats the classifier as one layer: permissions (M1) still limit what a hijacked
agent can do.
