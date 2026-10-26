"""Build the tiny ONNX + tokenizer fixture used to test the classifier ADAPTER (not a detector).

It is a bag-of-words max-pooling model: logit(injection) = max over tokens of a per-word weight. Real models
(ProtectAI DeBERTa v2, Prompt Guard 2) drop into the same adapter via AGENTSHIELD_CLASSIFIER_DIR.
Run: python scripts/make_tiny_classifier.py
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import onnx
from onnx import TensorProto, helper, numpy_helper
from tokenizers import Tokenizer, models, normalizers, pre_tokenizers, processors

OUT = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "tiny_classifier"
STRONG = {"ignore": 4.0, "disregard": 4.0, "previous": 1.5, "instructions": 2.5, "forward": 2.0, "jailbreak": 4.0, "override": 3.0}
VOCAB = ["[PAD]", "[UNK]", "[CLS]", "[SEP]", *STRONG, "the", "a", "meeting", "report", "please", "send", "to", "at", "on", "friday"]


def build_tokenizer() -> Tokenizer:
    tok = Tokenizer(models.WordLevel({w: i for i, w in enumerate(VOCAB)}, unk_token="[UNK]"))
    tok.normalizer = normalizers.Sequence([normalizers.NFKC(), normalizers.Lowercase()])
    tok.pre_tokenizer = pre_tokenizers.Whitespace()
    tok.post_processor = processors.TemplateProcessing(
        single="[CLS] $A [SEP]", special_tokens=[("[CLS]", 2), ("[SEP]", 3)])
    return tok


def build_model() -> onnx.ModelProto:
    table = np.zeros((len(VOCAB), 2), dtype=np.float32)
    table[:, 0] = 0.5                                         # SAFE logit
    for w, v in STRONG.items():
        table[VOCAB.index(w), 1] = v                          # INJECTION logit by word
    ids = helper.make_tensor_value_info("input_ids", TensorProto.INT64, ["batch", "seq"])
    mask = helper.make_tensor_value_info("attention_mask", TensorProto.INT64, ["batch", "seq"])
    logits = helper.make_tensor_value_info("logits", TensorProto.FLOAT, ["batch", 2])
    nodes = [
        helper.make_node("Gather", ["table", "input_ids"], ["emb"], axis=0),                        # [b, s, 2]
        helper.make_node("Cast", ["attention_mask"], ["maskf"], to=TensorProto.FLOAT),              # [b, s]
        helper.make_node("Unsqueeze", ["maskf", "axes"], ["mask3"]),                                # [b, s, 1]
        helper.make_node("Sub", ["one", "mask3"], ["inv"]),
        helper.make_node("Mul", ["inv", "neg"], ["pad_penalty"]),
        helper.make_node("Add", ["emb", "pad_penalty"], ["masked"]),
        helper.make_node("ReduceMax", ["masked"], ["logits"], axes=[1], keepdims=0),
    ]
    inits = [numpy_helper.from_array(table, "table"), numpy_helper.from_array(np.array([2], dtype=np.int64), "axes"),
             numpy_helper.from_array(np.array(1.0, dtype=np.float32), "one"),
             numpy_helper.from_array(np.array(-1e9, dtype=np.float32), "neg")]
    graph = helper.make_graph(nodes, "tiny", [ids, mask], [logits], inits)
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 17)])
    model.ir_version = 9
    onnx.checker.check_model(model)
    return model


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    onnx.save(build_model(), OUT / "model.onnx")
    build_tokenizer().save(str(OUT / "tokenizer.json"))
    (OUT / "config.json").write_text(json.dumps({"id2label": {"0": "SAFE", "1": "INJECTION"}, "max_position_embeddings": 512}))
    print("wrote", OUT, sorted(p.name for p in OUT.iterdir()))


if __name__ == "__main__":
    main()
