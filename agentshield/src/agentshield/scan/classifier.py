"""Prompt-injection classifier adapters (arch §2.2, layer 2).

`OnnxClassifier` runs any sequence-classification ONNX model that ships a Hugging Face `tokenizer.json`
(ProtectAI DeBERTa-v3 prompt-injection v2, Meta Prompt Guard 2, ...). Long text is scored in overlapping
windows and the highest probability wins. If the model cannot be loaded the platform degrades to rules-only and
SAYS so (`status == "degraded"`); it never reports a missing model as "clean".
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

log = logging.getLogger("agentshield.classifier")
MAX_WINDOWS = 8                       # first 4 + last 4 windows when a text is longer than that
POSITIVE_HINTS = ("injection", "jailbreak", "malicious", "unsafe", "attack", "label_1", "1")
MODEL_FILES = ("model_quantized.onnx", "model.onnx", "onnx/model_quantized.onnx", "onnx/model.onnx")


class Classifier(Protocol):
    name: str

    def score(self, text: str) -> float: ...


class NullClassifier:
    name = "null"

    def score(self, text: str) -> float:
        return 0.0


class StubClassifier:
    """Deterministic keyword scorer for tests and demos. NOT a detector."""

    name = "stub"

    def __init__(self, keyword_scores: dict[str, float] | None = None) -> None:
        self.keywords = keyword_scores or {"ignore previous": 0.95, "ignore all previous": 0.95, "forward all": 0.9}

    def score(self, text: str) -> float:
        low = text.lower()
        return max([s for k, s in self.keywords.items() if k in low], default=0.02)


def _softmax(row: list[float]) -> list[float]:
    m = max(row)
    exp = [math.exp(x - m) for x in row]
    total = sum(exp)
    return [e / total for e in exp]


SAFE_HINTS = ("safe", "benign", "normal", "clean", "legit", "harmless", "not_", "non_", "no_", "label_0")


def find_positive_indices(config: dict[str, Any], n_labels: int, override: str | int | None = None) -> list[int]:
    """Indices of every class that means "this is an attack". Binary models: the one non-safe label; multi-class
    models (benign / injection / jailbreak): all non-benign classes, so the score is P(any attack class)."""
    id2label = {int(k): str(v).lower() for k, v in (config.get("id2label") or {}).items()}
    if isinstance(override, int):
        return [override]
    if isinstance(override, str) and override.isdigit():
        return [int(override)]
    if isinstance(override, str):
        hits = [i for i, label in id2label.items() if label == override.lower()]
        if hits:
            return hits
    positives = [i for i, label in sorted(id2label.items()) if not any(h in label for h in SAFE_HINTS)]
    return positives or [min(1, n_labels - 1)]


class OnnxClassifier:
    def __init__(self, model_dir: str | Path, *, positive_label: str | int | None = None, max_length: int = 512,
                 stride: int = 64, intra_threads: int = 1) -> None:
        import numpy as np
        import onnxruntime as ort
        from tokenizers import Tokenizer

        d = Path(model_dir)
        model_path = next((d / f for f in MODEL_FILES if (d / f).is_file()), None)
        if model_path is None or not (d / "tokenizer.json").is_file():
            raise FileNotFoundError(f"{d} must contain tokenizer.json and one of {', '.join(MODEL_FILES)}")
        self.name = f"onnx:{d.name}"
        self.model_file = model_path.name
        self.model_size_bytes = model_path.stat().st_size
        cfg: dict[str, Any] = {}
        if (d / "config.json").is_file():
            cfg = json.loads((d / "config.json").read_text())
        self.max_length = min(max_length, int(cfg.get("max_position_embeddings", max_length)))
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = intra_threads
        opts.inter_op_num_threads = 1
        self._sess = ort.InferenceSession(str(model_path), opts, providers=["CPUExecutionProvider"])
        self._inputs = {i.name for i in self._sess.get_inputs()}
        out_shape = self._sess.get_outputs()[0].shape
        n_labels = out_shape[-1] if isinstance(out_shape[-1], int) else 2
        self.positive_indices = find_positive_indices(cfg, n_labels, positive_label)
        self._tok = Tokenizer.from_file(str(d / "tokenizer.json"))
        self._tok.enable_truncation(max_length=self.max_length, stride=stride)
        self._pad_id = self._tok.token_to_id("[PAD]") or self._tok.token_to_id("<pad>") or 0
        self._np = np

    def _windows(self, text: str) -> list[Any]:
        enc = self._tok.encode(text)
        wins = [enc, *enc.overflowing]
        if len(wins) > MAX_WINDOWS:
            wins = wins[: MAX_WINDOWS // 2] + wins[-MAX_WINDOWS // 2:]
        return wins

    def score(self, text: str) -> float:
        if not text.strip():
            return 0.0
        np = self._np
        wins = self._windows(text)
        width = max(len(w.ids) for w in wins)
        ids = np.full((len(wins), width), self._pad_id, dtype=np.int64)
        mask = np.zeros((len(wins), width), dtype=np.int64)
        for i, w in enumerate(wins):
            ids[i, : len(w.ids)] = w.ids
            mask[i, : len(w.ids)] = 1
        feed: dict[str, Any] = {"input_ids": ids, "attention_mask": mask}
        if "token_type_ids" in self._inputs:
            feed["token_type_ids"] = np.zeros_like(ids)
        logits = self._sess.run(None, {k: v for k, v in feed.items() if k in self._inputs})[0]
        return float(max(sum(_softmax([float(x) for x in row])[i] for i in self.positive_indices) for row in logits))


@dataclass
class ClassifierHandle:
    """What the pipeline holds: a classifier plus an honest status ('ok' | 'disabled' | 'degraded')."""

    impl: Classifier
    status: str = "disabled"
    reason: str = ""

    @property
    def name(self) -> str:
        return self.impl.name

    @property
    def active(self) -> bool:
        return self.status == "ok"

    async def ascore(self, text: str) -> float:
        return await asyncio.to_thread(self.impl.score, text)


def load_classifier(kind: str, model_dir: str = "") -> ClassifierHandle:
    if kind == "null":
        return ClassifierHandle(NullClassifier(), "disabled", "classifier disabled by configuration")
    if kind == "stub":
        return ClassifierHandle(StubClassifier(), "ok", "stub classifier (tests/demos only)")
    try:
        if not model_dir:
            raise FileNotFoundError("AGENTSHIELD_CLASSIFIER_DIR is not set")
        presets: dict[str, dict[str, Any]] = {
            "protectai_v2": {"max_length": 512},
            "prompt_guard_2_22m": {"max_length": 512},
            "onnx": {},
        }
        clf = OnnxClassifier(model_dir, **presets.get(kind, {}))
        return ClassifierHandle(clf, "ok", f"{clf.name} ({clf.model_file}, {clf.model_size_bytes / 1e6:.1f} MB)")
    except Exception as exc:                                         # noqa: BLE001
        log.error("classifier unavailable, running rules-only: %s", exc)
        return ClassifierHandle(NullClassifier(), "degraded", f"{type(exc).__name__}: {exc}")
