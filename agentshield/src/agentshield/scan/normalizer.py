"""Content normalizer: make hidden instructions visible before any detector runs (arch §2.2).

Everything the model could "read" but a human would not see is surfaced:
  * zero-width / bidi / invisible characters are removed (and reported);
  * Unicode *tag* characters (U+E0000..E007F, "ASCII smuggling") are decoded into hidden text;
  * HTML comments, <script>/<style>, `hidden` / `aria-hidden` and CSS-hidden or white-on-white text
    are moved from the visible channel into the hidden channel;
  * NFKC folds full-width and compatibility characters; mixed-script words (Latin + Cyrillic/Greek
    look-alikes) are folded to Latin;
  * base64 / hex / percent-encoded blobs are decoded (depth <= 2) into the hidden channel.
Every character keeps a source span, so a finding can be mapped back onto the original text.
"""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from dataclasses import dataclass, field
from html.entities import name2codepoint
from html.parser import HTMLParser
from urllib.parse import unquote

Pair = tuple[str, tuple[int, int]]          # (character, (source_start, source_end))

ZERO_WIDTH = set("​‌‍⁠﻿᠎­͏؜ᅟᅠ឴឵ㅤﾠ")
BIDI = set("‎‏‪‫‬‭‮⁦⁧⁨⁩")
INVISIBLE = ZERO_WIDTH | BIDI
HOMOGLYPHS = {   # Cyrillic / Greek look-alikes -> Latin
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ѕ": "s", "ј": "j", "ԁ": "d",
    "ɡ": "g", "һ": "h", "ԛ": "q", "ԝ": "w", "ν": "v", "ο": "o", "α": "a", "ι": "i", "κ": "k", "τ": "t", "ρ": "p",
    "υ": "u", "ε": "e", "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C",
    "Т": "T", "Х": "X", "Υ": "Y", "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
    "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X",
}
HIDDEN_TAGS = {"script", "style", "template"}
VOID = {"br", "img", "input", "meta", "link", "hr", "area", "base", "col", "embed", "source", "track", "wbr"}
_B64 = re.compile(r"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_-]{24,}={0,2}(?![A-Za-z0-9+/_-])")
_HEX = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){12,}(?![0-9A-Fa-f])")
_PCT = re.compile(r"(?:%[0-9A-Fa-f]{2}){6,}")
_ENTITY = re.compile(r"&(?:#\d{1,7}|#[xX][0-9a-fA-F]{1,6}|[A-Za-z][A-Za-z0-9]{1,31});")
_WORD = re.compile(r"[^\W\d_]{2,}")
_HIDDEN_STYLE = [re.compile(p) for p in (
    r"display:none", r"visibility:hidden", r"font-size:0(?:px|pt|em|rem|%)?(?![\d.])", r"opacity:0(?:\.0*)?(?![\d.])",
    r"text-indent:-\d{3,}", r"(?:left|top|margin-left|margin-top):-\d{4,}", r"max-height:0(?:px)?(?![\d.])",
    r"clip:rect\(0(?:px)?,0(?:px)?,0(?:px)?,0(?:px)?\)", r"color:transparent",
    r"(?:height|width):0(?:px)?(?![\d.]).*overflow:hidden", r"overflow:hidden.*(?:height|width):0(?:px)?(?![\d.])")]
_WHITE_TEXT = re.compile(r"(?<![-\w])color:(?:#fff(?:fff)?|white|rgb\(255,255,255\)|rgba\(255,255,255,1\))(?![\w])")


@dataclass
class Normalized:
    text: str = ""
    hidden_text: str = ""
    transforms: list[str] = field(default_factory=list)
    text_map: list[tuple[int, int]] | None = None         # None => identity (text index == source index)
    hidden_map: list[tuple[int, int]] = field(default_factory=list)
    source_len: int = 0
    truncated: bool = False
    unscannable: bool = False
    homoglyph_words: list[str] = field(default_factory=list)

    @property
    def has_hidden(self) -> bool:
        return bool(self.hidden_text.strip())


def to_original_span(norm: Normalized, span: tuple[int, int], *, hidden: bool = False) -> tuple[int, int]:
    """Map a [start, end) span in `text` (or `hidden_text`) onto the original string."""
    start, end = max(span[0], 0), max(span[1], span[0])
    mapping = norm.hidden_map if hidden else norm.text_map
    if mapping is None:
        return min(start, norm.source_len), min(end, norm.source_len)
    if not mapping or start >= len(mapping):
        return (norm.source_len, norm.source_len) if mapping else (0, 0)
    chunk = mapping[start:max(end, start + 1)]
    lo = min(c[0] for c in chunk)
    hi = max(c[1] for c in chunk)
    return max(0, min(lo, norm.source_len)), max(0, min(hi, norm.source_len))


def looks_binary(raw: bytes) -> bool:
    if not raw:
        return False
    sample = raw[:4096]
    if sample.count(0) > len(sample) * 0.02:
        return True
    text = sample.decode("utf-8", errors="replace")
    return text.count("�") > len(text) * 0.3


def _printable_ratio(s: str) -> float:
    return sum(1 for c in s if c.isprintable() or c in "\n\r\t") / max(len(s), 1)


def _decode_blob(kind: str, blob: str) -> str | None:
    try:
        if kind == "base64":
            padded = blob + "=" * (-len(blob) % 4)
            raw = base64.urlsafe_b64decode(padded) if ("-" in blob or "_" in blob) else base64.b64decode(padded, validate=True)
        elif kind == "hex":
            raw = bytes.fromhex(blob)
        else:
            return unquote(blob, errors="strict") if blob else None
        decoded = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if len(decoded) < 8 or _printable_ratio(decoded) < 0.92 or not re.search(r"[A-Za-z]{4}", decoded):
        return None
    return decoded


class _HtmlSplitter(HTMLParser):
    def __init__(self, src: str) -> None:
        super().__init__(convert_charrefs=False)
        self.src = src
        self.starts = [0]
        for m in re.finditer("\n", src):
            self.starts.append(m.end())
        self.visible: list[Pair] = []
        self.hidden: list[Pair] = []
        self.stack: list[tuple[str, bool]] = []
        self.kinds: set[str] = set()

    def _pos(self) -> int:
        line, col = self.getpos()
        return self.starts[min(line - 1, len(self.starts) - 1)] + col

    def _hidden_now(self) -> bool:
        return bool(self.stack and self.stack[-1][1])

    def _emit(self, text: str, start: int, end: int | None = None, *, per_char: bool = True) -> None:
        target = self.hidden if self._hidden_now() else self.visible
        for i, c in enumerate(text):
            target.append((c, (start + i, start + i + 1) if per_char else (start, end if end is not None else start + len(text))))

    @staticmethod
    def _is_hidden(tag: str, attrs: list[tuple[str, str | None]]) -> str | None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in HIDDEN_TAGS:
            return "html_script_style"
        if "hidden" in a or a.get("aria-hidden", "").lower() == "true":
            return "html_hidden_attr"
        style = re.sub(r"\s+", "", a.get("style", "").lower())
        if any(p.search(style) for p in _HIDDEN_STYLE):
            return "css_hidden"
        if _WHITE_TEXT.search(style) and not re.search(r"background(?:-color)?:(?!#fff|white|transparent|rgb\(255,255,255\))", style):
            return "css_white_text"
        if tag == "font" and a.get("color", "").lower().replace(" ", "") in {"#fff", "#ffffff", "white"}:
            return "css_white_text"
        return None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in VOID:
            return
        why = self._is_hidden(tag, attrs)
        if why:
            self.kinds.add(why)
        self.stack.append((tag, bool(why) or self._hidden_now()))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        return

    def handle_endtag(self, tag: str) -> None:
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                return

    def handle_data(self, data: str) -> None:
        self._emit(data, self._pos())

    def handle_entityref(self, name: str) -> None:
        cp = name2codepoint.get(name)
        pos = self._pos()
        if cp is None:
            self._emit(f"&{name};", pos)
        else:
            self._emit(chr(cp), pos, pos + len(name) + 2, per_char=False)

    def handle_charref(self, name: str) -> None:
        pos = self._pos()
        try:
            cp = int(name[1:], 16) if name[:1] in "xX" else int(name)
            ch = chr(cp)
        except (ValueError, OverflowError):
            ch = f"&#{name};"
        self._emit(ch, pos, pos + len(name) + 3, per_char=False)

    def handle_comment(self, data: str) -> None:
        pos = self._pos()
        self.kinds.add("html_comment")
        for c in data:
            self.hidden.append((c, (pos, pos + len(data) + 7)))
        self.hidden.append(("\n", (pos, pos + len(data) + 7)))


def _split_html(src: str, pairs: list[Pair], transforms: list[str]) -> tuple[list[Pair], list[Pair]]:
    parser = _HtmlSplitter(src)
    try:
        parser.feed(src)
        parser.close()
    except Exception:                                                 # noqa: BLE001  (malformed markup is data too)
        return pairs, []
    transforms.extend(sorted(parser.kinds))
    if _ENTITY.search(src):
        transforms.append("html_entities")
    visible = parser.visible
    # the parser never saw bytes it could not tokenize (e.g. a lone '<'): keep text it dropped
    if not visible and not parser.hidden and src.strip():
        return pairs, []
    return visible, parser.hidden


def _strip_invisible(pairs: list[Pair], transforms: list[str], tag_text: list[Pair]) -> list[Pair]:
    out: list[Pair] = []
    saw_zw = saw_bidi = False
    for c, span in pairs:
        if c in ZERO_WIDTH:
            saw_zw = True
        elif c in BIDI:
            saw_bidi = True
        elif 0xE0000 <= ord(c) <= 0xE007F:
            cp = ord(c) - 0xE0000
            tag_text.append((chr(cp) if 0x20 <= cp <= 0x7E else " ", span))
        elif unicodedata.category(c) in {"Cc"} and c not in "\n\r\t":
            continue
        else:
            out.append((c, span))
    if saw_zw:
        transforms.append("zero_width")
    if saw_bidi:
        transforms.append("bidi_controls")
    if tag_text:
        transforms.append("unicode_tags")
    return out


def _nfkc(pairs: list[Pair], transforms: list[str]) -> list[Pair]:
    out: list[Pair] = []
    i, n, changed = 0, len(pairs), False
    while i < n:
        c, span = pairs[i]
        j = i + 1
        while j < n and unicodedata.category(pairs[j][0]).startswith("M"):
            j += 1
        chunk = "".join(p[0] for p in pairs[i:j])
        norm = unicodedata.normalize("NFKC", chunk) if not chunk.isascii() else chunk
        if norm != chunk:
            changed = True
        hi = max(p[1][1] for p in pairs[i:j])
        for ch in norm:
            out.append((ch, (span[0], hi)))
        i = j
    if changed:
        transforms.append("nfkc")
    return out


def _fold_homoglyphs(pairs: list[Pair], transforms: list[str], found: list[str]) -> list[Pair]:
    text = "".join(p[0] for p in pairs)
    if text.isascii():
        return pairs
    out = list(pairs)
    folded = False
    for m in _WORD.finditer(text):
        word = m.group(0)
        if word.isascii():
            continue
        scripts = set()
        for ch in word:
            try:
                scripts.add(unicodedata.name(ch).split()[0])
            except ValueError:
                scripts.add("?")
        if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK"}:
            found.append(word)
            folded = True
            for k in range(m.start(), m.end()):
                rep = HOMOGLYPHS.get(out[k][0])
                if rep:
                    out[k] = (rep, out[k][1])
    if folded:
        transforms.append("homoglyphs")
    return out


def _decode_blobs(pairs: list[Pair], hidden: list[Pair], transforms: list[str], depth: int = 2) -> None:
    text = "".join(p[0] for p in pairs)
    queue = [(text, [p[1] for p in pairs], 0)]
    while queue:
        s, spans, d = queue.pop()
        if d >= depth:
            continue
        for kind, rx in (("base64", _B64), ("hex", _HEX), ("percent", _PCT)):
            for m in rx.finditer(s):
                decoded = _decode_blob(kind, m.group(0))
                if decoded is None:
                    continue
                span = (min(x[0] for x in spans[m.start():m.end()]), max(x[1] for x in spans[m.start():m.end()]))
                transforms.append(f"decoded_{kind}")
                for c in "\n" + decoded + "\n":
                    hidden.append((c, span))
                queue.append((decoded, [span] * len(decoded), d + 1))


def _identity_safe(s: str) -> bool:
    """Plain printable ASCII with no markup, entities, percent-escapes or long encoded-looking runs."""
    if not s.isascii() or any(ch in s for ch in "<&%"):
        return False
    if any(ord(c) < 32 and c not in "\n\r\t" for c in s):
        return False
    return not (_B64.search(s) or _HEX.search(s))


def normalize(raw: str | bytes, *, max_bytes: int = 200_000) -> Normalized:
    """Never raises: any input yields a `Normalized` (possibly flagged `unscannable` / `truncated`)."""
    if isinstance(raw, (bytes, bytearray)):
        if looks_binary(bytes(raw)):
            return Normalized(transforms=["unscannable"], unscannable=True, source_len=len(raw))
        s = bytes(raw).decode("utf-8", errors="replace")
    else:
        s = raw
    source_len = len(s)
    if not s:
        return Normalized(source_len=0)
    truncated = source_len > max_bytes
    if not truncated and _identity_safe(s):
        return Normalized(text=s, source_len=source_len)
    transforms: list[str] = []
    if truncated:
        half = max_bytes // 2
        marker = "\n[...truncated...]\n"
        pairs: list[Pair] = [(c, (i, i + 1)) for i, c in enumerate(s[:half])]
        pairs += [(c, (half, source_len - half)) for c in marker]
        pairs += [(c, (source_len - half + i, source_len - half + i + 1)) for i, c in enumerate(s[-half:])]
        transforms.append("truncated")
        src_for_html = None
    else:
        pairs = [(c, (i, i + 1)) for i, c in enumerate(s)]
        src_for_html = s if ("<" in s or _ENTITY.search(s)) else None
    hidden: list[Pair] = []
    if src_for_html is not None:
        pairs, hidden = _split_html(src_for_html, pairs, transforms)
    tag_text: list[Pair] = []
    pairs = _strip_invisible(pairs, transforms, tag_text)
    hidden = _strip_invisible(hidden, [], [])
    if tag_text:
        hidden += [("\n", tag_text[0][1]), *tag_text, ("\n", tag_text[-1][1])]
    pairs = _nfkc(pairs, transforms)
    hidden = _nfkc(hidden, [])
    found: list[str] = []
    pairs = _fold_homoglyphs(pairs, transforms, found)
    _decode_blobs(pairs, hidden, transforms)
    _decode_blobs(hidden, hidden, transforms) if len(hidden) < 50_000 else None
    return Normalized(
        text="".join(p[0] for p in pairs), hidden_text="".join(p[0] for p in hidden),
        transforms=list(dict.fromkeys(transforms)), text_map=[p[1] for p in pairs], hidden_map=[p[1] for p in hidden],
        source_len=source_len, truncated=truncated, homoglyph_words=found)


_ = html
