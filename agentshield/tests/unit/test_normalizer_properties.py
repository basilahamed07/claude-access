from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from agentshield.scan.normalizer import normalize, to_original_span

FRAGMENTS = list("<>&;!-/\"'=%#") + ["<!--", "-->", "<p>", "</p>", '<div style="display:none">', "&#105;", "\u200b", "\u202e",
                                      chr(0xE0041), "ﬁ", "а", "Zm9vYmFyYmF6cXV4", "%41%42%43%44%45%46"]
NASTY = st.lists(st.one_of(st.characters(blacklist_categories=("Cs",)), st.sampled_from(FRAGMENTS)),
                 max_size=120).map("".join)


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(NASTY)
def test_never_raises_and_spans_stay_inside_the_original(s):
    n = normalize(s)
    for hidden, text in ((False, n.text), (True, n.hidden_text)):
        for a, b in [(0, len(text)), (0, 1), (max(len(text) - 1, 0), len(text)), (len(text) // 2, len(text) // 2 + 3)]:
            lo, hi = to_original_span(n, (a, b), hidden=hidden)
            assert 0 <= lo <= hi <= len(s)


@settings(max_examples=200, deadline=None)
@given(st.binary(max_size=400))
def test_arbitrary_bytes_never_raise(b):
    n = normalize(b)
    assert isinstance(n.text, str)


@settings(max_examples=200, deadline=None)
@given(st.text(alphabet="abcdefghij klm.,!?\n", max_size=200))
def test_plain_text_is_unchanged(s):
    assert normalize(s).text == s


@settings(max_examples=150, deadline=None)
@given(NASTY)
def test_normalizing_twice_is_stable_for_visible_text(s):
    once = normalize(s).text
    assert normalize(once).text == normalize(normalize(once).text).text
