from agentshield.proxy.sse import SseParser, format_event


def test_parser_handles_any_chunking_and_preserves_raw_bytes():
    data = b"event: a\ndata: {\"x\":1}\n\n: keepalive\n\ndata: [DONE]\n\n"
    for size in (1, 2, 3, 5, len(data)):
        p, events = SseParser(), []
        for i in range(0, len(data), size):
            events += p.feed(data[i:i + size])
        assert b"".join(e.raw for e in events) == data
        assert [e.event for e in events] == ["a", None, None]
        assert events[0].json() == {"x": 1} and events[2].data == "[DONE]"


def test_parser_handles_crlf_and_multiline_data_and_no_space_after_colon():
    p = SseParser()
    ev = p.feed(b"event: m\r\ndata:{\"a\":1}\r\ndata: tail\r\n\r\n")[0]
    assert ev.event == "m" and ev.data == '{"a":1}\ntail'


def test_incomplete_event_stays_in_remainder():
    p = SseParser()
    assert p.feed(b"data: partial") == []
    assert p.remainder() == b"data: partial"


def test_format_event():
    assert format_event("x", {"a": 1}) == b'event: x\ndata: {"a":1}\n\n'
    assert format_event(None, "[DONE]") == b"data: [DONE]\n\n"
