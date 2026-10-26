"""M4 pieces without a database: the catalog, the heuristics and the log parsers."""

from datetime import UTC, datetime

import pytest

from agentshield.shadow import parsers
from agentshield.shadow.catalog import classify_host, services, suggested_alternative


def test_the_catalog_loads_and_every_entry_is_complete():
    cat = services()
    assert len(cat) >= 40
    assert all(s.vendor and s.category and s.risk in {"low", "medium", "high"} for s in cat.values())


@pytest.mark.parametrize(("host", "vendor"), [("chat.openai.com", "OpenAI"), ("API.OpenAI.com", "OpenAI"), ("www.claude.ai", "Anthropic"), ("eu.api.mistral.ai", "Mistral"),
                                              ("chatgpt.com:443", "OpenAI"), ("gemini.google.com.", "Google")])
def test_catalog_matches_the_host_and_its_subdomains(host, vendor):
    m = classify_host(host)
    assert m and m.vendor == vendor and m.reason == "catalog"


@pytest.mark.parametrize("host", ["example.com", "notopenai.com", "openai.com.evil.example", "localhost", "", "google.com", "mycompany.huggingface.co.attacker.net"])
def test_ordinary_and_look_alike_hosts_are_not_matched(host):
    assert classify_host(host) is None


def test_unknown_hosts_with_model_api_paths_are_flagged_by_heuristic():
    for path in ("/v1/chat/completions", "/v1/messages?beta=1", "/api/generate", "/openai/deployments/gpt4/chat", "/v1beta/models/gemini-pro:generateContent", "/v1/embeddings"):
        m = classify_host("llm.internal-startup.io", path)
        assert m and m.reason.startswith("heuristic") and m.vendor is None and m.risk == "high", path
    assert classify_host("shop.example.com", "/v1/orders") is None
    assert classify_host("shop.example.com", "/chat/completions-blog-post") is None


def test_the_suggested_alternative_names_the_tool():
    assert "chatgpt.com" in suggested_alternative(classify_host("chatgpt.com"))


def test_squid_lines_become_hits_with_the_user_or_client():
    hits, bad, _ = parsers.parse("squid", [
        "1790000000.123    120 10.0.0.5 TCP_MISS/200 5120 POST https://api.openai.com/v1/chat/completions alice HIER_DIRECT/1.2.3.4 application/json",
        "1790000001.000    10 10.0.0.6 TCP_TUNNEL/200 900 CONNECT chatgpt.com:443 - HIER_DIRECT/5.6.7.8 -", "garbage", ""], None)
    assert bad == 1 and len(hits) == 2
    assert (hits[0].user, hits[0].host, hits[0].path) == ("alice", "api.openai.com", "/v1/chat/completions")
    assert (hits[1].user, hits[1].host) == ("10.0.0.6", "chatgpt.com")
    assert hits[0].ts == datetime.fromtimestamp(1790000000.123, UTC)


def test_common_log_and_dns_lines():
    hits, bad, _ = parsers.parse("common", ['10.0.0.5 - bob [26/Oct/2026:10:00:00 +0000] "POST https://claude.ai/api/chat HTTP/1.1" 200 512',
                                            '10.0.0.5 - - [26/Oct/2026:10:00:01 +0000] "CONNECT poe.com:443 HTTP/1.1" 200 0', "nope"], None)
    assert bad == 1 and [(h.user, h.host) for h in hits] == [("bob", "claude.ai"), ("10.0.0.5", "poe.com")]
    hits, bad, _ = parsers.parse("dns", ["2026-10-26T10:00:00Z 10.0.0.7 chat.openai.com.", "# a comment", "short"], None)
    assert bad == 1 and hits[0].host == "chat.openai.com" and hits[0].user == "10.0.0.7"


def test_csv_with_flexible_headers_team_and_upload_size():
    hits, bad, _ = parsers.parse("csv", ["Timestamp,Username,Department,URL,Bytes_Sent", "2026-10-26T10:00:00Z,carol,Sales,https://chatgpt.com/backend-api/conversation,2500000",
                                         "2026-10-26T10:01:00Z,dan,,,5", "not a date,eve,,https://x.test/,1"], None)
    assert bad == 2 and len(hits) == 1
    assert (hits[0].user, hits[0].team, hits[0].host, hits[0].bytes_out) == ("carol", "Sales", "chatgpt.com", 2_500_000)


def test_records_and_their_failures():
    hits, bad, samples = parsers.parse("records", None, [{"ts": "2026-10-26T10:00:00Z", "host": "claude.ai", "user": "u1", "team": "Legal", "bytes_out": 12},
                                                         {"host": "x.test"}, {"ts": "2026-10-26T10:00:00Z"}, "not a dict"])  # type: ignore[list-item]
    assert len(hits) == 1 and bad == 3 and samples and hits[0].team == "Legal"


def test_overlong_lines_are_rejected_not_parsed():
    hits, bad, samples = parsers.parse("squid", ["x" * 5000], None)
    assert hits == [] and bad == 1 and samples == ["line too long"]
