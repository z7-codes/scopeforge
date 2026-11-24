import pytest

from dorklens.config import Config
from dorklens.modules.dirs import is_soft
from dorklens.modules.payloads import evaluate, replace_param, request_kwargs
from dorklens.report import dedupe
from dorklens.scope import Scope, ScopeError


class Response:
    def __init__(self, status: int, length: int, text: str = "") -> None:
        self.status = status
        self.length = length
        self.text = text
        self.headers: dict[str, str] = {}


def test_scope_wildcard() -> None:
    scope = Scope(allow=["*.t.io"])
    assert scope.in_scope("a.t.io")
    assert scope.in_scope("t.io")
    assert not scope.in_scope("t.io.evil.com")


def test_scope_deny_wins() -> None:
    scope = Scope(allow=["t.io", "*.t.io"], deny=["dev.t.io"])
    assert not scope.in_scope("dev.t.io")
    assert scope.in_scope("www.t.io")


def test_scope_needs_allow() -> None:
    with pytest.raises(ScopeError):
        Scope(allow=[])


def test_scope_norm() -> None:
    assert Scope(allow=["https://App.T.io/x"]).in_scope("app.t.io")


def test_replace_param() -> None:
    assert replace_param("http://a/?id=1", "id", "a b") == "http://a/?id=a+b"


def test_replace_param_keeps_others() -> None:
    result = replace_param("http://a/?x=1&id=9", "id", "'")
    assert "x=1" in result
    assert "id=%27" in result


def test_soft404() -> None:
    assert is_soft([(200, 4000)], 200, 4010)
    assert not is_soft([(200, 4000)], 500, 4000)


def test_length_delta() -> None:
    signal = {"type": "length_delta", "pct": 20}
    assert evaluate(signal, Response(200, 1000), Response(200, 2000), "x")[0]


def test_location_match() -> None:
    probe = Response(302, 0)
    probe.headers["location"] = "https://example.com/dorklens"
    signal = {"type": "location_match", "contains": "example.com"}
    assert evaluate(signal, Response(200, 10), probe, "x")[0]


def test_reflect_encoded() -> None:
    probe = Response(200, 100, "dorklens%3Csvg%2Fonload%3Dalert%281%29%3E")
    signal = {"type": "reflect", "raw": True}
    good, reason = evaluate(signal, Response(200, 10), probe, "dorklens<svg/onload=alert(1)>")
    assert good
    assert "encoded" in reason


def test_post_body_injection() -> None:
    spec = {"body": '{"email":{{INJECT}},"password":"x"}', "content_type": "application/json"}
    kwargs = request_kwargs(spec, '{"$ne":null}')
    assert kwargs["content"] == '{"email":{"$ne":null},"password":"x"}'
    assert kwargs["headers"]["Content-Type"] == "application/json"


def test_report_dedupe() -> None:
    base = {"url": "http://a.test/page?id=1", "param": "id", "category": "sqli_error", "confidence": 2}
    rows = [dict(base, payload="'"), dict(base, payload="1'")]
    result = dedupe(rows)
    assert len(result) == 1
    assert result[0]["variants"] == 1


def test_profile_full() -> None:
    cfg = Config.from_domain("example.com").apply_profile("full")
    assert cfg.stages == ["passive", "dork", "crawl", "dirs", "payload"]
    assert cfg.max_dork_queries == 40
    assert cfg.min_confidence == 2


def test_profile_deep() -> None:
    cfg = Config.from_domain("example.com").apply_profile("deep")
    assert "blind" in cfg.stages
    assert cfg.deep
