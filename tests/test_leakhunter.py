"""Offline regression tests for JS-LeakHunter (no network needed).

Run with:  pytest -q
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import leakhunter as lh  # noqa: E402

# Obviously fake values, shaped like real ones
FAKE_AWS = "AKIAQ3X7ZK2M9WLP4TNB"
RANDOM_VALUE = "k8Jd92LmQp3XvB7nRt5Zw"


def new_result() -> lh.ScanResult:
    return lh.ScanResult(target="https://t.example")


# ---------------------------------------------------------------- change 1: UA


def test_default_ua_is_browser_like():
    assert lh.DEFAULT_UA.startswith("Mozilla/5.0")
    assert "JS-LeakHunter" not in lh.DEFAULT_UA


def test_user_agent_can_be_overridden():
    args = lh.build_parser().parse_args(["https://t.example", "--user-agent", "custom/1.0"])
    assert args.user_agent == "custom/1.0"


# ---------------------------------------------------------- change 2: source maps


def test_find_sourcemap_ref():
    assert lh.find_sourcemap_ref("var a=1;\n//# sourceMappingURL=app.js.map") == "app.js.map"
    assert lh.find_sourcemap_ref("var a=1;\n//@ sourceMappingURL=old.map\n") == "old.map"
    assert lh.find_sourcemap_ref("var a=1; // no map here") is None


def test_clean_source_name():
    assert lh.clean_source_name("webpack:///./src/api.js") == "src/api.js"
    assert lh.clean_source_name("../src/a.js") == "src/a.js"


def test_iter_map_sources_handles_null_and_empty_content():
    data = {"sources": ["a.js", "b.js", "c.js"], "sourcesContent": ["code a", None, "  "]}
    assert list(lh.iter_map_sources(data)) == [("a.js", "code a")]


def test_iter_map_sources_indexed_map():
    inner = {"sources": ["x.js"], "sourcesContent": ["code x"]}
    data = {"sections": [{"map": inner}]}
    assert list(lh.iter_map_sources(data)) == [("x.js", "code x")]


def test_skip_map_source_vendor_and_webpack_runtime():
    assert lh.skip_map_source("node_modules/lodash/lodash.js")
    assert lh.skip_map_source("webpack/bootstrap")
    assert not lh.skip_map_source("src/api/client.js")


def test_data_uri_sourcemap():
    payload = json.dumps({"sources": ["src/a.js"], "sourcesContent": ["const x = 1;"]})
    ref = "data:application/json;base64," + base64.b64encode(payload.encode()).decode()
    label, sources = lh.load_sourcemap(None, "https://t.example/app.js", ref, 5, True, False)
    assert sources == [("src/a.js", "const x = 1;")]


def test_sourcemap_downloaded_and_scanned_with_original_filename():
    map_json = json.dumps(
        {
            "sources": ["webpack:///./src/config.js", "webpack:///./node_modules/x/index.js"],
            "sourcesContent": [f'const key = "{FAKE_AWS}";', f'const key = "{FAKE_AWS}";'],
        }
    )
    js = "var a=1;\n//# sourceMappingURL=app.js.map"
    result = new_result()
    requested = []

    def fake_fetch(session, url, timeout, verify, max_bytes=0):
        requested.append(url)
        return map_json

    with patch.object(lh, "fetch", fake_fetch):
        lh.scan_sourcemap(None, "https://t.example/static/app.js", js, result, 5, True, False)

    assert requested == ["https://t.example/static/app.js.map"]  # relative ref joined to JS URL
    assert result.sourcemaps[0]["sources_scanned"] == 1  # node_modules source skipped
    assert len(result.secrets) == 1
    assert result.secrets[0]["source"] == "app.js::src/config.js"


def test_sourcemap_on_other_host_is_not_fetched_by_default():
    js = "x\n//# sourceMappingURL=https://evil.example/app.js.map"
    result = new_result()
    with patch.object(lh, "fetch", side_effect=AssertionError("must not be requested")):
        lh.scan_sourcemap(None, "https://t.example/app.js", js, result, 5, True, False)
    assert result.sourcemaps == []


# ------------------------------------------------------ change 3: library detection


def test_detect_library_by_banner_even_with_generic_filename():
    banner = "/*! jQuery v3.6.0 | (c) OpenJS Foundation and other contributors */\n"
    assert lh.detect_library(banner + "x" * 500) == "jQuery"
    assert lh.detect_library("/*! Vue.js v2.7.14 */ ...") == "Vue.js"


def test_detect_library_ignores_app_code_and_late_mentions():
    assert lh.detect_library("function login(){ fetch('/api/login') }") is None
    # a banner far down the file belongs to something concatenated later, not the file itself
    assert lh.detect_library("x" * 5000 + "/*! jQuery v3.6.0 */") is None


def test_skipped_library_params_and_endpoints_do_not_reach_report(tmp_path):
    pages = {
        "https://t.example/": (
            '<html><script src="/static/bundle.js"></script>'
            '<script src="/static/app.js"></script></html>'
        ),
        # generic name, but jQuery inside: must be skipped completely
        "https://t.example/static/bundle.js": (
            "/*! jQuery v3.6.0 */ var u='/lib/only?s=1&template=2'; fetch('/lib/config');"
        ),
        "https://t.example/static/app.js": "var u='/api/orders?order_id=5'; fetch('/api/settings');",
    }
    out = tmp_path / "out.json"

    with patch.object(lh, "fetch", lambda s, url, *a, **k: pages.get(url)), patch.object(
        sys, "argv", ["leakhunter", "https://t.example/", "-o", str(out)]
    ):
        assert lh.main() == 0

    data = json.loads(out.read_text())
    assert data["js_files"] == ["https://t.example/static/app.js"]
    assert data["skipped_vendor"] == [
        {"url": "https://t.example/static/bundle.js", "reason": "content: jQuery"}
    ]
    assert "s" not in data["params"] and "template" not in data["params"]
    assert "order_id" in data["params"]
    assert "/lib/config" not in data["config_endpoints"]
    assert "/api/settings" in data["config_endpoints"]


# --------------------------------------------------- change 4: entropy + context


def test_shannon_entropy():
    assert lh.shannon_entropy("") == 0
    assert lh.shannon_entropy("aaaaaaaaaaaaaaaa") == 0
    assert lh.shannon_entropy(RANDOM_VALUE) > 3.5


def test_generic_rule_drops_repetitive_values_and_counts_them():
    result = new_result()
    lh.scan_text('var api_key = "aaaaaaaaaaaaaaaaaaaa";', "f.js", result)
    assert result.secrets == []
    assert result.filtered_low_entropy == 1


def test_generic_rule_keeps_random_values_with_high_confidence():
    result = new_result()
    lh.scan_text(f'var api_key = "{RANDOM_VALUE}";', "f.js", result)
    assert [s["confidence"] for s in result.secrets] == ["high"]


def test_placeholder_context_lowers_confidence_but_keeps_the_finding():
    result = new_result()
    lh.scan_text(f'// dummy credentials for the demo\nvar api_key = "{RANDOM_VALUE}";', "f.js", result)
    assert [s["confidence"] for s in result.secrets] == ["low"]


def test_prefixed_tokens_skip_entropy_check_and_are_high_confidence():
    result = new_result()
    lh.scan_text(f'var k = "{FAKE_AWS}";', "f.js", result)
    assert [(s["type"], s["confidence"]) for s in result.secrets] == [("AWS Access Key ID", "high")]


def test_aws_documentation_example_key_is_low_confidence():
    result = new_result()
    lh.scan_text('var k = "AKIAIOSFODNN7EXAMPLE";', "f.js", result)
    assert [s["confidence"] for s in result.secrets] == ["low"]


def test_same_value_is_not_reported_twice_by_specific_and_generic_rules():
    result = new_result()
    lh.scan_text(f'var secret = "{FAKE_AWS}";', "f.js", result)
    assert len(result.secrets) == 1
    assert result.secrets[0]["type"] == "AWS Access Key ID"


def test_secrets_are_masked_in_json_by_default():
    result = new_result()
    lh.scan_text(f'var api_key = "{RANDOM_VALUE}";', "f.js", result)
    assert result.to_dict()["secrets"][0]["value"] == lh.mask(RANDOM_VALUE)
    assert result.to_dict(reveal_secrets=True)["secrets"][0]["value"] == RANDOM_VALUE


# ------------------------------------------------ change 5: config/env flagging


def test_config_endpoint_positive_cases():
    result = new_result()
    js = """
        fetch("/api/config");
        axios.get('/runtime/env.json');
        $.getJSON("/settings");
        fetch(`${BASE}/app/configuration`);
        xhr.open("GET", "/environment");
        window.fetch("/api/v1/settings?x=1");
    """
    lh.scan_text(js, "app.js", result)
    assert set(result.config_endpoints) == {
        "/api/config",
        "/runtime/env.json",
        "/settings",
        "${BASE}/app/configuration",
        "/environment",
        "/api/v1/settings?x=1",
    }


def test_config_endpoint_negative_cases():
    result = new_result()
    js = """
        fetch("/api/users");
        axios.post("/api/prevent");
        fetch("/api/envelope");
        var notACall = "/config";
        fetch(url);
    """
    lh.scan_text(js, "app.js", result)
    assert result.config_endpoints == {}


def test_config_endpoint_is_flagged_only_and_never_requested():
    result = new_result()
    with patch.object(lh, "fetch", side_effect=AssertionError("must not be requested")):
        lh.scan_text('fetch("/api/config")', "app.js", result)
    assert "/api/config" in result.config_endpoints


# ------------------------------------------------------------- fetch() itself


class FakeResponse:
    def __init__(self, body: bytes, status=200, headers=None, encoding=None):
        self._body, self.status_code = body, status
        self.headers = headers or {}
        self.encoding = encoding

    def iter_content(self, size):
        for i in range(0, len(self._body), size):
            yield self._body[i : i + size]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeSession:
    def __init__(self, response):
        self.response = response

    def get(self, url, **kwargs):
        assert kwargs.get("stream") is True
        return self.response


def test_fetch_returns_text_and_decodes_utf8_without_charset():
    body = "var s = 'şəkil';".encode("utf-8")
    resp = FakeResponse(body, headers={"Content-Type": "text/javascript"}, encoding="ISO-8859-1")
    assert lh.fetch(FakeSession(resp), "https://t.example/a.js", 5, True) == "var s = 'şəkil';"


def test_fetch_rejects_declared_and_actual_oversize_and_non_200():
    big = FakeResponse(b"x" * 10, headers={"Content-Length": "999999"})
    assert lh.fetch(FakeSession(big), "https://t.example/a.js", 5, True, max_bytes=100) is None
    liar = FakeResponse(b"x" * 500)  # no Content-Length header, body too large
    assert lh.fetch(FakeSession(liar), "https://t.example/a.js", 5, True, max_bytes=100) is None
    assert lh.fetch(FakeSession(FakeResponse(b"", status=404)), "https://t.example/a.js", 5, True) is None
