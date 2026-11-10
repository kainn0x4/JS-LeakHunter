#!/usr/bin/env python3
"""JS-LeakHunter: passive JavaScript recon for authorized security testing.

Fetches a target page, discovers the JavaScript files it loads, and scans
them for hidden endpoints, leaked secrets and interesting URL parameters.

Use only against targets you own or have explicit written permission to test.
"""

from __future__ import annotations

import argparse
import base64
import json
import math
import re
import sys
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from urllib.parse import unquote, urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

__version__ = "0.2.0"

console = Console()

# A realistic browser UA: the old "JS-LeakHunter/x.y" UA was reset by a WAF at TLS
# level. Bump the Chrome version from time to time, or override with --user-agent.
DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
MAX_BODY_BYTES = 5 * 1024 * 1024  # skip JS/HTML responses larger than 5 MB
MAX_MAP_BYTES = 25 * 1024 * 1024  # source maps are much bigger than the code they describe
LIB_HEADER_CHARS = 3000  # license banners live at the very top of a file
CONTEXT_CHARS = 80  # how much text around a secret is checked for placeholder words
MIN_ENTROPY = 3.0  # Shannon entropy below this = repetitive junk like "aaaaaaaa..."

# --------------------------------------------------------------------------
# Patterns
# --------------------------------------------------------------------------

# Quoted relative paths such as "/api/v1/users" or "/admin/login?next=/"
RELATIVE_ENDPOINT_RE = re.compile(
    r"""["'`](/(?!/)[A-Za-z0-9_\-./~%{}$:]{2,}(?:\?[^"'`\s<>]{0,200})?)["'`]"""
)
# Quoted absolute URLs
ABSOLUTE_URL_RE = re.compile(r"""["'`](https?://[^\s"'`<>\\]{4,300})["'`]""")

# HTTP client calls whose first argument is a URL string: fetch("/x"), axios.get("/x"),
# $.getJSON("/x"), $http.get("/x") ...
HTTP_CALL_RE = re.compile(
    r"""(?<![\w$])(?:fetch|axios(?:\.(?:get|post|put|patch|delete|head|request))?"""
    r"""|\$\.(?:get|getJSON|post|ajax)|\$http\.(?:get|post))"""
    r"""\s*\(\s*["'`]([^"'`\n]{1,300})["'`]"""
)
# xhr.open("GET", "/x")
XHR_OPEN_RE = re.compile(
    r"""\.open\s*\(\s*["'`][A-Za-z]{3,7}["'`]\s*,\s*["'`]([^"'`\n]{1,300})["'`]"""
)
# Word tokens that make a request URL a runtime-config candidate
CONFIG_TOKENS = {"config", "configs", "configuration", "env", "environment", "settings", "setting"}

STATIC_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".css",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".map", ".mp4", ".mp3",
)

INTERESTING_KEYWORDS = (
    "api", "admin", "internal", "private", "graphql", "auth", "login",
    "oauth", "token", "upload", "debug", "config", "backup", "swagger",
    "v1", "v2", "v3", "user", "account", "payment", "export", "download",
)

# Well-known third-party library files are public code with nothing app-specific
# in them, so they are skipped by default (use --include-vendor to scan them).
# 1) By file name / path (cheap, works before downloading):
VENDOR_FILENAME_RE = re.compile(
    r"^(?:jquery(?:[-.](?:ui|migrate|slim|mobile|cookie))?|underscore|lodash|"
    r"bootstrap(?:\.bundle)?|popper|moment|axios|backbone|angular|react|react-dom|"
    r"vue|d3|gsap|swiper|slick|modernizr|polyfill|core-js|handlebars|mustache|"
    r"select2|datatables)"
    r"(?:[-.]?v?\d+(?:\.\d+)*)?(?:[-.](?:min|slim|umd|esm|bundle|production|development))*\.js$"
)
# Directory names / paths that normally hold third-party or CMS core code
VENDOR_PATH_HINTS = (
    "/vendor/", "/node_modules/", "/bower_components/", "/libs/",
    "/wp-includes/", "/core/misc/", "/core/assets/",  # WordPress / Drupal core
    "_incapsula_resource",  # Imperva WAF script
)
# 2) By content (works for bundle.js / vendor.js / chunk-abc123.js): license banners
#    in the first LIB_HEADER_CHARS characters of the file.
LIBRARY_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    (name, re.compile(pattern, re.IGNORECASE))
    for name, pattern in [
        ("jQuery", r"jQuery(?:\s+UI|\s+Migrate)?\s+(?:JavaScript\s+Library\s+)?v?\d+\.\d+"),
        ("OpenJS Foundation library", r"Copyright\s+(?:\(c\)\s*)?(?:OpenJS|JS)\s+Foundation"),
        ("Bootstrap", r"Bootstrap\s+v?\d+\.\d+"),
        ("Vue.js", r"Vue\.js\s+v?\d+\.\d+"),
        ("React", r"@license\s+React|React\s+v\d+\.\d+"),
        ("Angular", r"@license\s+Angular"),
        ("Lodash", r"lodash\.com|Lodash\s+\(Custom Build\)"),
        ("Underscore.js", r"Underscore\.js\s+\d"),
        ("Moment.js", r"Moment\.js"),
        ("Popper", r"Popper(?:\.js)?\s+v?\d+\.\d+"),
        ("Axios", r"Axios\s+v\d+\.\d+"),
        ("Swiper", r"Swiper\s+\d+\.\d+"),
        ("Owl Carousel", r"Owl\s+Carousel\s+v?\d+"),
        ("Slick", r"slick\.js|Slick\s+Slider"),
        ("Select2", r"Select2\s+\d+\.\d+"),
        ("Chart.js", r"Chart\.js\s+v?\d+\.\d+"),
        ("GSAP", r"GSAP\s+\d+\.\d+"),
        ("D3", r"d3js\.org"),
        ("Modernizr", r"Modernizr"),
        ("core-js", r"core-js"),
        ("Handlebars", r"Handlebars"),
        ("Backbone.js", r"Backbone\.js\s+\d"),
        ("Font Awesome", r"Font\s+Awesome"),
    ]
]

SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "AWS Access Key ID": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "Google API Key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "GitHub Token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "Slack Token": re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"),
    "Stripe Live Key": re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"),
    "Twilio API Key": re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
    "JSON Web Token": re.compile(
        r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"
    ),
    "Private Key Block": re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    ),
    "Generic Secret Assignment": re.compile(
        r"""(?i)\b(?:api[_-]?key|secret|access[_-]?token|auth[_-]?token|passwd|password)"""
        r"""["']?\s*[:=]\s*["']([A-Za-z0-9_\-/+=.]{16,})["']"""
    ),
}
# Only the loose rule needs an entropy check. Prefixed tokens (AKIA..., sk_live_...,
# ghp_...) are already a strong signal on their own.
ENTROPY_CHECKED = {"Generic Secret Assignment"}

# Words near a match that suggest it is sample / placeholder data, not a real secret.
PLACEHOLDER_RE = re.compile(
    r"(?<![a-z])(?:test|example|dummy|placeholder|sample|fake|mock|changeme|"
    r"your[_-]?(?:api[_-]?)?(?:key|token|secret)|x{4,})(?![a-z])",
    re.IGNORECASE,
)

PARAM_RE = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_\-\[\]]{0,39})=")

PARAM_CATEGORIES: dict[str, set[str]] = {
    "IDOR": {
        "id", "uid", "user", "user_id", "userid", "account", "account_id",
        "order", "order_id", "invoice", "doc", "profile", "customer",
    },
    "Open Redirect": {
        "url", "redirect", "redirect_uri", "redirect_url", "next", "return",
        "return_url", "returnto", "dest", "destination", "continue",
        "callback", "goto", "target", "link", "forward",
    },
    "XSS / Injection": {
        "q", "query", "search", "s", "keyword", "name", "msg", "message",
        "comment", "title", "text", "input", "page", "template", "lang",
    },
    "SSRF / File": {
        "file", "path", "filename", "dir", "folder", "load", "fetch",
        "image", "img", "src", "uri", "domain", "host", "proxy",
    },
}

SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=([^\s'\"]+)")

# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------


@dataclass
class ScanResult:
    target: str
    min_entropy: float = MIN_ENTROPY
    js_files: list[str] = field(default_factory=list)  # files that were really scanned
    skipped_vendor: list[dict[str, str]] = field(default_factory=list)
    sourcemaps: list[dict[str, object]] = field(default_factory=list)
    endpoints: dict[str, set[str]] = field(default_factory=dict)
    config_endpoints: dict[str, set[str]] = field(default_factory=dict)
    secrets: list[dict[str, str]] = field(default_factory=list)
    filtered_low_entropy: int = 0
    params: dict[str, set[str]] = field(default_factory=dict)

    def to_dict(self, reveal_secrets: bool = False) -> dict:
        return {
            "target": self.target,
            "js_files": self.js_files,
            "skipped_vendor": self.skipped_vendor,
            "sourcemaps": self.sourcemaps,
            "endpoints": {k: sorted(v) for k, v in sorted(self.endpoints.items())},
            "config_endpoints": {k: sorted(v) for k, v in sorted(self.config_endpoints.items())},
            "secrets": [
                {**s, "value": s["value"] if reveal_secrets else mask(s["value"])}
                for s in self.secrets
            ],
            "secrets_filtered_low_entropy": self.filtered_low_entropy,
            "params": {k: sorted(v) for k, v in sorted(self.params.items())},
        }


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def mask(value: str) -> str:
    """Hide most of a secret so reports are safe to share."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-2:]}"


def shannon_entropy(s: str) -> float:
    """Bits of entropy per character. Repetitive strings score low, random ones high."""
    if not s:
        return 0.0
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in Counter(s).values())


def fetch(
    session: requests.Session,
    url: str,
    timeout: int,
    verify: bool,
    max_bytes: int = MAX_BODY_BYTES,
) -> str | None:
    """GET a URL and return its text, or None on any failure.

    The body is streamed so an oversized response is abandoned early instead of
    being downloaded completely first.
    """
    shown = escape(url)
    try:
        with session.get(
            url, timeout=timeout, verify=verify, allow_redirects=True, stream=True
        ) as resp:
            if resp.status_code != 200:
                console.print(f"[yellow][!][/yellow] {shown} -> HTTP {resp.status_code}")
                return None
            declared = resp.headers.get("Content-Length", "")
            if declared.isdigit() and int(declared) > max_bytes:
                console.print(f"[yellow][!][/yellow] {shown} skipped (larger than {max_bytes // 1024 // 1024} MB)")
                return None
            chunks: list[bytes] = []
            size = 0
            for chunk in resp.iter_content(65536):
                size += len(chunk)
                if size > max_bytes:
                    console.print(f"[yellow][!][/yellow] {shown} skipped (larger than {max_bytes // 1024 // 1024} MB)")
                    return None
                chunks.append(chunk)
            # requests guesses ISO-8859-1 for text/* without a charset: trust only an explicit one
            has_charset = "charset" in resp.headers.get("Content-Type", "").lower()
            encoding = (resp.encoding if has_charset else None) or "utf-8"
    except requests.RequestException as exc:
        console.print(f"[red][-][/red] {shown} -> {exc.__class__.__name__}")
        return None

    data = b"".join(chunks)
    try:
        return data.decode(encoding, errors="replace")
    except LookupError:
        return data.decode("utf-8", errors="replace")


def extract_js_urls(html: str, base_url: str, include_external: bool) -> list[str]:
    """Find every JavaScript file referenced by the page."""
    soup = BeautifulSoup(html, "html.parser")
    base_host = urlparse(base_url).netloc
    found: set[str] = set()

    for tag in soup.find_all("script", src=True):
        found.add(urljoin(base_url, tag["src"]))

    # Also catch dynamically referenced files, e.g. "/static/app.js" in inline code
    for match in re.finditer(r"""["']([^"'\s]+\.js(?:\?[^"'\s]*)?)["']""", html):
        found.add(urljoin(base_url, match.group(1)))

    result = []
    for url in sorted(found):
        if urlparse(url).scheme not in ("http", "https"):
            continue
        if not include_external and urlparse(url).netloc != base_host:
            continue
        result.append(url)
    return result


def is_vendor(url: str) -> bool:
    """True for well-known library files (jQuery, lodash, ...) and vendor/core paths, by name."""
    path = urlparse(url).path.lower()
    filename = path.rsplit("/", 1)[-1]
    if VENDOR_FILENAME_RE.match(filename):
        return True
    return any(hint in path for hint in VENDOR_PATH_HINTS)


def detect_library(content: str) -> str | None:
    """Name of the library if the file's license banner identifies it, else None.

    Only the top of the file is checked: that is where banners live, and it keeps
    application code that merely *mentions* a library from being skipped.
    """
    header = content[:LIB_HEADER_CHARS]
    for name, pattern in LIBRARY_SIGNATURES:
        if pattern.search(header):
            return name
    return None


def is_static_asset(path: str) -> bool:
    return urlparse(path).path.lower().endswith(STATIC_EXTENSIONS)


def is_config_endpoint(url: str) -> bool:
    """True if the URL path contains a whole word like config / env / settings."""
    tokens = re.split(r"[^a-z0-9]+", url.split("?", 1)[0].lower())
    return any(token in CONFIG_TOKENS for token in tokens)


def scan_text(text: str, source: str, result: ScanResult) -> None:
    """Run every detector against one blob of text (HTML or JS)."""
    # Endpoints
    candidates = set(RELATIVE_ENDPOINT_RE.findall(text))
    candidates.update(ABSOLUTE_URL_RE.findall(text))
    for endpoint in candidates:
        if is_static_asset(endpoint):
            continue
        result.endpoints.setdefault(endpoint, set()).add(source)

    # Config / env endpoints: flagged only, never requested
    called = set(HTTP_CALL_RE.findall(text)) | set(XHR_OPEN_RE.findall(text))
    for url in called:
        if is_config_endpoint(url) and not is_static_asset(url):
            result.config_endpoints.setdefault(url, set()).add(source)

    # Secrets
    for name, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group(1) if match.groups() else match.group(0)
            # The same value can match a specific and the generic rule: keep the first (most specific)
            if any(s["value"] == value and s["source"] == source for s in result.secrets):
                continue
            if name in ENTROPY_CHECKED and shannon_entropy(value) < result.min_entropy:
                result.filtered_low_entropy += 1
                continue
            window = text[max(0, match.start() - CONTEXT_CHARS): match.end() + CONTEXT_CHARS]
            confidence = "low" if PLACEHOLDER_RE.search(window) else "high"
            result.secrets.append(
                {"type": name, "value": value, "source": source, "confidence": confidence}
            )

    # Parameters
    for param in PARAM_RE.findall(text):
        result.params.setdefault(param, set()).add(source)


def categorize_param(param: str) -> str | None:
    key = param.lower()
    for category, names in PARAM_CATEGORIES.items():
        if key in names:
            return category
    return None


def is_interesting(endpoint: str) -> bool:
    lowered = endpoint.lower()
    return any(word in lowered for word in INTERESTING_KEYWORDS)


# --------------------------------------------------------------------------
# Source maps
# --------------------------------------------------------------------------


def find_sourcemap_ref(js_content: str) -> str | None:
    """Return the value of the last //# sourceMappingURL=... comment, if any."""
    # The comment is always at the end of the file, so don't regex the whole bundle
    matches = SOURCEMAP_RE.findall(js_content[-4096:])
    return matches[-1] if matches else None


def clean_source_name(name: str) -> str:
    """webpack:///./src/api.js -> src/api.js"""
    name = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", name).lstrip("/")
    return re.sub(r"^(?:\.\./|\./)+", "", name)


def skip_map_source(name: str) -> bool:
    """Third-party code and bundler internals inside a source map are not worth scanning."""
    lowered = name.lower()
    return lowered.startswith("webpack/") or is_vendor("/" + lowered)


def iter_map_sources(data: object, depth: int = 0) -> Iterator[tuple[str, str]]:
    """Yield (original file name, original source code) pairs from a parsed source map."""
    if not isinstance(data, dict) or depth > 3:
        return
    for section in data.get("sections") or []:  # "indexed" source maps
        if isinstance(section, dict):
            yield from iter_map_sources(section.get("map"), depth + 1)
    names = data.get("sources") or []
    contents = data.get("sourcesContent") or []
    for name, content in zip(names, contents):
        if isinstance(name, str) and isinstance(content, str) and content.strip():
            yield clean_source_name(name), content


def decode_data_uri(ref: str) -> str | None:
    """Decode an inline data:application/json source map."""
    header, _, payload = ref.partition(",")
    if not header.lower().startswith("data:application/json"):
        return None
    try:
        if ";base64" in header.lower():
            return base64.b64decode(payload).decode("utf-8", errors="replace")
        return unquote(payload)
    except ValueError:
        return None


def load_sourcemap(
    session: requests.Session,
    js_url: str,
    ref: str,
    timeout: int,
    verify: bool,
    allow_external: bool,
) -> tuple[str, list[tuple[str, str]]] | None:
    """Download (or decode) a source map and return (label, [(file, code), ...])."""
    if ref.startswith("data:"):
        if len(ref) > MAX_MAP_BYTES * 2:
            return None
        raw = decode_data_uri(ref)
        label = "(inline data URI)"
    else:
        map_url = urljoin(js_url, ref)
        parsed = urlparse(map_url)
        if parsed.scheme not in ("http", "https"):
            return None
        # A map must live next to its script unless the user allowed external hosts
        if not allow_external and parsed.netloc != urlparse(js_url).netloc:
            console.print(f"[dim]    source map on another host skipped: {escape(map_url)}[/dim]")
            return None
        raw = fetch(session, map_url, timeout, verify, max_bytes=MAX_MAP_BYTES)
        label = map_url
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None

    sources = [
        (name, code) for name, code in iter_map_sources(data) if not skip_map_source(name)
    ]
    return label, sources


def scan_sourcemap(
    session: requests.Session,
    js_url: str,
    js_content: str,
    result: ScanResult,
    timeout: int,
    verify: bool,
    allow_external: bool,
) -> None:
    """If the JS file points to a source map, scan the original (unminified) sources."""
    ref = find_sourcemap_ref(js_content)
    if not ref:
        return
    loaded = load_sourcemap(session, js_url, ref, timeout, verify, allow_external)
    if loaded is None:
        return
    label, sources = loaded
    if not sources:
        console.print(f"[yellow][!][/yellow] source map found but it has no usable sourcesContent: {escape(label)}")
        return
    js_name = urlparse(js_url).path.rsplit("/", 1)[-1] or js_url
    for name, code in sources:
        scan_text(code, f"{js_name}::{name}", result)
    result.sourcemaps.append({"js": js_url, "map": label, "sources_scanned": len(sources)})
    console.print(
        f"[green][+][/green] source map: scanned {len(sources)} original file(s) from {escape(label)}"
    )


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------


def print_report(result: ScanResult, reveal_secrets: bool, show_all: bool) -> None:
    high = sum(1 for s in result.secrets if s["confidence"] == "high")
    low = len(result.secrets) - high
    console.print()
    console.print(
        Panel.fit(
            f"[bold]Target:[/bold] {escape(result.target)}\n"
            f"[bold]JS files:[/bold] {len(result.js_files)} "
            f"([dim]{len(result.skipped_vendor)} library files skipped[/dim])   "
            f"[bold]Source maps:[/bold] {len(result.sourcemaps)}\n"
            f"[bold]Endpoints:[/bold] {len(result.endpoints)}   "
            f"[bold]Config/env calls:[/bold] {len(result.config_endpoints)}   "
            f"[bold]Secrets:[/bold] {high} high / {low} low confidence   "
            f"[bold]Params:[/bold] {len(result.params)}",
            title="JS-LeakHunter summary",
            border_style="cyan",
        )
    )

    # Secrets first: highest value
    if result.secrets:
        table = Table(title="Potential secrets", border_style="red")
        table.add_column("Type", style="bold red")
        table.add_column("Confidence")
        table.add_column("Value")
        table.add_column("Source", overflow="fold")
        for s in sorted(result.secrets, key=lambda s: s["confidence"] != "high"):
            value = s["value"] if reveal_secrets else mask(s["value"])
            confidence = "[bold red]high[/bold red]" if s["confidence"] == "high" else "[dim]low[/dim]"
            table.add_row(s["type"], confidence, escape(value), escape(s["source"]))
        console.print(table)
    else:
        console.print("[green]No known secret patterns matched.[/green]")
    if result.filtered_low_entropy:
        console.print(
            f"[dim]{result.filtered_low_entropy} generic match(es) dropped: "
            f"entropy below {result.min_entropy} (repetitive placeholder values).[/dim]"
        )

    # Config / env endpoints (flagged only, no requests were sent to them)
    if result.config_endpoints:
        table = Table(
            title="Config / env endpoints called by the code (flagged only, not requested)",
            border_style="green",
        )
        table.add_column("Endpoint", overflow="fold")
        table.add_column("Found in", overflow="fold")
        for endpoint, sources in sorted(result.config_endpoints.items()):
            table.add_row(escape(endpoint), escape(", ".join(sorted(sources))[:120]))
        console.print(table)

    # Endpoints
    endpoints = sorted(result.endpoints.items())
    if not show_all:
        endpoints = [(e, s) for e, s in endpoints if is_interesting(e)]
    table = Table(
        title="Endpoints" + ("" if show_all else " (interesting only, use --all for everything)"),
        border_style="yellow",
    )
    table.add_column("Endpoint", overflow="fold")
    table.add_column("Found in", overflow="fold")
    for endpoint, sources in endpoints:
        table.add_row(escape(endpoint), escape(", ".join(sorted(sources))[:120]))
    console.print(table)

    # Parameters
    table = Table(title="Interesting parameters", border_style="magenta")
    table.add_column("Parameter", style="bold")
    table.add_column("Possible issue")
    table.add_column("Found in", overflow="fold")
    rows = []
    for param, sources in result.params.items():
        category = categorize_param(param)
        if category:
            rows.append((category, param, ", ".join(sorted(sources))[:100]))
    for category, param, sources in sorted(rows):
        table.add_row(escape(param), category, escape(sources))
    console.print(table)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leakhunter",
        description="Scan a website's JavaScript for endpoints, secrets and parameters.",
        epilog="Only test targets you own or are explicitly authorized to test.",
    )
    parser.add_argument("url", help="Target URL, e.g. https://example.com")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("-o", "--output", help="Save results to a JSON file")
    parser.add_argument("-H", "--header", action="append", default=[], metavar="'Name: value'",
                        help="Extra request header, can be repeated")
    parser.add_argument("--user-agent", default=DEFAULT_UA, help="Custom User-Agent (default: a Chrome-like browser UA)")
    parser.add_argument("--external", action="store_true", help="Also scan JS hosted on other domains (CDNs)")
    parser.add_argument("--max-js", type=int, default=50, help="Maximum JS files to scan (default: 50)")
    parser.add_argument("--include-vendor", action="store_true",
                        help="Also scan well-known library files such as jQuery (skipped by default)")
    parser.add_argument("--no-sourcemaps", action="store_true",
                        help="Do not look for or download source maps (.map)")
    parser.add_argument("--min-entropy", type=float, default=MIN_ENTROPY, metavar="BITS",
                        help=f"Drop generic secret matches below this Shannon entropy (default: {MIN_ENTROPY})")
    parser.add_argument("--insecure", action="store_true", help="Do not verify TLS certificates")
    parser.add_argument("--show-secrets", action="store_true", help="Show full secret values (default: masked)")
    parser.add_argument("--all", action="store_true", help="Show all endpoints, not just interesting ones")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main() -> int:
    args = build_parser().parse_args()

    target = args.url if "://" in args.url else f"https://{args.url}"
    if urlparse(target).scheme not in ("http", "https") or not urlparse(target).netloc:
        console.print("[red]Invalid URL.[/red]")
        return 2

    session = requests.Session()
    session.headers["User-Agent"] = args.user_agent
    for header in args.header:
        name, sep, value = header.partition(":")
        if not sep:
            console.print(f"[red]Bad header format:[/red] {escape(header)}")
            return 2
        session.headers[name.strip()] = value.strip()

    if args.insecure:
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]

    verify = not args.insecure
    console.print(f"[cyan][*][/cyan] Fetching {escape(target)}")
    html = fetch(session, target, args.timeout, verify)
    if html is None:
        return 1

    result = ScanResult(target=target, min_entropy=args.min_entropy)
    scan_text(html, "(main page)", result)

    js_urls = extract_js_urls(html, target, args.external)
    if not args.include_vendor:
        for url in js_urls:
            if is_vendor(url):
                result.skipped_vendor.append({"url": url, "reason": "file name / path"})
        js_urls = [u for u in js_urls if not is_vendor(u)]
    js_urls = js_urls[: args.max_js]  # the limit counts only files we will really download
    console.print(
        f"[cyan][*][/cyan] Found {len(js_urls)} JavaScript file(s) to check"
        + (f", skipped {len(result.skipped_vendor)} library file(s) by name" if result.skipped_vendor else "")
    )

    for js_url in js_urls:
        console.print(f"[dim]    scanning {escape(js_url)}[/dim]")
        body = fetch(session, js_url, args.timeout, verify)
        if not body:
            continue

        # Content-based library check: catches bundle.js / vendor.js / chunk-xxxx.js.
        # A skipped file contributes nothing: no endpoints, secrets, params or source map.
        library = None if args.include_vendor else detect_library(body)
        if library:
            result.skipped_vendor.append({"url": js_url, "reason": f"content: {library}"})
            console.print(f"[dim]    skipped, looks like a library ({library})[/dim]")
            continue

        result.js_files.append(js_url)
        scan_text(body, js_url, result)
        if not args.no_sourcemaps:
            scan_sourcemap(session, js_url, body, result, args.timeout, verify, args.external)

    print_report(result, args.show_secrets, args.all)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(result.to_dict(reveal_secrets=args.show_secrets), fh, indent=2)
        console.print(f"[green][+][/green] Results saved to {escape(args.output)}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(130)
