#!/usr/bin/env python3
"""JS-LeakHunter: passive JavaScript recon for authorized security testing.

Fetches a target page, discovers the JavaScript files it loads, and scans
them for hidden endpoints, leaked secrets and interesting URL parameters.

Use only against targets you own or have explicit written permission to test.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

__version__ = "0.1.0"

console = Console()

DEFAULT_UA = f"JS-LeakHunter/{__version__} (+authorized security testing)"
MAX_BODY_BYTES = 5 * 1024 * 1024  # skip responses larger than 5 MB

# --------------------------------------------------------------------------
# Patterns
# --------------------------------------------------------------------------

# Quoted relative paths such as "/api/v1/users" or "/admin/login?next=/"
RELATIVE_ENDPOINT_RE = re.compile(
    r"""["'`](/(?!/)[A-Za-z0-9_\-./~%{}$:]{2,}(?:\?[^"'`\s<>]{0,200})?)["'`]"""
)
# Quoted absolute URLs
ABSOLUTE_URL_RE = re.compile(r"""["'`](https?://[^\s"'`<>\\]{4,300})["'`]""")

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

# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------


@dataclass
class ScanResult:
    target: str
    js_files: list[str] = field(default_factory=list)
    skipped_vendor: list[str] = field(default_factory=list)
    endpoints: dict[str, set[str]] = field(default_factory=dict)
    secrets: list[dict[str, str]] = field(default_factory=list)
    params: dict[str, set[str]] = field(default_factory=dict)

    def to_dict(self, reveal_secrets: bool = False) -> dict:
        return {
            "target": self.target,
            "js_files": self.js_files,
            "skipped_vendor": self.skipped_vendor,
            "endpoints": {k: sorted(v) for k, v in sorted(self.endpoints.items())},
            "secrets": [
                {**s, "value": s["value"] if reveal_secrets else mask(s["value"])}
                for s in self.secrets
            ],
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


def fetch(session: requests.Session, url: str, timeout: int, verify: bool) -> str | None:
    """GET a URL and return its text, or None on any failure."""
    try:
        resp = session.get(url, timeout=timeout, verify=verify, allow_redirects=True)
    except requests.RequestException as exc:
        console.print(f"[red][-][/red] {url} -> {exc.__class__.__name__}")
        return None

    if resp.status_code != 200:
        console.print(f"[yellow][!][/yellow] {url} -> HTTP {resp.status_code}")
        return None
    if len(resp.content) > MAX_BODY_BYTES:
        console.print(f"[yellow][!][/yellow] {url} skipped (larger than 5 MB)")
        return None
    return resp.text


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
    """True for well-known library files (jQuery, lodash, ...) and vendor/core paths."""
    path = urlparse(url).path.lower()
    filename = path.rsplit("/", 1)[-1]
    if VENDOR_FILENAME_RE.match(filename):
        return True
    return any(hint in path for hint in VENDOR_PATH_HINTS)


def is_static_asset(path: str) -> bool:
    return urlparse(path).path.lower().endswith(STATIC_EXTENSIONS)


def scan_text(text: str, source: str, result: ScanResult) -> None:
    """Run every detector against one blob of text (HTML or JS)."""
    # Endpoints
    candidates = set(RELATIVE_ENDPOINT_RE.findall(text))
    candidates.update(ABSOLUTE_URL_RE.findall(text))
    for endpoint in candidates:
        if is_static_asset(endpoint):
            continue
        result.endpoints.setdefault(endpoint, set()).add(source)

    # Secrets
    for name, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group(1) if match.groups() else match.group(0)
            # The same value can match a specific and the generic rule: keep the first (most specific)
            if any(s["value"] == value and s["source"] == source for s in result.secrets):
                continue
            result.secrets.append({"type": name, "value": value, "source": source})

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
# Output
# --------------------------------------------------------------------------


def print_report(result: ScanResult, reveal_secrets: bool, show_all: bool) -> None:
    console.print()
    console.print(
        Panel.fit(
            f"[bold]Target:[/bold] {result.target}\n"
            f"[bold]JS files:[/bold] {len(result.js_files)} "
            f"([dim]{len(result.skipped_vendor)} library files skipped[/dim])   "
            f"[bold]Endpoints:[/bold] {len(result.endpoints)}   "
            f"[bold]Secrets:[/bold] {len(result.secrets)}   "
            f"[bold]Params:[/bold] {len(result.params)}",
            title="JS-LeakHunter summary",
            border_style="cyan",
        )
    )

    # Secrets first: highest value
    if result.secrets:
        table = Table(title="Potential secrets", border_style="red")
        table.add_column("Type", style="bold red")
        table.add_column("Value")
        table.add_column("Source", overflow="fold")
        for s in result.secrets:
            value = s["value"] if reveal_secrets else mask(s["value"])
            table.add_row(s["type"], value, s["source"])
        console.print(table)
    else:
        console.print("[green]No known secret patterns matched.[/green]")

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
        table.add_row(endpoint, ", ".join(sorted(sources))[:120])
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
        table.add_row(param, category, sources)
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
    parser.add_argument("--user-agent", default=DEFAULT_UA, help="Custom User-Agent")
    parser.add_argument("--external", action="store_true", help="Also scan JS hosted on other domains (CDNs)")
    parser.add_argument("--max-js", type=int, default=50, help="Maximum JS files to scan (default: 50)")
    parser.add_argument("--include-vendor", action="store_true",
                        help="Also scan well-known library files such as jQuery (skipped by default)")
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
            console.print(f"[red]Bad header format:[/red] {header}")
            return 2
        session.headers[name.strip()] = value.strip()

    if args.insecure:
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]

    verify = not args.insecure
    console.print(f"[cyan][*][/cyan] Fetching {target}")
    html = fetch(session, target, args.timeout, verify)
    if html is None:
        return 1

    result = ScanResult(target=target)
    scan_text(html, "(main page)", result)

    js_urls = extract_js_urls(html, target, args.external)
    if not args.include_vendor:
        result.skipped_vendor = [u for u in js_urls if is_vendor(u)]
        js_urls = [u for u in js_urls if not is_vendor(u)]
    js_urls = js_urls[: args.max_js]  # the limit counts only files we will really scan
    result.js_files = js_urls
    console.print(
        f"[cyan][*][/cyan] Found {len(js_urls)} JavaScript file(s) to scan"
        + (f", skipped {len(result.skipped_vendor)} library file(s)" if result.skipped_vendor else "")
    )

    for js_url in js_urls:
        console.print(f"[dim]    scanning {js_url}[/dim]")
        body = fetch(session, js_url, args.timeout, verify)
        if body:
            scan_text(body, js_url, result)

    print_report(result, args.show_secrets, args.all)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(result.to_dict(reveal_secrets=args.show_secrets), fh, indent=2)
        console.print(f"[green][+][/green] Results saved to {args.output}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(130)
