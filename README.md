# JS-LeakHunter

A fast, lightweight Python recon tool that scans a website's JavaScript for:

- **Hidden endpoints** (`/api/...`, `/admin/...`, absolute URLs)
- **Leaked secrets** (AWS keys, Google API keys, GitHub/Slack/Stripe tokens, JWTs, private keys, generic `api_key = "..."` assignments), each with a confidence level
- **Config / env endpoints** called by the code (`fetch("/api/config")`, `axios.get("/settings")`, ...), flagged for manual review
- **Interesting URL parameters** grouped by likely issue class (IDOR, Open Redirect, XSS/Injection, SSRF/File)
- **Original source code from source maps** (`.map`), so minified bundles can be scanned in readable form

> **Legal notice:** use this tool only on systems you own or have explicit written permission to test. The author takes no responsibility for misuse.

## How it works

1. Fetches the target page.
2. Extracts every referenced `.js` file (`<script src>` plus paths found inline).
3. Skips well-known third-party libraries, first by file name, then by the license banner at the top of the file (so `bundle.js` or `vendor.js` containing jQuery is skipped too).
4. Runs regex detectors against the page and each remaining JS file.
5. If a JS file points to a source map (`//# sourceMappingURL=...`), downloads it and scans the original, unminified sources inside it.
6. Prints a colored report and optionally saves JSON.

The tool only performs normal GET requests. Config/env endpoints are **flagged, never requested**. Detected secrets are **never validated** against any API. Secrets are masked by default so reports are safe to share.

## Installation

```bash
git clone https://github.com/kainn0x4/JS-LeakHunter.git
cd JS-LeakHunter
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Requires Python 3.10 or newer.

## Usage

```bash
python leakhunter.py https://target.example
python leakhunter.py https://target.example -o results.json
python leakhunter.py https://target.example --all --show-secrets
python leakhunter.py https://target.example -H "Cookie: session=abc" --external
python leakhunter.py https://target.example --no-sourcemaps --min-entropy 3.5
```

| Option | Description |
|---|---|
| `-t, --timeout` | Request timeout in seconds (default 10) |
| `-o, --output` | Save results as JSON |
| `-H, --header` | Extra header, repeatable |
| `--user-agent` | Custom User-Agent (default: a Chrome-like browser UA) |
| `--external` | Also scan JS (and source maps) hosted on other domains |
| `--max-js` | Limit number of JS files (default 50) |
| `--include-vendor` | Also scan well-known library files such as jQuery (skipped by default) |
| `--no-sourcemaps` | Do not look for or download source maps |
| `--min-entropy` | Drop generic secret matches below this Shannon entropy (default 3.0) |
| `--insecure` | Skip TLS verification |
| `--show-secrets` | Print unmasked secret values |
| `--all` | Show all endpoints, not only interesting ones |
| `--version` | Print the version |

## Reading the results

**Secrets** have a confidence level:

- `high`: the value matched a known token format or looks random enough.
- `low`: the surrounding text contains words like `test`, `example`, `dummy` or `placeholder`. These are kept in the report but should be reviewed first for false positives.

The loose `api_key = "..."` rule is also filtered by entropy. Repetitive values such as `aaaaaaaaaaaaaaaa` are dropped and counted in the report. Prefixed tokens (`AKIA...`, `sk_live_...`, `ghp_...`) skip the entropy check because the prefix is already a strong signal.

**Config / env endpoints** are URLs passed to `fetch`, `axios`, `$.get`, `$http` or `xhr.open` whose path contains a whole word such as `config`, `env` or `settings`. Runtime configuration often lives behind endpoints like these rather than in static JS. They are listed for manual review only.

**Source maps**: when found, each original file is scanned and reported as `app.js::src/config.js`. Third-party code (`node_modules`) and bundler internals inside the map are skipped. A map hosted on a different domain is only downloaded with `--external`.

### Example output (illustrative)

```text
[*] Fetching https://target.example
[*] Found 3 JavaScript file(s) to check, skipped 2 library file(s) by name
    scanning https://target.example/static/app.js
[+] source map: scanned 14 original file(s) from https://target.example/static/app.js.map

╭───────────────────────────── JS-LeakHunter summary ─────────────────────────────╮
│ Target: https://target.example                                                  │
│ JS files: 3 (2 library files skipped)   Source maps: 1                          │
│ Endpoints: 41   Config/env calls: 1   Secrets: 1 high / 0 low confidence        │
│ Params: 4                                                                       │
╰─────────────────────────────────────────────────────────────────────────────────╯
```

## Limitations

- Detection is regex-based and static. Code that is built or loaded at runtime is not executed or rendered.
- Source maps are found only through the `sourceMappingURL` comment. Maps that exist without that comment are not discovered yet.
- Content-based library detection looks at the first 3000 characters. A custom bundle that starts with a library banner (for example, concatenated files) can be skipped by mistake. Use `--include-vendor` to scan everything, and check the skipped list in the JSON output.
- Generic secret rules can still produce false positives. Always verify manually.

## Responsible use

- Test only what you own or are explicitly authorized to test, and read the program's rules before scanning.
- Follow the program's rate limits and avoid repeated rapid scans of the same target.
- If a program asks for an identification header, add it with `-H`, for example `-H "X-Bug-Bounty: your-handle"`.
- The default User-Agent is browser-like because some sites reset connections from unknown clients. This is not a way around access controls, and it is not meant to be used against programs that forbid it.
- Never test discovered secrets against live APIs. Report them to the owner instead.

## Development

```bash
pip install pytest
python -m pytest -q
```

The test suite runs offline using local fixtures (positive and negative samples for every detector).

## Roadmap

- [x] Source map (`.map`) discovery via `sourceMappingURL`
- [x] Content-based library detection
- [x] Entropy-based filtering for generic secrets
- [x] Config/env endpoint flagging
- [x] Unit tests
- [ ] `--probe-maps`: check `file.js.map` when the comment is missing
- [ ] Concurrent downloads (`ThreadPoolExecutor`)
- [ ] GitHub Actions CI
- [ ] Custom regex rules via YAML
- [ ] Split into a `leakhunter/` package (fetcher, detectors, reporter)

## License

MIT
