# JS-LeakHunter

A fast, lightweight Python recon tool that scans a website's JavaScript for:

- **Hidden endpoints** (`/api/...`, `/admin/...`, absolute URLs)
- **Leaked secrets** (AWS keys, Google API keys, GitHub/Slack/Stripe tokens, JWTs, private keys, generic `api_key = "..."` assignments)
- **Interesting URL parameters** grouped by likely issue class (IDOR, Open Redirect, XSS/Injection, SSRF/File)

> **Legal notice:** use this tool only on systems you own or have explicit written permission to test. The author takes no responsibility for misuse.

## How it works

1. Fetches the target page.
2. Extracts every referenced `.js` file (`<script src>` plus paths found inline).
3. Runs regex detectors against the page and each JS file.
4. Prints a colored report and optionally saves JSON.

The tool only performs normal `GET` requests. Secrets are **masked by default** so reports are safe to share.

## Installation

```bash
git clone https://github.com/kainn0x4/JS-LeakHunter.git
cd JS-LeakHunter
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

```bash
python leakhunter.py https://target.example
python leakhunter.py https://target.example -o results.json
python leakhunter.py https://target.example --all --show-secrets
python leakhunter.py https://target.example -H "Cookie: session=abc" --external
```

| Option | Description |
|---|---|
| `-t, --timeout` | Request timeout (default 10s) |
| `-o, --output` | Save results as JSON |
| `-H, --header` | Extra header, repeatable |
| `--external` | Also scan JS hosted on other domains |
| `--max-js` | Limit number of JS files (default 50) |
| `--insecure` | Skip TLS verification |
| `--show-secrets` | Print unmasked secret values |
| `--all` | Show all endpoints, not only interesting ones |

## Roadmap

- [ ] Split into a `leakhunter/` package (fetcher, detectors, reporter)
- [ ] Concurrent downloads (`ThreadPoolExecutor`)
- [ ] Source map (`.map`) discovery
- [ ] Entropy-based secret detection
- [ ] Custom regex rules via YAML
- [ ] Unit tests and GitHub Actions CI

## License

MIT
