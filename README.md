# wafscope

Multi-signal WAF and web-firewall fingerprinting. wafscope combines passive evidence (headers,
cookies, DNS/CNAME, IP ranges, TLS certificate), active probes compared against a control
request, and optional DNS history, then reports a confidence score with the evidence behind it.

- Zero dependencies: Python 3.9+ standard library only (`cryptography` is optional).
- Fast: every check runs concurrently, roughly two round trips plus DNS for a full scan.
- Explains itself: each vendor is listed with the exact signals that produced its score.
- Separates "a vendor is in front" from "something is actively blocking", which is the
  difference between a CDN-only setup, a WAF in monitor mode, and an enforcing WAF.

> **Authorised use only.** The active probes send inert XSS/SQLi/LFI/CMDi/SSTI/Log4j strings
> that WAFs are designed to flag, so they will raise alerts at the target. Only scan systems
> you own or have written permission to test. See [Disclaimer](#disclaimer).

## Example

Output against the bundled local simulator (`tests/mock_server.py`):

```text
  +--------------------------------------------------------+
  | #   #   ###   #####   ####   ####   ###   ####   ##### |
  | #   #  #   #  #      #      #      #   #  #   #  #     |
  | # # #  #####  ####    ###   #      #   #  ####   ####  |
  | ## ##  #   #  #          #  #      #   #  #      #     |
  | #   #  #   #  #      ####    ####   ###   #      ##### |
  +--------------------------------------------------------+
   WAF / firewall fingerprinting  v0.1.0
   passive + active + history  |  authorized targets only

Target  http://127.0.0.1:8141/
Result  [DETECTED] WAF detected: Cloudflare (confidence high); active blocking observed

-- Vendors ---------------------------------------------------
  [####################] 0.99  Cloudflare  << blocking confirmed
      +0.85 Cloudflare block page  <probe:xss-script>
      +0.60 cf-ray header  <baseline>
      +0.60 Server: cloudflare  <baseline>
      +0.50 Cloudflare cookie  <baseline>

-- Active probes (vs control) --------------------------------
  xss-script   403         2 ms  BLOCKED  HTTP 403 (control 200)
  xss-img      403         1 ms  BLOCKED  HTTP 403 (control 200)
  sqli-or      403         3 ms  BLOCKED  HTTP 403 (control 200)
  sqli-union   403         4 ms  BLOCKED  HTTP 403 (control 200)
  lfi          403         4 ms  BLOCKED  HTTP 403 (control 200)
  cmdi         403         4 ms  BLOCKED  HTTP 403 (control 200)
  ssti         403         4 ms  BLOCKED  HTTP 403 (control 200)
  log4j-hdr    403         5 ms  BLOCKED  HTTP 403 (control 200)
  scanner-ua   403         5 ms  BLOCKED  HTTP 403 (control 200)
  behavioural confidence [####################] 0.99

-- Network ---------------------------------------------------
  DNS   127.0.0.1

  11 requests in 0.01 s
```

## Install and run

```bash
git clone https://github.com/<your-user>/wafscope.git
cd wafscope
python3 wafscope.py example.com
```

Optional, for certificate analysis: `pip install cryptography`.

```bash
python3 wafscope.py https://example.com            # full scan
python3 wafscope.py example.com --no-active        # passive signals only, no payloads sent
python3 wafscope.py example.com --json             # machine-readable output
python3 wafscope.py example.com --burst 30         # also look for rate limiting
SECURITYTRAILS_APIKEY=... python3 wafscope.py example.com --history
python3 wafscope.py example.com --no-color --no-banner
```

| Option | Purpose |
|---|---|
| `--no-active` | Send only the baseline requests; no payloads |
| `--burst N` | Send N rapid requests to observe `429` rate limiting |
| `--history` | DNS A-record history from SecurityTrails (needs `SECURITYTRAILS_APIKEY`) |
| `--json` | JSON output, no banner |
| `--insecure` | Do not verify the TLS certificate |
| `--timeout`, `--concurrency` | Per-request timeout (default 8 s) and parallelism (default 12) |
| `--no-color`, `--no-banner` | Plain output (colours also switch off when stdout is not a terminal) |

Exit codes: `0` a vendor or active blocking was found, `1` no evidence, `2` target unreachable.

## How it works

1. **Baseline.** Fetches the page (following up to three redirects). Every hop is kept as evidence.
2. **Passive signals.** Matches 77 signatures for 21 vendors against headers, cookies, response
   bodies, the CNAME chain, resolved IPs and the TLS certificate.
3. **Active probes.** Sends a benign control request (`?q=wafscope`) and nine probes: two XSS,
   two SQLi, LFI, command injection, SSTI, Log4Shell (in a header) and a scanner User-Agent. A probe
   counts as blocked only if its response differs from the control: a strong status such as
   `403`/`406`/`429`, a redirect to a challenge page, a dropped connection, or a block page
   served with `200`.
4. **Scoring.** Each signature carries a weight. Signals for the same vendor are merged with a
   noisy-OR, so independent weak signals add up without ever reaching certainty:
   `confidence = 1 - prod(1 - weight)`, capped at 0.99. Behavioural evidence from the probes is
   scored separately as the generic confidence.

### Reading the result

| Result | Meaning |
|---|---|
| `DETECTED` | Vendor fingerprints found **and** payloads were blocked |
| `FINGERPRINT` | Vendor fingerprints found, nothing blocked: CDN only, monitor mode, or rules these probes do not trigger |
| `GENERIC` | Payloads are blocked but no vendor could be identified |
| `NONE` | No evidence with these signals. This is not proof that no WAF exists |

## Supported vendors

Cloudflare, Akamai, AWS (CloudFront / AWS WAF), Imperva / Incapsula, F5 BIG-IP, Fastly / Signal
Sciences, Sucuri, ModSecurity / OWASP CRS, Barracuda, Fortinet FortiWeb, Azure (Front Door /
Application Gateway), Google Cloud, Citrix NetScaler, Radware, Wordfence, Reblaze, DataDome,
HUMAN / PerimeterX, Alibaba Cloud WAF, Wallarm, SonicWall.

## Limitations

This is an early prototype (v0.1.0). Please read these before trusting a verdict.

- Tested against a local simulator and a small number of live sites. There is no benchmark against
  other tools yet, so no claim of being more accurate or faster than them is made.
- A WAF in monitor mode, or one whose rules these nine probes do not trigger, will show only
  fingerprints. Probes are sent as `GET` query strings; request-body inspection is not tested yet.
- If the site ignores query parameters entirely (some single-page apps), the probes cannot prove
  anything, and wafscope does not yet say so.
- Vendor presence does not imply WAF: several vendors are also CDNs.
- IP-range signatures can go stale and carry low weights for that reason.
- `--history` (SecurityTrails) has not been tested against the live API.

## Roadmap

- Probes in `POST` bodies (form and JSON)
- Detect and report ignored query parameters
- Fuse vendor fingerprints with observed blocking into one confidence value
- `--verbose` to show the headers and body of the first blocked response
- Signatures in an external YAML file
- Batch mode (`-l targets.txt`) with CSV/JSON output
- Subdomain-aware scanning and TLS/HTTP2 fingerprinting

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The suite starts local simulators (plain site, Cloudflare-like, generic 406, silent connection
drop, soft block with `200`) and asserts the verdicts. It needs no network access.

## Contributing

New and corrected signatures are the most useful contribution. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Disclaimer

wafscope is provided for security research and authorised testing. The authors accept no
liability for misuse. Scanning systems without permission may be illegal in your jurisdiction.
The probes are inert strings, but they are designed to trigger security tooling and will appear
in the target's logs and alerts.

## License

MIT. See [LICENSE](LICENSE).
