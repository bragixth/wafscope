# Contributing

The most useful contribution is a new or corrected signature. Every vendor entry lives in the
`SIGS` dictionary at the top of `wafscope.py`.

## Adding a signature

Each signature is a tuple: `(kind, pattern, weight, description)`.

| kind | matches |
|---|---|
| `hdr` | a header with exactly this name exists |
| `hdrre` | some header name matches the regex |
| `hdrv` | `"name:regex"` against the value of a header |
| `cookie` | regex against cookie names |
| `body` | regex against the response body (block pages, brand markers) |
| `cname` | regex against the host's CNAME chain |
| `cert` | regex against the certificate issuer, subject and SAN |
| `ip` | comma-separated CIDR list |

Weight guide (per-signal confidence, combined with a noisy-OR):

- 0.85-0.95: unique to the vendor (a dedicated block page, a vendor-only header)
- 0.55-0.75: strongly associated (a vendor CNAME, a vendor cookie)
- 0.25-0.45: weak or shared (a generic CDN header, an IP range that may be stale)

## Before opening a pull request

1. Include a real sample of the evidence: the header, cookie, CNAME or block-page text, with the
   target redacted if it is not yours.
2. Add or update a test in `tests/test_wafscope.py` when the change fixes a missed detection.
3. Run `python3 -m unittest discover -s tests -v`.

Only test targets you own or are authorised to test.
