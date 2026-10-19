# SSRF (Server-Side Request Forgery)

Known, publicly-documented SSRF test cases Tom should attempt. SSRF makes the server issue
HTTP (or other) requests to a destination the attacker controls — reaching internal
services, cloud metadata, or the loopback interface the client can't touch directly.

**Status in the engine:** Documented — oracle not yet implemented (see below).

## Sources

- OWASP WSTG-INPV-19 — Testing for Server-Side Request Forgery
- OWASP API Security Top 10 — API7:2023 Server Side Request Forgery
- PortSwigger Web Security Academy — SSRF
- OWASP / PayloadsAllTheThings — Server Side Request Forgery
- CWE-918 — Server-Side Request Forgery (SSRF)

## Where to look

Any parameter that carries a URL, host, or reference the server will fetch: `url=`,
`uri=`, `next=`, `dest=`, `callback=`, `webhook=`, `image=`, `avatar=`, `feed=`, PDF/
thumbnail/preview generators, link-unfurlers, import-from-URL features, and XML/SVG inputs
(for blind variants). Both query parameters and JSON body fields.

## How Tom would confirm it (the oracle)

Confirmation must be **out-of-band and deterministic** — the server, not the browser, must
be observed making the request:

1. Supply a URL pointing at a **collaborator** the test controls (a unique, per-probe
   token in the hostname/path) and/or an in-scope listener the harness owns.
2. Confirm **only** when that listener receives a request carrying the one-time token —
   proof the *server* fetched our URL.
3. A blind-SSRF fallback is **time-based**: point the parameter at a non-routable address
   and confirm on a reproducible connect-timeout delay versus a fast control. The response
   body reflecting a URL is **not** proof on its own.

Testing stays within the authorization boundary: internal targets probed are only those in
scope, and the collaborator is the harness's own listener — never a third party.

## Test cases

| # | Target | Payload | What confirms it |
|---|--------|---------|------------------|
| 1 | Out-of-band callback | `url=http://<token>.<collaborator>/` | listener gets the token |
| 2 | Loopback | `url=http://127.0.0.1:<port>/` | internal service response / delay |
| 3 | Cloud metadata | `url=http://169.254.169.254/latest/meta-data/` | metadata returned |
| 4 | Alternate scheme | `url=file:///etc/passwd`, `gopher://`, `dict://` | non-HTTP fetch succeeds |
| 5 | Blind / time-based | `url=http://10.255.255.1/` (non-routable) | reproducible timeout delay |
| 6 | Parser bypass | `url=http://127.0.0.1#@<collaborator>/`, decimal/oct IPs | callback still fires |

## Method (per OWASP WSTG-INPV-19)

1. Enumerate parameters/fields the server dereferences as a URL.
2. Point each at a tokenized collaborator (or, for blind, a non-routable host).
3. Observe the out-of-band listener (or the timing) — never the response body alone.
4. On a confirmed server-side request, `report_finding` with the payload and the observed
   callback/timing.

## Oracle to implement

An out-of-band listener the harness owns, keyed by a one-time token per probe (mirroring
the XSS `SINK` idea at the network layer), plus a time-based fallback for blind SSRF.
