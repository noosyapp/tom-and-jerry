# IDOR / BOLA (Broken Object-Level Authorization)

Known, publicly-documented IDOR / BOLA test cases Tom should attempt. Insecure Direct
Object Reference (web) and Broken Object-Level Authorization (API) are the same flaw: one
user reaches another user's object by changing an identifier the server fails to
authorize.

**Status in the engine:** Documented — oracle not yet implemented (see below). On the
roadmap in `CLAUDE.md`.

## Sources

- OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization
- OWASP WSTG-ATHZ-04 — Testing for Insecure Direct Object References
- PortSwigger Web Security Academy — Access control vulnerabilities and IDOR
- CWE-639 — Authorization Bypass Through User-Controlled Key

## Where to look

Any request that names an object by id: `/api/users/{id}`, `/api/orders/{id}`,
`?account=`, `?invoice=`, `document_id`, filenames, and sequential or guessable ids in
URLs, query strings, JSON bodies, and headers. Also mass-assignment siblings (`?user_id=`
in a body that should be derived from the session).

## How Tom would confirm it (the oracle)

IDOR confirmation is **differential and requires two identities**, which is why it depends
on the authenticated-session step on the roadmap (`CLAUDE.md` → Scope / roadmap):

1. As **user A**, capture a legitimate object reference and user A's response for it.
2. Replay the same request as **user B** (different session) for **user A's** id.
3. Confirm **only** when user B receives user A's object (same private content, HTTP 200)
   rather than a 401/403/404. A deterministic comparison of the two responses is the
   proof — not the mere fact that an id can be changed.

A safe, read-only variant also compares an authenticated request against the **same
request with no credentials**: private data returned unauthenticated is a confirmed
finding. Never modify or delete another user's object to "prove" it.

## Test cases

| # | Pattern | Example | What confirms it |
|---|---------|---------|------------------|
| 1 | Sequential id swap | `GET /api/orders/1001` → `/api/orders/1002` | B reads A's order |
| 2 | UUID / id in body | `{"account_id":"<A's>"}` sent as B | B reads A's account |
| 3 | Unauthenticated access | authed `GET /api/users/{id}` replayed with no cookie | private data returned |
| 4 | Filename / path ref | `?file=invoice_1001.pdf` → `invoice_1002.pdf` | B downloads A's file |
| 5 | Mass assignment | body adds `user_id`/`role` the session should set | server honors it |

## Method (per OWASP API1:2023 / WSTG-ATHZ-04)

1. Enumerate endpoints that take an object id (URL, query, body, header).
2. Establish two identities (and/or an unauthenticated client).
3. Request one identity's object as the other; compare responses deterministically.
4. On confirmed cross-user read, `report_finding` with the two requests and the proof.

## Oracle to implement

A session-aware differential probe: issue the same request under two stored sessions (or
authed vs anonymous) and confirm when the lower-privileged one returns the higher-
privileged object. Depends on the authenticated-session login step.
