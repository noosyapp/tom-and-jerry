# SQL Injection

Known, publicly-documented SQL-injection test cases Tom attempts against our app. The
implemented code playbook is `src/playbooks/sql-injection.ts` and the oracle is
`Session.sqliProbe`; this file is the catalog and the reasoning behind it.

**Status in the engine:** Implemented (time-based blind, GET parameters).

## Sources

- OWASP WSTG-INPV-05 — Testing for SQL Injection
- PortSwigger Web Security Academy — SQL injection, and "Blind SQL injection"
- OWASP / PayloadsAllTheThings — SQL Injection (time-based payloads)
- CWE-89 — Improper Neutralization of Special Elements used in an SQL Command

## Where to look

Any parameter or field that reaches a database query: numeric ids (`?id=`, `?user=`),
filters, sort/order columns, pagination, search terms, and login fields. The **backend
API** (`TJ_BACKEND_URL`) is usually the richest surface — test its query parameters and
JSON body values, not just the frontend.

## How Tom confirms it (the oracle)

A reflected SQL error or a changed response is **not** by itself a finding here. Tom uses
a **time-based blind** oracle (`Session.sqliProbe`):

1. Time a **baseline** request to the endpoint with a benign value.
2. For each payload, send a request whose injected SQL asks the database to sleep for a
   fixed delay (5 s).
3. Confirm **only** when the injected request is reproducibly slower than the baseline by
   ~the delay — the probe re-checks the slow payload before reporting, so a single slow
   response (network jitter, a cold cache) never becomes a finding.

A measured, repeatable delay is proof the database executed our injected `SLEEP`/
`pg_sleep`/`WAITFOR` — it does not depend on any error message being reflected.

## Test cases

Each payload sleeps 5 seconds; variants cover the common engines and breakouts (quote,
double-quote, numeric, closing paren) with comment terminators.

| # | Engine | Payload | Breakout |
|---|--------|---------|----------|
| 1 | MySQL / MariaDB | `1' AND SLEEP(5)-- -` | single-quote string |
| 2 | MySQL / MariaDB | `1" AND SLEEP(5)-- -` | double-quote string |
| 3 | MySQL / MariaDB | `1 AND SLEEP(5)` | numeric context |
| 4 | MySQL / MariaDB | `1') AND SLEEP(5)-- -` | closing paren |
| 5 | MySQL / MariaDB | `1' OR SLEEP(5)-- -` | OR-based, single-quote |
| 6 | MSSQL | `1'; WAITFOR DELAY '0:0:5'-- -` | stacked query, single-quote |
| 7 | MSSQL | `1); WAITFOR DELAY '0:0:5'-- -` | stacked query, closing paren |
| 8 | PostgreSQL | `1' AND 1=(SELECT 1 FROM PG_SLEEP(5))-- -` | subquery, single-quote |
| 9 | PostgreSQL | `1; SELECT PG_SLEEP(5)-- -` | stacked query |
| 10 | PostgreSQL | `1 OR PG_SLEEP(5)` | numeric OR |

## Method (per OWASP WSTG-INPV-05)

1. Identify a parameter that likely reaches a query (id, filter, sort, search, login).
2. Build a `urlTemplate` with `PAYLOAD` at the injection point and run `sqli_probe`.
3. The oracle times a baseline against the time-delay payloads above and re-checks any
   delay before confirming.
4. On a confirmed, reproducible delay, `report_finding` with the payload and steps.

## Not yet covered (candidates to add)

- **Form / POST-body SQLi** — the current oracle injects GET query parameters only; login
  and search forms that POST need a form-submitting time-based probe (same oracle, form
  transport).
- **Boolean-based blind** — differential TRUE (`' AND 1=1-- `) vs FALSE (`' AND 1=2-- `)
  response comparison, for endpoints where time functions are unavailable.
- **UNION / error-based extraction** — once injection is confirmed, extracting data; needs
  a response-parsing oracle and is higher-touch.
