# Reflected Cross-Site Scripting (XSS)

Known, publicly-documented reflected-XSS test cases Tom attempts against our app. The
implemented code playbook is `src/playbooks/xss-reflected.ts`; this file is the catalog
and the reasoning behind it.

## Sources

- OWASP WSTG-INPV-01 — Testing for Reflected Cross Site Scripting
- OWASP XSS Filter Evasion Cheat Sheet
- PortSwigger Web Security Academy — Reflected XSS and "Cross-site scripting contexts"
- OWASP / PayloadsAllTheThings — XSS Injection

## Where to look

Inputs whose value is echoed back into the HTML response: search boxes, query-string
parameters (`?q=`, `?email=`, `?token=`), error and "not found" pages that repeat the
input, and any value that appears verbatim in the page source.

## How Tom confirms it (the oracle)

Reflection alone is **not** a finding. Each payload carries a `SINK` marker; at probe
time the marker is replaced by a call to a one-time browser binding (`__tjXss`) seeded
with a random token. The case is confirmed **only** when the injected script actually
executes in the page and calls the binding with that token. A payload that is reflected
but never runs produces no finding. Two probe paths share this oracle:

- `xss_probe` / `Session.xssProbe` — GET injection: builds a URL from a template with the
  `PAYLOAD` marker and navigates to it. For query-string parameters and reflected paths.
- `xss_probe_form` / `Session.xssProbeForm` — form injection: fills a field, submits
  (clicks a submit control or presses Enter), and checks the oracle. For search boxes,
  login, signup, comment, and other inputs that are not URL parameters.

## Test cases

Each case targets a specific **reflection context** — where in the HTML the input lands
decides which payload can break out and execute. `SINK` = the executable proof marker.

| # | Context it targets | Payload | Notes / source |
|---|--------------------|---------|----------------|
| 1 | HTML body (tag injection allowed) | `<img src=x onerror="SINK">` | Classic error-handler execution; fires without user interaction. |
| 2 | HTML body | `<svg onload="SINK">` | `onload` on an inline SVG; alternative to `img/onerror`. |
| 3 | Inside a double-quoted attribute | `"><img src=x onerror="SINK">` | Breaks out of the attribute and the tag, then injects a new element. |
| 4 | Inside a single-quoted attribute | `'><img src=x onerror="SINK">` | Single-quote variant of case 3. |
| 5 | Inside `<title>` | `</title><img src=x onerror="SINK">` | Closes the title element first, since its content is treated as text. |
| 6 | Inside `<textarea>` | `</textarea><img src=x onerror="SINK">` | Closes the textarea, whose content is otherwise inert text. |
| 7 | Attribute breakout, SVG variant | `"><svg/onload=SINK>` | Slash separator and unquoted handler to dodge naive filters. |
| 8 | Inside an existing `<script>` block | `<script>SINK</script>` | Direct script injection where input lands in script context. |
| 9 | HTML body, `body` handler | `<body onload="SINK">` | Fires on document load in contexts that accept a `body` tag. |
| 10 | HTML body, interaction-free handler | `<details open ontoggle="SINK">` | `ontoggle` on an open `<details>`; useful when common handlers are filtered. |

## Method (per OWASP WSTG-INPV-01)

1. Inject a harmless unique marker first to find which parameters reflect, and where.
2. Identify the reflection context: HTML body, an attribute value, `<title>`,
   `<textarea>`, or inside a `<script>` block.
3. Choose the payload that breaks out of that specific context (table above).
4. Probe the input — `xss_probe` for a URL parameter, `xss_probe_form` for a form field.
   Only a fired `SINK` is a real finding.

## Not yet covered (candidates to add)

Documented elsewhere but not in the current payload set; add with its source when
attempted and confirmable:

- DOM-based reflected XSS via `location`/`hash` sinks (PortSwigger — DOM XSS). Needs a
  DOM-sink oracle, distinct from the server-reflection oracle above.
- JavaScript-string-context breakouts (`';SINK//`) when input lands inside a quoted JS
  string rather than an HTML attribute.
- Event handlers requiring interaction (`onmouseover`, `onfocus autofocus`) — lower
  confidence without a driven interaction step.
