---
description: Apply the fixes from a Tom & Jerry remediation plan to the target repo, without committing.
argument-hint: "[path to remediation.md | runId]  (optional; defaults to the newest run)"
---

Apply the remediation plan Jerry produced for a confirmed Tom & Jerry run.

Requested plan: `$ARGUMENTS`

**Run this from the root of the scanned application's repository** — the working directory is the
target repo whose source you will edit. The findings are black-box, so every fix must be confirmed
against the real source before you trust it.

Follow these steps exactly:

1. Resolve `$ARGUMENTS` to a remediation plan file:
   - A path ending in `remediation.md`: use it as given.
   - A `runId`: use `<scanner-repo>/reports/<runId>/remediation.md` (the path the scan printed).
   - **Empty**: use the newest `reports/<runId>/remediation.md` you can find — first under the
     current directory, then under the Tom & Jerry scanner repo if you know its path. If you
     cannot find one, stop and ask the user for the plan's path.
2. Read the plan and the matching `findings.jsonl` in the same run directory. If the plan says
   there were no findings, say so and stop.
3. For each finding, in severity order (critical → high → …):
   a. Locate the vulnerable code **in the current repository** using the finding's URL, parameter,
      and payload. Only edit files inside this repo — never outside it.
   b. Apply the fix Jerry recommended for that class (e.g. parameterized queries / prepared
      statements for SQLi; contextual output encoding and a CSP for reflected XSS). Prefer the
      smallest change that removes the flaw; match the surrounding code's style.
   c. If you cannot confidently map a finding to source, do not guess — list it as needing manual
      attention and move on.
4. Verify with the repo's own gates (typecheck / lint / tests, whatever it has) and fix any
   violations your changes introduced.
5. **Do not commit, do not push, do not open a PR.** Present a summary of the diff per finding
   (what changed and why it closes the vuln), note anything left for manual attention, and then
   ask the user whether to commit. Only if the user says yes, commit — following this repo's own
   commit conventions and the user's global Git rules.
