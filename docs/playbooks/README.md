# Attack Playbooks — documented test cases

This folder documents, in human-readable form, the **publicly-known test cases** Tom
attempts against our own application during an authorized scan. One file per
vulnerability class. Each entry names its public source (OWASP, PortSwigger, etc.),
the payload or request shape, the condition it targets, and how Tom & Jerry **confirms**
it rather than guessing.

## Relationship to `src/playbooks/`

- `src/playbooks/*.ts` is **code**: the subset of this knowledge that is rendered into
  Tom's system prompt (`renderPlaybook`) and, for XSS, used as the default payload set.
- `docs/playbooks/*.md` is **documentation**: the full catalog of known cases and the
  references behind them, including context and reasoning that does not belong in a
  prompt. It is where a case is researched and written up before (or alongside) landing
  in the code playbook.

Keep the two in sync: when a payload or tactic is added to a `.ts` playbook, record the
case and its source here; when a case documented here graduates into an attempted probe,
link it from the code.

## The confirmation rule (non-negotiable)

A documented case is only ever reported as a finding when a **deterministic oracle**
confirms it — see `CLAUDE.md` → "How a finding is proven, not guessed". Reflection,
similarity, or a suggestive response is never enough. Every case below states what would
count as proof.

## Scope

These cases are applied **only** to hosts inside the run's configured scope (the
authorization boundary in `src/engine/session.ts`). Nothing here authorizes testing any
host the user has not put in scope.

## Index

| Class | File | Status in the engine |
|-------|------|-----------------------|
| Reflected XSS | [`xss-reflected.md`](./xss-reflected.md) | Implemented |
| SQL injection | [`sql-injection.md`](./sql-injection.md) | Implemented (time-based blind, GET) |
| IDOR / BOLA | [`idor-bola.md`](./idor-bola.md) | Documented — oracle pending |
| SSRF | [`ssrf.md`](./ssrf.md) | Documented — oracle pending |
| OS command injection | [`command-injection.md`](./command-injection.md) | Documented — oracle pending |

A "Documented — oracle pending" class has its cases and sources written up here, with the
deterministic oracle each one needs, but no engine support yet: Tom cannot attempt it until
that oracle lands, because a finding requires a confirming oracle (`CLAUDE.md` → Invariants).
Each file's "Oracle to implement" section is the spec for that slice.
