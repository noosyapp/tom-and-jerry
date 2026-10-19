# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Tom & Jerry is an LLM-driven DAST (dynamic application security testing) tool for testing
**your own** web apps. It drives a real Chromium browser, intercepts and mutates HTTP traffic,
and confirms vulnerabilities by observation rather than heuristics. It is language-agnostic: it
tests running behavior through the browser and HTTP, so the target's stack does not matter.

Two Claude-driven agents:
- **Tom** (`src/agents/tom.ts`) — the attacker. Runs a Claude tool-use loop over Playwright-backed
  tools, probes inputs, and only records a finding once a deterministic oracle confirms it.
- **Jerry** (`src/agents/jerry.ts`) — the monitor. Subscribes to Tom's event stream live, triages
  each confirmed finding (impact + escalation path), and consolidates the run into a report.

## Commands

```bash
pnpm install                 # install deps
pnpm exec playwright install chromium   # one-time: fetch the browser
pnpm dev                     # run a scan with tsx (no build step)
pnpm dev -- --frontend=http://192.168.0.10:3000 --max-steps=60
pnpm typecheck               # tsc --noEmit
pnpm check                   # biome lint + format check
pnpm build                   # emit dist/

docker compose run --rm tom-and-jerry   # run fully containerized (Chromium bundled)
```

In Docker the host is reachable as `host.docker.internal` (not `localhost`); the browser runs
headless and `./reports` is a bind mount. See `Dockerfile` / `docker-compose.yml`.

Config comes from `.env` (see `.env.example`) and is overridable per run via CLI flags
(`--frontend`, `--backend`, `--scope`, `--max-steps`, `--headless`). `ANTHROPIC_API_KEY` is read
from the environment by the SDK.

## Architecture

The flow is one-directional: **Tom acts → Bus → Evidence + Jerry**.

- `src/engine/session.ts` — the only code that touches Playwright. Owns the browser, the request
  interception (`context.route`), the request log, and the request mutator hook. **Enforces the
  scope boundary**: every request to a host not in `scopeHosts` is aborted before it leaves the
  browser, and navigation asserts scope. This is the authorization guardrail — do not bypass it.
- `src/engine/bus.ts` — typed `AgentEvent` pub/sub. Tom emits; Jerry and Evidence consume.
- `src/engine/evidence.ts` — append-only `events.jsonl` / `findings.jsonl` per run under
  `reports/<runId>/`, plus the final `report.md`.
- `src/agents/tools.ts` — the Playwright-backed tools exposed to Tom (`betaZodTool`). Every tool
  logs to the bus. `report_finding` is the only path a finding enters the system.
- `src/playbooks/` — versioned, community-documented knowledge per vuln class (references, where
  to look, tactics, known payloads). `renderPlaybook` injects it into Tom's system prompt and
  `xss_probe` defaults to the playbook's payloads. Adding a vuln class starts with a playbook here.
- Model is `claude-opus-5-5` via the SDK tool runner (`client.beta.messages.toolRunner`).

## Launching

`.claude/commands/tom-and-jerry.md` defines the `/tom-and-jerry [port | host:port | URL]` slash
command. A bare port (`/tom-and-jerry 3000`) resolves to the machine's LAN IP so the app is hit as
a real network client would; `localhost`/`127.0.0.1` map to `host.docker.internal` for Docker. It
locks scope to that one host and runs the scan via `docker compose run`. That is the intended entry point.

### How a finding is proven, not guessed

The XSS oracle (`Session.xssProbe` + the `__tjXss` binding registered in `Session.start`) confirms
reflected XSS only when the injected payload *actually executes* in the page and calls a binding
with a one-time token. A payload that is reflected but not executed never produces a finding. Any
new vuln module must follow the same rule: a deterministic oracle confirms before `report_finding`.

## Invariants

- **Scope is the authorization boundary.** Only hosts in `scopeHosts` (targets + `TJ_SCOPE_HOSTS`)
  may be touched. Never widen scope implicitly or route around `Session.assertInScope` /
  `isInScope`.
- **No finding without a confirming oracle.** Tom must not report on reflection or a hunch alone.
- **One place owns Playwright** — `Session`. Agents and tools never import `playwright` directly.

## Scope / roadmap

Implemented: engine, Tom↔Jerry wiring, and the **reflected-XSS** module end-to-end.
Next slices (not yet built): **IDOR** and **authz / privilege-escalation** modules, and an
authenticated-session login step so escalation tests start from a normal user's position.
