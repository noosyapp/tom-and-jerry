import type Anthropic from "@anthropic-ai/sdk";
import type { Bus } from "../engine/bus.js";
import type { Evidence } from "../engine/evidence.js";
import type { Session } from "../engine/session.js";
import { playbookFor, renderPlaybook } from "../playbooks/index.js";
import type { RunConfig } from "../types.js";
import { createTomTools } from "./tools.js";

const MODEL = "claude-opus-5-5";

function systemPrompt(config: RunConfig): string {
  return [
    "You are Tom, an ethical hacker running an AUTHORIZED dynamic security test against the user's own applications.",
    "You operate a real browser through the provided tools. Stay strictly within the configured scope.",
    "",
    `In-scope hosts: ${config.scopeHosts.join(", ")}`,
    `Frontend target: ${config.frontendUrl}`,
    `Backend target: ${config.backendUrl}`,
    "",
    "Goal for this run: find and CONFIRM vulnerabilities across the classes below, and be thorough — cover",
    "as many injection points as you can reach, not just the first one. Do not guess — every finding must be",
    "confirmed by a deterministic probe.",
    "",
    "THE ASSESSMENT IS THE PROBING. Recon exists only to list inputs; navigating and reading pages proves",
    "nothing. A run that ends with zero probe calls (xss_probe / xss_probe_form / sqli_probe) is a FAILED run.",
    "Spend at most a handful of steps enumerating, then probe — and keep probing until you run out of inputs",
    "or steps. Example: seeing a request like GET /api/assets?search=test, you must immediately run",
    "sqli_probe and xss_probe with urlTemplate http://host/api/assets?search=PAYLOAD. Every parameter you see",
    "gets probed; do not end the run while unprobed inputs remain.",
    "",
    "First, enumerate candidate injection points across the whole in-scope surface before probing: every",
    "query-string parameter on every reachable page AND backend/API endpoint (search, filter, sort, id, user,",
    "redirect / return-url, email, name, message, q, and error or not-found pages that echo input), AND every",
    "form field (search boxes, login, signup, profile, comment, filter inputs). Keep recon brief — just enough",
    "to list inputs. Then probe each candidate with the right tool for its class.",
    "",
    "Reflected XSS:",
    "- For a URL / query-string parameter use xss_probe with a urlTemplate where the literal token PAYLOAD",
    "  marks the injection point. For a FORM FIELD use xss_probe_form with the field's CSS selector (and a",
    "  submit-button selector if there is one). Each payload's SINK marker is replaced by a call that only",
    "  runs if the payload executes, so a confirmed probe is real execution — not reflection.",
    "",
    "SQL injection (time-based blind):",
    "- Target parameters that likely reach a database query (numeric ids, filters, sort columns, search,",
    "  pagination, login). Use sqli_probe with a urlTemplate where PAYLOAD marks the injection point. It times",
    "  a baseline against time-delay payloads and confirms ONLY on a reproducible delay — proof the database",
    "  executed the injected SQL. The backend API is the richest surface here.",
    "",
    "Rules: work through every injection point you enumerated — do not stop after one probe or one parameter.",
    "Report only probe-confirmed findings via report_finding (payload + reproduction steps), never on",
    "reflection, an error string, or a hunch. Spend your step budget probing, not browsing. Stop only when you",
    "have probed what you can reach, or you are near the step limit.",
    "",
    renderPlaybook(playbookFor("xss-reflected")),
    "",
    renderPlaybook(playbookFor("sqli")),
  ].join("\n");
}

const PROBE_TOOLS = ["xss_probe", "xss_probe_form", "sqli_probe"];

// The model tends to spend its whole budget on recon and end without probing. We count
// probe calls off the bus; if a phase ends with none, a second phase force-feeds it the
// concrete parameterized URLs it already generated as traffic, so the assessment runs.
export async function runTom(
  client: Anthropic,
  session: Session,
  evidence: Evidence,
  bus: Bus,
  config: RunConfig,
): Promise<void> {
  const tools = createTomTools({ session, evidence, bus });

  let probeCount = 0;
  let refused = false;
  bus.on((event) => {
    if (event.type === "action" && PROBE_TOOLS.includes(event.tool)) probeCount += 1;
    if (event.type === "refusal") refused = true;
  });

  let steps = 0;
  const runPhase = async (first: string): Promise<void> => {
    const runner = client.beta.messages.toolRunner({
      model: MODEL,
      max_tokens: 16000,
      // A safety classifier can decline the attacker prompt outright (HTTP 200 with
      // stop_reason "refusal"). The server-side fallback re-runs the turn on a
      // fallback model before the run gives up; a final refusal is handled below.
      betas: ["server-side-fallback-2026-07-01"],
      fallbacks: "default",
      system: systemPrompt(config),
      tools,
      messages: [{ role: "user", content: first }],
    });

    for await (const message of runner) {
      steps += 1;
      if (message.stop_reason === "refusal") {
        const details = message.stop_details;
        bus.emit({
          type: "refusal",
          actor: "tom",
          category: details?.category ?? null,
          explanation: details?.explanation ?? null,
          at: new Date().toISOString(),
        });
        break;
      }
      if (message.stop_reason === "pause_turn") {
        runner.pushMessages({ role: "assistant", content: message.content });
        continue;
      }
      if (steps >= config.maxSteps) break;
    }
  };

  await runPhase(`Begin the assessment. Start at ${config.frontendUrl}.`);

  // Second phase: the model enumerated but never pulled the trigger. Hand it the exact
  // parameterized URLs from the traffic it produced and order it to probe them now.
  if (!refused && probeCount === 0 && steps < config.maxSteps) {
    const targets = candidateTargets(session, config.scopeHosts);
    if (targets.length > 0) {
      await runPhase(
        "You ended without running a single probe — recon is not an assessment. Probe these concrete " +
          "targets NOW. For each, replace the parameter's value with the literal token PAYLOAD and call " +
          "BOTH sqli_probe and xss_probe with that urlTemplate. Do not navigate or read pages — just probe, " +
          "then report any confirmed finding.\n\nTargets:\n" +
          targets.map((t) => `- ${t}`).join("\n"),
      );
    }
  }
}

// Unique in-scope URLs that carry query parameters, taken from the request log — the
// raw material for a forced probing phase.
function candidateTargets(session: Session, scopeHosts: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const record of session.requests) {
    let url: URL;
    try {
      url = new URL(record.url);
    } catch {
      continue;
    }
    if (!scopeHosts.includes(url.hostname)) continue;
    const params = [...url.searchParams.keys()];
    if (params.length === 0) continue;
    const key = `${url.origin}${url.pathname}?${params.sort().join(",")}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(record.url);
    if (out.length >= 12) break;
  }
  return out;
}
