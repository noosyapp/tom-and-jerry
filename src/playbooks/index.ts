import type { Playbook, VulnClass } from "../types.js";
import { sqlInjection } from "./sql-injection.js";
import { xssReflected } from "./xss-reflected.js";

// The registry of known-vuln playbooks. Add a module per class as it is implemented.
export const playbooks: Partial<Record<VulnClass, Playbook>> = {
  "xss-reflected": xssReflected,
  sqli: sqlInjection,
};

export function playbookFor(vulnClass: VulnClass): Playbook {
  const found = playbooks[vulnClass];
  if (!found) throw new Error(`No playbook registered for ${vulnClass}`);
  return found;
}

export function renderPlaybook(playbook: Playbook): string {
  return [
    `## Playbook: ${playbook.title}`,
    `References: ${playbook.references.join("; ")}`,
    "",
    `Where to look: ${playbook.lookFor}`,
    "",
    "Tactics:",
    ...playbook.tactics.map((t, i) => `${i + 1}. ${t}`),
    "",
    "Known payloads / test cases:",
    ...playbook.payloads.map((p) => `- ${p}`),
  ].join("\n");
}
