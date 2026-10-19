import type Anthropic from "@anthropic-ai/sdk";
import type { Bus } from "../engine/bus.js";
import type { Evidence } from "../engine/evidence.js";
import type { AgentEvent, Finding } from "../types.js";

type RefusalEvent = Extract<AgentEvent, { type: "refusal" }>;

const MODEL = "claude-opus-5-5";

interface Assessment {
  findingId: string;
  verdict: string;
  escalation: string;
  remediation: string;
}

// Jerry watches Tom's stream live, triages each confirmed finding, and consolidates
// the run into a human-readable report.
export class Jerry {
  private readonly assessments: Assessment[] = [];
  private readonly pending: Promise<void>[] = [];
  private refusal: RefusalEvent | null = null;

  constructor(
    private readonly client: Anthropic,
    private readonly evidence: Evidence,
    private readonly bus: Bus,
  ) {}

  listen(): void {
    this.bus.on((event) => {
      if (event.type === "finding") {
        this.pending.push(this.triage(event.finding));
      }
      if (event.type === "refusal") {
        this.refusal = event;
      }
      this.evidence.record(event);
    });
  }

  private async triage(finding: Finding): Promise<void> {
    const response = await this.client.messages.create({
      model: MODEL,
      max_tokens: 1500,
      system:
        "You are Jerry, a defensive security analyst. Given one confirmed finding from an authorized test, " +
        "write a three-part note with these exact headings: VERDICT (impact and why it matters), ESCALATION " +
        "(how a normal user could push this further toward data or privileges they should not have), and " +
        "REMEDIATION (the code-level fix a developer should apply). For REMEDIATION be specific to the vuln " +
        "class and the observed parameter/payload (e.g. parameterized queries / prepared statements for SQLi, " +
        "contextual output encoding and a CSP for reflected XSS), and name what to verify after the fix. The " +
        "test is black-box, so you do not know the exact file — describe the fix so the engineer can locate " +
        "and apply it in the source. Be concrete and terse.",
      messages: [{ role: "user", content: JSON.stringify(finding, null, 2) }],
    });
    const text = response.content
      .filter((b): b is Anthropic.TextBlock => b.type === "text")
      .map((b) => b.text)
      .join("\n");
    const { verdict, escalation, remediation } = splitNote(text);
    this.assessments.push({ findingId: finding.id, verdict, escalation, remediation });
    this.bus.emit({
      type: "assessment",
      findingId: finding.id,
      verdict,
      escalation,
      remediation,
      at: new Date().toISOString(),
    });
  }

  async finalize(): Promise<string> {
    await Promise.all(this.pending);
    const findings = this.evidence.findings();
    const lines: string[] = [
      "# Tom & Jerry — Security Report",
      "",
      `Run: ${this.evidence.runId}`,
      "",
    ];

    if (findings.length === 0 && this.refusal) {
      const category = this.refusal.category ? ` (category: ${this.refusal.category})` : "";
      lines.push(
        "## Run blocked by policy",
        "",
        `Tom's attacker model declined this run${category}, so no inputs were probed.`,
        this.refusal.explanation ?? "No explanation was provided.",
        "",
        "The absence of findings here is not evidence the target is secure — the assessment never ran.",
      );
    } else if (findings.length === 0) {
      lines.push("No confirmed findings in this run.");
    } else {
      lines.push(`## Summary (${findings.length} confirmed)`, "");
      for (const f of findings) {
        lines.push(`- **${f.id}** [${f.severity}] ${f.title} — ${f.url}`);
      }
      lines.push("");
      for (const f of findings) {
        const a = this.assessments.find((x) => x.findingId === f.id);
        lines.push(`## ${f.id} — ${f.title}`, "");
        lines.push(
          `- **Severity:** ${f.severity}`,
          `- **Class:** ${f.vulnClass}`,
          `- **URL:** ${f.url}`,
        );
        if (f.payload) lines.push(`- **Payload:** \`${f.payload}\``);
        lines.push("", `**Evidence:** ${f.evidence}`, "");
        lines.push("**Reproduction:**");
        for (const [i, step] of f.reproduction.entries()) {
          lines.push(`${i + 1}. ${step}`);
        }
        lines.push("");
        if (a)
          lines.push(
            `**Jerry — verdict:** ${a.verdict}`,
            "",
            `**Jerry — escalation:** ${a.escalation}`,
            "",
            `**Jerry — remediation:** ${a.remediation}`,
            "",
          );
      }
    }

    this.evidence.writeRemediation(this.buildRemediation(findings));
    return this.evidence.writeReport(lines.join("\n"));
  }

  // The handoff the fix step reads from the target repo: Jerry's recommended fix per
  // confirmed finding, wrapped in instructions that keep the next agent inside the repo
  // and off the commit button until the user approves.
  private buildRemediation(findings: Finding[]): string {
    const lines: string[] = [
      "# Tom & Jerry — Remediation plan",
      "",
      `Run: ${this.evidence.runId}`,
      "",
    ];

    if (findings.length === 0) {
      lines.push("No confirmed findings in this run — nothing to fix.");
      return lines.join("\n");
    }

    lines.push(
      "## How to apply this",
      "",
      "Run from the **root of the target application's repository** (the app that was scanned).",
      "For each finding below: locate the vulnerable code, apply the recommended fix, and verify",
      "it with the repo's own gates (typecheck / lint / tests). Stay inside this repository.",
      "**Do not commit.** When every fix is in place, show the diff and ask the user whether to",
      "commit — the user decides. These findings are black-box, so confirm each fix against the",
      "real source before trusting it.",
      "",
    );

    for (const f of findings) {
      const a = this.assessments.find((x) => x.findingId === f.id);
      lines.push(`## ${f.id} — ${f.title} [${f.severity}]`, "");
      lines.push(`- **Class:** ${f.vulnClass}`, `- **URL:** ${f.url}`);
      if (f.payload) lines.push(`- **Payload:** \`${f.payload}\``);
      lines.push("", `**Evidence:** ${f.evidence}`, "");
      lines.push(`**Recommended fix:** ${a?.remediation ?? "Not assessed."}`, "");
    }

    return lines.join("\n");
  }
}

interface Note {
  verdict: string;
  escalation: string;
  remediation: string;
}

function splitNote(text: string): Note {
  const escIndex = text.search(/escalation/i);
  const remIndex = text.search(/remediation/i);

  if (escIndex === -1) {
    return { verdict: text.trim(), escalation: "Not assessed.", remediation: "Not assessed." };
  }

  const verdict = text
    .slice(0, escIndex)
    .replace(/verdict:?/i, "")
    .trim();

  // Remediation may precede or follow escalation depending on the model's ordering; use
  // whichever index is valid and after escalation to bound the escalation slice.
  if (remIndex === -1 || remIndex < escIndex) {
    return {
      verdict,
      escalation: text
        .slice(escIndex)
        .replace(/escalation:?/i, "")
        .trim(),
      remediation: "Not assessed.",
    };
  }

  return {
    verdict,
    escalation: text
      .slice(escIndex, remIndex)
      .replace(/escalation:?/i, "")
      .trim(),
    remediation: text
      .slice(remIndex)
      .replace(/remediation:?/i, "")
      .trim(),
  };
}
