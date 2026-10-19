import { appendFileSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { AgentEvent, Finding } from "../types.js";

// Append-only record of a run: every event lands in events.jsonl as it happens, and
// confirmed findings are mirrored into findings.jsonl for Jerry's report.
export class Evidence {
  readonly runId: string;
  readonly dir: string;
  private readonly findingsList: Finding[] = [];

  constructor(baseDir = "reports") {
    this.runId = new Date().toISOString().replace(/[:.]/g, "-");
    this.dir = join(baseDir, this.runId);
    mkdirSync(this.dir, { recursive: true });
  }

  record(event: AgentEvent): void {
    appendFileSync(join(this.dir, "events.jsonl"), `${JSON.stringify(event)}\n`);
    if (event.type === "finding") {
      this.findingsList.push(event.finding);
      appendFileSync(join(this.dir, "findings.jsonl"), `${JSON.stringify(event.finding)}\n`);
    }
  }

  findings(): Finding[] {
    return [...this.findingsList];
  }

  writeReport(markdown: string): string {
    const path = join(this.dir, "report.md");
    writeFileSync(path, markdown);
    return path;
  }

  // The remediation handoff: a self-describing plan the fix step reads from the target
  // repo. It is separate from report.md because it is an instruction set for the next
  // agent, not a record of the run.
  writeRemediation(markdown: string): string {
    const path = join(this.dir, "remediation.md");
    writeFileSync(path, markdown);
    return path;
  }
}
