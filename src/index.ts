import Anthropic from "@anthropic-ai/sdk";
import { Jerry } from "./agents/jerry.js";
import { runTom } from "./agents/tom.js";
import { loadConfig } from "./config.js";
import { Bus } from "./engine/bus.js";
import { Evidence } from "./engine/evidence.js";
import { Session } from "./engine/session.js";
import type { RunConfig } from "./types.js";

function parseArgs(argv: string[]): Partial<RunConfig> {
  const overrides: Partial<RunConfig> = {};
  for (const arg of argv) {
    const [key, value] = arg.replace(/^--/, "").split("=");
    if (!value) continue;
    if (key === "frontend") overrides.frontendUrl = value;
    if (key === "backend") overrides.backendUrl = value;
    if (key === "scope") overrides.scopeHosts = value.split(",").map((h) => h.trim());
    if (key === "max-steps") overrides.maxSteps = Number(value);
    if (key === "headless") overrides.headful = value !== "true";
  }
  return overrides;
}

async function main(): Promise<void> {
  const config = loadConfig(parseArgs(process.argv.slice(2)));
  const client = new Anthropic();

  const bus = new Bus();
  const evidence = new Evidence();
  const session = new Session(config.scopeHosts, config.headful);

  const jerry = new Jerry(client, evidence, bus);
  jerry.listen();

  console.log(`Tom & Jerry — run ${evidence.runId}`);
  console.log(`Scope: ${config.scopeHosts.join(", ")}`);
  console.log(`Frontend: ${config.frontendUrl}\n`);

  await session.start();
  try {
    await runTom(client, session, evidence, bus, config);
  } finally {
    await session.close();
  }

  const reportPath = await jerry.finalize();
  console.log(`\nReport written to ${reportPath}`);
  console.log(`Remediation plan written to ${reportPath.replace(/report\.md$/, "remediation.md")}`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
