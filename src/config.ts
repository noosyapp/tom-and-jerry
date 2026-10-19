import { readFileSync } from "node:fs";
import { networkInterfaces } from "node:os";
import type { RunConfig } from "./types.js";

// The app is exercised over the LAN as a real client would reach it, so targets
// default to the machine's own LAN IP rather than localhost. en0/en1 are the
// primary interfaces on macOS; fall back to any non-internal IPv4, then localhost.
function detectLanIp(): string {
  const ifaces = networkInterfaces();
  for (const name of ["en0", "en1"]) {
    const addr = ifaces[name]?.find((a) => a.family === "IPv4" && !a.internal);
    if (addr) return addr.address;
  }
  for (const iface of Object.values(ifaces)) {
    const addr = iface?.find((a) => a.family === "IPv4" && !a.internal);
    if (addr) return addr.address;
  }
  return "localhost";
}

// Treats a blank env var as unset, so an empty TJ_* value falls through to the
// auto-detected default instead of becoming an empty URL.
function nonEmpty(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}

// Minimal .env loader so the project needs no dotenv dependency. Only fills vars
// that are not already set, so real environment always wins.
function loadEnvFile(path = ".env"): void {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    return;
  }
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    const value = trimmed.slice(eq + 1).trim();
    if (!(key in process.env)) process.env[key] = value;
  }
}

function hostOf(url: string): string {
  return new URL(url).hostname;
}

export function loadConfig(overrides: Partial<RunConfig> = {}): RunConfig {
  loadEnvFile();

  const lanHost = detectLanIp();
  const frontendUrl =
    overrides.frontendUrl ?? nonEmpty(process.env.TJ_FRONTEND_URL) ?? `http://${lanHost}:3000`;
  const backendUrl =
    overrides.backendUrl ?? nonEmpty(process.env.TJ_BACKEND_URL) ?? `http://${lanHost}:9000`;

  const scopeFromEnv = (process.env.TJ_SCOPE_HOSTS ?? "")
    .split(",")
    .map((h) => h.trim())
    .filter(Boolean);

  // The targets are always in scope; anything else must be opted in explicitly.
  const scopeHosts = Array.from(
    new Set([...(overrides.scopeHosts ?? scopeFromEnv), hostOf(frontendUrl), hostOf(backendUrl)]),
  );

  return {
    frontendUrl,
    backendUrl,
    scopeHosts,
    userEmail: overrides.userEmail ?? process.env.TJ_USER_EMAIL ?? null,
    userPassword: overrides.userPassword ?? process.env.TJ_USER_PASSWORD ?? null,
    headful: overrides.headful ?? process.env.TJ_HEADFUL !== "false",
    maxSteps: overrides.maxSteps ?? 60,
  };
}

export function isInScope(url: string, scopeHosts: string[]): boolean {
  try {
    return scopeHosts.includes(new URL(url).hostname);
  } catch {
    return false;
  }
}
