import { betaZodTool } from "@anthropic-ai/sdk/helpers/beta/zod";
import { z } from "zod";
import type { Bus } from "../engine/bus.js";
import type { Evidence } from "../engine/evidence.js";
import type { Session } from "../engine/session.js";
import { playbookFor } from "../playbooks/index.js";
import type { Finding, Severity, VulnClass } from "../types.js";

export interface ToolContext {
  session: Session;
  evidence: Evidence;
  bus: Bus;
}

function now(): string {
  return new Date().toISOString();
}

function logAction(ctx: ToolContext, tool: string, detail: string): void {
  ctx.bus.emit({ type: "action", actor: "tom", tool, detail, at: now() });
}

export function createTomTools(ctx: ToolContext) {
  const navigate = betaZodTool({
    name: "navigate",
    description: "Open a URL in the browser. Only in-scope hosts are allowed.",
    inputSchema: z.object({ url: z.string().describe("Absolute URL to open") }),
    run: async ({ url }) => {
      await ctx.session.goto(url);
      logAction(ctx, "navigate", url);
      const page = await ctx.session.readPage();
      return `Loaded ${page.url}\nTitle: ${page.title}\n\n${page.text}`;
    },
  });

  const readPage = betaZodTool({
    name: "read_page",
    description: "Return the current page URL, title and visible text.",
    inputSchema: z.object({}),
    run: async () => {
      const page = await ctx.session.readPage();
      return `${page.url}\nTitle: ${page.title}\n\n${page.text}`;
    },
  });

  const click = betaZodTool({
    name: "click",
    description: "Click an element matching a CSS selector.",
    inputSchema: z.object({ selector: z.string() }),
    run: async ({ selector }) => {
      await ctx.session.click(selector);
      logAction(ctx, "click", selector);
      return `Clicked ${selector}. Now at ${ctx.session.currentUrl()}`;
    },
  });

  const typeText = betaZodTool({
    name: "type_text",
    description: "Fill a form field matching a CSS selector with a value.",
    inputSchema: z.object({ selector: z.string(), value: z.string() }),
    run: async ({ selector, value }) => {
      await ctx.session.fill(selector, value);
      logAction(ctx, "type_text", `${selector} = ${value}`);
      return `Filled ${selector}`;
    },
  });

  const listRequests = betaZodTool({
    name: "list_requests",
    description: "List the HTTP requests the browser has made so far (newest last).",
    inputSchema: z.object({ limit: z.number().int().positive().max(100).optional() }),
    run: async ({ limit }) => {
      const items = ctx.session.requests.slice(-(limit ?? 25));
      return items
        .map((r) => `${r.method} ${r.url}${r.postData ? ` | body: ${r.postData}` : ""}`)
        .join("\n");
    },
  });

  const xssProbe = betaZodTool({
    name: "xss_probe",
    description:
      "Test a URL for reflected XSS. Provide a urlTemplate containing the literal token PAYLOAD " +
      "where the injection goes. Each payload may contain the literal token SINK, which is replaced " +
      "by a call that only executes if the payload runs in the page. Returns whether execution was confirmed.",
    inputSchema: z.object({
      urlTemplate: z.string().describe("e.g. http://host:3000/search?q=PAYLOAD"),
      payloads: z
        .array(z.string())
        .optional()
        .describe(
          'Defaults to a built-in set. Use SINK as the executable marker, e.g. <img src=x onerror="SINK">',
        ),
    }),
    run: async ({ urlTemplate, payloads }) => {
      const list =
        payloads && payloads.length > 0 ? payloads : playbookFor("xss-reflected").payloads;
      const result = await ctx.session.xssProbe(urlTemplate, list);
      logAction(
        ctx,
        "xss_probe",
        `${urlTemplate} -> ${result.confirmed ? "CONFIRMED" : "no execution"}`,
      );
      return JSON.stringify(result);
    },
  });

  const xssProbeForm = betaZodTool({
    name: "xss_probe_form",
    description:
      "Test a FORM FIELD for reflected XSS (use this when the input is not a URL query parameter). " +
      "Navigates to pageUrl, fills fieldSelector with each payload (the literal token SINK is replaced by a " +
      "call that only executes if the payload runs), submits, and reports whether execution was confirmed. " +
      "Submits by clicking submitSelector when given, otherwise by pressing Enter in the field.",
    inputSchema: z.object({
      pageUrl: z.string().describe("Absolute URL of the page holding the form"),
      fieldSelector: z.string().describe("CSS selector of the input to inject into"),
      submitSelector: z
        .string()
        .optional()
        .describe("CSS selector of the submit control; omit to press Enter in the field"),
      payloads: z
        .array(z.string())
        .optional()
        .describe(
          'Defaults to a built-in set. Use SINK as the executable marker, e.g. <img src=x onerror="SINK">',
        ),
    }),
    run: async ({ pageUrl, fieldSelector, submitSelector, payloads }) => {
      const list =
        payloads && payloads.length > 0 ? payloads : playbookFor("xss-reflected").payloads;
      const result = await ctx.session.xssProbeForm(pageUrl, fieldSelector, list, submitSelector);
      logAction(
        ctx,
        "xss_probe_form",
        `${pageUrl} [${fieldSelector}] -> ${result.confirmed ? "CONFIRMED" : "no execution"}`,
      );
      return JSON.stringify(result);
    },
  });

  const sqliProbe = betaZodTool({
    name: "sqli_probe",
    description:
      "Test a URL parameter for SQL injection with a time-based blind oracle. Provide a urlTemplate " +
      "containing the literal token PAYLOAD where the injection goes. It times a baseline request against " +
      "time-delay payloads and confirms injection ONLY when the injected delay reproducibly slows the " +
      "response — proof the database executed the injected SQL. A reflected error or a hunch is never enough.",
    inputSchema: z.object({
      urlTemplate: z.string().describe("e.g. http://host:9000/api/items?id=PAYLOAD"),
      payloads: z
        .array(z.string())
        .optional()
        .describe(
          "Defaults to a built-in time-based set (5s delay) covering MySQL, PostgreSQL and MSSQL.",
        ),
    }),
    run: async ({ urlTemplate, payloads }) => {
      const list = payloads && payloads.length > 0 ? payloads : playbookFor("sqli").payloads;
      const result = await ctx.session.sqliProbe(urlTemplate, list);
      const delta = (result.injectedMs ?? 0) - (result.baselineMs ?? 0);
      logAction(
        ctx,
        "sqli_probe",
        `${urlTemplate} -> ${result.confirmed ? `CONFIRMED (+${delta}ms)` : "no delay"}`,
      );
      return JSON.stringify(result);
    },
  });

  const reportFinding = betaZodTool({
    name: "report_finding",
    description:
      "Record a confirmed security finding. Only call this once you have concrete evidence (e.g. a confirmed xss_probe).",
    inputSchema: z.object({
      vulnClass: z.enum(["xss-reflected", "xss-stored", "sqli", "idor", "authz-escalation"]),
      severity: z.enum(["info", "low", "medium", "high", "critical"]),
      title: z.string(),
      url: z.string(),
      evidence: z.string().describe("Why this is real — the observed proof."),
      payload: z.string().optional(),
      reproduction: z.array(z.string()).describe("Ordered steps to reproduce."),
    }),
    run: async (input) => {
      const finding: Finding = {
        id: `F-${ctx.evidence.findings().length + 1}`,
        vulnClass: input.vulnClass as VulnClass,
        severity: input.severity as Severity,
        title: input.title,
        url: input.url,
        evidence: input.evidence,
        payload: input.payload,
        reproduction: input.reproduction,
        foundAt: now(),
      };
      ctx.bus.emit({ type: "finding", finding });
      return `Recorded ${finding.id} (${finding.severity}). Jerry has been notified.`;
    },
  });

  return [
    navigate,
    readPage,
    click,
    typeText,
    listRequests,
    xssProbe,
    xssProbeForm,
    sqliProbe,
    reportFinding,
  ];
}
