import { type Browser, type BrowserContext, chromium, type Page, type Route } from "playwright";
import { isInScope } from "../config.js";
import type { RequestRecord } from "../types.js";

export type RequestMutator = (req: {
  url: string;
  method: string;
  headers: Record<string, string>;
  postData: string | null;
}) => { url?: string; headers?: Record<string, string>; postData?: string } | null;

const XSS_BINDING = "__tjXss";

// Time-based blind SQLi oracle: payloads sleep this many seconds, and an injected
// request is treated as confirming only when it is at least the threshold slower
// than a baseline request to the same endpoint. The margin absorbs network jitter.
const SQLI_DELAY_SECONDS = 5;
const SQLI_DELAY_THRESHOLD_MS = (SQLI_DELAY_SECONDS - 1) * 1000;

export class Session {
  private browser: Browser | null = null;
  private context: BrowserContext | null = null;
  private pageRef: Page | null = null;
  private mutator: RequestMutator | null = null;
  private firedTokens = new Set<string>();

  readonly requests: RequestRecord[] = [];

  constructor(
    private readonly scopeHosts: string[],
    private readonly headful: boolean,
  ) {}

  get page(): Page {
    if (!this.pageRef) throw new Error("Session not started");
    return this.pageRef;
  }

  async start(): Promise<void> {
    this.browser = await chromium.launch({ headless: !this.headful });
    this.context = await this.browser.newContext({ ignoreHTTPSErrors: true });

    // The oracle: a page proves reflected XSS by calling this binding with a token
    // only our injected payload knows. A call means our script actually executed.
    await this.context.exposeBinding(XSS_BINDING, (_source, token: string) => {
      this.firedTokens.add(token);
    });

    await this.context.route("**/*", (route) => this.handleRoute(route));
    this.pageRef = await this.context.newPage();
  }

  private async handleRoute(route: Route): Promise<void> {
    const request = route.request();
    const url = request.url();

    // The authorization boundary: never let a request reach a host outside scope.
    if (!isInScope(url, this.scopeHosts)) {
      await route.abort("blockedbyclient");
      return;
    }

    const headers = request.headers();
    const postData = request.postData() ?? null;
    this.requests.push({
      method: request.method(),
      url,
      headers,
      postData,
      timestamp: new Date().toISOString(),
    });

    if (this.mutator) {
      const patch = this.mutator({ url, method: request.method(), headers, postData });
      if (patch) {
        await route.continue(patch);
        return;
      }
    }
    await route.continue();
  }

  setMutator(mutator: RequestMutator): void {
    this.mutator = mutator;
  }

  clearMutator(): void {
    this.mutator = null;
  }

  assertInScope(url: string): void {
    if (!isInScope(url, this.scopeHosts)) {
      throw new Error(
        `Refused: ${url} is outside the configured scope (${this.scopeHosts.join(", ")})`,
      );
    }
  }

  async goto(url: string): Promise<void> {
    this.assertInScope(url);
    await this.page.goto(url, { waitUntil: "domcontentloaded" });
  }

  currentUrl(): string {
    return this.page.url();
  }

  async click(selector: string): Promise<void> {
    await this.page.click(selector, { timeout: 5000 });
  }

  async fill(selector: string, value: string): Promise<void> {
    await this.page.fill(selector, value, { timeout: 5000 });
  }

  async readPage(maxChars = 8000): Promise<{ url: string; title: string; text: string }> {
    const title = await this.page.title();
    const text = await this.page.innerText("body").catch(() => "");
    return { url: this.page.url(), title, text: text.slice(0, maxChars) };
  }

  // Navigates one URL per payload (PAYLOAD placeholder substituted) and reports the
  // first payload whose script actually ran against the oracle binding.
  async xssProbe(
    urlTemplate: string,
    payloads: string[],
  ): Promise<{ confirmed: boolean; payload?: string; firedUrl?: string }> {
    for (const payload of payloads) {
      const token = `tj_${Math.random().toString(36).slice(2)}`;
      const concrete = `window.${XSS_BINDING}('${token}')`;
      const url = urlTemplate.replace(
        /PAYLOAD/g,
        encodeURIComponent(payload.replace(/SINK/g, concrete)),
      );
      this.assertInScope(url);
      await this.page.goto(url, { waitUntil: "domcontentloaded" }).catch(() => undefined);
      await this.page.waitForTimeout(400);
      if (this.firedTokens.has(token)) {
        return { confirmed: true, payload, firedUrl: url };
      }
    }
    return { confirmed: false };
  }

  // The form counterpart to xssProbe: for inputs that are not GET query params.
  // Reloads the page per payload, fills the field, submits (clicks submitSelector,
  // or presses Enter), and reports the first payload whose script runs against the
  // oracle binding. A fired SINK after submit is proof the reflected value executed.
  async xssProbeForm(
    pageUrl: string,
    fieldSelector: string,
    payloads: string[],
    submitSelector?: string,
  ): Promise<{ confirmed: boolean; payload?: string; firedUrl?: string }> {
    this.assertInScope(pageUrl);
    for (const payload of payloads) {
      const token = `tj_${Math.random().toString(36).slice(2)}`;
      const concrete = `window.${XSS_BINDING}('${token}')`;
      const value = payload.replace(/SINK/g, concrete);
      await this.page.goto(pageUrl, { waitUntil: "domcontentloaded" }).catch(() => undefined);
      await this.page.fill(fieldSelector, value, { timeout: 5000 }).catch(() => undefined);
      if (submitSelector) {
        await this.page.click(submitSelector, { timeout: 5000 }).catch(() => undefined);
      } else {
        await this.page.press(fieldSelector, "Enter", { timeout: 5000 }).catch(() => undefined);
      }
      await this.page.waitForTimeout(600);
      if (this.firedTokens.has(token)) {
        return { confirmed: true, payload, firedUrl: this.page.url() };
      }
    }
    return { confirmed: false };
  }

  // Times a baseline request against each time-delay payload and reports the first
  // whose injected delay is reproducible: a payload only confirms when BOTH the first
  // request and a re-check are at least the threshold slower than the baseline, so a
  // single slow response never produces a finding.
  async sqliProbe(
    urlTemplate: string,
    payloads: string[],
  ): Promise<{
    confirmed: boolean;
    payload?: string;
    baselineMs?: number;
    injectedMs?: number;
    firedUrl?: string;
  }> {
    const baselineUrl = urlTemplate.replace(/PAYLOAD/g, encodeURIComponent("1"));
    this.assertInScope(baselineUrl);
    const baselineMs = await this.timeRequest(baselineUrl);
    for (const payload of payloads) {
      const url = urlTemplate.replace(/PAYLOAD/g, encodeURIComponent(payload));
      this.assertInScope(url);
      const injectedMs = await this.timeRequest(url);
      if (injectedMs - baselineMs < SQLI_DELAY_THRESHOLD_MS) continue;
      const recheckMs = await this.timeRequest(url);
      if (recheckMs - baselineMs >= SQLI_DELAY_THRESHOLD_MS) {
        return { confirmed: true, payload, baselineMs, injectedMs: recheckMs, firedUrl: url };
      }
    }
    return { confirmed: false, baselineMs };
  }

  // Elapsed wall-clock to the response committing, in ms. "commit" fires when the
  // server's response arrives, before rendering, so the measurement reflects the
  // backend's processing time — which is what a time-based payload inflates.
  private async timeRequest(url: string): Promise<number> {
    const start = Date.now();
    await this.page.goto(url, { waitUntil: "commit" }).catch(() => undefined);
    return Date.now() - start;
  }

  async close(): Promise<void> {
    await this.context?.close();
    await this.browser?.close();
  }
}
