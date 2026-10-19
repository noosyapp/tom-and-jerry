export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type VulnClass = "xss-reflected" | "xss-stored" | "sqli" | "idor" | "authz-escalation";

export interface Finding {
  id: string;
  vulnClass: VulnClass;
  severity: Severity;
  title: string;
  url: string;
  evidence: string;
  payload?: string;
  reproduction: string[];
  foundAt: string;
}

export interface RequestRecord {
  method: string;
  url: string;
  headers: Record<string, string>;
  postData: string | null;
  timestamp: string;
}

export type AgentEvent =
  | { type: "action"; actor: "tom" | "jerry"; tool: string; detail: string; at: string }
  | { type: "finding"; finding: Finding }
  | {
      type: "assessment";
      findingId: string;
      verdict: string;
      escalation: string;
      remediation: string;
      at: string;
    }
  | {
      type: "refusal";
      actor: "tom";
      category: string | null;
      explanation: string | null;
      at: string;
    }
  | { type: "log"; actor: "tom" | "jerry"; message: string; at: string };

// A playbook encodes community-documented knowledge for one vuln class: where it
// shows up, how to approach it, and the payloads to try. It is the repertoire Tom
// draws on, kept in code so it is versioned and reviewable.
export interface Playbook {
  vulnClass: VulnClass;
  title: string;
  references: string[];
  lookFor: string;
  tactics: string[];
  payloads: string[];
}

export interface RunConfig {
  frontendUrl: string;
  backendUrl: string;
  scopeHosts: string[];
  userEmail: string | null;
  userPassword: string | null;
  headful: boolean;
  maxSteps: number;
}
