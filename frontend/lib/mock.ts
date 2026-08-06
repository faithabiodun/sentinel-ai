// Stand-in data until the CockroachDB cluster is connected. Shapes mirror
// db/schema.sql exactly, so swapping this for real queries is a data-source
// change and not a component change.

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type IncidentStatus =
  | "triage"
  | "investigating"
  | "contained"
  | "closed"
  | "false_positive";
export type HypothesisStatus = "open" | "confirmed" | "refuted";
export type Verdict = "malicious" | "suspicious" | "benign" | "unknown";
export type EntityKind = "ip" | "domain" | "hash" | "user" | "host" | "process";

export interface Hypothesis {
  id: string;
  statement: string;
  status: HypothesisStatus;
  confidence: number;
  supporting: number;
  contradicting: number;
  note?: string;
}

export interface TimelineEvent {
  seq: number;
  at: string;
  action: string;
  mono?: string;
  technique?: string;
}

export interface EntityMemory {
  kind: EntityKind;
  value: string;
  verdict: Verdict;
  reasoning: string;
  timesSeen: number;
  firstSeen: string;
  riskScore: number;
  clearedCount: number;
}

export interface Incident {
  ref: string;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  host: string;
  user: string;
  technique?: string;
  openedAt: string;
  alertCount: number;
  summary?: string;
  resembles?: { ref: string; similarity: number; why: string };
  hypotheses: Hypothesis[];
  timeline: TimelineEvent[];
  entities: EntityMemory[];
}

export const incidents: Incident[] = [
  {
    ref: "INC-0042",
    title: "Credential access on WKS-DEV-04",
    severity: "critical",
    status: "investigating",
    host: "WKS-DEV-04",
    user: "a.okafor",
    technique: "T1003.001",
    openedAt: "08:02",
    alertCount: 11,
    summary:
      "An encoded PowerShell process opened a handle on lsass.exe eight minutes after a mail attachment executed. A local administrator account was created shortly after.",
    resembles: {
      ref: "INC-0017",
      similarity: 0.89,
      why: "same technique, same entry vector",
    },
    hypotheses: [
      {
        id: "h1",
        statement: "LSASS memory was accessed by an unsigned process",
        status: "confirmed",
        confidence: 0.94,
        supporting: 4,
        contradicting: 0,
      },
      {
        id: "h2",
        statement: "Credentials were used for lateral movement",
        status: "open",
        confidence: 0.41,
        supporting: 2,
        contradicting: 1,
        note: "gathering — awaiting remote logon events",
      },
      {
        id: "h3",
        statement: "Initial access came through the VPN gateway",
        status: "refuted",
        confidence: 0.08,
        supporting: 0,
        contradicting: 3,
        note: "no gateway auth events in the window — ruled out 09:22",
      },
    ],
    timeline: [
      {
        seq: 1,
        at: "08:02",
        action: "Attachment opened from",
        mono: "outlook.exe",
        technique: "T1566.001",
      },
      {
        seq: 2,
        at: "08:06",
        action: "Encoded process spawned",
        mono: "powershell.exe -enc",
        technique: "T1059.001",
      },
      {
        seq: 3,
        at: "08:08",
        action: "Handle opened on",
        mono: "lsass.exe",
        technique: "T1003.001",
      },
      {
        seq: 4,
        at: "08:15",
        action: "Local admin account created",
        mono: "svc_backup2",
        technique: "T1136.001",
      },
      {
        seq: 5,
        at: "08:18",
        action: "Outbound transfer to",
        mono: "185.220.101.34",
        technique: "T1041",
      },
    ],
    entities: [
      {
        kind: "ip",
        value: "185.220.101.34",
        verdict: "malicious",
        reasoning:
          "Appeared in 3 prior incidents, first on 12 Jan. Associated with credential stuffing against the perimeter.",
        timesSeen: 4,
        firstSeen: "12 Jan",
        riskScore: 92,
        clearedCount: 0,
      },
      {
        kind: "user",
        value: "a.okafor",
        verdict: "unknown",
        reasoning: "First appearance in an incident. No prior history.",
        timesSeen: 1,
        firstSeen: "today",
        riskScore: 40,
        clearedCount: 0,
      },
    ],
  },
  {
    ref: "INC-0041",
    title: "Encoded PowerShell on FS-BACKUP-01",
    severity: "low",
    status: "false_positive",
    host: "FS-BACKUP-01",
    user: "svc_backup",
    technique: "T1059.001",
    openedAt: "02:14",
    alertCount: 3,
    summary:
      "Closed automatically. The command line matches the nightly backup routine cleared in INC-0031.",
    hypotheses: [
      {
        id: "h1",
        statement: "Encoded command is the nightly backup routine",
        status: "confirmed",
        confidence: 0.97,
        supporting: 5,
        contradicting: 0,
        note: "matched against entity memory before any tool ran",
      },
    ],
    timeline: [
      {
        seq: 1,
        at: "02:14",
        action: "Encoded process spawned",
        mono: "powershell.exe -enc",
      },
    ],
    entities: [
      {
        kind: "process",
        value: "powershell.exe -enc <backup routine>",
        verdict: "benign",
        reasoning:
          "Matches nightly backup job; cleared in INC-0031, confirmed by ops on 4 Mar.",
        timesSeen: 14,
        firstSeen: "4 Mar",
        riskScore: 5,
        clearedCount: 4,
      },
    ],
  },
  {
    ref: "INC-0040",
    title: "Impossible travel for m.adeyemi",
    severity: "high",
    status: "contained",
    host: "—",
    user: "m.adeyemi",
    technique: "T1078",
    openedAt: "Yesterday 19:41",
    alertCount: 6,
    hypotheses: [],
    timeline: [],
    entities: [],
  },
  {
    ref: "INC-0039",
    title: "Scheduled task persistence on APP-PROD-02",
    severity: "medium",
    status: "triage",
    host: "APP-PROD-02",
    user: "SYSTEM",
    technique: "T1053.005",
    openedAt: "Yesterday 14:07",
    alertCount: 2,
    hypotheses: [],
    timeline: [],
    entities: [],
  },
  {
    ref: "INC-0038",
    title: "Suspicious archive staged in %TEMP%",
    severity: "medium",
    status: "closed",
    host: "WKS-FIN-11",
    user: "t.balogun",
    technique: "T1074.001",
    openedAt: "2 days ago",
    alertCount: 4,
    hypotheses: [],
    timeline: [],
    entities: [],
  },
];

export function getIncident(ref: string): Incident | undefined {
  return incidents.find((i) => i.ref.toLowerCase() === ref.toLowerCase());
}

// The memory browser. Note how many of these are benign: knowing what is
// cleared is what stops the same false positive being re-investigated.
export const knownEntities: EntityMemory[] = [
  {
    kind: "ip",
    value: "185.220.101.34",
    verdict: "malicious",
    reasoning:
      "Appeared in 3 prior incidents, first on 12 Jan. Associated with credential stuffing against the perimeter.",
    timesSeen: 4,
    firstSeen: "12 Jan",
    riskScore: 92,
    clearedCount: 0,
  },
  {
    kind: "process",
    value: "powershell.exe -enc <backup routine>",
    verdict: "benign",
    reasoning:
      "Matches nightly backup job; cleared in INC-0031, confirmed by ops on 4 Mar.",
    timesSeen: 14,
    firstSeen: "4 Mar",
    riskScore: 5,
    clearedCount: 4,
  },
  {
    kind: "host",
    value: "FS-BACKUP-01",
    verdict: "benign",
    reasoning:
      "Runs scheduled archival between 02:00 and 03:00. Encoded commands in that window are expected.",
    timesSeen: 22,
    firstSeen: "4 Mar",
    riskScore: 8,
    clearedCount: 6,
  },
  {
    kind: "hash",
    value: "a3f1c9e2b7d84e05f6a1c3d9b2e7f480",
    verdict: "malicious",
    reasoning: "Credential dumping tool. Matched in INC-0017 and INC-0042.",
    timesSeen: 2,
    firstSeen: "17 Feb",
    riskScore: 97,
    clearedCount: 0,
  },
  {
    kind: "domain",
    value: "updates.contoso-cdn.net",
    verdict: "suspicious",
    reasoning:
      "Registered 11 days before first sighting. Not on any allowlist, but no confirmed payload yet.",
    timesSeen: 3,
    firstSeen: "26 Jul",
    riskScore: 61,
    clearedCount: 0,
  },
  {
    kind: "user",
    value: "svc_deploy",
    verdict: "benign",
    reasoning:
      "Service account for the release pipeline. Off-hours logons are expected on deploy days.",
    timesSeen: 31,
    firstSeen: "9 Jan",
    riskScore: 12,
    clearedCount: 9,
  },
];

// Headline counters for the queue. Deliberately not a "needs attention"
// dashboard — these are filters over the queue, not vanity metrics.
export const queueStats = {
  open: incidents.filter((i) => i.status === "triage" || i.status === "investigating").length,
  autoCleared: incidents.filter((i) => i.status === "false_positive").length,
  entitiesKnown: 1284,
};
