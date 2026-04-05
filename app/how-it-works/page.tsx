import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Shield, Brain, Zap, GitMerge,
  Database, Cloud, Lock, Activity,
} from "lucide-react";

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

const SEVERITY_STYLE: Record<Severity, string> = {
  CRITICAL: "bg-red-500/10 text-red-400 border-red-500/30",
  HIGH:     "bg-orange-500/10 text-orange-400 border-orange-500/30",
  MEDIUM:   "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  LOW:      "bg-sky-500/10 text-sky-400 border-sky-500/30",
};

const rules = [
  {
    id: "AWS-001", name: "Root Account Usage", severity: "CRITICAL" as Severity,
    description: "Any CloudTrail event where userIdentity.type = Root. Root has unrestricted access to every resource and should never be used for day-to-day operations.",
    mitigation: "Enable MFA on root, lock away root credentials, use IAM roles instead.",
  },
  {
    id: "AWS-002", name: "CloudTrail Logging Disabled", severity: "CRITICAL" as Severity,
    description: "StopLogging or DeleteTrail was called — a classic attacker move to erase evidence before or after an intrusion.",
    mitigation: "Enable CloudTrail log file validation and configure SNS alerts on trail changes.",
  },
  {
    id: "AWS-003", name: "IAM Privilege Escalation", severity: "CRITICAL" as Severity,
    description: "AdministratorAccess or PowerUser policy attached via AttachUserPolicy, AttachRolePolicy, PutUserPolicy, or PutRolePolicy — grants near-unlimited permissions.",
    mitigation: "Use permission boundaries, require MFA for sensitive IAM actions, alert on any admin policy change.",
  },
  {
    id: "AWS-004", name: "Excessive Access Denied", severity: "HIGH" as Severity,
    description: "More than 10 AccessDenied errors from the same principal within 5 minutes — credential brute-force or automated enumeration.",
    mitigation: "Rotate suspected credentials, review IAM policies, block IP if external.",
  },
  {
    id: "AWS-005", name: "S3 Bucket Made Public", severity: "HIGH" as Severity,
    description: "DeleteBucketPublicAccessBlock, PutBucketAcl with AllUsers/AuthenticatedUsers, or PutBucketPolicy with Principal: * was called.",
    mitigation: "Enable S3 Block Public Access at account level, use SCPs to prevent public bucket creation.",
  },
  {
    id: "AWS-006", name: "Multiple Failed Console Logins", severity: "HIGH" as Severity,
    description: "More than 3 failed AWS Console login attempts from the same user within 10 minutes.",
    mitigation: "Enforce MFA for all IAM users, consider IP-based conditional access policies.",
  },
  {
    id: "AWS-007", name: "Bulk S3 Object Download", severity: "HIGH" as Severity,
    description: "More than 20 S3 GetObject calls from the same principal within 5 minutes — possible data exfiltration.",
    mitigation: "Enable S3 data events in CloudTrail, restrict GetObject with resource-based policies.",
  },
  {
    id: "AWS-008", name: "Mass S3 Deletion", severity: "CRITICAL" as Severity,
    description: "More than 10 S3 DeleteObject/DeleteObjects calls within 5 minutes — ransomware or destructive insider attack.",
    mitigation: "Enable S3 Versioning and MFA Delete on critical buckets.",
  },
  {
    id: "AWS-009", name: "New IAM User / Access Key", severity: "MEDIUM" as Severity,
    description: "CreateUser or CreateAccessKey was called — a possible backdoor for persistent programmatic access.",
    mitigation: "Alert on all IAM user creation, enforce JIT access patterns, review new users immediately.",
  },
  {
    id: "AWS-010", name: "Off-Hours Console Access", severity: "MEDIUM" as Severity,
    description: "Any CloudTrail event outside business hours (10 PM – 6 AM). May indicate a compromised account.",
    mitigation: "Use time-based IAM condition keys (aws:CurrentTime) to restrict sensitive actions off-hours.",
  },
];

const awsActions = [
  { action: "disable_access_keys",    what: "Lists all IAM access keys for the user and marks them Inactive via UpdateAccessKey.", when: "Stolen credentials or key compromise." },
  { action: "detach_admin_policy",    what: "Detaches AdministratorAccess managed policy from the user via DetachUserPolicy.", when: "IAM privilege escalation (AWS-003)." },
  { action: "enable_cloudtrail",      what: "Calls StartLogging on the trail ARN to re-enable audit logging.", when: "CloudTrail was disabled (AWS-002)." },
  { action: "block_s3_public_access", what: "Applies account-level S3 Block Public Access via PutPublicAccessBlock.", when: "Bucket made public (AWS-005)." },
  { action: "quarantine_user",        what: "Creates a Deny-All inline policy and attaches it to the user, effectively freezing all their permissions.", when: "High-confidence threat with no specific fix." },
  { action: "notify_admin",           what: "No AWS API call — alert is stored and surfaced in the dashboard only.", when: "Medium/low confidence or uncertain verdict." },
];

export default function HowItWorksPage() {
  return (
    <div className="flex flex-col gap-8 p-6 max-w-4xl">

      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight">How it Works</h1>
        <p className="text-sm text-muted-foreground mt-1">
          End-to-end walkthrough — from raw CloudTrail event to automated AWS remediation.
        </p>
      </div>

      {/* Pipeline overview */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <GitMerge className="h-4 w-4 text-primary" />
            3-Layer Detection Pipeline
          </CardTitle>
        </CardHeader>
        <CardContent className="pb-5">
          <div className="flex flex-col gap-0">
            {[
              {
                icon: Shield, color: "text-blue-500", bg: "bg-blue-500/10 border-blue-500/20",
                label: "Layer 1 — Rule Engine",
                desc: "10 hand-written rules check every event against known attack patterns (root usage, IAM escalation, bulk deletion, off-hours access, etc.). Fast, deterministic, and zero false negatives for known threats.",
              },
              {
                icon: Activity, color: "text-purple-500", bg: "bg-purple-500/10 border-purple-500/20",
                label: "Layer 2 — Isolation Forest (ML)",
                desc: "Isolation Forest — a classical ML algorithm — scores every event 0–1 based on how anomalous it looks compared to normal behaviour. No neural network or training data needed; it uses random decision trees to spot outliers. Catches threats no rule covers — unusual timing, rare action bursts, suspicious user types.",
              },
              {
                icon: Brain, color: "text-amber-500", bg: "bg-amber-500/10 border-amber-500/20",
                label: "Layer 3 — GPT-4.1 Final Verdict",
                desc: "Every suspect (rule match OR anomaly score > 0.62) is reviewed by GPT-4.1. It receives the full event, all matched rules, and the ML score, then returns a structured verdict: isThreat, confidence %, severity, plain-English reasoning, and a recommended AWS action.",
              },
              {
                icon: Zap, color: "text-green-500", bg: "bg-green-500/10 border-green-500/20",
                label: "Auto-Remediation",
                desc: "If GPT-4.1 returns isThreat=true with confidence ≥ 75%, the system immediately executes the recommended AWS action — disabling access keys, detaching admin policies, blocking public S3 access, or quarantining the user.",
              },
            ].map((step, i) => (
              <div key={i} className="flex gap-4">
                <div className="flex flex-col items-center">
                  <div className={`flex h-8 w-8 items-center justify-center rounded-full border ${step.bg} shrink-0`}>
                    <step.icon className={`h-4 w-4 ${step.color}`} />
                  </div>
                  {i < 3 && <div className="w-px flex-1 bg-border my-1" />}
                </div>
                <div className="pb-5">
                  <p className="text-sm font-semibold">{step.label}</p>
                  <p className="text-xs text-muted-foreground mt-0.5 leading-relaxed">{step.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Data flow */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Database className="h-4 w-4 text-primary" />
            Step-by-Step Data Flow
          </CardTitle>
        </CardHeader>
        <CardContent className="pb-5">
          <div className="flex flex-col gap-2">
            {[
              { n: "1", text: "Events fetched from AWS CloudTrail (LookupEvents API) or the built-in simulator." },
              { n: "2", text: "User history pre-fetched from MongoDB to support rate-based rules — e.g. counting AccessDenied errors in the last 5 minutes." },
              { n: "3", text: "Rule engine evaluates each event against all 10 rules in memory. Matches stored in a map keyed by event_id." },
              { n: "4", text: "Isolation Forest scores every event. Feature vector: off-hours flag, action risk level, root/assumed-role flags, public permission flag, recent activity rate." },
              { n: "5", text: "Suspects collected: any event with at least one rule match OR an anomaly score above 0.62." },
              { n: "6", text: "GPT-4.1 called for each suspect with full context (event JSON + rule matches + ML score). Max 5 concurrent calls to respect rate limits." },
              { n: "7", text: "If confidence ≥ 75% and isThreat=true, the recommended AWS action executes immediately via the AWS SDK." },
              { n: "8", text: "All logs and enriched alerts (with AI verdict + action result) bulk-written to MongoDB. Dashboard reflects the results on next load." },
            ].map(({ n, text }) => (
              <div key={n} className="flex gap-3 items-start">
                <span className="shrink-0 flex h-5 w-5 items-center justify-center rounded-full bg-muted text-[10px] font-bold text-foreground mt-0.5">
                  {n}
                </span>
                <span className="text-xs text-muted-foreground leading-relaxed">{text}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Isolation Forest */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Activity className="h-4 w-4 text-purple-500" />
            How Isolation Forest Scores Events
          </CardTitle>
        </CardHeader>
        <CardContent className="pb-5">
          <p className="text-xs text-muted-foreground mb-3">
            Each event is converted into a 6-number feature vector. The Isolation Forest algorithm fits on 300 synthetic normal events to establish a baseline, then scores real events by how many random tree splits it takes to isolate them — fewer splits = more anomalous = higher score.
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mb-3">
            {[
              { feat: "isOffHours",    desc: "1 if outside 9 AM–6 PM on a weekday" },
              { feat: "actionRisk",    desc: "0.0–1.0  —  VIEW=0.0, DELETE=0.7, IAM_ESCALATION=1.0" },
              { feat: "isRoot",        desc: "1 if user_type is root" },
              { feat: "isAssumedRole", desc: "1 if user_type is assumed_role" },
              { feat: "hasPublicPerm", desc: "1 if permission_type contains 'public'" },
              { feat: "recentRate",    desc: "Events from this user in the last 5 min, normalised 0–1" },
            ].map(({ feat, desc }) => (
              <div key={feat} className="flex gap-2 items-start rounded-md border bg-muted/30 px-3 py-2">
                <code className="text-[11px] font-mono text-purple-500 shrink-0 mt-0.5">{feat}</code>
                <span className="text-xs text-muted-foreground">{desc}</span>
              </div>
            ))}
          </div>
          <p className="text-xs text-muted-foreground">
            Score closer to <span className="font-semibold text-foreground">1.0</span> = harder to explain with normal patterns = more anomalous.
            Threshold is <span className="font-semibold text-foreground">0.62</span> — events above this get sent to GPT-4.1 as suspects even if no rule fired.
          </p>
        </CardContent>
      </Card>

      {/* AWS actions */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Lock className="h-4 w-4 text-green-500" />
            AWS Auto-Remediation Actions
          </CardTitle>
        </CardHeader>
        <CardContent className="pb-5">
          <p className="text-xs text-muted-foreground mb-3">
            GPT-4.1 picks one action from a fixed list. Only executes when <span className="font-semibold text-foreground">confidence ≥ 75%</span> and <span className="font-semibold text-foreground">isThreat = true</span>. Result (SUCCESS / FAILED / SKIPPED) is stored on the alert.
          </p>
          <div className="flex flex-col divide-y">
            {awsActions.map(({ action, what, when }) => (
              <div key={action} className="py-3 flex flex-col gap-0.5">
                <code className="text-[11px] font-mono text-green-600 dark:text-green-400">{action}</code>
                <p className="text-xs text-muted-foreground">{what}</p>
                <p className="text-[11px] text-muted-foreground/60 italic">Used when: {when}</p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Detection rules */}
      <div>
        <h2 className="text-base font-semibold mb-3 flex items-center gap-2">
          <Cloud className="h-4 w-4 text-primary" />
          Detection Rules
        </h2>
        <div className="flex flex-col gap-3">
          {rules.map((rule) => (
            <Card key={rule.id}>
              <CardHeader className="pb-1.5">
                <div className="flex items-center gap-3 flex-wrap">
                  <span className="font-mono text-xs bg-muted px-2 py-0.5 rounded text-muted-foreground shrink-0">
                    {rule.id}
                  </span>
                  <CardTitle className="text-sm font-semibold flex-1">{rule.name}</CardTitle>
                  <span className={`text-[11px] font-semibold border rounded px-2 py-0.5 shrink-0 ${SEVERITY_STYLE[rule.severity]}`}>
                    {rule.severity}
                  </span>
                </div>
              </CardHeader>
              <CardContent className="pb-3 flex flex-col gap-1">
                <p className="text-xs text-muted-foreground">{rule.description}</p>
                <p className="text-[11px] text-muted-foreground/70">
                  <span className="font-semibold text-muted-foreground">Mitigation: </span>
                  {rule.mitigation}
                </p>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {/* API */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-semibold">Running the Pipeline</CardTitle>
        </CardHeader>
        <CardContent className="pb-4 text-sm text-muted-foreground flex flex-col gap-2">
          <p>Hit <code className="text-xs bg-muted px-1 py-0.5 rounded">POST /api/run</code> to trigger a full scan:</p>
          <pre className="rounded-md bg-muted px-4 py-3 text-xs font-mono text-foreground overflow-x-auto whitespace-pre-wrap">
{`# Simulated events (no AWS credentials needed)
POST /api/run
{ "source": "simulated" }

# Real AWS CloudTrail events
POST /api/run
{
  "source": "aws",
  "region": "ap-south-1",
  "aws_access_key": "AKIA…",
  "aws_secret_key": "…"
}`}
          </pre>
          <p>Or use the <span className="font-semibold text-foreground">Simulate</span> button in the sidebar to run a simulated scan instantly.</p>
        </CardContent>
      </Card>

    </div>
  );
}
