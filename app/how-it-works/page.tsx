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
    description: "Fires on any CloudTrail event where the identity type is Root. The root account has unrestricted access to everything and should never be used for routine operations.",
    mitigation: "Enable MFA on root, lock the credentials away, and use IAM roles for all day-to-day tasks.",
  },
  {
    id: "AWS-002", name: "CloudTrail Logging Disabled", severity: "CRITICAL" as Severity,
    description: "StopLogging or DeleteTrail was called. This is a well-known attacker technique used to wipe evidence before or after a breach.",
    mitigation: "Enable CloudTrail log file validation and set up SNS alerts for any trail modifications.",
  },
  {
    id: "AWS-003", name: "IAM Privilege Escalation", severity: "CRITICAL" as Severity,
    description: "AdministratorAccess or PowerUser policy was attached to an IAM user or role via AttachUserPolicy, AttachRolePolicy, PutUserPolicy, or PutRolePolicy. This grants near-unlimited permissions.",
    mitigation: "Use permission boundaries, require MFA before sensitive IAM operations, and alert on every admin policy change.",
  },
  {
    id: "AWS-004", name: "Excessive Access Denied", severity: "HIGH" as Severity,
    description: "More than 10 AccessDenied errors from the same principal within 5 minutes. This pattern usually points to credential brute-force or an automated enumeration tool.",
    mitigation: "Rotate the suspected credentials, review IAM policies for over-broad denies, and block the IP if it is external.",
  },
  {
    id: "AWS-005", name: "S3 Bucket Made Public", severity: "HIGH" as Severity,
    description: "DeleteBucketPublicAccessBlock, PutBucketAcl with AllUsers or AuthenticatedUsers as the grantee, or PutBucketPolicy with Principal set to * was detected.",
    mitigation: "Enable S3 Block Public Access at the account level and use SCPs to prevent public bucket creation entirely.",
  },
  {
    id: "AWS-006", name: "Multiple Failed Console Logins", severity: "HIGH" as Severity,
    description: "More than 3 failed AWS Console login attempts from the same user within 10 minutes, which is a strong indicator of a password guessing attack.",
    mitigation: "Enforce MFA for all IAM users and consider restricting console access by IP range.",
  },
  {
    id: "AWS-007", name: "Bulk S3 Object Download", severity: "HIGH" as Severity,
    description: "More than 20 S3 GetObject calls from the same principal within 5 minutes. This volume of downloads is unusual and may indicate data exfiltration.",
    mitigation: "Enable S3 data events in CloudTrail and restrict GetObject access using resource-based policies.",
  },
  {
    id: "AWS-008", name: "Mass S3 Deletion", severity: "CRITICAL" as Severity,
    description: "More than 10 DeleteObject or DeleteObjects calls within 5 minutes. This could be ransomware wiping data or a destructive insider attack.",
    mitigation: "Enable S3 Versioning and require MFA Delete on all critical buckets.",
  },
  {
    id: "AWS-009", name: "New IAM User / Access Key", severity: "MEDIUM" as Severity,
    description: "CreateUser or CreateAccessKey was called. Attackers often create new users or keys to maintain persistent programmatic access after an initial compromise.",
    mitigation: "Alert on all IAM user creation, enforce just-in-time access patterns, and review any new users immediately.",
  },
  {
    id: "AWS-010", name: "Off-Hours Console Access", severity: "MEDIUM" as Severity,
    description: "A CloudTrail event occurred outside business hours, between 10 PM and 6 AM. While not always malicious, it is worth investigating as it may indicate a compromised account.",
    mitigation: "Use time-based IAM condition keys like aws:CurrentTime to restrict sensitive actions during off-hours.",
  },
];

const awsActions = [
  { action: "disable_access_keys",    what: "Lists all IAM access keys belonging to the user and marks each one as Inactive using UpdateAccessKey.", when: "Stolen credentials or suspected key compromise." },
  { action: "detach_admin_policy",    what: "Removes the AdministratorAccess managed policy from the user using DetachUserPolicy.", when: "IAM privilege escalation is detected (AWS-003)." },
  { action: "enable_cloudtrail",      what: "Calls StartLogging on the trail ARN to immediately re-enable audit logging.", when: "CloudTrail was disabled (AWS-002)." },
  { action: "block_s3_public_access", what: "Applies an account-level S3 Block Public Access configuration using PutPublicAccessBlock.", when: "A bucket was made public (AWS-005)." },
  { action: "quarantine_user",        what: "Creates a Deny-All inline IAM policy and attaches it directly to the user, which freezes all their permissions without deleting the account.", when: "High-confidence threat where no specific fix applies." },
  { action: "notify_admin",           what: "No AWS API call is made. The alert is stored and surfaces in the dashboard for manual review.", when: "Medium or low confidence verdict, or when GPT-4.1 is uncertain." },
];

export default function HowItWorksPage() {
  return (
    <div className="flex flex-col gap-8 p-6 max-w-4xl">

      <div>
        <h1 className="text-2xl font-bold tracking-tight">How it Works</h1>
        <p className="text-sm text-muted-foreground mt-1">
          A full walkthrough of the system, from a raw CloudTrail event all the way to an automated AWS response.
        </p>
      </div>

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
                desc: "Ten hand-written rules check every incoming event against known attack patterns like root account usage, IAM privilege escalation, and bulk S3 deletion. This layer is fast, deterministic, and will never miss a known threat.",
              },
              {
                icon: Activity, color: "text-purple-500", bg: "bg-purple-500/10 border-purple-500/20",
                label: "Layer 2 — Isolation Forest",
                desc: "Isolation Forest is a classical ML algorithm that scores every event between 0 and 1 based on how unusual it looks compared to a baseline of normal behaviour. It catches threats that no written rule would cover, such as unusual access timing, sudden bursts of activity, or rare user types. No training data or neural network involved.",
              },
              {
                icon: Brain, color: "text-amber-500", bg: "bg-amber-500/10 border-amber-500/20",
                label: "Layer 3 — GPT-4.1 Final Verdict",
                desc: "Every suspect (any event that matched a rule or scored above 0.62 on the anomaly scale) gets reviewed by GPT-4.1. It receives the full event, all matched rules, and the ML score together, then returns a structured verdict with isThreat, confidence percentage, severity, plain-English reasoning, and a recommended AWS action.",
              },
              {
                icon: Zap, color: "text-green-500", bg: "bg-green-500/10 border-green-500/20",
                label: "Auto-Remediation",
                desc: "When GPT-4.1 returns isThreat as true with a confidence of 75% or more, the system immediately calls the AWS API to carry out the recommended action. This could mean disabling access keys, removing admin policies, blocking public S3 access, or quarantining the user entirely.",
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
              { n: "1", text: "Events are fetched from AWS CloudTrail using the LookupEvents API, or generated by the built-in simulator." },
              { n: "2", text: "The user history for each unique actor is pre-fetched from MongoDB. This is needed for rate-based rules that count events over a time window, such as 10 AccessDenied errors in 5 minutes." },
              { n: "3", text: "The rule engine evaluates every event against all 10 rules in memory. Any matches are stored in a map keyed by event ID." },
              { n: "4", text: "Isolation Forest scores every event using a 6-feature vector. Events that score above 0.62 are flagged as anomalies." },
              { n: "5", text: "Suspects are collected. An event is a suspect if it matched at least one rule, or if its anomaly score exceeded the threshold." },
              { n: "6", text: "GPT-4.1 is called for each suspect with full context including the event JSON, matched rules, and ML score. Up to 5 calls run in parallel to stay within rate limits." },
              { n: "7", text: "If GPT-4.1 returns isThreat as true with confidence at or above 75%, the recommended AWS action is executed immediately using the AWS SDK. This could be disabling the user's access keys, detaching an admin policy, re-enabling CloudTrail, blocking public S3 access, or quarantining the user with a Deny-All policy. The outcome (SUCCESS, FAILED, or SKIPPED) is recorded on the alert." },
              { n: "8", text: "All logs and enriched alerts, including the AI verdict, confidence score, reasoning, and action result, are bulk-written to MongoDB. The dashboard and alerts page reflect the new data on the next load." },
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

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Activity className="h-4 w-4 text-purple-500" />
            How Isolation Forest Scores Events
          </CardTitle>
        </CardHeader>
        <CardContent className="pb-5">
          <p className="text-xs text-muted-foreground mb-3">
            Each event is turned into a 6-number feature vector before scoring. The algorithm fits on 300 synthetic normal events to build a baseline, then scores real events by counting how many random tree splits it takes to isolate them. Events that get isolated quickly are unusual, and unusual events get higher scores.
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mb-3">
            {[
              { feat: "isOffHours",    desc: "Set to 1 if the event happened outside 9 AM to 6 PM on a weekday" },
              { feat: "actionRisk",    desc: "A score from 0.0 to 1.0 where VIEW is 0.0, DELETE is 0.7, and IAM_ESCALATION is 1.0" },
              { feat: "isRoot",        desc: "Set to 1 if the user type is root" },
              { feat: "isAssumedRole", desc: "Set to 1 if the user type is assumed_role" },
              { feat: "hasPublicPerm", desc: "Set to 1 if the permission type contains the word public" },
              { feat: "recentRate",    desc: "How many events this user triggered in the last 5 minutes, normalised to a value between 0 and 1" },
            ].map(({ feat, desc }) => (
              <div key={feat} className="flex gap-2 items-start rounded-md border bg-muted/30 px-3 py-2">
                <code className="text-[11px] font-mono text-purple-500 shrink-0 mt-0.5">{feat}</code>
                <span className="text-xs text-muted-foreground">{desc}</span>
              </div>
            ))}
          </div>
          <p className="text-xs text-muted-foreground">
            A score closer to <span className="font-semibold text-foreground">1.0</span> means the event is harder to explain using normal patterns and is therefore more anomalous.
            The cutoff is <span className="font-semibold text-foreground">0.62</span>. Anything above this gets forwarded to GPT-4.1 for review, even if no rule matched.
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Lock className="h-4 w-4 text-green-500" />
            AWS Auto-Remediation Actions
          </CardTitle>
        </CardHeader>
        <CardContent className="pb-5">
          <p className="text-xs text-muted-foreground mb-3">
            GPT-4.1 picks one action from a fixed list of six. The action only runs when confidence is at least 75% and isThreat is true. The result (SUCCESS, FAILED, or SKIPPED) is saved directly on the alert record.
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

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-semibold">Running the Pipeline</CardTitle>
        </CardHeader>
        <CardContent className="pb-4 text-sm text-muted-foreground flex flex-col gap-2">
          <p>Send a POST request to <code className="text-xs bg-muted px-1 py-0.5 rounded">/api/run</code> to kick off a full scan:</p>
          <pre className="rounded-md bg-muted px-4 py-3 text-xs font-mono text-foreground overflow-x-auto whitespace-pre-wrap">
{`# Simulated events (no AWS credentials needed)
POST /api/run
{ "source": "simulated" }

# Real AWS CloudTrail events
POST /api/run
{
  "source": "aws",
  "region": "ap-south-1",
  "aws_access_key": "AKIA...",
  "aws_secret_key": "..."
}`}
          </pre>
          <p>You can also hit the <span className="font-semibold text-foreground">Simulate</span> button in the sidebar to run a scan without any setup.</p>
        </CardContent>
      </Card>

    </div>
  );
}
