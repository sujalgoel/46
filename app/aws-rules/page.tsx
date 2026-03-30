import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Cloud, ShieldAlert, AlertTriangle, Zap } from "lucide-react";

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

const SEVERITY_STYLE: Record<Severity, string> = {
  CRITICAL: "bg-red-500/10 text-red-400 border-red-500/30",
  HIGH:     "bg-orange-500/10 text-orange-400 border-orange-500/30",
  MEDIUM:   "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  LOW:      "bg-sky-500/10 text-sky-400 border-sky-500/30",
};

const rules = [
  {
    id: "AWS-001",
    name: "Root Account Usage",
    severity: "CRITICAL" as Severity,
    description:
      "The AWS root account was used. Root has unrestricted access to every resource and should never be used for day-to-day operations.",
    triggers: ["Any CloudTrail event where userIdentity.type = Root"],
    mitigation: "Enable MFA on root, lock away root credentials, use IAM roles instead.",
  },
  {
    id: "AWS-002",
    name: "CloudTrail Logging Disabled",
    severity: "CRITICAL" as Severity,
    description:
      "StopLogging or DeleteTrail was called — a classic attacker move to erase evidence before or after an intrusion.",
    triggers: ["StopLogging", "DeleteTrail"],
    mitigation: "Enable CloudTrail log file validation and configure SNS alerts on trail changes.",
  },
  {
    id: "AWS-003",
    name: "IAM Privilege Escalation",
    severity: "CRITICAL" as Severity,
    description:
      "An AdministratorAccess or PowerUser managed policy was attached to an IAM user or role, granting near-unlimited permissions.",
    triggers: [
      "AttachUserPolicy (policyArn contains AdministratorAccess or PowerUser)",
      "AttachRolePolicy (same condition)",
      "PutUserPolicy / PutRolePolicy with inline admin policy",
    ],
    mitigation: "Use permission boundaries, require MFA for sensitive IAM actions, and alert on any admin policy change.",
  },
  {
    id: "AWS-004",
    name: "Excessive Access Denied Errors",
    severity: "HIGH" as Severity,
    description:
      "More than 10 AccessDenied errors from the same principal within 5 minutes — indicates credential brute-force, automated enumeration, or a misconfigured tool.",
    triggers: ["Any event where errorCode = AccessDenied / AccessDeniedException"],
    mitigation: "Rotate suspected credentials, review IAM policies for over-broad denies, block IP if external.",
  },
  {
    id: "AWS-005",
    name: "S3 Bucket Made Public",
    severity: "HIGH" as Severity,
    description:
      "A bucket ACL or policy was changed to allow public access, or the S3 Block Public Access setting was removed.",
    triggers: [
      "DeleteBucketPublicAccessBlock",
      "PutBucketAcl (with AllUsers or AuthenticatedUsers grantee)",
      "PutObjectAcl (with public grantee)",
      'PutBucketPolicy (policy contains "Principal": "*")',
    ],
    mitigation: "Enable S3 Block Public Access at account level, use SCPs to prevent public bucket creation.",
  },
  {
    id: "AWS-006",
    name: "Multiple Failed Console Logins",
    severity: "HIGH" as Severity,
    description:
      "More than 3 failed AWS Management Console login attempts from the same user within 10 minutes.",
    triggers: ['ConsoleLogin where responseElements.ConsoleLogin = "Failure"'],
    mitigation: "Enforce MFA for all IAM users, consider IP-based conditional access policies.",
  },
  {
    id: "AWS-007",
    name: "Bulk S3 Object Download",
    severity: "HIGH" as Severity,
    description:
      "More than 20 S3 GetObject calls from the same principal within 5 minutes — possible data exfiltration.",
    triggers: ["GetObject (S3 data events must be enabled in CloudTrail)"],
    mitigation: "Enable S3 data events in CloudTrail, restrict GetObject with resource-based policies.",
  },
  {
    id: "AWS-008",
    name: "Mass S3 Deletion",
    severity: "CRITICAL" as Severity,
    description:
      "More than 10 S3 object deletions from the same principal within 5 minutes — could indicate ransomware or a destructive insider attack.",
    triggers: ["DeleteObject", "DeleteObjects"],
    mitigation: "Enable S3 Versioning and MFA Delete on critical buckets.",
  },
  {
    id: "AWS-009",
    name: "New IAM User or Access Key Created",
    severity: "MEDIUM" as Severity,
    description:
      "CreateUser or CreateAccessKey was called — a possible backdoor for persistent programmatic access.",
    triggers: ["CreateUser", "CreateAccessKey"],
    mitigation: "Alert on all IAM user creation, enforce JIT access patterns, review new users immediately.",
  },
  {
    id: "AWS-010",
    name: "Off-Hours Cloud Console Access",
    severity: "MEDIUM" as Severity,
    description:
      "AWS Console or API activity detected outside business hours (10 PM – 6 AM). May indicate a compromised account.",
    triggers: ["Any CloudTrail event outside the configured business-hours window"],
    mitigation: "Use time-based IAM condition keys (aws:CurrentTime) to restrict sensitive actions off-hours.",
  },
];

const requiredEvents = [
  { event: "Management Events", note: "Enabled by default in CloudTrail — covers IAM, S3 control-plane, login, etc." },
  { event: "S3 Data Events",    note: "Must be explicitly enabled — required for AWS-007 (bulk download) and AWS-008 (mass delete)." },
];

export default function AwsRulesPage() {
  const critical = rules.filter((r) => r.severity === "CRITICAL").length;
  const high     = rules.filter((r) => r.severity === "HIGH").length;
  const medium   = rules.filter((r) => r.severity === "MEDIUM").length;

  return (
    <div className="flex flex-col gap-6 p-6 max-w-4xl">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
          <Cloud className="h-6 w-6 text-primary" />
          AWS CloudTrail Detection Rules
        </h1>
        <p className="text-sm text-muted-foreground mt-1">
          10 rules designed for AWS environments. Feeds from the CloudTrail{" "}
          <code className="text-xs bg-muted px-1 py-0.5 rounded">LookupEvents</code> API via the{" "}
          <code className="text-xs bg-muted px-1 py-0.5 rounded">AWSCloudTrailAdapter</code>.
        </p>
      </div>

      {/* Summary pills */}
      <div className="flex flex-wrap gap-3">
        <div className={`flex items-center gap-2 rounded-lg border px-4 py-2 text-sm font-medium ${SEVERITY_STYLE["CRITICAL"]}`}>
          <ShieldAlert className="h-4 w-4" />
          {critical} Critical
        </div>
        <div className={`flex items-center gap-2 rounded-lg border px-4 py-2 text-sm font-medium ${SEVERITY_STYLE["HIGH"]}`}>
          <AlertTriangle className="h-4 w-4" />
          {high} High
        </div>
        <div className={`flex items-center gap-2 rounded-lg border px-4 py-2 text-sm font-medium ${SEVERITY_STYLE["MEDIUM"]}`}>
          <Zap className="h-4 w-4" />
          {medium} Medium
        </div>
      </div>

      {/* CloudTrail prerequisite note */}
      <Card className="border-blue-500/20 bg-blue-500/5">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-semibold text-blue-400">CloudTrail Prerequisites</CardTitle>
        </CardHeader>
        <CardContent className="p-0 pb-3">
          <div className="divide-y divide-blue-500/10">
            {requiredEvents.map((r) => (
              <div key={r.event} className="flex items-start gap-3 px-6 py-2.5 text-sm">
                <span className="font-mono text-xs bg-blue-500/10 border border-blue-500/20 text-blue-300 px-2 py-0.5 rounded shrink-0 mt-0.5">
                  {r.event}
                </span>
                <span className="text-muted-foreground">{r.note}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Rules */}
      <div className="flex flex-col gap-4">
        {rules.map((rule) => (
          <Card key={rule.id}>
            <CardHeader className="pb-2">
              <div className="flex items-center gap-3 flex-wrap">
                <span className="font-mono text-xs bg-muted px-2 py-0.5 rounded text-muted-foreground shrink-0">
                  {rule.id}
                </span>
                <CardTitle className="text-sm font-semibold flex-1">{rule.name}</CardTitle>
                <span
                  className={`text-[11px] font-semibold border rounded px-2 py-0.5 shrink-0 ${SEVERITY_STYLE[rule.severity]}`}
                >
                  {rule.severity}
                </span>
              </div>
              <p className="text-xs text-muted-foreground mt-1 pl-0">{rule.description}</p>
            </CardHeader>
            <CardContent className="pb-4 flex flex-col gap-3">
              {/* Triggers */}
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground/60 mb-1.5">
                  CloudTrail events
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {rule.triggers.map((t, i) => (
                    <span
                      key={i}
                      className="font-mono text-[11px] bg-muted border border-border rounded px-2 py-0.5 text-foreground/80"
                    >
                      {t}
                    </span>
                  ))}
                </div>
              </div>
              {/* Mitigation */}
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground/60 mb-1">
                  Mitigation
                </p>
                <p className="text-xs text-muted-foreground">{rule.mitigation}</p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* How to activate */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-semibold">Activating AWS Rules</CardTitle>
        </CardHeader>
        <CardContent className="pb-4 text-sm text-muted-foreground flex flex-col gap-2">
          <p>
            In <code className="text-xs bg-muted px-1 py-0.5 rounded">app.py</code>, the AWS rule engine is
            automatically selected when the <code className="text-xs bg-muted px-1 py-0.5 rounded">source</code> is{" "}
            <code className="text-xs bg-muted px-1 py-0.5 rounded">&quot;aws&quot;</code>:
          </p>
          <pre className="rounded-md bg-muted px-4 py-3 text-xs font-mono text-foreground overflow-x-auto whitespace-pre-wrap">
{`POST /api/run
{
  "source": "aws",
  "region": "ap-south-1",
  "aws_access_key": "AKIA…",
  "aws_secret_key": "…"
}

# Or run the built-in simulation (sidebar button)
POST /api/run  { "source": "simulated" }`}
          </pre>
          <p>
            Rules are defined in{" "}
            <code className="text-xs bg-muted px-1 py-0.5 rounded">config.RULES</code> and evaluated by the
            same <code className="text-xs bg-muted px-1 py-0.5 rounded">RuleEngine</code> used by the simulator,
            with two additional rule types:{" "}
            <code className="text-xs bg-muted px-1 py-0.5 rounded">single_event</code> and{" "}
            <code className="text-xs bg-muted px-1 py-0.5 rounded">actor_type</code>.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
