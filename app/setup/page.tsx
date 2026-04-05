import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  CheckCircle2,
  Terminal,
  Settings,
  KeyRound,
  Globe,
  Cloud,
  ShieldCheck,
} from "lucide-react";

const awsSteps = [
  {
    icon: Globe,
    title: "Enable CloudTrail",
    description: "Create a trail in your AWS account to capture management and data events.",
    items: [
      "Open AWS Console → CloudTrail → Create trail",
      "Choose a name and an S3 bucket for log delivery",
      "Under Events: enable Management events (Read + Write)",
      "Also enable S3 Data events for bulk-download / mass-delete detection (AWS-007, AWS-008)",
    ],
  },
  {
    icon: KeyRound,
    title: "Create an IAM User / Role",
    description: "Grant the IDS read-only access to CloudTrail's LookupEvents API.",
    items: [
      "IAM → Users → Create user (e.g. ids-cloudtrail-reader)",
      "Attach inline or managed policy with cloudtrail:LookupEvents",
      "Also add s3:GetObject on the log bucket if you need S3-pull mode",
      "Generate an Access Key and note the Key ID and Secret",
    ],
    code: `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["cloudtrail:LookupEvents"],
    "Resource": "*"
  }]
}`,
  },
  {
    icon: Terminal,
    title: "Install boto3",
    description: "The AWS SDK for Python, required to pull events from CloudTrail.",
    code: "pip install boto3",
  },
  {
    icon: Settings,
    title: "Set AWS Credentials",
    description: "Export credentials as environment variables before starting app.py.",
    code: `export AWS_ACCESS_KEY_ID=AKIA…
export AWS_SECRET_ACCESS_KEY=…
export AWS_DEFAULT_REGION=ap-south-1`,
  },
  {
    icon: Settings,
    title: "Run analysis via the API",
    description: "Send a POST request to /api/run with source set to aws. The pipeline runs all 10 rules plus ML anomaly detection automatically.",
    code: `curl -X POST http://127.0.0.1:8080/api/run \\
  -H "Content-Type: application/json" \\
  -d '{
    "source":  "aws",
    "region":  "ap-south-1",
    "hours_back": 24
  }'`,
  },
];

const awsRuleCompat = [
  { id: "AWS-001", name: "Root Account Usage",             note: "" },
  { id: "AWS-002", name: "CloudTrail Logging Disabled",    note: "" },
  { id: "AWS-003", name: "IAM Privilege Escalation",       note: "" },
  { id: "AWS-004", name: "Excessive Access Denied Errors", note: "" },
  { id: "AWS-005", name: "S3 Bucket Made Public",          note: "" },
  { id: "AWS-006", name: "Multiple Failed Console Logins", note: "" },
  { id: "AWS-007", name: "Bulk S3 Object Download",        note: "Enable S3 data events in trail" },
  { id: "AWS-008", name: "Mass S3 Deletion",               note: "Enable S3 data events in trail" },
  { id: "AWS-009", name: "New IAM User / Access Key",      note: "" },
  { id: "AWS-010", name: "Off-Hours Console Access",       note: "" },
];

export default function SetupPage() {
  return (
    <div className="flex flex-col gap-6 p-6 max-w-4xl">

      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
          <Cloud className="h-5 w-5 text-primary" />
          AWS CloudTrail Setup
        </h1>
        <p className="text-sm text-muted-foreground mt-1">
          Connect the IDS to a real AWS account using the CloudTrail{" "}
          <code className="text-xs bg-muted px-1 py-0.5 rounded">LookupEvents</code> API.
          All 10 detection rules activate automatically when you pass{" "}
          <code className="text-xs bg-muted px-1 py-0.5 rounded">source=aws</code>.
        </p>
      </div>

      {/* Notice */}
      <Card className="border-blue-500/20 bg-blue-500/5">
        <CardContent className="flex gap-3 p-4">
          <ShieldCheck className="h-5 w-5 text-blue-400 shrink-0 mt-0.5" />
          <div className="text-sm">
            <p className="font-medium text-blue-400 mb-1">S3 data events for full coverage</p>
            <p className="text-muted-foreground">
              Management events like IAM changes, logins, and CloudTrail modifications are captured by default.
              To detect bulk downloads (AWS-007) and mass deletions (AWS-008) you also need to
              enable <strong className="text-foreground">S3 data events</strong> in your trail.
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Steps */}
      <div className="flex flex-col gap-4">
        {awsSteps.map((step, i) => (
          <Card key={i}>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <span className="flex h-6 w-6 items-center justify-center rounded-full bg-primary/10 text-primary text-xs font-bold shrink-0">
                  {i + 1}
                </span>
                <step.icon className="h-4 w-4 text-muted-foreground" />
                {step.title}
              </CardTitle>
              <p className="text-xs text-muted-foreground pl-8">{step.description}</p>
            </CardHeader>
            <CardContent className="pl-8 pb-4">
              {"items" in step && step.items && (
                <ul className="flex flex-col gap-1.5 mb-2">
                  {step.items.map((item, j) => (
                    <li key={j} className="flex items-start gap-2 text-sm">
                      <span className="text-primary mt-0.5">›</span>
                      <span className="text-muted-foreground">{item}</span>
                    </li>
                  ))}
                </ul>
              )}
              {"code" in step && step.code && (
                <pre className="mt-1 rounded-md bg-muted px-4 py-3 text-xs font-mono text-foreground overflow-x-auto whitespace-pre-wrap">
                  {step.code}
                </pre>
              )}
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Rule compatibility */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-semibold">Rule Compatibility</CardTitle>
          <p className="text-xs text-muted-foreground">
            All 10 AWS rules work with CloudTrail. AWS-007 and AWS-008 additionally require S3 data events.
          </p>
        </CardHeader>
        <CardContent className="p-0 pb-2">
          <div className="divide-y">
            {awsRuleCompat.map((r) => (
              <div key={r.id} className="flex items-center gap-3 px-6 py-2.5 text-sm">
                <span className="font-mono text-xs bg-muted px-1.5 py-0.5 rounded w-[76px] shrink-0 text-center">
                  {r.id}
                </span>
                <span className="flex-1 text-muted-foreground">{r.name}</span>
                <CheckCircle2 className="h-4 w-4 text-green-500 shrink-0" />
                {r.note && (
                  <span className="text-[11px] text-muted-foreground/60 hidden sm:block max-w-[240px] text-right">
                    {r.note}
                  </span>
                )}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

    </div>
  );
}
