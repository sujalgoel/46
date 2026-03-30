// frontend/lib/config.ts
export const ORG_DOMAIN = "s.amity.edu";
export const OFF_HOURS_START = 22; // 10 PM
export const OFF_HOURS_END = 6;    // 6 AM

export type RuleSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type RuleType = "frequency" | "single_event" | "actor_type" | "permission" | "time";

export interface Rule {
  id: string;
  name: string;
  description: string;
  severity: RuleSeverity;
  type: RuleType;
  action?: string;
  threshold?: number;
  window_minutes?: number;
  actor_type?: string;
}

export const RULES: Rule[] = [
  {
    id: "AWS-001",
    name: "Root Account Usage",
    description: "The AWS root account was used. Root should never be used for day-to-day operations — it has unrestricted access to every resource.",
    severity: "CRITICAL",
    type: "actor_type",
    actor_type: "root",
  },
  {
    id: "AWS-002",
    name: "CloudTrail Logging Disabled",
    description: "StopLogging or DeleteTrail was called, disabling audit logging. A common attacker tactic to cover tracks.",
    severity: "CRITICAL",
    type: "single_event",
    action: "LOGGING_DISABLED",
  },
  {
    id: "AWS-003",
    name: "IAM Privilege Escalation",
    description: "An AdministratorAccess or PowerUser policy was attached to an IAM user or role, granting near-unlimited permissions.",
    severity: "CRITICAL",
    type: "single_event",
    action: "IAM_ESCALATION",
  },
  {
    id: "AWS-004",
    name: "Excessive Access Denied Errors",
    description: "More than 10 AccessDenied errors from the same principal within 5 minutes — indicates brute-force enumeration or a compromised credential.",
    severity: "HIGH",
    type: "frequency",
    action: "ACCESS_DENIED",
    threshold: 10,
    window_minutes: 5,
  },
  {
    id: "AWS-005",
    name: "S3 Bucket Made Public",
    description: "A bucket ACL or policy was changed to allow public access, or the PublicAccessBlock was removed — risk of data exposure.",
    severity: "HIGH",
    type: "permission",
    action: "PERMISSION_CHANGE",
  },
  {
    id: "AWS-006",
    name: "Multiple Failed Console Logins",
    description: "More than 3 failed AWS Console login attempts from the same user within 10 minutes.",
    severity: "HIGH",
    type: "frequency",
    action: "LOGIN_FAIL",
    threshold: 3,
    window_minutes: 10,
  },
  {
    id: "AWS-007",
    name: "Bulk S3 Object Download",
    description: "More than 20 S3 GetObject calls from the same principal within 5 minutes — possible data exfiltration.",
    severity: "HIGH",
    type: "frequency",
    action: "DOWNLOAD",
    threshold: 20,
    window_minutes: 5,
  },
  {
    id: "AWS-008",
    name: "Mass S3 Deletion",
    description: "More than 10 S3 object deletions from the same principal within 5 minutes — ransomware or destructive insider attack.",
    severity: "CRITICAL",
    type: "frequency",
    action: "DELETE",
    threshold: 10,
    window_minutes: 5,
  },
  {
    id: "AWS-009",
    name: "New IAM User or Access Key Created",
    description: "CreateUser or CreateAccessKey was called — a possible backdoor for persistent access.",
    severity: "MEDIUM",
    type: "single_event",
    action: "IAM_CREATE_USER",
  },
  {
    id: "AWS-010",
    name: "Off-Hours Cloud Console Access",
    description: "AWS Console or API activity detected outside business hours (10 PM – 6 AM).",
    severity: "MEDIUM",
    type: "time",
  },
];
