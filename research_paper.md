# Rule-Based Intrusion Detection System for AWS CloudTrail Audit Logs

**Riya Karagwal · Rhea T. Chakraborty**  
B.Tech Computer Science Engineering, Amity University  
Guide: Prof. (Dr.) S. K. Dubey  
Group 46

---

## Abstract

Cloud infrastructure has become the default deployment target for organisations of all sizes, yet the audit trail it produces is rarely monitored with any rigour. AWS CloudTrail records every API call made against an account — who called what service, from where, at what time, and whether it succeeded — but most deployments leave this stream sitting unexamined in an S3 bucket. This paper presents a real-time, rule-based intrusion detection system (IDS) built on AWS CloudTrail that normalises raw API audit events into a canonical schema, evaluates each event against ten detection rules spanning the most dangerous AWS attack patterns, and persists findings to a MongoDB Atlas database exposed through a Next.js dashboard. The system is implemented entirely in TypeScript as a serverless Next.js application deployed on Vercel, with Prisma as the database abstraction layer. A simulated data adapter injects all ten attack patterns on demand, making the system demonstrable without a live AWS account. Evaluation over fifty simulation runs confirms zero false negatives on injected patterns, with an average of 47 alerts per run. A bulk-insert architecture reduces per-run database I/O from approximately 400 sequential writes to two parallel batch commands, cutting end-to-end processing time from over 60 seconds to under 5 seconds on the serverless runtime. The rule-based approach is justified over machine learning on the grounds that CloudTrail event names are high-signal and unambiguous, require no per-account training data, and produce fully interpretable alert details. The paper discusses design decisions, threshold calibration, limitations of batch polling, and directions for extension toward streaming ingestion and cross-user correlation.

---

## 1. Introduction

### 1.1 Motivation

The economics of cloud computing have shifted access to enterprise-grade infrastructure from large organisations to individuals. A university student can provision a multi-region AWS environment in minutes. The same democratisation that lowers the barrier to building extends to attacking: an adversary who obtains a single IAM access key — leaked in a public Git commit, phished from an employee, or extracted from a misconfigured EC2 instance metadata endpoint — gains the ability to read every S3 object, escalate their own privileges, create backdoor users, and disable the audit trail that would reveal their presence, all through authenticated HTTP requests indistinguishable from legitimate operations.

AWS publishes a native audit service, CloudTrail, that records every API call to most services with sub-second granularity. In principle, this gives defenders a complete chronicle of account activity. In practice, organisations commonly enable CloudTrail, route events to an S3 bucket, and never look at them again. The logs are there; the tooling to act on them in real time is either absent, expensive (commercial SIEM), or operationally complex (self-managed ELK stack).

### 1.2 Problem Statement

Given a stream of AWS CloudTrail events, the problem is to detect anomalous or clearly malicious API activity as it occurs, generate structured alerts with sufficient context for a human reviewer to act, and present the results through a low-friction interface accessible to a team without a dedicated security operations centre.

The detection scope is intentionally bounded: this system targets the ten highest-signal, most unambiguous threat categories that appear repeatedly in public AWS breach post-mortems — root account usage, audit log tampering, IAM privilege escalation, failed login storms, bulk data exfiltration, mass deletion, new backdoor user creation, and off-hours access. It does not attempt to detect sophisticated low-and-slow attacks that blend into normal traffic patterns.

### 1.3 Contributions

This paper makes the following contributions:

1. A complete open-source implementation of a cloud IDS as a Next.js 16 serverless application with TypeScript, Prisma 5, and MongoDB Atlas, deployable to Vercel in under five minutes with no infrastructure to manage.
2. A rule engine architecture that separates detection logic from storage and presentation, allowing new rules to be added as configuration objects with no engine code changes.
3. A UTC-aware timestamp parsing scheme that prevents false negatives from timezone interpretation errors on non-UTC hosts.
4. A bulk-insert optimisation that replaces O(n) sequential Prisma writes with two parallel native MongoDB commands, reducing processing time by more than 90% on the Vercel serverless runtime.
5. A simulated data adapter that injects all ten attack patterns with randomised burst sizes and timing, providing a reproducible test harness without requiring a live AWS account.

### 1.4 Paper Organisation

Section 2 surveys background work on intrusion detection and the specific properties of CloudTrail as a log source. Section 3 defines the threat model. Section 4 describes the system architecture. Section 5 details CloudTrail event normalisation. Section 6 specifies all ten detection rules with their rationale and thresholds. Section 7 covers implementation details including the TypeScript rule engine, bulk-insert optimisation, and timezone handling. Section 8 presents evaluation results. Section 9 discusses limitations. Section 10 proposes future work. Section 11 concludes.

---

## 2. Background and Related Work

### 2.1 Taxonomy of Intrusion Detection Systems

IDS research historically classifies systems along two orthogonal axes.

**Placement** — Host-based IDS (HIDS) operates on a single machine, monitoring system calls, file integrity, and login records. Network-based IDS (NIDS) observes traffic at a network boundary, inspecting packet headers and payloads. Cloud-based or API-based IDS does not fit cleanly into either category. CloudTrail events are neither file system records nor network packets; they are structured JSON documents describing authenticated API calls to cloud control planes and data planes.

**Detection method** — Signature-based (or rule-based) detection matches events against known-bad patterns defined a priori. Anomaly-based detection constructs a statistical model of normal behaviour during a baseline period and flags deviations. Hybrid systems combine both. This system is primarily signature-based — the `single_event` and `actor_type` rule types fire on specific, unambiguous event patterns — but the `frequency` type has an anomaly-based character: it flags behaviour that exceeds a rate threshold, which could technically occur legitimately in edge cases.

### 2.2 Why Rule-Based Over Machine Learning for CloudTrail

The argument for applying machine learning to audit log analysis typically rests on the assumption that attack patterns are subtle, blended with normal traffic, and do not map cleanly to discrete signatures. This assumption holds for network intrusion detection, where attacks like port scanning or slow-rate data exfiltration may differ only quantitatively from normal background traffic.

CloudTrail events are fundamentally different. The event namespace is controlled by AWS: event names like `StopLogging`, `DeleteTrail`, `AttachUserPolicy`, and `ConsoleLogin` are defined in the API schema, not inferred from traffic. An event where `eventName = StopLogging` is unambiguously an attempt to disable audit logging — there is no legitimate business use case that generates this event accidentally. A rule that fires on the presence of this event has a theoretical false positive rate of zero.

ML-based approaches applied to CloudTrail data [1, 2] face several practical problems: they require months of per-account baseline data before producing reliable anomaly scores; they produce scores without explanations, making it difficult for a reviewer to determine why an alert fired; they are sensitive to distribution shift when normal usage patterns change (new deployments, new teams, seasonal traffic); and they typically require dedicated training infrastructure.

For the threat categories this system targets, simple rules work better. A neural network is not needed to detect root account activity — a conditional check on `user_type == "root"` is sufficient and correct.

### 2.3 AWS CloudTrail as a Log Source

CloudTrail records API calls to the vast majority of AWS services. Each record contains: the event name, the caller identity (root, IAM user, IAM role, assumed role, federated user), the source IP address, the AWS region, the request parameters, the response elements, an error code if the call failed, and a precise UTC timestamp.

CloudTrail distinguishes two event categories:

**Management events** (also called control-plane events) record operations that configure AWS resources: creating or deleting IAM users, modifying S3 bucket policies, starting and stopping EC2 instances. Management events are recorded by default at no additional cost beyond CloudTrail storage.

**Data events** (also called data-plane events) record read and write operations on objects within services: S3 `GetObject` and `DeleteObject`, Lambda function invocations, DynamoDB item-level operations. Data events must be explicitly enabled per trail and per service, and they generate significantly higher log volumes (an active S3 bucket serving a web application may produce millions of events per day).

Rules AWS-007 (bulk download) and AWS-008 (mass deletion) require S3 data events to be enabled because they detect high rates of `GetObject` and `DeleteObject` respectively. The remaining eight rules operate entirely on management events.

### 2.4 Related Systems

**AWS GuardDuty** is Amazon's managed threat detection service. It ingests CloudTrail, VPC Flow Logs, and DNS logs, and applies a combination of ML models and curated threat intelligence signatures. GuardDuty covers most of the same threat categories as this system and more, but it is a subscription service priced per event volume. At scale it is cost-effective; for academic or proof-of-concept use, the cost-to-insight ratio is poor. Additionally, GuardDuty treats its detection logic as a black box — the exact conditions under which a finding fires are not publicly documented.

**Sigma** [6] is an open standard for writing detection rules in a vendor-neutral YAML format, analogous to Snort rules for network traffic. The Sigma community maintains a library of CloudTrail detection rules translated from public threat intelligence. This system's rule semantics are inspired by the Sigma approach (rule type, action, threshold, window) but implemented natively in TypeScript rather than as YAML documents compiled to a SIEM query language.

**CloudTrail Lake** is a managed analytics feature that stores CloudTrail events in an AWS-managed data lake and allows SQL queries via Athena. It provides excellent ad hoc investigation capability but no automated real-time alerting.

Academic work on cloud intrusion detection includes LSTM-based sequence models applied to CloudTrail event names [3], graph analysis of IAM relationships to detect lateral movement [4], and isolation forest models trained on API call frequency vectors [1]. All of these approaches share the training data requirement limitation discussed in Section 2.2.

---

## 3. Threat Model

The system assumes a cloud environment hosted on AWS with CloudTrail enabled. The adversary is a principal — human or automated — who has obtained some level of AWS credentials: an access key ID and secret, console login credentials, or the ability to make API calls as an assumed role from a compromised compute resource.

The threat model covers the following attack categories, in approximate order of severity:

**Audit evasion** — Disabling or deleting CloudTrail trails (`StopLogging`, `DeleteTrail`) to eliminate the audit record before or during an attack. This is the highest-priority category because it directly impairs detection capability.

**Privilege escalation** — Attaching an administrator or power-user policy to an IAM principal to expand access beyond what was originally granted. A low-privilege user who achieves this becomes an administrator.

**Credential abuse** — Using the root account for operations that should be performed by named IAM users. Root has unrestricted access to every resource and cannot be limited by IAM policies.

**Brute-force access** — Generating high rates of `AccessDenied` errors (automated enumeration of resource names or permission boundaries) or failed console logins (credential stuffing).

**Data exfiltration** — Downloading large volumes of S3 objects in a short time window, consistent with bulk data theft.

**Destructive attack** — Deleting large numbers of S3 objects in a short time window, consistent with ransomware or a destructive insider.

**Persistence establishment** — Creating new IAM users or access keys to maintain access after a primary credential is rotated or revoked.

**Stealth access** — Accessing cloud resources outside business hours, potentially indicating an attacker operating in a different time zone or deliberately avoiding observation.

**Exposure misconfiguration** — Removing public access blocks or modifying bucket ACLs to make S3 objects accessible to the internet.

The threat model explicitly excludes:

- Attackers operating entirely within rate limits and business hours who avoid the specific event signatures targeted by the rules.
- Attacks distributed across multiple compromised identities to stay below per-user frequency thresholds.
- Supply-chain attacks against the AWS account itself (e.g., compromised IAM Identity Center).
- Infrastructure-level attacks against CloudTrail delivery (tampered log files in S3 before the system reads them).

---

## 4. System Architecture

### 4.1 Overview

The system is a Next.js 16 application structured as a serverless pipeline. Figure 1 shows the component layout.

```
┌──────────────────────────────┐
│        Data Source Layer     │
│  SimulatedAdapter            │
│  AWSCloudTrailAdapter        │
└─────────────┬────────────────┘
              │  LogEvent[]
              ▼
┌──────────────────────────────┐
│        Rule Engine           │
│  evaluate(event, history)    │
│  → TriggeredAlert[]          │
└─────────────┬────────────────┘
              │
              ▼
┌──────────────────────────────┐
│        Alert Manager         │
│  storeLogs()  (bulk)         │
│  storeAlerts() (bulk)        │
│  getUserHistory()            │
│  getAlerts() / getLogs()     │
│  getStats()  (aggregations)  │
└─────────────┬────────────────┘
              │  Prisma 5 / $runCommandRaw
              ▼
┌──────────────────────────────┐
│     MongoDB Atlas            │
│  collection: logs            │
│  collection: alerts          │
└──────────────────────────────┘
              ▲
              │ server components (direct import)
┌──────────────────────────────┐
│      Next.js Frontend        │
│  /           Dashboard       │
│  /alerts     Alert table     │
│  /logs       Audit log table │
│  /api/run    POST: ingest     │
│  /api/stats  GET: summary    │
│  /api/alerts GET: filter     │
│  /api/logs   GET: filter     │
│  /api/clear  POST: reset     │
└──────────────────────────────┘
```

### 4.2 Data Source Layer

Two adapters implement the same structural interface — both return `LogEvent[]`:

**`SimulatedAdapter`** generates 180–420 synthetic events per invocation with deterministic attack patterns injected for all ten rules. It requires no external credentials and is the primary test harness. Each instantiation shuffles the user list so repeated runs produce different per-user alert distributions.

**`AWSCloudTrailAdapter`** calls the AWS CloudTrail `LookupEvents` API via the AWS SDK v3, paginates through all available management events within the lookback window (default: last 24 hours), and normalises each record to the canonical `LogEvent` schema. It accepts credentials as constructor parameters (region, access key ID, secret access key) or falls back to environment variables and the standard AWS credential provider chain.

The adapter boundary means the rule engine has no knowledge of where events came from. New sources — GCP Cloud Audit Logs, Azure Monitor activity logs, or a synthetic adapter generating specific edge cases for a test run — can be added by implementing the same return type.

### 4.3 Rule Engine

The rule engine (`lib/rule-engine.ts`) is a pure TypeScript class with no I/O dependencies. Its public interface is a single method:

```typescript
evaluate(event: LogEvent, history: LogEvent[]): TriggeredAlert[]
```

It loops over the rule list from `lib/config.ts`, dispatches each rule to the appropriate type handler, and returns all alerts for rules that fired. The engine is stateless between calls; history must be passed in by the caller. This design allows the engine to be tested in isolation without a database and enables the batch-processing optimisation described in Section 7.3.

### 4.4 Alert Manager

The alert manager (`lib/alert-manager.ts`) is the sole interface to the database. It exposes functions for:

- Bulk-inserting a batch of log events (`storeLogs`)
- Bulk-inserting a batch of alerts (`storeAlerts`)
- Querying user history for frequency rule evaluation (`getUserHistory`)
- Listing and filtering logs and alerts (`getLogs`, `getAlerts`)
- Aggregating statistics for the dashboard (`getStats`)
- Acknowledging individual alerts (`acknowledgeAlert`)
- Clearing all data (`clearAll`)

Aggregation queries (counts by severity, counts by rule, hourly event distribution) bypass Prisma's query builder and execute native MongoDB aggregation pipelines via `$runCommandRaw`, as Prisma 5 does not expose an aggregation pipeline API for MongoDB.

### 4.5 API Routes

Six Next.js Route Handlers expose the system's functionality over HTTP:

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/run` | Ingest events, run rule engine, batch-write results |
| GET | `/api/stats` | Aggregated dashboard statistics |
| GET | `/api/alerts` | Paginated, filterable alert list |
| POST | `/api/alerts/[id]/acknowledge` | Mark a single alert acknowledged |
| GET | `/api/logs` | Paginated, filterable event log |
| POST | `/api/clear` | Delete all logs and alerts |

All routes return JSON. Error responses include a `message` field. The `/api/run` route has a `maxDuration` of 60 seconds (Vercel's maximum for the Hobby plan) — the batch-insert optimisation in Section 7.3 ensures this limit is not reached in practice.

### 4.6 Frontend

The frontend consists of three server-rendered pages. Because Next.js server components execute on the server and have direct access to Node.js modules, they call the alert manager functions directly rather than fetching their own API routes over HTTP. This eliminates a round-trip and avoids the ECONNREFUSED errors that occur when a serverless function tries to connect to localhost.

The dashboard (`/`) displays: total events processed, total alerts triggered, unacknowledged alert count, active user count, a pie chart of alerts by severity (Recharts), and a bar chart of top triggered rules (Recharts).

The alerts page (`/alerts`) renders a sortable table with per-row severity colour coding, rule details, user, description, acknowledgement status, and an acknowledge button. Filter controls allow narrowing by severity (CRITICAL, HIGH, MEDIUM, LOW) and by rule ID.

The logs page (`/logs`) renders the full event audit trail with timestamp, user, action badge, file/resource, IP address, and source. Filter controls allow narrowing by action type.

---

## 5. CloudTrail Event Normalisation

### 5.1 Raw CloudTrail Format

The AWS SDK's `LookupEvents` response returns records of the form:

```json
{
  "EventId": "a1b2c3d4-...",
  "EventName": "AttachUserPolicy",
  "EventTime": "2026-03-30T14:32:00.000Z",
  "Username": "ops-user",
  "Resources": [],
  "CloudTrailEvent": "{\"eventVersion\":\"1.08\",
    \"userIdentity\":{\"type\":\"IAMUser\",
    \"principalId\":\"AIDA...\",\"arn\":\"arn:aws:iam::...\",
    \"accountId\":\"123456789012\",\"userName\":\"ops-user\"},
    \"requestParameters\":{\"userName\":\"target-user\",
    \"policyArn\":\"arn:aws:iam::aws:policy/AdministratorAccess\"},
    \"responseElements\":null,
    \"errorCode\":\"\"}"
}
```

The `CloudTrailEvent` field is a JSON-encoded string embedded within the outer JSON, requiring a second parse pass. Many fields needed for detection — `errorCode`, `userIdentity.type`, `requestParameters`, `responseElements.ConsoleLogin` — exist only inside this nested payload.

### 5.2 Canonical Schema

Every event is normalised to the following TypeScript interface:

```typescript
interface LogEvent {
  event_id:        string;   // EventId from CloudTrail, or UUID if absent
  timestamp:       string;   // ISO 8601, no timezone suffix, UTC
  user_email:      string;   // username@domain or "root@aws"
  user_type:       string;   // "root" | "iamuser" | "assumedrole" | "federated"
  action:          string;   // normalised action code (see §5.3)
  file_name:       string;   // resource ARN or S3 object key
  ip_address:      string;   // source IP of the API call
  permission_type: string;   // "public" when a public-access change is detected
}
```

### 5.3 Action Mapping

The full CloudTrail API namespace — hundreds of event names across dozens of services — is compressed into eleven action codes:

| Action code | Source event names |
|-------------|-------------------|
| `ACCESS_DENIED` | Any event where `errorCode` contains `"AccessDenied"` |
| `LOGIN_FAIL` | `ConsoleLogin` where `responseElements.ConsoleLogin == "Failure"` |
| `LOGGING_DISABLED` | `StopLogging`, `DeleteTrail` |
| `IAM_ESCALATION` | `AttachUserPolicy` or `AttachRolePolicy` where `policyArn` contains `AdministratorAccess` or `PowerUser` |
| `IAM_CREATE_USER` | `CreateUser`, `CreateAccessKey` |
| `PERMISSION_CHANGE` | `DeleteBucketPublicAccessBlock`, `PutBucketAcl` with public grants, `PutBucketPolicy` permitting public access |
| `DELETE` | `DeleteObject`, `DeleteObjects`, `DeleteBucket` |
| `DOWNLOAD` | `GetObject` |
| `UPLOAD` | `PutObject`, `CopyObject` |
| `MOVE` | `MoveObject` (not a native CloudTrail event; reserved for future adapters) |
| `VIEW` | All other events (catch-all for non-suspicious activity) |

When `errorCode` contains `AccessDenied`, that code takes precedence over the event name mapping. This ensures that, for example, a failed `GetObject` is classified as `ACCESS_DENIED` rather than `DOWNLOAD`.

The `permission_type` field is set to `"public"` for `PERMISSION_CHANGE` events that specifically involve removing public access restrictions or granting public read/write access. Non-public permission changes (e.g., adding a bucket policy that grants access to a specific account) also produce a `PERMISSION_CHANGE` action but with an empty `permission_type`, which does not trigger AWS-005.

---

## 6. Detection Rules

### 6.1 Rule Schema

Each rule is a TypeScript object implementing the following interface, stored in `lib/config.ts`:

```typescript
interface Rule {
  id:              string;         // e.g. "AWS-004"
  name:            string;         // human-readable name
  description:     string;         // alert detail template
  severity:        RuleSeverity;   // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
  type:            RuleType;       // handler to invoke
  action?:         string;         // required for frequency, single_event, permission
  threshold?:      number;         // required for frequency
  window_minutes?: number;         // required for frequency
  actor_type?:     string;         // required for actor_type
}
```

This configuration-driven design means that adding a new rule requires no changes to the engine code. The rule author specifies what to detect; the engine handles how to detect it.

### 6.2 Rule Types and Handlers

**`actor_type`** — Fires when `event.user_type` (lowercased) matches `rule.actor_type`. Used exclusively for AWS-001 to detect root account activity.

**`single_event`** — Fires on the first occurrence of a specific action code, regardless of frequency or context. Used for events that are unambiguous regardless of count: disabling CloudTrail, privilege escalation, and creating backdoor users.

**`frequency`** — Evaluates the count of events matching `rule.action` in the user's history within the last `rule.window_minutes` minutes, including the current event. Fires when this count reaches `rule.threshold`. The window is computed from the current event's timestamp, not wall-clock time, so the check works correctly on historical data.

```typescript
private checkFrequency(rule: Rule, event: LogEvent, history: LogEvent[]): [boolean, string] {
  if (event.action !== rule.action) return [false, ""];
  const windowMs  = (rule.window_minutes ?? 60) * 60 * 1_000;
  const eventMs   = this.parseTimestamp(event.timestamp).getTime();
  const cutoffMs  = eventMs - windowMs;
  const count     = history.filter(
    h => h.action === rule.action &&
         this.parseTimestamp(h.timestamp).getTime() >= cutoffMs
  ).length + 1; // +1 for current event
  if (count >= (rule.threshold ?? 10)) {
    return [true, `${count} ${rule.action} events in ${rule.window_minutes ?? 60} min`];
  }
  return [false, ""];
}
```

**`permission`** — Fires when `event.action === rule.action` and `event.permission_type` is non-empty. Currently used only for AWS-005 to distinguish public-exposure changes from benign permission modifications.

**`time`** — Fires when the hour of the event's UTC timestamp falls before `OFF_HOURS_END` (6 AM) or at or after `OFF_HOURS_START` (10 PM). Business hours are defined in `lib/config.ts` and can be adjusted per deployment.

### 6.3 Rule Specifications

**AWS-001 — Root Account Usage** (CRITICAL, `actor_type`)

The AWS root account is created when an AWS account is first opened. It has unrestricted access to every resource and cannot be constrained by IAM policies. AWS best practice is to enable MFA on the root account and never use it for day-to-day operations. Any API call from the root account is a red flag — it indicates either a security policy violation or an active compromise of the highest-privilege credential in the account.

*Trigger*: `event.user_type == "root"`  
*False positive rate*: Near zero in a well-governed account.

---

**AWS-002 — CloudTrail Logging Disabled** (CRITICAL, `single_event`)

`StopLogging` and `DeleteTrail` are the two CloudTrail API calls that terminate the audit record. A sophisticated attacker will often call one of these before performing the bulk of their activity so that subsequent events are not recorded. Detecting this call is the most time-critical alert in the system — the window between disabling logging and the attacker acting is narrow.

*Trigger*: `action == "LOGGING_DISABLED"`  
*False positive rate*: Zero in normal operations. No legitimate automated process disables CloudTrail.

---

**AWS-003 — IAM Privilege Escalation** (CRITICAL, `single_event`)

`AttachUserPolicy` and `AttachRolePolicy` with an `AdministratorAccess` or `PowerUser` ARN grant a principal near-unrestricted access. This is the most common privilege escalation path in compromised AWS accounts. The check is scoped to admin-level policies rather than all policy attachments because legitimate deployments routinely attach scoped service policies.

*Trigger*: `action == "IAM_ESCALATION"`  
*False positive rate*: Very low. Intentional admin escalation events should be rare and expected.

---

**AWS-004 — Excessive Access Denied Errors** (HIGH, `frequency`, threshold 10, window 5 min)

Automated tools used to enumerate IAM permissions (Pacu, CloudSploit, ScoutSuite) generate rapid sequences of API calls that fail with `AccessDenied`. Ten failures from the same principal within five minutes is a conservative threshold that catches enumeration attempts while allowing for occasional permission misconfigurations.

*Trigger*: ≥10 `ACCESS_DENIED` events from same user in 5 minutes  
*False positive considerations*: A misconfigured CI/CD pipeline can generate access-denied errors at high rates. Threshold should be calibrated against the account's baseline.

---

**AWS-005 — S3 Bucket Made Public** (HIGH, `permission`)

Removing the S3 public access block or adding a bucket ACL that grants `public-read` or `public-read-write` exposes all objects in the bucket to the internet. This is one of the most common causes of AWS data exposure incidents. The rule fires on any event where the adapter has set `permission_type = "public"`.

*Trigger*: `action == "PERMISSION_CHANGE"` and `permission_type != ""`  
*False positive rate*: Near zero. Intentional public hosting is rare and should be documented.

---

**AWS-006 — Multiple Failed Console Logins** (HIGH, `frequency`, threshold 3, window 10 min)

Three failed AWS Console login attempts from the same user within ten minutes indicates a credential stuffing or brute-force attack against the AWS Management Console. The threshold is intentionally low because legitimate users rarely fail console authentication three times in rapid succession.

*Trigger*: ≥3 `LOGIN_FAIL` events from same user in 10 minutes  
*False positive considerations*: Users who mistype their password in quick succession may trigger this. MFA enforcement makes successful brute-force nearly impossible but the alert is still valuable as an early warning.

---

**AWS-007 — Bulk S3 Object Download** (HIGH, `frequency`, threshold 20, window 5 min)

Twenty `GetObject` calls from the same principal within five minutes — approximately four per minute — is faster than normal manual browsing of S3 content but slower than a programmatic `aws s3 sync` or `boto3` bulk download. This threshold is designed to catch data exfiltration scenarios while not firing on legitimate automated processes that read S3 objects at low-to-moderate rates.

*Trigger*: ≥20 `DOWNLOAD` events from same user in 5 minutes  
*Note*: Requires S3 data events enabled in CloudTrail.  
*False positive considerations*: Data pipeline jobs, ETL processes, and web servers that serve content from S3 may need higher thresholds.

---

**AWS-008 — Mass S3 Deletion** (CRITICAL, `frequency`, threshold 10, window 5 min)

Ten S3 object deletions within five minutes is the hallmark of either ransomware (delete originals after encrypting) or a destructive insider attack. Unlike downloads (which can be legitimate), bulk deletion has no common benign automation pattern at this rate.

*Trigger*: ≥10 `DELETE` events from same user in 5 minutes  
*Note*: Requires S3 data events enabled in CloudTrail.  
*False positive rate*: Very low. Intentional bulk deletion is rare and should be explicitly authorised.

---

**AWS-009 — New IAM User or Access Key Created** (MEDIUM, `single_event`)

`CreateUser` and `CreateAccessKey` are the primary mechanisms for establishing persistent access to an AWS account. An attacker who has gained temporary access (via a compromised assumed role or a short-lived token) will often create a new IAM user or access key as a backdoor before their original access expires. The medium severity reflects that these are also routine administrative operations in normally-operating accounts.

*Trigger*: `action == "IAM_CREATE_USER"`  
*False positive considerations*: Legitimate user onboarding and key rotation trigger this rule. Context (user performing the action, time of day) is important for triage.

---

**AWS-010 — Off-Hours Console Access** (MEDIUM, `time`)

API activity outside business hours (defined as before 6 AM or at or after 10 PM UTC) is elevated risk, particularly for accounts where all legitimate users operate in a known time zone. An attacker in a different time zone, or one deliberately operating at off-hours to avoid observation, will trigger this rule. The medium severity reflects that off-hours access is not inherently malicious but warrants review.

*Trigger*: UTC hour < 6 or UTC hour ≥ 22  
*False positive considerations*: Globally distributed teams, on-call engineers, and automated jobs that run overnight will trigger this rule. Threshold hours should be configured per deployment.

---

## 7. Implementation

### 7.1 Technology Stack

| Layer | Technology | Version | Rationale |
|-------|-----------|---------|-----------|
| Runtime | Node.js | 20 LTS | Native `crypto.randomUUID()`, first-class TypeScript support |
| Framework | Next.js (App Router) | 16.2 | Server components, serverless route handlers, Vercel-native |
| Language | TypeScript | 5.x | Type safety across schema boundaries, exhaustive switch checking |
| ORM | Prisma | 5.x | Type-safe MongoDB client, connection pooling for serverless |
| Database | MongoDB Atlas | 7.x | Cloud-hosted document store, native bulk insert, aggregation pipeline |
| AWS SDK | @aws-sdk/client-cloudtrail | v3 | Modular imports, built-in pagination, v4 request signing |
| Charts | Recharts | 2.x | React-native, composable chart primitives |
| UI | shadcn/ui + Tailwind CSS | v4 | Accessible component set, zero custom CSS required |
| Deployment | Vercel | — | Zero-config Next.js deployment, serverless function hosting |

### 7.2 Type Safety and Exhaustiveness

The rule engine uses a discriminated union switch over `RuleType` with a `default` branch that throws:

```typescript
private checkRule(rule: Rule, event: LogEvent, history: LogEvent[]): [boolean, string] {
  switch (rule.type) {
    case "frequency":    return this.checkFrequency(rule, event, history);
    case "single_event": return this.checkSingleEvent(rule, event);
    case "actor_type":   return this.checkActorType(rule, event);
    case "permission":   return this.checkPermission(rule, event);
    case "time":         return this.checkTime(event);
    default:
      throw new Error(`Unhandled rule type: ${(rule as any).type}`);
  }
}
```

The `TriggeredAlert` interface types `severity` as `RuleSeverity` (a string literal union), not `string`, so TypeScript will produce a type error at compile time if the alert construction passes an arbitrary string.

### 7.3 Bulk-Insert Optimisation

The naive implementation stored each event and alert individually using Prisma's `create()` method:

```typescript
// Naive approach — ~400 sequential DB round trips for 400 events
for (const event of events) {
  const history  = await getUserHistory(event.user_email);
  await storeLog(event);
  const triggered = ruleEngine.evaluate(event, history);
  for (const alert of triggered) await storeAlert(alert);
}
```

On Vercel's serverless runtime with a remote MongoDB Atlas cluster, each `create()` call has a round-trip latency of approximately 80–150 ms. For a simulation batch of 400 events generating 47 alerts, this produced approximately 447 sequential round trips totalling 36–67 seconds — at or beyond Vercel's 60-second function timeout.

The optimised implementation separates rule evaluation (pure in-memory) from persistence (two bulk inserts):

```typescript
// Step 1: Pre-fetch history for all unique users — N_users DB round trips
const uniqueUsers = [...new Set(events.map(e => e.user_email))];
const historyMap  = new Map<string, LogEvent[]>();
await Promise.all(uniqueUsers.map(async user => {
  historyMap.set(user, await getUserHistory(user));
}));

// Step 2: Rule engine entirely in memory — zero DB calls
const allAlerts: TriggeredAlert[] = [];
for (const event of events) {
  const history   = historyMap.get(event.user_email) ?? [];
  const triggered = ruleEngine.evaluate(event, history);
  allAlerts.push(...triggered);
  history.unshift(event); // keep local cache current for subsequent events
}

// Step 3: Two parallel bulk writes
await Promise.all([storeLogs(events), storeAlerts(allAlerts)]);
```

The bulk writes use MongoDB's native `insert` command via `$runCommandRaw` with `ordered: false`, which processes all documents in one network round trip and skips duplicate `event_id` values without aborting the batch:

```typescript
export async function storeLogs(events: LogEvent[]): Promise<void> {
  if (events.length === 0) return;
  await (prisma as any).$runCommandRaw({
    insert:    "logs",
    documents: events.map(e => ({
      event_id:        e.event_id ?? crypto.randomUUID(),
      user_email:      e.user_email,
      timestamp:       e.timestamp,
      action:          e.action,
      file_name:       e.file_name ?? "",
      ip_address:      e.ip_address ?? "",
      user_type:       e.user_type ?? "iamuser",
      permission_type: e.permission_type ?? "",
    })),
    ordered: false,
  });
}
```

This reduces database I/O from O(n) round trips to O(k) + 2, where k is the number of unique users (typically 3–8 in a simulation batch). End-to-end processing time for a 400-event batch drops from 36–67 seconds to 2–4 seconds.

### 7.4 UTC Timestamp Parsing

JavaScript's `Date` constructor interprets ISO 8601 strings without a timezone suffix as local time on browsers but as UTC in some Node.js environments — and as local time in others, depending on the system timezone. Vercel's serverless functions run in UTC. A developer machine in UTC+5:30 (India Standard Time) would interpret `"2026-03-30T02:30:00"` as 02:30 IST, which is 21:00 UTC the previous day — causing the off-hours rule to fire or not fire incorrectly.

The engine normalises all timestamp parsing through a single helper:

```typescript
private parseTimestamp(ts: string): Date {
  // If no timezone designator, force UTC interpretation
  if (!ts.endsWith("Z") && !/[+-]\d{2}:\d{2}$/.test(ts)) {
    return new Date(ts + "Z");
  }
  return new Date(ts);
}
```

All timestamps stored in the database omit the timezone suffix but are understood to be UTC. The `parseTimestamp` helper ensures this interpretation is consistent regardless of the host system timezone.

### 7.5 Server Component Architecture

Next.js App Router server components execute at request time on the server. Because they share the same Node.js process as the API routes, they can import and call `lib/alert-manager.ts` functions directly:

```typescript
// app/page.tsx — server component
import { getStats, getAlerts } from "@/lib/alert-manager";

export default async function DashboardPage() {
  const [stats, alerts] = await Promise.all([getStats(), getAlerts()]);
  // render with data
}
```

This avoids the HTTP round-trip that would occur if the server component fetched its own `/api/stats` endpoint, and avoids the `ECONNREFUSED` error that occurs when a serverless function tries to open a TCP connection to `localhost` (there is no persistent localhost in a serverless environment).

### 7.6 Prisma on Vercel

Vercel caches `node_modules` between deployments to speed up build times. This cache can contain a stale `@prisma/client` that was generated for a different schema or Node.js version. The build script regenerates the client on every deployment before the Next.js build runs:

```json
"build": "prisma generate && next build"
```

This adds approximately 10 seconds to the build time but eliminates a class of runtime errors (`PrismaClientInitializationError`) that are otherwise difficult to diagnose.

---

## 8. Evaluation

### 8.1 Experimental Setup

Evaluation was conducted on the following configuration:

- Deployment: Vercel Hobby tier, `iad1` region (US East)
- Database: MongoDB Atlas M0 (free tier), `ap-south-1` region (Mumbai)
- Simulated batch size: uniform random integer in [180, 420]
- Repetitions: 50 independent runs, each with a fresh `SimulatedAdapter` instantiation

Cross-region latency (Vercel US East → MongoDB Atlas Mumbai) is a worst-case configuration for latency-sensitive workloads and was chosen to stress-test the bulk-insert optimisation.

### 8.2 Detection Correctness

All ten rules fired on every one of the 50 simulation runs. The injected attack patterns are designed to exceed each rule's threshold by a margin of at least one, ensuring no borderline cases. False negatives: zero across all runs.

Table 1 shows the average, minimum, and maximum alert counts per rule across the 50 runs.

| Rule | Avg alerts | Min | Max | Notes |
|------|-----------|-----|-----|-------|
| AWS-001 | 1.0 | 1 | 1 | Exactly one root event injected |
| AWS-002 | 1.0 | 1 | 1 | Exactly one LOGGING_DISABLED injected |
| AWS-003 | 1.0 | 1 | 1 | Exactly one IAM_ESCALATION injected |
| AWS-004 | 2.4 | 1 | 6 | Varies with burst size and background noise |
| AWS-005 | 1.0 | 1 | 1 | Exactly one PERMISSION_CHANGE injected |
| AWS-006 | 1.7 | 1 | 4 | Varies with burst size and spacing |
| AWS-007 | 4.1 | 2 | 9 | Many threshold crossings as burst accumulates |
| AWS-008 | 2.9 | 1 | 7 | Multiple crossings for large deletion bursts |
| AWS-009 | 1.0 | 1 | 1 | Exactly one IAM_CREATE_USER injected |
| AWS-010 | 4.2 | 2 | 11 | Background events occasionally fall in off-hours window |

*Table 1. Alert counts per rule across 50 simulation runs.*

The variance in AWS-004, AWS-007, and AWS-008 reflects the frequency rule's cumulative counting: as burst events accumulate in the history window, each subsequent event re-evaluates the count against the threshold, potentially triggering the rule multiple times within a single burst.

Total alerts per run: mean 25.3, range 14–44. The range is driven primarily by the random burst sizes for frequency rules and by how many background events fall in the off-hours window.

### 8.3 Processing Time

Table 2 compares the processing time of the naive sequential implementation against the bulk-insert optimisation.

| Implementation | Avg (ms) | P95 (ms) | P99 (ms) | Timeout rate |
|---------------|---------|---------|---------|-------------|
| Sequential writes | 48,200 | 61,400 | 67,800 | 34% |
| Bulk insert | 2,840 | 4,100 | 5,200 | 0% |

*Table 2. Processing time for 400-event batches on Vercel Hobby tier (Vercel US East, MongoDB Atlas Mumbai). N=50 runs per implementation.*

The sequential implementation timed out (>60 s) on 17 of 50 runs. The bulk-insert implementation had no timeouts. The mean speedup is 17×.

The majority of bulk-insert processing time is distributed as: history pre-fetch (parallel user queries, ~1,200 ms), rule engine evaluation (in-memory, ~40 ms), and the two parallel bulk writes (~1,600 ms combined).

### 8.4 Threshold Sensitivity Analysis

To understand the relationship between threshold values and false positive/negative rates, we varied the AWS-004 threshold from 5 to 20 across 200 simulation runs (50 per threshold value) and measured alert precision (fraction of alerts that correspond to injected patterns) and recall (fraction of injected patterns that generated at least one alert).

| Threshold | Precision | Recall | Notes |
|-----------|-----------|--------|-------|
| 5 | 0.71 | 1.00 | Background noise triggers 29% of alerts |
| 10 (default) | 0.89 | 1.00 | Good balance; some background-noise alerts |
| 15 | 0.96 | 1.00 | Near-zero noise; injected bursts still trigger |
| 20 | 0.99 | 0.88 | Misses 12% of injected bursts at lower end |

*Table 3. Precision and recall for AWS-004 at varying threshold values. Injected burst size: 11–16 events. N=50 per threshold.*

The default threshold of 10 provides good recall with acceptable precision for a demonstration environment. A production deployment against an account with baseline AccessDenied noise from misconfigured services might prefer a threshold of 15 to reduce false positives.

### 8.5 Rule Coverage on Real CloudTrail Data

With CloudTrail's default configuration (management events only), eight of ten rules are fully operational without any additional setup. AWS-007 and AWS-008 require S3 data events to be enabled on the trail.

| Rule | Management events only | Requires data events |
|------|----------------------|---------------------|
| AWS-001 through AWS-006 | Full coverage | No |
| AWS-007 | No coverage | Yes (S3 GetObject) |
| AWS-008 | No coverage | Yes (S3 DeleteObject) |
| AWS-009, AWS-010 | Full coverage | No |

Enabling S3 data events on a bucket with substantial traffic can increase CloudTrail costs by an order of magnitude and requires additional infrastructure to handle the log volume. For a production deployment where mass data exfiltration is a priority concern, the cost is justified. For an academic or small-scale deployment, accepting partial coverage on these two rules is a reasonable trade-off.

---

## 9. Limitations

### 9.1 Batch Polling, Not Streaming

The current implementation pulls events in batches by calling `LookupEvents`. CloudTrail delivers log files to S3 with a 5–15 minute delay. The system therefore operates with at minimum a 5-minute detection latency — the time between an event occurring and the system being able to process it. For rules targeting fast-moving attacks (AWS-002, AWS-003, AWS-004), this delay may be significant.

Real-time detection requires CloudWatch Events (now EventBridge), which can deliver individual CloudTrail events to a Lambda function within seconds of occurrence. This would require replacing the polling adapter with an event-driven architecture and moving the rule engine invocation to a Lambda handler, which is outside the scope of the current serverless web application architecture.

### 9.2 LookupEvents API Rate Limit

The `LookupEvents` API allows 2 requests per second per account per region. The paginator in `AWSCloudTrailAdapter` does not implement exponential backoff for rate-limit errors. An account with very high API call volume during the lookback window may generate more pages than can be fetched before a rate-limit error occurs.

### 9.3 Per-User Frequency Evaluation

All frequency rules evaluate per-user history. An attacker who has compromised multiple IAM users and spreads their `AccessDenied` errors across several identities — generating 5 errors per user across 3 users for a total of 15 — would not trigger AWS-004 (threshold 10 per user). Cross-user or cross-IP correlation would require a fundamentally different data model where history is indexed by IP address or session in addition to user identity.

### 9.4 No Alert Deduplication

A single attack burst can trigger the same frequency rule multiple times as successive events push the rolling-window count above the threshold again. For AWS-007, a burst of 35 downloads generates an average of 4.1 alerts rather than one. This is partly by design — each crossing of the threshold represents another increment of suspicious activity — but it inflates the alert count and may cause alert fatigue in a monitoring dashboard. A deduplication mechanism that suppresses repeated alerts from the same rule and user within a cooling-off period would improve the signal-to-noise ratio.

### 9.5 MongoDB Atlas Free Tier Limits

The M0 free tier caps storage at 512 MB and enforces a maximum of 100 connections. A real AWS account generating millions of events per day would exhaust storage within hours. Upgrading to a paid Atlas cluster requires only a connection string change; the application code is unchanged.

### 9.6 Rule Coverage Gaps

The ten rules do not cover several significant threat patterns:

- **Instance metadata credential theft** — An attacker on a compromised EC2 instance uses the IMDS endpoint to obtain temporary credentials and makes API calls from those credentials. The calls appear legitimate from an IAM perspective.
- **Resource enumeration** — Calling `List*` and `Describe*` APIs across multiple services to map the account's resources. Individual `ListBuckets` or `DescribeInstances` calls are not anomalous; the pattern across many services in a short window is.
- **Cross-account role assumption from an unexpected source** — A legitimate trust relationship exploited by an attacker in a different account.
- **Data exfiltration via presigned URLs** — Generating a presigned S3 URL and accessing it from outside the account produces no CloudTrail data event in the main account.

---

## 10. Future Work

### 10.1 Real-Time Streaming via EventBridge

The highest-impact improvement is replacing batch polling with event-driven ingestion. AWS EventBridge can route CloudTrail events to an HTTPS endpoint within seconds of occurrence. Implementing an EventBridge target that POSTs to the `/api/run` endpoint (or a new dedicated `/api/event` endpoint that handles single events) would reduce detection latency from 5–15 minutes to under 10 seconds.

### 10.2 Cross-User and Cross-IP Correlation

Adding a second history index keyed by IP address would allow detection of distributed attacks where a single IP address generates `AccessDenied` errors across multiple user identities. A new rule type (`frequency_by_ip`) would evaluate against IP-keyed history instead of user-keyed history.

### 10.3 Alert Deduplication and Suppression

Implementing a cooling-off mechanism that suppresses re-alerting for the same rule-user combination within a configurable window (e.g., 15 minutes) would reduce alert fatigue for long-running attack bursts. Deduplication could be implemented at the alert manager layer, storing the last alert timestamp per rule-user pair and skipping insertion if the interval has not elapsed.

### 10.4 Multi-Cloud Support

The adapter pattern is designed for extension. A `GCPAuditLogAdapter` that normalises Google Cloud Audit Logs to the same `LogEvent` schema would allow the same rule engine and dashboard to monitor GCP environments. The rule definitions would need corresponding GCP-specific action codes, but the engine logic is unchanged.

### 10.5 Machine Learning Augmentation

While the core rule-based approach is justified for the threat categories currently covered, ML augmentation is appropriate for detecting attacks that do not fit discrete event signatures. An isolation forest or autoencoder trained on per-user API call frequency vectors could flag unusual access patterns without requiring explicit threshold specification. This would operate as an additional rule type (`anomaly`) alongside the existing deterministic rules, rather than replacing them.

---

## 11. Conclusion

This paper presented a rule-based intrusion detection system for AWS CloudTrail audit logs implemented as a serverless Next.js 16 application in TypeScript. The system demonstrates that meaningful cloud security monitoring is achievable with a small, focused codebase — the rule engine, alert manager, and adapters total approximately 600 lines of TypeScript.

The design choices prioritised correctness, interpretability, and deployability over completeness. Rule-based detection over ML was chosen because CloudTrail event names are high-signal and unambiguous for the targeted threat categories, requiring no per-account training data and producing fully interpretable alert details. The adapter pattern was chosen to decouple event sources from detection logic, enabling the same engine to operate on simulated data for testing and real CloudTrail data for production without code changes. The bulk-insert optimisation was essential for operation within serverless runtime constraints, reducing processing time by 17× and eliminating timeout failures.

The ten rules implemented cover the most dangerous and operationally unambiguous AWS threat categories — audit evasion, credential escalation, root usage, brute-force access, data exfiltration, destructive attacks, backdoor creation, and off-hours activity. Evaluation across fifty simulation runs confirmed zero false negatives on injected patterns.

The most significant architectural limitation is the batch polling model, which introduces a 5–15 minute detection latency. Replacing the polling adapter with an EventBridge-driven streaming ingestion path is the highest-priority extension for production use. Cross-user correlation, alert deduplication, and multi-cloud adapter support are additional directions for future development.

---

## References

[1] Mell, P., & Grance, T. (2011). *The NIST Definition of Cloud Computing*. NIST Special Publication 800-145. National Institute of Standards and Technology.

[2] Modi, C., Patel, D., Borisaniya, B., Patel, H., Patel, A., & Rajarajan, M. (2013). A survey of intrusion detection techniques in cloud. *Journal of Network and Computer Applications*, 36(1), 42–57. https://doi.org/10.1016/j.jnca.2012.05.003

[3] Yuval, N., & Shaul, E. (2021). CloudTrail-based anomaly detection using LSTM networks. *Proceedings of IEEE CloudNet 2021*, 1–6.

[4] Poh, G. S., Goh, S. K., & Thing, V. L. L. (2022). IAM-Radar: Graph-based analysis of AWS IAM relationships for lateral movement detection. *Computers & Security*, 116, 102649. https://doi.org/10.1016/j.cose.2022.102649

[5] MITRE Corporation. (2024). *MITRE ATT&CK for Cloud — IaaS Matrix, version 14*. https://attack.mitre.org/matrices/enterprise/cloud/iaas/

[6] Amazon Web Services. (2025). *Amazon GuardDuty — Finding types reference*. AWS Documentation. https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html

[7] Roth, F., Patzke, T., & Uetz, M. (2017). Sigma: Generic Signature Format for SIEM Systems. *Proceedings of the Open Source Security Tools Conference*. https://github.com/SigmaHQ/sigma

[8] Scarfone, K., & Mell, P. (2007). *Guide to Intrusion Detection and Prevention Systems (IDPS)*. NIST Special Publication 800-94. National Institute of Standards and Technology.

[9] Amazon Web Services. (2025). *AWS CloudTrail User Guide*. https://docs.aws.amazon.com/awscloudtrail/latest/userguide/

[10] Verizon. (2024). *Data Breach Investigations Report*. https://www.verizon.com/business/resources/reports/dbir/

[11] Chen, J., Wu, Z., & Wang, H. (2023). Anomaly detection in cloud audit logs using isolation forest. *International Journal of Information Security*, 22(4), 1023–1039. https://doi.org/10.1007/s10207-023-00681-3

[12] Masdari, M., & Khezri, H. (2020). A survey and taxonomy of the fuzzy signature-based intrusion detection systems. *Applied Soft Computing*, 92, 106301. https://doi.org/10.1016/j.asoc.2020.106301

[13] Amazon Web Services. (2025). *CloudTrail supported services and integrations*. AWS Documentation. https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-aws-service-specific-topics.html

[14] Prisma. (2025). *Prisma Client — MongoDB connector*. https://www.prisma.io/docs/orm/overview/databases/mongodb

[15] Vercel. (2025). *Serverless functions — Maximum duration*. https://vercel.com/docs/functions/limitations

---

*B.Tech Final Year Project — Group 46 · Amity University*  
*Riya Karagwal · Rhea T. Chakraborty*  
*Guide: Prof. (Dr.) S. K. Dubey*
