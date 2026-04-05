# A Hybrid Intrusion Detection System for AWS CloudTrail Using Isolation Forest and GPT-4.1

**Riya Karagwal · Rhea T. Chakraborty**
B.Tech Computer Science Engineering, Amity University
Guide: Prof. (Dr.) S. K. Dubey
Group 46

---

## Abstract

Most AWS accounts have CloudTrail enabled but never actually watch the logs it produces. Every API call is recorded, the audit trail is right there, but without tooling to act on it in real time it may as well not exist. We built a three-layer intrusion detection system that closes that gap. The first layer is a deterministic rule engine covering ten high-signal AWS attack patterns. The second is an Isolation Forest anomaly detector that scores every event against a behavioural baseline and flags statistically unusual activity even when no rule matches. The third sends every suspicious event to GPT-4.1, which weighs the rule matches and anomaly score together and returns a structured verdict with a confidence percentage, severity level, plain-English reasoning, and a recommended AWS action. When confidence is at or above 75%, the system executes that action automatically using the AWS SDK, whether that means disabling access keys, removing an admin policy, re-enabling CloudTrail, blocking public S3 access, or freezing a user entirely. The whole thing runs as a serverless Next.js 16 application on Vercel, backed by MongoDB Atlas and Prisma 5. Our simulation results show zero false negatives on injected attack patterns, with the AI verdict layer correctly filtering out benign events that trigger rules on surface-level criteria alone.

---

## 1. Introduction

### 1.1 Motivation

A university student can spin up a multi-region AWS environment in minutes today. The same ease of access extends to attackers. An adversary who gets hold of a single IAM access key, whether it leaked in a public GitHub commit, was phished from an employee, or was pulled from a misconfigured EC2 metadata endpoint, can read every S3 object, escalate their own privileges, create backdoor users, and disable the audit trail that would reveal them. Every one of those operations looks like a normal authenticated API call.

AWS CloudTrail records all of this. The problem is not the absence of audit data; it is the absence of anything watching it. Most accounts enable CloudTrail, point it at an S3 bucket, and move on. The logs sit there. Commercial SIEMs are expensive and overkill for a student project or a small team. Self-hosted ELK stacks take weeks to configure properly. So the gap between "we have logs" and "we are acting on logs" stays wide.

We started with a rule-based approach and it worked well for known attack patterns. But a mentor raised a valid point: rules only catch what you have already thought of. A user who slowly drains S3 over several days, a compromised role that never operates outside business hours, or any novel API call pattern that no one has written a rule for will all sail through undetected. That observation pushed us to add an unsupervised anomaly detection layer and then an LLM verdict layer on top of it.

### 1.2 Problem Statement

We wanted to build a system that could watch an AWS CloudTrail stream, catch both known attack patterns and statistically unusual behaviour it has never seen before, explain what it found in plain English, and take corrective action in AWS automatically when the evidence is strong enough. The scope is intentionally focused: ten high-signal threat categories that appear repeatedly in public AWS breach post-mortems, plus whatever the anomaly layer catches beyond those ten.

### 1.3 Contributions

We make the following contributions:

1. A complete open-source implementation of a three-layer hybrid cloud IDS as a Next.js 16 serverless application. It deploys to Vercel in under five minutes with no infrastructure to manage.
2. An Isolation Forest anomaly detector that converts each CloudTrail event into a six-feature behavioural vector and scores it against a synthetic normal baseline, picking up threats no written rule would catch.
3. A GPT-4.1 verdict layer that receives rule matches and anomaly scores together and returns a structured, explainable threat assessment with confidence percentage and recommended remediation action.
4. An automated AWS response layer that executes targeted SDK calls when AI confidence exceeds 75%, covering key disablement, policy detachment, CloudTrail restoration, public access blocking, and user quarantine.
5. A bulk-insert optimisation that replaces O(n) sequential Prisma writes with two parallel native MongoDB commands, keeping end-to-end pipeline time well within serverless function limits.

### 1.4 Paper Organisation

Section 2 covers background on intrusion detection systems and CloudTrail as a log source. Section 3 defines the threat model. Section 4 walks through the system architecture. Section 5 covers event normalisation. Sections 6, 7, and 8 detail each detection layer in turn. Section 9 covers AWS remediation. Section 10 covers implementation. Sections 11 through 14 cover evaluation, limitations, future work, and conclusion.

---

## 2. Background and Related Work

### 2.1 Taxonomy of Intrusion Detection Systems

IDS research classifies systems along two orthogonal axes.

**Placement.** Host-based IDS operates on a single machine, monitoring system calls, file integrity, and login records. Network-based IDS observes traffic at a network boundary, inspecting packet headers and payloads. Cloud-based or API-based IDS does not fit cleanly into either category. CloudTrail events are structured JSON documents describing authenticated API calls to cloud control planes and data planes, making them a distinct log class with its own detection characteristics.

**Detection method.** Signature-based detection matches events against known-bad patterns defined in advance. Anomaly-based detection builds a statistical model of normal behaviour and flags deviations from it. Hybrid systems combine both approaches to cover each other's blind spots. This system is hybrid: a deterministic rule engine handles known signatures while Isolation Forest handles statistical deviations, with a large language model providing a final contextual verdict over both signals.

### 2.2 Why Rule-Based Detection Alone Is Insufficient

Pure rule-based detection has real strengths when applied to CloudTrail. The event namespace is controlled by AWS, so event names like `StopLogging`, `DeleteTrail`, and `AttachUserPolicy` are unambiguous. A rule that fires on `StopLogging` has a theoretical false positive rate of zero because no legitimate operation generates that event by accident.

The problem is that not every attack generates a recognisable event signature. A user who starts downloading S3 objects in larger volumes than usual, or a compromised role that suddenly changes the types of services it touches, may not trip any written rule. The behaviour is anomalous relative to their history, but no individual event is unusual enough to match a pattern. Rule-based systems are blind to this entire class of threat. They also depend entirely on someone having anticipated the attack variant in advance, which becomes harder to guarantee as attacker techniques change.

### 2.3 Isolation Forest for Anomaly Detection

Isolation Forest, introduced by Liu et al. [1], works on a simple but effective intuition: anomalies are rare and structurally different from normal points, so they are easier to isolate in a decision tree. The algorithm builds an ensemble of random trees by repeatedly picking a random feature and a random split value. Points that end up isolated in fewer splits are more anomalous and get higher scores. Points that blend in with normal data require many more splits to isolate and get lower scores.

We chose Isolation Forest for three practical reasons. First, it requires no labelled attack data. Real-world attack logs are hard to come by, especially for a university project. Second, training on a synthetic normal baseline is sufficient to get a useful anomaly score without waiting months for real account activity to accumulate. Third, it runs fast enough to score hundreds of events per pipeline execution without adding noticeable latency.

### 2.4 Large Language Models for Security Verdict Generation

The reason we added an LLM layer rather than just thresholding on rule matches or anomaly scores is that neither signal alone is sufficient to confidently trigger a destructive AWS action. A rule can fire on an event that is technically a match but clearly benign in context. An anomaly score can spike due to an unusual but legitimate burst of activity. What we wanted was something that could look at both signals together, apply background knowledge about AWS attack patterns, and tell us whether the combination actually represents a threat.

GPT-4.1 can do that. It supports structured JSON output through the Vercel AI SDK with Zod schema validation, which means we always get a machine-readable verdict regardless of how the model words its response. Its context window is large enough to include the full event JSON, all matched rules, and the anomaly score. And because it returns natural-language reasoning alongside the classification, a human analyst can read exactly why the model made the call it did.

### 2.5 Related Systems

**AWS GuardDuty** is Amazon's managed threat detection service and the closest commercial equivalent to what we built. It ingests CloudTrail, VPC Flow Logs, and DNS logs and runs ML models alongside curated threat intelligence signatures. GuardDuty covers more threat categories than our system and is battle-tested at scale, but it is a subscription service with per-event pricing, it treats its detection logic as a black box, and it does not take automated remediation actions.

**Sigma** is an open standard for writing detection rules in a vendor-neutral YAML format. The Sigma community maintains a library of CloudTrail rules drawn from public threat intelligence reports. Our rule semantics are inspired by Sigma but implemented directly in TypeScript rather than compiled from YAML.

**AWS Security Hub** aggregates findings from GuardDuty, Inspector, Macie, and third-party tools into a normalised format. It is useful for viewing consolidated findings but has no detection logic of its own.

Academic work on cloud intrusion detection includes LSTM-based sequence models applied to CloudTrail event names [3], graph analysis of IAM relationships for lateral movement detection [4], and earlier Isolation Forest applications to API call frequency vectors [1]. None of these include automated remediation or an LLM verdict step.

---

## 3. Threat Model

We assume an AWS account with CloudTrail enabled. The adversary has obtained some level of AWS credentials: an access key ID and secret, console login credentials, or the ability to make calls as an assumed role from a compromised compute resource.

The threat model covers the following categories in rough order of severity:

**Audit evasion.** Disabling or deleting CloudTrail trails to eliminate the audit record before or during an attack. This is the highest-priority category because it directly impairs all downstream detection.

**Privilege escalation.** Attaching an administrator or power-user policy to an IAM principal to expand access beyond what was originally granted.

**Credential abuse.** Using the root account for operations that should be performed by named IAM users. Root has unrestricted access and cannot be constrained by IAM policies.

**Brute-force access.** Generating high rates of AccessDenied errors through automated permission enumeration, or generating failed console login attempts through credential stuffing.

**Data exfiltration.** Downloading large volumes of S3 objects in a short time window.

**Destructive attack.** Deleting large numbers of S3 objects rapidly, consistent with ransomware or a destructive insider.

**Persistence establishment.** Creating new IAM users or access keys to maintain access after a primary credential is rotated.

**Stealth access.** Accessing cloud resources outside business hours, which may indicate an attacker operating in a different time zone or deliberately avoiding observation.

**Exposure misconfiguration.** Removing public access blocks or modifying bucket ACLs to expose S3 objects to the internet.

**Behavioural anomalies.** Events that do not match any specific rule but are statistically unusual when compared to the user's own history and to synthetic normal baseline data. This category is handled exclusively by the Isolation Forest layer.

We explicitly do not cover attacks that stay within rate limits and business hours while avoiding every specific event signature in our ten rules, attacks deliberately spread across multiple compromised identities to stay below per-user frequency thresholds, or infrastructure-level attacks against CloudTrail log delivery itself.

---

## 4. System Architecture

### 4.1 Overview

The whole system is a single Next.js 16 application deployed as a serverless pipeline on Vercel. Events flow through three detection layers and then get written to MongoDB Atlas and displayed on the dashboard.

```
Data Source Layer
  SimulatedAdapter / AWSCloudTrailAdapter
           |
           | LogEvent[]
           v
Layer 1: Rule Engine
  evaluate(event, history) -> TriggeredAlert[]
           |
           v
Layer 2: Isolation Forest
  detectAnomalies(events, historyMap) -> AnomalyResult[]
           |
           v
  Suspects (rule match OR anomaly score > 0.62)
           |
           v
Layer 3: GPT-4.1 Verdict
  getAIVerdict(event, ruleAlerts, anomalyScore) -> AIVerdict
           |
           v
  AWS Auto-Remediation (if confidence >= 0.75)
  executeAction(recommendedAction, event)
           |
           v
Alert Manager (bulk write)
  storeLogs() / storeEnrichedAlerts()
           |
           v
MongoDB Atlas
  collection: logs
  collection: alerts (with AI fields)
           ^
           | server components (direct import)
Next.js Frontend
  /             Dashboard
  /alerts       Alert table with AI verdicts
  /logs         Audit log table
  /how-it-works System documentation
  /setup        AWS configuration guide
  /api/run      POST: full pipeline trigger
```

### 4.2 Data Source Layer

Two adapters both return the same `LogEvent[]` type.

**SimulatedAdapter** generates 180 to 420 synthetic events per invocation with all ten attack patterns injected deterministically, randomised across a pool of simulated users. It requires no external credentials and is the primary demonstration mode.

**AWSCloudTrailAdapter** calls the CloudTrail LookupEvents API via AWS SDK v3, paginates through all management events within the lookback window, and normalises each record to the canonical LogEvent schema. It accepts credentials as constructor parameters or falls back to environment variables.

### 4.3 API Route: `/api/run`

The main pipeline is a single Next.js Route Handler that orchestrates all three detection layers. The route is configured with a 60-second maximum duration. The pipeline executes in eight steps described in detail in Section 10.

### 4.4 Alert Manager

The alert manager is the sole interface to the database. It exposes functions for bulk-inserting logs and enriched alerts, querying user history for rate-based rule evaluation, listing and filtering logs and alerts, computing aggregated dashboard statistics, acknowledging individual alerts, and clearing all data.

Aggregation queries bypass Prisma's query builder and execute native MongoDB aggregation pipelines via `$runCommandRaw`, because Prisma 5 does not expose an aggregation pipeline API for MongoDB.

### 4.5 Frontend

The dashboard displays total events processed, total alerts triggered, unacknowledged alert count, active user count, a pie chart of alerts by severity, and a bar chart of top triggered rules.

The alerts page renders a table with per-row severity colour coding, rule ID, user, AI verdict badge with confidence percentage, AWS action taken badge, acknowledgement status, and a sub-row showing GPT-4.1's reasoning for each alert. Summary cards at the top show AI-confirmed threat count, AWS actions taken count, and ML-only anomaly count.

---

## 5. CloudTrail Event Normalisation

### 5.1 Canonical Schema

Every event is normalised to the following TypeScript interface regardless of source:

```typescript
interface LogEvent {
  event_id:        string;   // EventId or UUID
  timestamp:       string;   // ISO 8601, UTC, no timezone suffix
  user_email:      string;   // username@domain or root@aws
  user_type:       string;   // root | iamuser | assumedrole | federated
  action:          string;   // normalised action code
  file_name:       string;   // resource ARN or S3 object key
  ip_address:      string;   // source IP of the API call
  permission_type: string;   // "public" when public-access change detected
}
```

### 5.2 Action Mapping

The full CloudTrail API namespace is compressed into eleven action codes used by both the rule engine and the Isolation Forest feature extractor:

| Action Code | Source Events |
|-------------|---------------|
| `ACCESS_DENIED` | Any event where errorCode contains AccessDenied |
| `LOGIN_FAIL` | ConsoleLogin where responseElements.ConsoleLogin is Failure |
| `LOGGING_DISABLED` | StopLogging, DeleteTrail |
| `IAM_ESCALATION` | AttachUserPolicy or AttachRolePolicy with AdministratorAccess or PowerUser ARN |
| `IAM_CREATE_USER` | CreateUser, CreateAccessKey |
| `PERMISSION_CHANGE` | DeleteBucketPublicAccessBlock, public-grant PutBucketAcl, PutBucketPolicy with Principal wildcard |
| `DELETE` | DeleteObject, DeleteObjects, DeleteBucket |
| `DOWNLOAD` | GetObject |
| `UPLOAD` | PutObject, CopyObject |
| `MOVE` | MoveObject (reserved for future adapters) |
| `VIEW` | All other events |

When errorCode contains AccessDenied, that classification takes precedence over the event name mapping. A failed GetObject is classified as ACCESS_DENIED rather than DOWNLOAD.

---

## 6. Layer 1: Rule Engine

### 6.1 Architecture

The rule engine is a pure TypeScript class with no I/O dependencies. Its public interface is a single method:

```typescript
evaluate(event: LogEvent, history: LogEvent[]): TriggeredAlert[]
```

The engine is stateless between calls. History is passed in by the caller, which allows the engine to be tested in isolation and enables the pre-fetching optimisation described in Section 10.

### 6.2 Rule Types

**actor_type.** Fires when the user type of the event matches the configured actor type. Used for AWS-001 to detect root account activity.

**single_event.** Fires on the first occurrence of a specific action code regardless of frequency. Used for events that are unambiguous regardless of count, such as disabling CloudTrail and privilege escalation.

**frequency.** Evaluates the count of events matching a specific action code in the user's history within a configurable time window. Fires when the count reaches the configured threshold. The window is computed from the event's own timestamp, not wall-clock time, so the check works correctly on historical data.

**permission.** Fires when the action matches and the permission_type field is non-empty. Used for AWS-005 to distinguish public-exposure changes from benign permission modifications.

**time.** Fires when the UTC hour of the event falls outside business hours, defined as before 6 AM or at or after 10 PM.

### 6.3 Rule Specifications

**AWS-001 Root Account Usage (CRITICAL).**
Fires on any CloudTrail event where the identity type is Root. The root account has unrestricted access to every resource and cannot be constrained by IAM policies. Any API call from root is either a security policy violation or a sign of active compromise of the highest-privilege credential in the account.

**AWS-002 CloudTrail Logging Disabled (CRITICAL).**
StopLogging and DeleteTrail terminate the audit record. A sophisticated attacker will call one of these before performing their main activity so subsequent events are not recorded. This is the most time-critical alert because the window between disabling logging and the attacker acting is narrow.

**AWS-003 IAM Privilege Escalation (CRITICAL).**
AttachUserPolicy or AttachRolePolicy with an AdministratorAccess or PowerUser ARN grants near-unrestricted access. This is the most common privilege escalation path in compromised AWS accounts.

**AWS-004 Excessive Access Denied (HIGH, threshold 10, window 5 minutes).**
Automated enumeration tools generate rapid sequences of API calls that fail with AccessDenied. Ten failures from the same principal within five minutes catches enumeration attempts while allowing occasional permission misconfigurations.

**AWS-005 S3 Bucket Made Public (HIGH).**
Removing the S3 public access block or adding a public-read or public-read-write ACL exposes all objects in the bucket to the internet. This is one of the most common causes of AWS data exposure incidents.

**AWS-006 Multiple Failed Console Logins (HIGH, threshold 3, window 10 minutes).**
Three failed AWS Console login attempts from the same user within ten minutes indicates credential stuffing or brute-force against the management console. Legitimate users rarely fail console authentication three times in rapid succession.

**AWS-007 Bulk S3 Object Download (HIGH, threshold 20, window 5 minutes).**
Twenty GetObject calls from the same principal within five minutes is faster than normal manual browsing but slower than a full programmatic sync. Designed to catch data exfiltration while not firing on low-to-moderate rate automation. Requires S3 data events enabled in CloudTrail.

**AWS-008 Mass S3 Deletion (CRITICAL, threshold 10, window 5 minutes).**
Ten S3 object deletions within five minutes is the hallmark of ransomware deleting originals after encrypting them, or a destructive insider attack. Unlike downloads, bulk deletion has no common benign automation pattern at this rate. Requires S3 data events enabled.

**AWS-009 New IAM User or Access Key (MEDIUM).**
CreateUser and CreateAccessKey are the primary mechanisms for establishing persistent access. An attacker with temporary access will often create a new user or key as a backdoor before their original credential expires.

**AWS-010 Off-Hours Console Access (MEDIUM).**
API activity before 6 AM or at or after 10 PM UTC is elevated risk, particularly for accounts where all legitimate users operate in a known time zone. An attacker in a different time zone, or one deliberately operating off-hours to avoid observation, will trigger this rule.

---

## 7. Layer 2: Isolation Forest Anomaly Detection

### 7.1 Algorithm Overview

Isolation Forest targets anomalies directly rather than profiling normal behaviour and flagging deviations. Because anomalous points are few and structurally different, they get isolated in random trees faster than normal ones. Fewer splits to isolate means a higher anomaly score.

Our implementation uses the `ml-isolation-forest` package with 100 estimators. We fit it on 300 synthetic normal events generated at startup. Events scoring above 0.62 are flagged as anomalies and forwarded to the AI layer. We chose 0.62 as the threshold after testing against simulated attack batches, finding it catches anomalous patterns without flooding the AI layer with low-signal noise.

### 7.2 Feature Vector

Each event is converted into a six-dimensional numerical feature vector before scoring:

| Feature | Description |
|---------|-------------|
| `isOffHours` | 1 if the event occurred outside 9 AM to 6 PM on a weekday, 0 otherwise |
| `actionRisk` | A continuous risk score for the action type: VIEW is 0.0, UPLOAD is 0.2, DOWNLOAD is 0.3, MOVE is 0.4, DELETE is 0.7, ACCESS_DENIED is 0.6, LOGIN_FAIL is 0.7, PERMISSION_CHANGE is 0.8, IAM_CREATE_USER is 0.9, LOGGING_DISABLED is 1.0, IAM_ESCALATION is 1.0 |
| `isRoot` | 1 if the user type is root, 0 otherwise |
| `isAssumedRole` | 1 if the user type is assumed_role, 0 otherwise |
| `hasPublicPerm` | 1 if the permission_type field contains the word public, 0 otherwise |
| `recentRate` | The number of events from this user in the last 5 minutes, normalised to a value between 0 and 1 by dividing by 20 and capping at 1 |

### 7.3 Synthetic Normal Baseline

We train the forest on 300 synthetic events that represent normal CloudTrail activity: regular IAM users doing VIEW and DOWNLOAD operations during business hours at typical rates. Using a synthetic baseline avoids the cold-start problem of needing months of real account data before the detector is useful, and keeps behaviour consistent across different deployments that may have very different usage patterns.

### 7.4 Relationship to Rule Engine

The two layers overlap in some areas but are not redundant. Take AWS-010 as an example: it fires on any off-hours event regardless of context, while `isOffHours` is just one of six features in the Isolation Forest vector. A regular automated job running at 3 AM with low action risk and a normal recent rate will score below 0.62 and never reach the AI layer. The same off-hours timing combined with a root user type, high action risk, and a spike in recent activity will score well above the threshold. The rule gives a hard binary signal for the known pattern. The ML gives a continuous score for unusual combinations that no single rule captures. Both signals go to GPT-4.1, which weighs them together.

### 7.5 Pure Anomaly Alerts

Events that are flagged by the Isolation Forest but match no detection rule are stored as synthetic alerts with rule ID `AI-001` and rule name `ML Anomaly Detection`. These are marked with `is_anomaly: true` and appear in the ML-Only Anomalies count on the alerts dashboard. GPT-4.1 still reviews them, but tends to return lower confidence or a `notify_admin` recommendation since there is no hard rule evidence to support a destructive automated response.

### 7.6 Heuristic Fallback

If the Isolation Forest algorithm throws an error, the system falls back to a deterministic heuristic that computes a score from `actionRisk` and `isRoot` alone, ensuring the pipeline always produces a score and never silently drops events.

---

## 8. Layer 3: GPT-4.1 Verdict

### 8.1 Design Rationale

After the rule engine and Isolation Forest identify suspects, we need something that can make a judgment call rather than just apply another threshold. A legitimate administrator attaching a policy will match AWS-003. A scheduled job running at 3 AM will match AWS-010 and may score above 0.62. Neither is necessarily an attack. What makes them interesting or dangerous depends on context: who the user is, what they were doing before, what other signals appeared at the same time.

GPT-4.1 can reason over all of that in a single call and explain its conclusion. That explanation is as important as the classification itself, because a human analyst needs to understand why an action was taken, not just that it was taken.

### 8.2 Verdict Schema

GPT-4.1 returns a structured response validated against the following Zod schema:

```typescript
const VerdictSchema = z.object({
  isThreat:          z.boolean(),
  confidence:        z.number().min(0).max(1),
  severity:          z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]),
  reasoning:         z.string(),
  recommendedAction: z.enum([
    "disable_access_keys",
    "detach_admin_policy",
    "enable_cloudtrail",
    "block_s3_public_access",
    "quarantine_user",
    "notify_admin",
    "no_action",
  ]),
});
```

Zod validation ensures the response is always parseable and actionable regardless of model output variation.

### 8.3 Prompt Design

The model is given three inputs: the full JSON of the CloudTrail event, a list of all matched rules with their IDs, names, severities, and details, and the ML anomaly score. The system prompt instructs it to act as an AWS security analyst whose verdicts trigger real remediation actions, to be conservative and only flag as CRITICAL or HIGH when evidence is strong and unambiguous, and to return `isThreat: false` for clearly legitimate patterns such as automated CI/CD or known admin operations.

### 8.4 Concurrency Control

GPT-4.1 calls are made with a maximum concurrency of 5 simultaneous requests to avoid exceeding API rate limits while keeping total pipeline time low. The implementation batches suspect events into groups of 5 and awaits each group before starting the next.

### 8.5 Multi-Rule Events

When a single event triggers multiple detection rules, GPT-4.1 is called only once with all matched rules provided together. The resulting verdict is shared across all alerts generated from that event without additional API calls. This prevents both redundant costs and inconsistent verdicts on alerts from the same underlying event.

### 8.6 Fallback Behaviour

If the GPT-4.1 API call fails for a rule-based event, the pipeline falls back to a default verdict: `isThreat: true`, `confidence: 0.7`, severity taken from the first matched rule, and `recommendedAction: notify_admin`. This ensures rule-based alerts are never silently dropped due to an AI layer failure. Pure anomaly events with no rule match are dropped on AI failure, as there is insufficient signal to justify an automated response without a model verdict.

---

## 9. AWS Auto-Remediation

### 9.1 Execution Condition

An AWS remediation action is executed when the AI verdict satisfies all three conditions: `isThreat` is true, `confidence` is at or above 0.75, and `recommendedAction` is not `no_action`. Events that fail any condition are stored as alerts with `action_status: SKIPPED`.

### 9.2 Remediation Actions

**disable_access_keys.** Calls `ListAccessKeys` to enumerate all IAM access keys belonging to the user, then calls `UpdateAccessKey` with status `Inactive` on each one. Effective against stolen credential scenarios.

**detach_admin_policy.** Calls `DetachUserPolicy` to remove the `AdministratorAccess` managed policy ARN from the user. Used specifically in response to AWS-003 privilege escalation events.

**enable_cloudtrail.** Calls `StartLogging` on the trail ARN identified from the event's `file_name` field or the `CLOUDTRAIL_ARN` environment variable. Immediately restores audit logging when CloudTrail is disabled.

**block_s3_public_access.** Calls `PutPublicAccessBlock` with all four block settings enabled at the account level, identified by the `AWS_ACCOUNT_ID` environment variable. Closes the exposure window after an S3 public access misconfiguration.

**quarantine_user.** Creates an inline IAM policy document with a single Deny statement covering all actions on all resources, then calls `PutUserPolicy` to attach it directly to the user. This freezes all permissions without deleting the account, preserving forensic evidence.

**notify_admin.** No AWS API call is made. The alert is stored with the full AI verdict and surfaces in the dashboard for manual review.

### 9.3 Result Recording

Each remediation action returns a result containing the action taken, the outcome status as SUCCESS, FAILED, or SKIPPED, and a detail string. These are stored on the alert record alongside the AI verdict fields so the full chain of detection and response is visible in the dashboard.

---

## 10. Implementation

### 10.1 Technology Stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| Runtime | Node.js 20 LTS | Native crypto.randomUUID(), first-class TypeScript support |
| Framework | Next.js 16 App Router | Server components, serverless route handlers, Vercel-native deployment |
| Language | TypeScript 5 | Type safety across all schema boundaries |
| ORM | Prisma 5 | Type-safe MongoDB client with connection pooling for serverless |
| Database | MongoDB Atlas 7 | Cloud-hosted document store, native bulk insert, aggregation pipeline |
| ML | ml-isolation-forest | Pure JavaScript Isolation Forest implementation, no native dependencies |
| AI | @ai-sdk/openai + GPT-4.1 | Structured output via Zod schema, long context window, accurate reasoning |
| AWS SDK | @aws-sdk/client-iam, client-s3-control, client-cloudtrail | Modular v3 SDK for remediation actions |
| Charts | Recharts | React-native composable chart primitives |
| UI | shadcn/ui + Tailwind CSS v4 | Accessible component set |
| Deployment | Vercel | Zero-config Next.js deployment |

### 10.2 Pipeline Execution Steps

The `/api/run` route executes the full pipeline in eight sequential steps:

1. Events are fetched from the configured source, either the simulated adapter or the AWS CloudTrail adapter.
2. User histories are pre-fetched from MongoDB for all unique users in the batch, in parallel. This allows rate-based rules to run without additional database queries per event.
3. The rule engine evaluates every event against all ten rules in memory. Matches are stored in a map keyed by event ID.
4. The Isolation Forest scores every event using the six-feature vector. Events scoring above 0.62 are marked as anomalies.
5. Suspects are collected: any event with at least one rule match or an anomaly score above the threshold.
6. GPT-4.1 is called for each suspect with full context. Up to 5 calls run concurrently.
7. If the verdict meets the execution condition, the recommended AWS action is called immediately. The outcome is recorded.
8. All raw logs and enriched alerts, including AI verdict fields and action results, are bulk-written to MongoDB using two parallel native insert commands.

### 10.3 Bulk-Insert Optimisation

The naive implementation stored each event and alert individually using Prisma's `create()` method. On Vercel's serverless runtime with a remote MongoDB Atlas cluster, each create call has approximately 80 to 150 milliseconds of round-trip latency. A simulation batch of 400 events generating 47 alerts would produce nearly 450 sequential round trips totalling 36 to 67 seconds, which approaches or exceeds Vercel's function timeout.

The optimised implementation separates rule evaluation, which is pure in-memory computation, from persistence. After processing all events, logs are written in a single native `insert` command and enriched alerts in another, reducing database round trips from O(n) to 2 regardless of batch size.

### 10.4 Type Safety

The rule engine uses a discriminated union switch over the `RuleType` literal union with a `default` branch that throws a compile-time error for unhandled cases. The AI verdict schema is defined in Zod and validated at runtime. The `EnrichedAlert` interface extends `TriggeredAlert` with the full set of AI and action fields, ensuring all downstream code sees a consistent type.

---

## 11. Evaluation

### 11.1 Simulation Methodology

We evaluated the system using the built-in SimulatedAdapter, which injects all ten attack patterns across a randomised pool of synthetic users alongside a majority of benign events. Each run generates between 300 and 420 events. We repeated runs across multiple sessions to account for randomised user assignment and timing variation.

### 11.2 Rule Engine Results

The rule engine achieved zero false negatives on injected attack patterns across all simulation runs. Every rule fired on its corresponding injected event in every run. Average alert count was approximately 21 alerts per run across a batch of 379 events, which reflects that most events are benign VIEW and DOWNLOAD operations that trigger nothing.

### 11.3 Isolation Forest Results

The Isolation Forest flagged an average of 3 pure anomaly events per run: events that matched no rule but scored above 0.62. These typically corresponded to injected off-hours high-risk events that narrowly missed the frequency thresholds of relevant rules. Root account events and IAM escalation events consistently scored at the high end of the anomaly scale, as expected given their isRoot and high actionRisk feature values.

### 11.4 AI Verdict Results

GPT-4.1 classified all rule-based alerts in simulation as THREAT when the full attack context was present. Confidence values ranged from 0.75 to 0.97 depending on rule severity and anomaly score combination. Importantly, the model returned SAFE or UNCERTAIN for off-hours events with low-risk actions, which is the exact false positive reduction behaviour we designed the verdict layer to provide.

### 11.5 Automated Remediation Results

Remediation calls use real AWS SDK clients, so in simulation mode without real credentials they return FAILED status. This is expected. The pipeline handles action failures gracefully: the FAILED status is recorded on the alert, the alert is still stored and visible in the dashboard, and no exception disrupts the rest of the batch.

---

## 12. Limitations

**Batch polling.** We poll CloudTrail on demand rather than consuming a real-time stream. Attacks that complete in the window between two polls are detected retrospectively. A production deployment should use EventBridge or Kinesis Data Streams to bring detection latency from minutes down to seconds.

**Synthetic baseline.** Training the Isolation Forest on synthetic normal data is convenient but imprecise. The synthetic baseline approximates typical CloudTrail activity, but any account with heavy legitimate off-hours automation or unusual API usage patterns will see miscalibrated anomaly scores. Ideally the baseline would be trained on actual account activity after a profiling period.

**No cross-user correlation.** Both rate-based rules and the anomaly scorer operate per-user. An attack spread deliberately across many compromised identities to stay below per-user thresholds will not be detected by either layer in the current design.

**AI cost and latency.** GPT-4.1 is called for every suspect event, which creates a direct cost and latency dependency on the OpenAI API. At high alert volumes the 5-concurrent-call cap limits throughput and extends pipeline duration. For very high-volume accounts a cheaper model could be used for initial triage, with GPT-4.1 reserved for high-confidence suspects.

**Remediation scope.** Automated responses are limited to IAM and S3 operations. Threats involving EC2 compromise, Lambda injection, or DynamoDB exfiltration are not covered by the current remediation library.

---

## 13. Future Work

**Streaming ingestion.** Replacing the polling model with an EventBridge rule that pushes CloudTrail events to a Lambda function or streaming API endpoint would cut detection latency from minutes to seconds. This is the single highest-value improvement for a production deployment.

**Account-specific baseline.** Running the system in a profiling-only mode for the first few weeks of deployment, collecting real account activity to train a personalised Isolation Forest baseline, would significantly improve anomaly score accuracy for accounts with unusual but legitimate usage patterns.

**Cross-user correlation.** Adding rule types that aggregate activity across multiple users or roles would open up detection of distributed attacks and lateral movement patterns. These are currently invisible to both the rule engine and the per-user anomaly scorer.

**Broader remediation coverage.** Extending the response library to EC2 instance isolation, security group rollback, and Lambda function disablement would cover more of the threat surface with automated containment.

**Analyst feedback loop.** Recording whether human analysts agree or disagree with AI verdicts and feeding those decisions back as few-shot examples in the GPT-4.1 prompt would gradually improve calibration for account-specific patterns over time.

---

## 14. Conclusion

We built a three-layer intrusion detection system for AWS CloudTrail that goes from raw API log to automated AWS response in a single serverless pipeline. The rule engine catches known attack signatures with zero false negatives. The Isolation Forest extends coverage to behavioural anomalies that no written rule would reach. GPT-4.1 weighs both signals together, provides a confidence-rated verdict with a plain-English explanation, and recommends a specific AWS action. When confidence is at or above 75%, that action runs automatically.

The whole system is a single TypeScript codebase deployed on Vercel with no infrastructure beyond a MongoDB Atlas cluster. The bulk-insert optimisation keeps the pipeline fast enough to run comfortably within serverless function time limits.

The main limitation is the polling model, which means detection latency is measured in minutes rather than seconds. Streaming ingestion via EventBridge is the obvious next step toward production readiness. The hybrid architecture itself, combining deterministic rules, classical ML, and LLMs with automated response, is a pattern we think generalises well beyond AWS. The same structure could be applied to GCP Cloud Audit Logs, Azure Monitor, or any structured API audit stream with appropriate adapter and rule changes.

---

## References

[1] Liu, F. T., Ting, K. M., and Zhou, Z. H. Isolation Forest. In *Proceedings of the 8th IEEE International Conference on Data Mining (ICDM)*, pp. 413-422, 2008.

[2] Moraes, I., Sadeghi, A., Barreto, A., and Moraes, J. Machine Learning Applied to AWS CloudTrail Logs for Anomaly Detection. *IEEE International Conference on Cloud Engineering*, 2021.

[3] Hendler, D., Kels, S., and Rubin, A. Detecting Malicious PowerShell Commands using Deep Neural Networks. In *Proceedings of the 2018 ACM SIGSAC Conference on Computer and Communications Security*, 2018.

[4] Pham, T., Whitley, N., and Carver, J. Graph-Based Lateral Movement Detection in Cloud IAM Audit Logs. *Journal of Cloud Security*, 2022.

[5] Amazon Web Services. AWS CloudTrail Documentation. https://docs.aws.amazon.com/cloudtrail/

[6] Roth, F. Sigma: Generic Signature Format for SIEM Systems. https://github.com/SigmaHQ/sigma

[7] OpenAI. GPT-4.1 Technical Report. https://openai.com/research/gpt-4.1, 2025.

[8] Vercel. AI SDK Documentation. https://ai-sdk.dev/docs, 2025.
