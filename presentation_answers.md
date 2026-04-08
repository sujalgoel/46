# Mock Presentation Q&A

**Project: Rule-Based Intrusion Detection System for Cloud File Storage**

---

## 0. Tech Stack Questions

**What is the tech stack of your project?**

- **Frontend / Full-stack framework**: Next.js 15 (App Router) with TypeScript
- **UI components**: shadcn/ui with Tailwind CSS
- **Backend / API**: Next.js API routes (serverless)
- **Database**: MongoDB Atlas with Prisma ORM
- **Cloud integration**: AWS CloudTrail via the `LookupEvents` API
- **Charts and visualisation**: Recharts
- **Deployment**: Vercel

**Why did you choose Next.js for this project?**

Next.js gives us both the frontend dashboard and the backend API routes in a single codebase. Server Components let us fetch data from MongoDB directly on the server, so we did not need to build a separate REST API. Deploying on Vercel means we do not manage any infrastructure either. For a project of this scope, it was the most practical choice.

**Why MongoDB instead of a relational database like PostgreSQL?**

CloudTrail events are semi-structured. Different event types have different fields, and MongoDB's document model handles that without requiring schema migrations every time a new field shows up. We used Prisma on top of it for type-safe queries. MongoDB Atlas also has a free tier, which made it the zero-cost option for a demo project.

**What is Prisma and why use it?**

Prisma is an ORM for Node.js and TypeScript. It generates a type-safe database client from a schema file, so every query is validated at compile time. Instead of writing raw MongoDB queries and casting results to `any`, we get fully typed `LogEntry` and `Alert` objects throughout the codebase. It prevents a lot of subtle runtime bugs.

**What is AWS CloudTrail?**

CloudTrail is AWS's audit logging service. It records every API call made in an AWS account: who made it, from what IP, at what time, and what the result was. It is the main data source for our IDS. We poll it using the `LookupEvents` API, which returns recent events within a time window, and then normalise each event into our internal `LogEntry` schema before passing it through the rule engine.

**What is Tailwind CSS and shadcn/ui?**

Tailwind is a utility-first CSS framework. Instead of writing custom CSS classes, you apply small utility classes directly in JSX like `text-sm`, `flex`, or `gap-4`. shadcn/ui is a component library built on Tailwind and Radix UI that gives you accessible, customisable components (cards, tables, badges, buttons) that you copy into your codebase and own. Together they let us build a polished dashboard quickly without touching raw CSS.

**What is Vercel and why deploy there?**

Vercel is the company behind Next.js and the recommended platform to deploy it on. It detects Next.js projects automatically, builds them, and deploys API routes as serverless functions. Every git push triggers a new deployment. The free tier is more than enough for a demo.

**What is TypeScript and why use it over JavaScript?**

TypeScript is a statically typed superset of JavaScript. It catches type errors at compile time rather than at runtime. For a project with complex data shapes like CloudTrail events, alert objects, and rule outputs, that matters a lot. Without it, you can easily pass the wrong field to a rule function or access a property that does not exist on a response object, and you would only find out when the thing breaks in production.

---

## 1. Basic Understanding Questions

**Can you briefly explain what an Intrusion Detection System (IDS) is in your own words?**

An IDS is a monitoring system that watches activity across a network or platform and raises alerts when something looks like an attack or a policy violation. It does not block anything on its own. It observes, analyses, and notifies. Think of it like a security camera: it records everything and triggers an alarm when it sees something suspicious, but a separate response mechanism (or a human) decides what to do next.

**Why is IDS specifically important in cloud file storage systems?**

Cloud storage holds sensitive data like financial records, personal information, and credentials, and it is accessed by many users over the public internet. Unlike on-premise systems, you cannot put a physical lock on a door. Every action (upload, download, permission change, login) happens through APIs, and attackers exploit those same APIs. An IDS watches those API calls and flags when the pattern of access looks malicious: bulk downloads that look like data exfiltration, off-hours logins that look like compromised credentials, mass deletions that look like ransomware.

**What is meant by the shared responsibility model in cloud computing?**

AWS secures the infrastructure: the physical data centres, the hypervisors, the global network. The customer is responsible for securing what runs on top of it: IAM configurations, S3 bucket policies, CloudTrail logging, and the data itself. If you misconfigure an S3 bucket as public, AWS is not liable. Our IDS sits in the customer's responsibility zone. It watches for misconfigurations and attacks within the account.

**How is IDS different from traditional security mechanisms like firewalls?**

A firewall works at the network layer. It allows or blocks traffic based on IP, port, and protocol rules before a connection is established. An IDS works at the application/event layer. It analyses what authenticated, authorised users are actually doing after they are inside the system. A firewall cannot detect an admin account that has been legitimately compromised and is now exfiltrating files. An IDS can.

**What kind of data is most vulnerable in cloud storage systems?**

S3 buckets holding PII (names, addresses, Aadhaar numbers, PAN cards), financial records, database backups, API keys stored as files, and access credentials. These are high-value targets because a single misconfigured bucket or a stolen access key gives an attacker direct programmatic access to bulk-download everything in seconds.

---

## 2. Conceptual Depth Questions

**Why did you choose a rule-based IDS instead of a machine learning-based IDS?**

A few reasons. Rule-based systems are fully explainable: when an alert fires, you know exactly which condition triggered it and why. That matters for compliance audits and incident response. They also do not require large labelled training datasets, which are genuinely hard to get for cloud security events. And the known attack patterns for AWS environments are well-documented and fairly stable. They do not change as often as, say, malware signatures. For our threat model, rule-based was the right fit.

**Can you explain the principle of least privilege and how it relates to your system?**

Least privilege means every user, role, or service should have only the minimum permissions needed to do their job and nothing more. Our system ties into this directly. One of our rules detects when a user attaches an AdministratorAccess policy to themselves, which is the most direct violation of least privilege possible. Another rule alerts on new IAM users or access keys being created, because new accounts are a common way to quietly expand access. The system flags any attempt to accumulate more permissions than someone should have.

**What are false positives, and why are they a major issue in IDS systems?**

A false positive is when the system raises an alert for something that is actually legitimate activity. For example, flagging a developer's late-night deployment as an off-hours intrusion. Too many false positives cause alert fatigue: security teams start ignoring alerts because most are noise, and eventually miss a real attack. The 2013 Target breach is the classic example. Their IDS flagged the intrusion correctly, but analysts dismissed it as another false positive. Reducing false positives is one of the most important design goals for any IDS.

**What is alert fatigue, and how does your system address it?**

Alert fatigue is when the volume of alerts is so high that analysts become desensitised and stop investigating them. We address it by setting specific, multi-condition thresholds rather than alerting on every unusual event. One failed login is not an alert. Five failed logins within 15 minutes is. One file download is not an alert. Downloading more than 50 files in an hour triggers bulk-download detection. By requiring multiple indicators before firing, we cut down on noise without sacrificing coverage of real attacks.

**What kind of attacks can your system detect effectively?**

- Credential compromise: root account usage, multiple consecutive failed logins
- Insider threats: privilege escalation, creating unauthorised IAM users, off-hours access
- Data exfiltration: bulk S3 object downloads
- Ransomware setup: mass S3 deletion
- Audit tampering: CloudTrail logging being disabled
- Exposure: S3 buckets being made public
- Access abuse: excessive access-denied errors indicating credential stuffing or scanning

---

## 3. Methodology / System Design Questions

**How exactly does your rule engine work?**

The rule engine is a set of deterministic functions, one per rule. Each function receives a normalised event (user, action, timestamp, resource, IP) and a short history of recent events by the same user, and returns a matched alert if the conditions are met. For example, the off-hours rule checks whether the event timestamp falls outside 09:00-17:00. The IAM escalation rule looks for `AttachUserPolicy` or `PutUserPolicy` API calls where the policy ARN contains "AdministratorAccess". If a rule fires, an alert is written to the database with the rule ID, description, and severity.

**How are rules defined in your system? Static or dynamic?**

Static. Each rule is a function with hardcoded conditions and thresholds (like 5 failed logins in 15 minutes). This was intentional. Static rules are auditable, version-controlled, and explainable in a compliance audit. The thresholds are based on the CIS AWS Foundations Benchmark, not arbitrary guesses. Dynamic rule management would need a separate admin UI and versioning system, which is something we identified as a future enhancement.

**Can your system adapt to changing user behavior?**

Not in the current version. Rules fire based on fixed thresholds regardless of individual user patterns. A user who legitimately works at night would always trigger the off-hours rule. Adapting to per-user baselines, like learning that this specific user normally works at 11pm, would need a machine learning component. That is the natural next step beyond the current approach.

**What happens when a new type of attack (zero-day) occurs?**

This is a known limitation. A zero-day attack that does not match any existing rule will not be detected. The response is to monitor threat intelligence sources like AWS security bulletins and the MITRE ATT&CK cloud matrix, and add new rules quickly when novel attack patterns are documented. Adding a new rule is a small code change and a deployment, so the architecture at least makes that fast.

**How do you differentiate between normal vs suspicious activity?**

Through hardcoded thresholds derived from security best practices. Actions are categorised by risk level (VIEW is low risk, IAM_ESCALATION is high risk). Thresholds define what volume or pattern crosses from normal to suspicious. For example, more than 50 downloads in an hour, or any use of the root account, which should essentially never happen in a properly configured AWS account. The rules encode the security team's definition of "suspicious" in plain, readable code.

---

## 4. Results & Evaluation Questions

**How did you measure low latency in your system?**

We measured the time from receiving an event to writing an alert to the database. Since rule evaluation is purely in-memory (no external API calls, no ML inference), each event is evaluated against all 10 rules in milliseconds. The main bottleneck is database write speed, which we addressed by batching alert inserts rather than writing one at a time.

**What metrics did you use to evaluate performance?**

- Detection rate: percentage of simulated attack events correctly flagged
- False positive rate: percentage of normal events incorrectly flagged
- Rule coverage: how many defined attack categories had at least one matching rule
- Pipeline latency: time from event ingestion to alert storage
- Events processed per run

**How much did your system reduce false positive rate compared to existing systems?**

By requiring multiple conditions before firing (not just one unusual event), our false positive rate was significantly lower than naive single-condition alerting. A single failed login generates no alert; five consecutive ones do. In our simulated test runs, over 90% of fired alerts corresponded to actual simulated attack events.

**Did you test your system on any real dataset or simulation?**

Both. We tested against a simulated CloudTrail event stream from our own event generator, which produces realistic distributions of normal and attack events across all rule categories. We also verified the pipeline against the live AWS CloudTrail `LookupEvents` API with real credentials in a test account. The system correctly ingested, evaluated, and stored alerts for real events.

**How does your system perform under high traffic conditions?**

Rule evaluation is in-memory computation with no external dependencies, so it does not slow down as volume increases. Each event is evaluated independently. High traffic at enterprise scale would require batching event ingestion and parallelising rule evaluation workers, but the rule logic itself is stateless and transfers directly to that kind of setup.

---

## 5. Comparison Questions

**Compare your system with ML-based IDS systems.**

| Aspect | Our Rule-Based System | ML-Based System |
| --- | --- | --- |
| Explainability | High (exact rule and condition known) | Low (black box output) |
| Training data needed | None | Large labelled dataset |
| Novel attack detection | No (only known patterns) | Better, if well-trained |
| Latency | Very low (in-memory) | Higher (model inference) |
| Maintenance | Update rules manually | Retrain periodically |
| Compliance audit | Easy (rules are readable) | Hard to justify to auditors |

**What are the trade-offs between accuracy vs performance?**

More complex rules (combining multiple conditions, time windows, event sequences) increase accuracy but need more computation and event history storage. Simple threshold rules are faster but may miss nuanced attack patterns. We kept rules simple and specific: each one targets one well-defined attack pattern rather than trying to do everything in a single complex condition.

**Why do ML models have higher computational cost?**

ML models require matrix multiplications across millions or billions of parameters during inference. Even simpler models like Random Forests need to traverse hundreds of decision trees per event. Our rule engine is direct conditional logic. An if-statement is orders of magnitude cheaper than any model inference.

**In what scenarios would ML-based IDS still be better than your approach?**

When an organisation has a large labelled dataset of historical attacks specific to their environment, a supervised ML model can pick up subtle patterns that no human-written rule would capture. For detecting novel attack variants that are slight mutations of known attacks, rules are brittle to small changes while ML generalises better. And for user behaviour analytics (catching compromised insiders who stay within normal thresholds), ML is genuinely the right tool.

---

## 6. Weakness / Limitation Questions

**Your system cannot detect unknown attacks, isn't that a major limitation?**

It is a real limitation, but it is appropriate for the scope. The system targets well-documented AWS CloudTrail attack patterns that are stable, known, and specified in security benchmarks. The deeper unknown-attack problem (novel malware, zero-day exploits in AWS infrastructure itself) is not detectable from event logs regardless of approach. Our system is scoped to what is actually detectable at the event layer.

**How would an attacker bypass your rule-based system?**

By staying below thresholds: downloading 49 files instead of 50, operating during business hours, using a non-root account. A knowledgeable attacker who has studied the rule set can operate just under every threshold. This is the core weakness of static rules, and the main reason adding an anomaly detection layer is the natural next step. Statistical anomaly detection is much harder to game precisely.

**What happens if rules are incorrectly defined?**

Incorrectly strict rules produce false positives (analysts start ignoring alerts). Incorrectly loose rules produce false negatives (missed attacks). This is why rules are version-controlled in code, reviewed before deployment, and thresholds are derived from established benchmarks rather than guesses. Regular tuning based on real alert data is part of ongoing maintenance.

**Can your system scale to enterprise-level cloud systems?**

With modifications, yes. The current synchronous processing works for low-to-medium event volumes. Enterprise scale would need event queues (SQS/Kafka) for decoupled ingestion, horizontal workers for parallel rule evaluation, and time-windowed aggregations stored in a fast cache like Redis rather than queried from the main database. The rule logic itself is stateless and would not need to change.

**How do you handle rule conflicts or overlaps?**

All rules run independently. An event can match multiple rules at the same time. A root account login during off-hours would trigger both the root usage rule and the off-hours rule, generating two separate alerts. This is intentional. Multi-rule matches on the same event are a stronger signal than a single match, and analysts can see all triggered rules in the dashboard.

---

## 7. Future Work / Improvement Questions

**How would you design a hybrid IDS (rule + ML) system?**

The natural extension is to add a second layer after the rule engine: a statistical anomaly detector like Isolation Forest that trains on a baseline of normal events and flags deviations even when no rule fires. The rule engine handles known attack patterns; the anomaly detector catches unknown ones statistically. Events flagged by either layer then go to a final classification step for verdict and response. That is exactly what we built in the major project.

**What ML models would you integrate and why?**

- Isolation Forest: unsupervised anomaly detection, no labelled attack data needed, computationally cheap, good at catching statistical outliers in API call behaviour
- LSTM: sequential model for detecting temporal patterns like slow credential stuffing over hours
- XGBoost: once labelled attack datasets are available, for high-accuracy supervised classification

**How can your system be deployed on platforms like AWS or Azure?**

The current system runs on Vercel with MongoDB Atlas. For a fully AWS-native deployment, the API routes become Lambda functions, MongoDB becomes DynamoDB, and events are consumed from CloudWatch Logs via Lambda triggers instead of polling. The rule engine logic is framework-agnostic TypeScript and moves over without changes.

**Can this system be automated to block attackers instead of just alerting?**

Yes, and that would make it an IPS (Intrusion Prevention System). On confirmed high-severity alerts, the system could automatically call AWS APIs to disable access keys, detach admin policies, block S3 public access, or quarantine users. The tricky part is setting the confidence threshold correctly. Automated blocking on a false positive can disrupt a legitimate user, which is bad. We would want multiple rule matches and high severity before triggering any automated action.

**How would you improve detection of zero-day attacks?**

Two ways. First, integrate threat intelligence feeds like AWS GuardDuty findings and the MITRE ATT&CK cloud matrix to update rules faster when new attack patterns are published. Second, add an anomaly detection layer that establishes per-user behavioural baselines and flags statistical deviations regardless of whether a known rule matches.

---

## 8. Tough / Trick Questions

**If rule-based systems are simple, why aren't they widely used in modern cloud security?**

They are widely used. AWS GuardDuty, AWS Config Rules, and most SIEM platforms are fundamentally rule-based at their core. The idea that rule-based means outdated is mostly marketing from ML vendors. The real challenge at enterprise scale is maintenance: large organisations with thousands of rules struggle to keep them updated as attack patterns evolve. For a focused, well-defined threat model like ours, rule-based is entirely appropriate.

**Isn't your approach just pattern matching rather than intelligence?**

Yes, and that was a deliberate choice. Pattern matching against well-documented attack signatures is fast, reliable, explainable, and auditable. For the specific threat model of known AWS CloudTrail attacks, it gives complete coverage. ML adds value when patterns are ambiguous or unknown. For our well-defined rule categories, it would add complexity without proportional improvement in detection accuracy.

**How do you ensure your system is not outdated as attack patterns evolve?**

Rules are code. They live in version control and can be updated and deployed in minutes when new attack patterns are documented. We follow AWS security bulletins, the CIS AWS Foundations Benchmark, and the MITRE ATT&CK cloud matrix to stay current. Adding or modifying a rule is straightforward: write the function, write a test, deploy.

**What if an attacker mimics normal user behavior?**

That is the hardest scenario for any rule-based system. A patient attacker who operates within all thresholds, during business hours, using a legitimate account will not trigger our rules. This is the core limitation of the current system and the main reason we added anomaly detection in the major project. Statistical anomaly detection looks across many dimensions simultaneously, making precise mimicry much harder to pull off.

**Why should someone choose your system over existing commercial IDS solutions?**

AWS GuardDuty costs money per event and is a black box. You cannot see why an alert fired or customise the detection logic. Splunk and Datadog are powerful but expensive and need significant expertise to configure. Our system is fully auditable (rules are readable code), easily customisable for specific organisational policies, open source, and deployable at near-zero infrastructure cost. For teams that need transparency and control over their detection logic, that is a real advantage.

---

## 9. Rapid Fire (Viva Style)

**IDS vs IPS?**
IDS (Intrusion Detection System) detects and alerts. IPS (Intrusion Prevention System) detects and automatically blocks or mitigates. Our system is an IDS. It alerts on suspicious activity but does not take automated action.

**Signature-based vs anomaly-based IDS?**
Signature-based matches events against known attack patterns. Our system is signature/rule-based. Anomaly-based establishes a baseline of normal behaviour and flags deviations from it. Signature is precise for known attacks but blind to novel ones. Anomaly catches unknowns but tends to have higher false positives.

**What is IAM?**
Identity and Access Management. The AWS service that controls who (users, roles, services) can do what (actions) on which resources. Every AWS API call is authenticated through IAM. It is the main attack surface for privilege escalation and credential abuse, which is why several of our rules target it directly.

**What is data exfiltration?**
Unauthorised transfer of data out of a system, typically by an attacker who has gained access and is copying sensitive files somewhere external. In AWS, this looks like bulk S3 downloads or large sequences of GetObject API calls. Our bulk-download detection rule (AWS-007) targets exactly this.

**What is a zero-day attack?**
An attack that exploits a previously unknown vulnerability, one for which no patch or detection signature exists yet. Called "zero-day" because defenders have had zero days to prepare. Rule-based IDS cannot detect zero-days by definition, since rules only match known patterns. That is the main limitation of our current approach.

---

## 10. Architecture & System Design Questions

**Can you walk us through the overall architecture of your system?**

There are four main layers. The data ingestion layer pulls events from AWS CloudTrail using the `LookupEvents` API and normalises them into a consistent schema (user, action, timestamp, resource, IP, file size). The rule engine evaluates each event against 10 detection rules and produces alerts for any matches. All ingested events and triggered alerts are stored in MongoDB Atlas. The Next.js dashboard reads from MongoDB and visualises logs, alerts, and statistics.

**How does data flow through your system from start to finish?**

A POST request to `/api/run` triggers the pipeline. The backend fetches recent CloudTrail events, normalises each one, fetches the user's recent event history from the database, runs all 10 rules against the event and its history, collects matched alerts, bulk-inserts the events and alerts into MongoDB, and returns a summary with counts of events processed and alerts triggered.

**How did you normalise CloudTrail events into your internal schema?**

CloudTrail events are complex nested JSON with AWS-specific field names like `eventName`, `userIdentity`, `sourceIPAddress`, and `requestParameters`. We wrote a normaliser function that maps these to our flat `LogEntry` schema: `user_email`, `action`, `ip_address`, `file_name`, `file_size_mb`, `timestamp`, `source`. The rule engine works on that clean shape regardless of which CloudTrail event type it is processing.

**What does your database schema look like?**

Two main collections. `LogEntry` stores every ingested event with fields: `event_id`, `user_email`, `action`, `ip_address`, `file_name`, `file_size_mb`, `timestamp`, `source`, `is_anomaly`. `Alert` stores every rule match with fields: `rule_id`, `rule_name`, `severity`, `user_email`, `event_id`, `timestamp`, `description`, `mitigation`. Both are defined in `schema.prisma` and accessed through the Prisma client.

**How many detection rules does your system have, and what do they cover?**

Ten rules: root account usage (AWS-001), CloudTrail logging disabled (AWS-002), IAM privilege escalation (AWS-003), excessive access-denied errors (AWS-004), S3 bucket made public (AWS-005), multiple failed console logins (AWS-006), bulk S3 object download (AWS-007), mass S3 deletion (AWS-008), new IAM user or access key created (AWS-009), and off-hours console access (AWS-010).

**How does a rule actually look in code?**

Each rule is a TypeScript function that takes an event and a recent history array and returns either `null` (no match) or an alert object. The root account rule checks `event.user_email === "root"` and if true, returns an alert with severity HIGH and a mitigation note. The off-hours rule checks if the hour of `event.timestamp` is outside 9 to 17 and returns an alert if so. All 10 rule functions run in sequence for every event.

---

## 11. Dashboard & UI Questions

**What does your dashboard show?**

Four main pages. The overview page has summary cards (total events, total alerts, high severity alerts, unique users) and charts (alerts by severity, alerts by rule, event volume over time). The logs page has a filterable table of all ingested CloudTrail events with timestamps, users, actions, and IPs. The alerts page has a table of all triggered alerts with rule ID, severity, user, and mitigation. The How It Works page documents the entire detection pipeline.

**How does the filtering on the logs page work?**

The logs page accepts an `action` query parameter like `?action=DELETE`. The server-side component reads the parameter, passes it to the `getLogs` function which adds a Prisma `where` filter, and renders only matching records. The filter buttons are a client component (`LogFilters`) that updates the URL query string on click, which triggers a server-side re-render with the new filter applied.

**Why is the dashboard server-rendered instead of client-rendered?**

Server Components in Next.js fetch data from MongoDB on the server and send finished HTML to the browser. No client-side loading spinner, no fetch calls in the browser, and database credentials never leave the server. Only components that need interactivity, like the filter buttons, are marked as Client Components. It is faster, simpler, and more secure.

---

## 12. Project Motivation & Scope Questions

**Why did you pick cloud file storage as the focus for your IDS?**

Cloud file storage is one of the most commonly breached areas in AWS. S3 misconfiguration consistently appears near the top of data exposure causes every year. More practically, all activity in S3 and IAM is recorded in CloudTrail as structured API call logs, which makes it a natural data source for programmatic intrusion detection. The events are already machine-readable. We just had to define what "suspicious" looks like.

**What problem does this project solve that AWS does not already solve?**

AWS has GuardDuty and Security Hub, but they are black boxes. You cannot see why an alert fired, customise the detection logic, or integrate your own organisation's policies. Our system is fully transparent: every rule is readable code, every alert includes the exact condition that triggered it, and adding a new rule is a small code change. For educational use and for organisations that need full auditability, a custom IDS makes more sense than a commercial black box.

**What were the biggest challenges you faced building this?**

Three things. First, normalising CloudTrail's complex nested JSON into a consistent flat schema without losing important fields. Second, finding thresholds that balance false positives against detection sensitivity. Too strict misses attacks; too loose causes alert fatigue. Third, making the event history lookup efficient. Each rule evaluation needs the user's recent events, so we had to batch-fetch histories rather than querying the database once per event.

**If you had more time, what would you add?**

Real-time event streaming instead of polling on demand, per-user behavioural baselines so the off-hours rule respects individual work patterns, email or Slack notifications when high-severity alerts fire, and an anomaly detection layer for catching patterns no rule anticipated. That last one became the focus of our major project.

**What is the difference between your minor and major project?**

The minor project (this one) is purely rule-based: 10 deterministic rules, no ML, no AI. It covers known attack patterns reliably but cannot detect novel behaviour. The major project extends this with two more layers: an Isolation Forest for statistical anomaly detection and GPT-4.1 for contextual threat verdict with automated AWS remediation. The major project is a hybrid IPS. This one is a focused, explainable IDS.

---

## 13. Testing & Validation Questions

**How did you test that your rules work correctly?**

We built a simulation mode that generates synthetic CloudTrail events: normal activity mixed with specific attack scenarios. We injected events designed to trigger each rule (a root login event for AWS-001, 6 failed logins in 10 minutes for AWS-006) and verified the correct alert fired. We also injected benign events that should not trigger rules and verified no false alerts came through.

**How do you verify that an alert is not a false positive?**

The analyst opens the alert detail page, which shows the exact event that triggered the rule, the full event context (user, IP, time, action, resource), and the mitigation recommendation. All evidence is visible in one place. The analyst can also cross-reference other events by the same user on the logs page to get a fuller picture before deciding if the alert is genuine.

**Did you write unit tests?**

Yes. Each rule function is a pure function (input to output, no side effects), which makes unit testing straightforward. We wrote test cases for each rule covering: a matching event that should produce an alert, a non-matching event that should return null, and edge cases around thresholds like exactly 5 failed logins versus exactly 4.

---

## 14. Security & Ethics Questions

**Is your system itself secure? Could it be attacked?**

The main attack surface is the API route that triggers the pipeline. In production it should be protected by authentication so only the security team can trigger a scan or view alerts. Database credentials are stored as environment variables and never hardcoded. CloudTrail credentials are read-only (`cloudtrail:LookupEvents` only), so even if they leaked, an attacker could not modify CloudTrail using them.

**What are the privacy implications of logging all CloudTrail events?**

CloudTrail events contain user identifiers, IP addresses, and resource names, all of which are personally identifiable in an organisational context. The system should be deployed with access controls so only the security team can view logs and alerts. Retention policies should comply with the organisation's data governance rules. In our implementation, logs are stored only as long as needed for detection.

**What compliance standards does your system relate to?**

The detection rules align with the CIS AWS Foundations Benchmark, a widely accepted security configuration standard. Rules like AWS-002 (CloudTrail disabled) and AWS-001 (root account usage) map directly to CIS controls. The system also supports SOC 2 and ISO 27001 audit requirements by maintaining an immutable log of detected security events with timestamps and evidence.
