# Cloud IDS — AWS Intrusion Detection System

A real-time cloud intrusion detection system that monitors AWS CloudTrail events, evaluates them against a rule engine, and surfaces security alerts through a live dashboard.

![Dashboard](ids_next_dashboard.png)

---

## Features

- **Live dashboard** — event counts, alert breakdown by severity, top triggered rules, hourly activity chart
- **Rule engine** — 10 built-in detection rules covering the most common AWS attack patterns
- **Alerts page** — filterable by severity and rule, with one-click acknowledgement
- **Audit logs** — full event log filterable by action type
- **Two data sources** — simulated attack scenarios for testing, or live AWS CloudTrail via API keys
- **Bulk processing** — handles 400+ events in a single run without timeouts

---

## Detection Rules

| Rule | Name | Severity | Trigger |
|------|------|----------|---------|
| AWS-001 | Root Account Usage | CRITICAL | Any activity from the root account |
| AWS-002 | CloudTrail Logging Disabled | CRITICAL | `StopLogging` or `DeleteTrail` called |
| AWS-003 | IAM Privilege Escalation | CRITICAL | `AdministratorAccess` policy attached |
| AWS-004 | Excessive Access Denied Errors | HIGH | 10+ `AccessDenied` errors in 5 minutes |
| AWS-005 | S3 Bucket Made Public | HIGH | Bucket ACL/policy changed to public |
| AWS-006 | Multiple Failed Console Logins | HIGH | 3+ failed logins in 10 minutes |
| AWS-007 | Bulk S3 Object Download | HIGH | 20+ downloads in 5 minutes |
| AWS-008 | Mass S3 Deletion | CRITICAL | 10+ deletions in 5 minutes |
| AWS-009 | New IAM User / Access Key Created | MEDIUM | `CreateUser` or `CreateAccessKey` called |
| AWS-010 | Off-Hours Console Access | MEDIUM | Activity between 10 PM – 6 AM |

---

## Tech Stack

- **Framework** — Next.js 16 (App Router, server components)
- **Database** — MongoDB Atlas via Prisma 5
- **Charts** — Recharts
- **UI** — shadcn/ui + Tailwind CSS
- **Deployment** — Vercel

---

## Getting Started

### Prerequisites

- Node.js 18+
- A MongoDB Atlas cluster
- (Optional) AWS credentials for live CloudTrail ingestion

### 1. Install dependencies

```bash
npm install
```

### 2. Set environment variables

Create a `.env` file at the project root:

```env
MONGODB_URI=mongodb+srv://<user>:<password>@<cluster>.mongodb.net/<dbname>

# Optional — only needed for live AWS CloudTrail ingestion
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your_key
AWS_SECRET_ACCESS_KEY=your_secret
```

### 3. Generate Prisma client

```bash
npx prisma generate
```

### 4. Run the dev server

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

---

## Running a Simulation

Click **Run Simulation** in the sidebar (or the button on the dashboard). This generates ~400 synthetic CloudTrail events with all 10 attack patterns injected and processes them through the rule engine in one shot.

To ingest live AWS CloudTrail events instead, pass `source: "aws"` in the request body along with your region and credentials.

---

## API Routes

| Method | Route | Description |
|--------|-------|-------------|
| `POST` | `/api/run` | Ingest events and run rule engine |
| `GET` | `/api/stats` | Dashboard summary stats |
| `GET` | `/api/alerts` | List alerts (filterable by severity, rule) |
| `POST` | `/api/alerts/[id]/acknowledge` | Acknowledge an alert |
| `GET` | `/api/logs` | List audit log events (filterable by action) |
| `POST` | `/api/clear` | Clear all logs and alerts |

---

## Project Structure

```
├── app/
│   ├── page.tsx              # Dashboard
│   ├── alerts/page.tsx       # Alerts table
│   ├── logs/page.tsx         # Audit log table
│   └── api/                  # API routes
├── components/               # UI components
├── lib/
│   ├── rule-engine.ts        # Detection rule evaluation
│   ├── alert-manager.ts      # Database read/write helpers
│   ├── config.ts             # Rules definitions + constants
│   └── adapters/
│       ├── simulated.ts      # Synthetic event generator
│       └── aws-cloudtrail.ts # Live AWS CloudTrail ingestion
└── prisma/
    └── schema.prisma         # MongoDB schema (Log, Alert)
```
