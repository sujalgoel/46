// frontend/lib/adapters/simulated.ts
import { ORG_DOMAIN } from "../config";
import type { LogEvent } from "../rule-engine";

const _USER_TEMPLATES = [
  "rhea.chakraborty@{d}", "riya.karagwal@{d}", "suhani.sidhu@{d}",
  "sujal.goel@{d}", "sk.dubey@{d}", "admin@{d}",
];

const _S3_OBJECTS = [
  "s3://amity-research/papers/network_security_2025.pdf",
  "s3://amity-research/datasets/student_records_2025.csv",
  "s3://amity-backup/thesis/draft_v3.docx",
  "s3://amity-backup/lab/dataset_backup.zip",
  "s3://amity-assets/course_material_sem4.pdf",
  "s3://amity-hr/faculty_salary_sheet.xlsx",
  "s3://amity-projects/group46/project_report.pdf",
  "s3://amity-admissions/admission_data_2025.csv",
  "s3://amity-lms/lecture_notes_week12.pdf",
  "s3://amity-logs/network_logs_raw.tar.gz",
];

const _INTERNAL_IPS = ["10.0.0.101", "10.0.0.102", "10.0.0.103", "192.168.1.50", "172.16.0.20"];
const _ATTACKER_IP  = "203.0.113.99";
const _NORMAL_ACTIONS = ["VIEW", "DOWNLOAD", "UPLOAD", "VIEW", "VIEW"]; // VIEW weighted

function randInt(min: number, max: number) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
function randFloat(min: number, max: number) {
  return Math.random() * (max - min) + min;
}
function randChoice<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}
function shuffle<T>(arr: T[]): T[] {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}
function isoSec(d: Date): string {
  return d.toISOString().slice(0, 19);
}

function makeEvent(
  userEmail: string,
  action: string,
  resource: string,
  ipAddress: string,
  ts: Date,
  userType = "iamuser",
  permissionType = "",
): LogEvent {
  return {
    event_id:        crypto.randomUUID(),
    timestamp:       isoSec(ts),
    user_email:      userEmail,
    user_type:       userType,
    action,
    file_name:       resource,
    ip_address:      ipAddress,
    permission_type: permissionType,
  };
}

export class SimulatedAdapter {
  private numEvents: number;
  private users: string[];

  constructor(orgDomain = ORG_DOMAIN, numEvents?: number) {
    this.numEvents = numEvents ?? randInt(180, 420);
    this.users = shuffle(_USER_TEMPLATES.map(t => t.replace("{d}", orgDomain)));
  }

  fetchLogs(): LogEvent[] {
    const now    = new Date();
    const events: LogEvent[] = [];

    // AWS-001 – root account
    events.push(makeEvent(
      "root@aws", "VIEW", "s3://amity-hr/faculty_salary_sheet.xlsx",
      _ATTACKER_IP,
      new Date(now.getTime() - randFloat(0.5, 2) * 3_600_000),
      "root",
    ));

    // AWS-002 – CloudTrail logging disabled
    events.push(makeEvent(
      this.users[0], "LOGGING_DISABLED", "arn:aws:cloudtrail:ap-south-1:trail/amity-trail",
      _ATTACKER_IP,
      new Date(now.getTime() - randFloat(0.5, 3) * 3_600_000),
    ));

    // AWS-003 – IAM privilege escalation
    events.push(makeEvent(
      this.users[0], "IAM_ESCALATION", "arn:aws:iam::123456789:user/backdoor-user",
      _ATTACKER_IP,
      new Date(now.getTime() - randFloat(0.5, 2) * 3_600_000),
    ));

    // AWS-004 – Excessive AccessDenied (11–16 in a burst)
    const base004 = new Date(now.getTime() - randInt(3, 8) * 60_000);
    for (let i = 0; i < randInt(11, 16); i++) {
      events.push(makeEvent(
        this.users[1], "ACCESS_DENIED", randChoice(_S3_OBJECTS),
        _ATTACKER_IP,
        new Date(base004.getTime() + i * 15_000),
      ));
    }

    // AWS-005 – S3 bucket made public
    events.push(makeEvent(
      this.users[2], "PERMISSION_CHANGE", "s3://amity-research",
      _INTERNAL_IPS[1],
      new Date(now.getTime() - randInt(10, 40) * 60_000),
      "iamuser",
      "public",
    ));

    // AWS-006 – Multiple failed console logins (4–7 attempts)
    const base006 = new Date(now.getTime() - randInt(5, 20) * 60_000);
    for (let i = 0; i < randInt(4, 7); i++) {
      events.push(makeEvent(
        this.users[3], "LOGIN_FAIL", "",
        _ATTACKER_IP,
        new Date(base006.getTime() + i * 60_000),
      ));
    }

    // AWS-007 – Bulk S3 download (21–35 GetObject calls)
    const base007 = new Date(now.getTime() - randInt(5, 30) * 60_000);
    for (let i = 0; i < randInt(21, 35); i++) {
      events.push(makeEvent(
        this.users[4], "DOWNLOAD", randChoice(_S3_OBJECTS.slice(0, 6)),
        randChoice(_INTERNAL_IPS),
        new Date(base007.getTime() + i * 8_000),
      ));
    }

    // AWS-008 – Mass S3 deletion (11–18 DeleteObject calls)
    const base008 = new Date(now.getTime() - randInt(5, 30) * 60_000);
    for (let i = 0; i < randInt(11, 18); i++) {
      events.push(makeEvent(
        this.users[5], "DELETE", randChoice(_S3_OBJECTS),
        _INTERNAL_IPS[2],
        new Date(base008.getTime() + i * 12_000),
      ));
    }

    // AWS-009 – New IAM user created
    events.push(makeEvent(
      this.users[0], "IAM_CREATE_USER", "arn:aws:iam::123456789:user/new-user",
      _ATTACKER_IP,
      new Date(now.getTime() - randFloat(0.5, 4) * 3_600_000),
    ));

    // AWS-010 – Off-hours access (1–5 AM)
    const offDate = new Date(now);
    offDate.setUTCDate(offDate.getUTCDate() - randInt(0, 2));
    offDate.setUTCHours(randInt(1, 5), randInt(0, 59), 0, 0);
    events.push(makeEvent(
      this.users[2], randChoice(["VIEW", "DOWNLOAD"]), randChoice(_S3_OBJECTS),
      randChoice(_INTERNAL_IPS),
      offDate,
    ));

    // Background events
    const remaining = Math.max(0, this.numEvents - events.length);
    for (let i = 0; i < remaining; i++) {
      const ts = new Date(now.getTime() - randFloat(0, 48) * 3_600_000);
      if (ts.getUTCHours() < 6 || ts.getUTCHours() >= 22) {
        ts.setUTCHours(randInt(9, 17));
      }
      events.push(makeEvent(
        randChoice(this.users),
        randChoice(_NORMAL_ACTIONS),
        randChoice(_S3_OBJECTS),
        randChoice(_INTERNAL_IPS),
        ts,
      ));
    }

    events.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    return events;
  }
}
