// frontend/lib/adapters/aws-cloudtrail.ts
import {
  CloudTrailClient,
  LookupEventsCommand,
  type LookupEventsCommandInput,
  type Event as CTEvent,
} from "@aws-sdk/client-cloudtrail";
import type { LogEvent } from "../rule-engine";

const EVENT_MAP: Record<string, string> = {
  GetObject:                      "DOWNLOAD",
  PutObject:                      "UPLOAD",
  CopyObject:                     "MOVE",
  DeleteObject:                   "DELETE",
  DeleteObjects:                  "DELETE",
  CreateBucket:                   "UPLOAD",
  DeleteBucket:                   "DELETE",
  PutBucketAcl:                   "PERMISSION_CHANGE",
  PutBucketPolicy:                "PERMISSION_CHANGE",
  PutObjectAcl:                   "PERMISSION_CHANGE",
  DeleteBucketPublicAccessBlock:  "PERMISSION_CHANGE",
  PutPublicAccessBlock:           "PERMISSION_CHANGE",
  ConsoleLogin:                   "VIEW",
  StopLogging:                    "LOGGING_DISABLED",
  DeleteTrail:                    "LOGGING_DISABLED",
  UpdateTrail:                    "VIEW",
  CreateUser:                     "IAM_CREATE_USER",
  CreateAccessKey:                "IAM_CREATE_USER",
  AttachUserPolicy:               "IAM_ESCALATION",
  AttachRolePolicy:               "IAM_ESCALATION",
  PutUserPolicy:                  "IAM_ESCALATION",
  PutRolePolicy:                  "IAM_ESCALATION",
};

const PUBLIC_ACL_URIS = new Set([
  "http://acs.amazonaws.com/groups/global/AllUsers",
  "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
]);

interface AdapterOptions {
  region?: string;
  accessKeyId?: string;
  secretAccessKey?: string;
  maxEvents?: number;
  hoursBack?: number;
}

export class AWSCloudTrailAdapter {
  private client: CloudTrailClient;
  private maxEvents: number;
  private hoursBack: number;

  constructor(opts: AdapterOptions = {}) {
    this.maxEvents = opts.maxEvents ?? 500;
    this.hoursBack = opts.hoursBack ?? 24;
    this.client = new CloudTrailClient({
      region: opts.region ?? process.env.AWS_REGION ?? "us-east-1",
      ...(opts.accessKeyId && opts.secretAccessKey
        ? { credentials: { accessKeyId: opts.accessKeyId, secretAccessKey: opts.secretAccessKey } }
        : {}),
    });
  }

  async fetchLogs(): Promise<LogEvent[]> {
    const start     = new Date(Date.now() - this.hoursBack * 3_600_000);
    const events: LogEvent[] = [];
    let nextToken: string | undefined;

    do {
      const input: LookupEventsCommandInput = {
        StartTime: start,
        MaxResults: 50,
        NextToken: nextToken,
      };
      const resp = await this.client.send(new LookupEventsCommand(input));
      for (const raw of resp.Events ?? []) {
        const parsed = this.parseEvent(raw);
        if (parsed) events.push(parsed);
        if (events.length >= this.maxEvents) break;
      }
      nextToken = resp.NextToken;
    } while (nextToken && events.length < this.maxEvents);

    return events.slice(0, this.maxEvents);
  }

  private parseEvent(raw: CTEvent): LogEvent | null {
    try {
      const eventName    = raw.EventName ?? "";
      const detailStr    = raw.CloudTrailEvent ?? "{}";
      const d            = JSON.parse(detailStr);
      const errorCode    = d.errorCode ?? "";
      const userIdentity = d.userIdentity ?? {};
      const userType     = (userIdentity.type ?? "").toLowerCase();
      const reqParams    = d.requestParameters ?? {};
      const respElements = d.responseElements ?? {};

      let action = EVENT_MAP[eventName] ?? "VIEW";

      if (["AccessDenied", "AccessDeniedException", "Client.UnauthorizedOperation"].includes(errorCode)) {
        action = "ACCESS_DENIED";
      } else if (eventName === "ConsoleLogin") {
        action = respElements.ConsoleLogin === "Failure" ? "LOGIN_FAIL" : "VIEW";
      } else if (action === "IAM_ESCALATION") {
        const policyArn = reqParams.policyArn ?? "";
        if (!policyArn.includes("AdministratorAccess") && !policyArn.includes("PowerUser")) {
          action = "VIEW";
        }
      }

      let permissionType = "";
      if (action === "PERMISSION_CHANGE") {
        permissionType = resolvePermissionType(eventName, reqParams);
      }

      const tsRaw = raw.EventTime ?? new Date();
      const ts    = tsRaw instanceof Date ? tsRaw : new Date(tsRaw);
      const tsStr = ts.toISOString().slice(0, 19);

      let username = raw.Username ?? "";
      if (!username) username = userIdentity.userName ?? userIdentity.arn ?? "unknown";
      if (!username || username === "HIDDEN_DUE_TO_SECURITY_REASONS") username = "unknown@aws";
      if (!username.includes("@")) username = `${username}@aws`;

      let fileName = "";
      for (const res of raw.Resources ?? []) {
        if (res.ResourceType === "AWS::S3::Object" || res.ResourceType === "AWS::S3::Bucket") {
          fileName = res.ResourceName ?? "";
          break;
        }
      }
      if (!fileName) {
        const bucket = reqParams.bucketName ?? "";
        const key    = reqParams.key ?? "";
        if (bucket) fileName = `s3://${bucket}/${key}`.replace(/\/$/, "");
      }

      return {
        event_id:        crypto.randomUUID(),
        timestamp:       tsStr,
        user_email:      username,
        user_type:       userType,
        action,
        file_name:       fileName,
        ip_address:      d.sourceIPAddress ?? "",
        permission_type: permissionType,
      };
    } catch {
      return null;
    }
  }
}

function resolvePermissionType(eventName: string, reqParams: Record<string, unknown>): string {
  if (eventName === "DeleteBucketPublicAccessBlock") return "public";

  if (eventName === "PutBucketAcl" || eventName === "PutObjectAcl") {
    const acp = reqParams?.AccessControlPolicy as { AccessControlList?: { Grant?: unknown } } | undefined;
    const grants: unknown[] = (acp?.AccessControlList?.Grant as unknown[]) ?? [];
    const list = Array.isArray(grants) ? grants : [grants];
    if (list.some(g => PUBLIC_ACL_URIS.has((g as { Grantee?: { URI?: string } })?.Grantee?.URI ?? ""))) return "public";
  }

  if (eventName === "PutBucketPolicy") {
    const policy = (reqParams?.bucketPolicy as string) ?? "";
    if (policy.includes('"Principal":"*"') || policy.includes('"Principal": "*"')) return "public";
  }

  return "internal";
}
