import {
  IAMClient,
  ListAccessKeysCommand,
  UpdateAccessKeyCommand,
  DetachUserPolicyCommand,
  CreatePolicyCommand,
  AttachUserPolicyCommand,
} from "@aws-sdk/client-iam";
import { CloudTrailClient, StartLoggingCommand } from "@aws-sdk/client-cloudtrail";
import { S3ControlClient, PutPublicAccessBlockCommand } from "@aws-sdk/client-s3-control";
import type { LogEvent } from "./rule-engine";

const awsCfg = () => ({
  region: process.env.AWS_REGION ?? "us-east-1",
  ...(process.env.AWS_ACCESS_KEY_ID
    ? {
        credentials: {
          accessKeyId:     process.env.AWS_ACCESS_KEY_ID!,
          secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!,
        },
      }
    : {}),
});

function iamUsername(userEmail: string): string {
  return userEmail.split("@")[0];
}

function extractBucket(fileName: string): string | null {
  const m = fileName.match(/^s3:\/\/([^/]+)/);
  return m ? m[1] : null;
}

export interface ActionResult {
  action: string;
  status: "SUCCESS" | "FAILED" | "SKIPPED";
  detail: string;
}

export async function disableAccessKeys(event: LogEvent): Promise<ActionResult> {
  const username = iamUsername(event.user_email);
  const client   = new IAMClient(awsCfg());
  try {
    const { AccessKeyMetadata = [] } = await client.send(
      new ListAccessKeysCommand({ UserName: username }),
    );
    await Promise.all(
      AccessKeyMetadata.map(k =>
        client.send(
          new UpdateAccessKeyCommand({
            UserName:    username,
            AccessKeyId: k.AccessKeyId!,
            Status:      "Inactive",
          }),
        ),
      ),
    );
    return {
      action: "disable_access_keys",
      status: "SUCCESS",
      detail: `Disabled ${AccessKeyMetadata.length} key(s) for IAM user "${username}"`,
    };
  } catch (e: any) {
    return { action: "disable_access_keys", status: "FAILED", detail: e.message };
  }
}

export async function detachAdminPolicy(event: LogEvent): Promise<ActionResult> {
  const username  = iamUsername(event.user_email);
  const policyArn = "arn:aws:iam::aws:policy/AdministratorAccess";
  const client    = new IAMClient(awsCfg());
  try {
    await client.send(new DetachUserPolicyCommand({ UserName: username, PolicyArn: policyArn }));
    return {
      action: "detach_admin_policy",
      status: "SUCCESS",
      detail: `Detached AdministratorAccess policy from IAM user "${username}"`,
    };
  } catch (e: any) {
    return { action: "detach_admin_policy", status: "FAILED", detail: e.message };
  }
}

export async function enableCloudTrail(event: LogEvent): Promise<ActionResult> {
  const trailArn = event.file_name.startsWith("arn:")
    ? event.file_name
    : (process.env.CLOUDTRAIL_ARN ?? "");
  if (!trailArn) {
    return { action: "enable_cloudtrail", status: "SKIPPED", detail: "No trail ARN found — set CLOUDTRAIL_ARN env var" };
  }
  const client = new CloudTrailClient(awsCfg());
  try {
    await client.send(new StartLoggingCommand({ Name: trailArn }));
    return { action: "enable_cloudtrail", status: "SUCCESS", detail: `Re-enabled CloudTrail logging on "${trailArn}"` };
  } catch (e: any) {
    return { action: "enable_cloudtrail", status: "FAILED", detail: e.message };
  }
}

export async function blockS3PublicAccess(event: LogEvent): Promise<ActionResult> {
  const bucket    = extractBucket(event.file_name);
  const accountId = process.env.AWS_ACCOUNT_ID;
  if (!bucket)    return { action: "block_s3_public_access", status: "SKIPPED", detail: "Could not parse bucket from event" };
  if (!accountId) return { action: "block_s3_public_access", status: "SKIPPED", detail: "AWS_ACCOUNT_ID env var not set" };

  const client = new S3ControlClient(awsCfg());
  try {
    await client.send(
      new PutPublicAccessBlockCommand({
        AccountId: accountId,
        PublicAccessBlockConfiguration: {
          BlockPublicAcls:       true,
          BlockPublicPolicy:     true,
          IgnorePublicAcls:      true,
          RestrictPublicBuckets: true,
        },
      }),
    );
    return { action: "block_s3_public_access", status: "SUCCESS", detail: `Blocked all public access on bucket "${bucket}"` };
  } catch (e: any) {
    return { action: "block_s3_public_access", status: "FAILED", detail: e.message };
  }
}

export async function quarantineUser(event: LogEvent): Promise<ActionResult> {
  const username = iamUsername(event.user_email);
  const client   = new IAMClient(awsCfg());
  try {
    const { Policy } = await client.send(
      new CreatePolicyCommand({
        PolicyName:     `IDS-Quarantine-${username}-${Date.now()}`,
        PolicyDocument: JSON.stringify({
          Version:   "2012-10-17",
          Statement: [{ Effect: "Deny", Action: "*", Resource: "*" }],
        }),
        Description: `Auto-quarantine by IDS — user ${username}`,
      }),
    );
    await client.send(
      new AttachUserPolicyCommand({ UserName: username, PolicyArn: Policy!.Arn! }),
    );
    return { action: "quarantine_user", status: "SUCCESS", detail: `Applied Deny-All quarantine policy to IAM user "${username}"` };
  } catch (e: any) {
    return { action: "quarantine_user", status: "FAILED", detail: e.message };
  }
}

const ACTION_MAP: Record<string, (event: LogEvent) => Promise<ActionResult>> = {
  disable_access_keys:    disableAccessKeys,
  detach_admin_policy:    detachAdminPolicy,
  enable_cloudtrail:      enableCloudTrail,
  block_s3_public_access: blockS3PublicAccess,
  quarantine_user:        quarantineUser,
};

export async function executeAction(
  recommendedAction: string,
  event: LogEvent,
): Promise<ActionResult> {
  const handler = ACTION_MAP[recommendedAction];
  if (!handler) {
    return { action: recommendedAction, status: "SKIPPED", detail: "No handler registered for this action" };
  }
  return handler(event);
}
