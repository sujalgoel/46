// frontend/app/api/run/route.ts
import { NextRequest, NextResponse } from "next/server";
import { ruleEngine } from "@/lib/rule-engine";
import { storeLogs, storeAlerts, getUserHistory } from "@/lib/alert-manager";
import type { TriggeredAlert } from "@/lib/rule-engine";
import { SimulatedAdapter } from "@/lib/adapters/simulated";
import { AWSCloudTrailAdapter } from "@/lib/adapters/aws-cloudtrail";
import type { LogEvent } from "@/lib/rule-engine";

export const maxDuration = 60;

export async function POST(req: NextRequest) {
  try {
    const body   = await req.json().catch(() => ({}));
    const source = (body.source ?? "simulated") as string;

    let events: LogEvent[];
    if (source === "aws") {
      const adapter = new AWSCloudTrailAdapter({
        region:          body.region          ?? process.env.AWS_REGION,
        accessKeyId:     body.aws_access_key  ?? process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: body.aws_secret_key  ?? process.env.AWS_SECRET_ACCESS_KEY,
      });
      events = await adapter.fetchLogs();
    } else {
      events = new SimulatedAdapter().fetchLogs();
    }

    // Pre-fetch history for all unique users to avoid N×DB round-trips
    const uniqueUsers = [...new Set(events.map(e => e.user_email))];
    const historyMap  = new Map<string, LogEvent[]>();
    await Promise.all(
      uniqueUsers.map(async user => {
        historyMap.set(user, await getUserHistory(user));
      })
    );

    // Run rule engine entirely in memory — no DB writes in the loop
    const allAlerts: TriggeredAlert[] = [];
    for (const event of events) {
      const history = historyMap.get(event.user_email) ?? [];
      const triggered = ruleEngine.evaluate(event, history);
      allAlerts.push(...triggered);
      history.unshift(event); // keep local cache current for subsequent events
    }

    // Batch-write everything: 2 DB calls instead of ~400
    await Promise.all([storeLogs(events), storeAlerts(allAlerts)]);

    return NextResponse.json({
      status: "ok",
      events_processed: events.length,
      alerts_triggered: allAlerts.length,
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ status: "error", message }, { status: 500 });
  }
}
