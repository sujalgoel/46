// frontend/lib/alert-manager.ts
import { prisma } from "./prisma";
import type { LogEvent, TriggeredAlert } from "./rule-engine";
import type { EnrichedAlert } from "./ai-verdict";

export async function storeLog(event: LogEvent): Promise<void> {
  try {
    await prisma.log.create({
      data: {
        event_id:        event.event_id ?? crypto.randomUUID(),
        user_email:      event.user_email,
        timestamp:       event.timestamp,
        action:          event.action,
        file_name:       event.file_name ?? "",
        ip_address:      event.ip_address ?? "",
        user_type:       event.user_type ?? "iamuser",
        permission_type: event.permission_type ?? "",
      },
    });
  } catch (e: any) {
    if (e?.code !== "P2002") throw e; // P2002 = unique constraint — skip duplicate
  }
}

export async function getLogs(limit = 100, action?: string) {
  return prisma.log.findMany({
    where:   action ? { action } : undefined,
    orderBy: { timestamp: "desc" },
    take:    limit,
  });
}

export async function getUserHistory(userEmail: string, lastN = 200): Promise<LogEvent[]> {
  const rows = await prisma.log.findMany({
    where:   { user_email: userEmail },
    orderBy: { timestamp: "desc" },
    take:    lastN,
  });
  return rows.map(r => ({
    event_id:        r.event_id,
    user_email:      r.user_email,
    timestamp:       r.timestamp,
    action:          r.action,
    file_name:       r.file_name,
    ip_address:      r.ip_address,
    user_type:       r.user_type,
    permission_type: r.permission_type,
  }));
}

export async function storeAlert(alert: TriggeredAlert): Promise<void> {
  try {
    await prisma.alert.create({
      data: {
        alert_id:   crypto.randomUUID(),
        timestamp:  alert.timestamp,
        rule_id:    alert.rule_id,
        rule_name:  alert.rule_name,
        severity:   alert.severity,
        user_email: alert.user_email,
        details:    alert.details,
        event:      alert.event as object,
      },
    });
  } catch (e: any) {
    if (e?.code !== "P2002") throw e;
  }
}

// Bulk insert all logs in one MongoDB command (ordered:false skips duplicates)
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
    ordered: false, // skip duplicates, keep going
  });
}

// Bulk insert all alerts in one MongoDB command
export async function storeAlerts(alerts: TriggeredAlert[]): Promise<void> {
  if (alerts.length === 0) return;
  await (prisma as any).$runCommandRaw({
    insert:    "alerts",
    documents: alerts.map(a => ({
      alert_id:     crypto.randomUUID(),
      timestamp:    a.timestamp,
      rule_id:      a.rule_id,
      rule_name:    a.rule_name,
      severity:     a.severity,
      user_email:   a.user_email,
      details:      a.details,
      event:        a.event,
      acknowledged: false,
    })),
    ordered: false,
  });
}

// Bulk insert enriched alerts (with AI verdict + action fields)
export async function storeEnrichedAlerts(alerts: EnrichedAlert[]): Promise<void> {
  if (alerts.length === 0) return;
  await (prisma as any).$runCommandRaw({
    insert:    "alerts",
    documents: alerts.map(a => ({
      alert_id:      crypto.randomUUID(),
      timestamp:     a.timestamp,
      rule_id:       a.rule_id,
      rule_name:     a.rule_name,
      severity:      a.severity,
      user_email:    a.user_email,
      details:       a.details,
      event:         a.event,
      acknowledged:  false,
      anomaly_score: a.anomaly_score ?? null,
      ai_verdict:    a.ai_verdict    ?? null,
      ai_confidence: a.ai_confidence ?? null,
      ai_reasoning:  a.ai_reasoning  ?? null,
      ai_action:     a.ai_action     ?? null,
      action_taken:  a.action_taken  ?? null,
      action_status: a.action_status ?? null,
      is_anomaly:    a.is_anomaly    ?? false,
    })),
    ordered: false,
  });
}

export async function getAlerts(limit = 500, severity?: string, ruleId?: string) {
  return prisma.alert.findMany({
    where: {
      ...(severity ? { severity: severity.toUpperCase() } : {}),
      ...(ruleId   ? { rule_id: ruleId }                  : {}),
    },
    orderBy: { timestamp: "desc" },
    take:    limit,
  });
}

export async function acknowledgeAlert(alertId: string): Promise<void> {
  await prisma.alert.update({
    where: { alert_id: alertId },
    data:  { acknowledged: true },
  });
}

export async function getStats() {
  const [totalEvents, totalAlerts, unacked, activeUsersRows] = await Promise.all([
    prisma.log.count(),
    prisma.alert.count(),
    prisma.alert.count({ where: { acknowledged: false } }),
    prisma.log.findMany({ select: { user_email: true }, distinct: ["user_email"] }),
  ]);

  // Aggregations — Prisma MongoDB doesn't support these natively, use raw commands
  const severityAgg = await (prisma as any).$runCommandRaw({
    aggregate: "alerts",
    pipeline:  [{ $group: { _id: "$severity", cnt: { $sum: 1 } } }],
    cursor:    {},
  }) as { cursor: { firstBatch: Array<{ _id: string; cnt: number }> } };

  const bySeverity: Record<string, number> = {};
  for (const doc of severityAgg.cursor.firstBatch) {
    bySeverity[doc._id] = doc.cnt;
  }

  const ruleAgg = await (prisma as any).$runCommandRaw({
    aggregate: "alerts",
    pipeline: [
      { $group: { _id: { rule_id: "$rule_id", rule_name: "$rule_name" }, cnt: { $sum: 1 } } },
      { $sort: { cnt: -1 } },
    ],
    cursor: {},
  }) as { cursor: { firstBatch: Array<{ _id: { rule_id: string; rule_name: string }; cnt: number }> } };

  const byRule = ruleAgg.cursor.firstBatch.map(doc => ({
    rule_id:   doc._id.rule_id,
    rule_name: doc._id.rule_name,
    count:     doc.cnt,
  }));

  const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1_000).toISOString().slice(0, 19);
  const hourlyAgg = await (prisma as any).$runCommandRaw({
    aggregate: "logs",
    pipeline: [
      { $match: { timestamp: { $gte: cutoff } } },
      { $group: { _id: { $substr: ["$timestamp", 11, 2] }, cnt: { $sum: 1 } } },
      { $sort: { _id: 1 } },
    ],
    cursor: {},
  }) as { cursor: { firstBatch: Array<{ _id: string; cnt: number }> } };

  const hourly: Record<string, number> = {};
  for (const doc of hourlyAgg.cursor.firstBatch) {
    hourly[doc._id] = doc.cnt;
  }

  return {
    total_events:   totalEvents,
    total_alerts:   totalAlerts,
    unacknowledged: unacked,
    active_users:   activeUsersRows.length,
    by_severity:    bySeverity,
    by_rule:        byRule,
    hourly,
  };
}

export async function clearAll(): Promise<void> {
  await Promise.all([prisma.log.deleteMany(), prisma.alert.deleteMany()]);
}
