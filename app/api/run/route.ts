import { NextRequest, NextResponse } from "next/server";
import { ruleEngine } from "@/lib/rule-engine";
import { storeLogs, storeEnrichedAlerts, getUserHistory } from "@/lib/alert-manager";
import type { TriggeredAlert, LogEvent } from "@/lib/rule-engine";
import { SimulatedAdapter } from "@/lib/adapters/simulated";
import { AWSCloudTrailAdapter } from "@/lib/adapters/aws-cloudtrail";
import { detectAnomalies } from "@/lib/anomaly-detector";
import { getAIVerdict, type EnrichedAlert } from "@/lib/ai-verdict";
import { executeAction } from "@/lib/aws-response";

export const maxDuration = 60;

// Run AI verdicts with limited concurrency to avoid rate limits
async function withConcurrency<T>(
  tasks: (() => Promise<T>)[],
  limit = 5,
): Promise<T[]> {
  const results: T[] = [];
  for (let i = 0; i < tasks.length; i += limit) {
    const batch = await Promise.all(tasks.slice(i, i + limit).map(t => t()));
    results.push(...batch);
  }
  return results;
}

export async function POST(req: NextRequest) {
  try {
    const body   = await req.json().catch(() => ({}));
    const source = (body.source ?? "simulated") as string;

    // ── 1. Fetch events ──────────────────────────────────────────────────────
    let events: LogEvent[];
    if (source === "aws") {
      const adapter = new AWSCloudTrailAdapter({
        region:          body.region         ?? process.env.AWS_REGION,
        accessKeyId:     body.aws_access_key ?? process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: body.aws_secret_key ?? process.env.AWS_SECRET_ACCESS_KEY,
      });
      events = await adapter.fetchLogs();
    } else {
      events = new SimulatedAdapter().fetchLogs();
    }

    // ── 2. Pre-fetch user history ────────────────────────────────────────────
    const uniqueUsers = [...new Set(events.map(e => e.user_email))];
    const historyMap  = new Map<string, LogEvent[]>();
    await Promise.all(
      uniqueUsers.map(async user => {
        historyMap.set(user, await getUserHistory(user));
      }),
    );

    // ── 3. Rule engine (pure in-memory) ─────────────────────────────────────
    const ruleAlertMap = new Map<string, TriggeredAlert[]>(); // event_id → alerts
    const allRuleAlerts: TriggeredAlert[] = [];

    for (const event of events) {
      const history  = historyMap.get(event.user_email) ?? [];
      const triggered = ruleEngine.evaluate(event, history);
      if (triggered.length > 0) {
        ruleAlertMap.set(event.event_id, triggered);
        allRuleAlerts.push(...triggered);
      }
      history.unshift(event);
    }

    // ── 4. Isolation Forest anomaly detection ────────────────────────────────
    const anomalyResults = detectAnomalies(events, historyMap);
    const anomalyMap     = new Map(anomalyResults.map(r => [r.event.event_id, r]));

    // ── 5. Collect suspects: rule fired OR high anomaly score ────────────────
    const suspects = events.filter(e =>
      ruleAlertMap.has(e.event_id) || (anomalyMap.get(e.event_id)?.isAnomaly ?? false),
    );

    // ── 6. AI verdict for each suspect (max 5 concurrent) ───────────────────
    const enrichedAlerts: EnrichedAlert[] = [];

    const verdictTasks = suspects.map(event => async () => {
      const ruleAlerts  = ruleAlertMap.get(event.event_id) ?? [];
      const anomaly     = anomalyMap.get(event.event_id)!;
      const isPureAnomaly = ruleAlerts.length === 0;

      let verdict;
      try {
        verdict = await getAIVerdict(event, ruleAlerts, anomaly.score);
      } catch {
        // If AI call fails, fall back to rule engine result or skip pure anomaly
        if (isPureAnomaly) return;
        verdict = {
          isThreat:          true,
          confidence:        0.7,
          severity:          ruleAlerts[0].severity as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE",
          reasoning:         "AI verdict unavailable — rule engine match used as fallback.",
          recommendedAction: "notify_admin" as const,
        };
      }

      // ── 7. Execute AWS action if high-confidence threat ──────────────────
      let actionTaken  = "none";
      let actionStatus = "SKIPPED";

      if (verdict.isThreat && verdict.confidence >= 0.75 && verdict.recommendedAction !== "no_action") {
        const result = await executeAction(verdict.recommendedAction, event);
        actionTaken  = result.detail;
        actionStatus = result.status;
      }

      // Build base alert (from rule or synthetic for pure anomaly)
      const baseAlert: TriggeredAlert = ruleAlerts[0] ?? {
        rule_id:    "AI-001",
        rule_name:  "ML Anomaly Detection",
        severity:   verdict.severity === "NONE" ? "LOW" : verdict.severity,
        user_email: event.user_email,
        timestamp:  event.timestamp,
        details:    `Anomaly score ${anomaly.score.toFixed(3)} — ${verdict.reasoning}`,
        event,
      };

      // For rule-based events, override severity if AI says it's higher
      const finalSeverity = verdict.isThreat
        ? (verdict.severity === "NONE" ? baseAlert.severity : verdict.severity)
        : "LOW";

      enrichedAlerts.push({
        ...baseAlert,
        severity:      finalSeverity,
        anomaly_score: anomaly.score,
        ai_verdict:    verdict.isThreat ? "THREAT" : "SAFE",
        ai_confidence: verdict.confidence,
        ai_reasoning:  verdict.reasoning,
        ai_action:     verdict.recommendedAction,
        action_taken:  actionTaken,
        action_status: actionStatus,
        is_anomaly:    isPureAnomaly,
      });

      // Add any additional rule alerts from same event (without re-running AI)
      for (const extra of ruleAlerts.slice(1)) {
        enrichedAlerts.push({
          ...extra,
          anomaly_score: anomaly.score,
          ai_verdict:    verdict.isThreat ? "THREAT" : "SAFE",
          ai_confidence: verdict.confidence,
          ai_reasoning:  verdict.reasoning,
          ai_action:     verdict.recommendedAction,
          action_taken:  actionTaken,
          action_status: actionStatus,
          is_anomaly:    false,
        });
      }
    });

    await withConcurrency(verdictTasks, 5);

    // ── 8. Batch-write logs + enriched alerts ────────────────────────────────
    await Promise.all([storeLogs(events), storeEnrichedAlerts(enrichedAlerts)]);

    const threats = enrichedAlerts.filter(a => a.ai_verdict === "THREAT").length;
    const actions = enrichedAlerts.filter(a => a.action_status === "SUCCESS").length;

    return NextResponse.json({
      status:           "ok",
      events_processed: events.length,
      alerts_triggered: enrichedAlerts.length,
      ai_threats:       threats,
      actions_taken:    actions,
      anomalies_found:  anomalyResults.filter(r => r.isAnomaly).length,
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ status: "error", message }, { status: 500 });
  }
}
