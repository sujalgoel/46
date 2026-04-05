import { IsolationForest } from "ml-isolation-forest";
import type { LogEvent } from "./rule-engine";

const ACTION_RISK: Record<string, number> = {
  VIEW:              0.0,
  UPLOAD:            0.1,
  DOWNLOAD:          0.2,
  MOVE:              0.2,
  ACCESS_DENIED:     0.5,
  LOGIN_FAIL:        0.5,
  DELETE:            0.7,
  PERMISSION_CHANGE: 0.8,
  IAM_CREATE_USER:   0.9,
  IAM_ESCALATION:    1.0,
  LOGGING_DISABLED:  1.0,
};

function parseTs(ts: string): number {
  return new Date(ts.endsWith("Z") || /[+-]\d{2}:\d{2}$/.test(ts) ? ts : ts + "Z").getTime();
}

function extractFeatures(event: LogEvent, history: LogEvent[]): number[] {
  const tsMs  = parseTs(event.timestamp);
  const hour  = new Date(tsMs).getUTCHours();

  const isOffHours         = hour < 6 || hour >= 22 ? 1 : 0;
  const actionRisk         = ACTION_RISK[event.action] ?? 0.3;
  const isRoot             = event.user_type.toLowerCase() === "root" ? 1 : 0;
  const isAssumedRole      = event.user_type.toLowerCase() === "assumedrole" ? 0.5 : 0;
  const hasPublicPerm      = event.permission_type === "public" ? 1 : 0;

  // Rate of same action in last 30 min (normalised to 0-1 with cap at 20)
  const windowMs    = 30 * 60 * 1_000;
  const recentCount = history.filter(
    h => h.action === event.action && tsMs - parseTs(h.timestamp) < windowMs,
  ).length;
  const recentRate  = Math.min(recentCount / 20, 1);

  return [isOffHours, actionRisk, isRoot, isAssumedRole, hasPublicPerm, recentRate];
}

// 300 synthetic "normal" events — business-hours, low-risk, IAM user, low rate
function generateNormalData(n = 300): number[][] {
  const data: number[][] = [];
  for (let i = 0; i < n; i++) {
    const rnd = Math.random();
    data.push([
      0,                                                    // business hours
      rnd < 0.6 ? 0 : rnd < 0.8 ? 0.1 : 0.2,             // VIEW / UPLOAD / DOWNLOAD
      0,                                                    // not root
      0,                                                    // not assumed role
      0,                                                    // no public permission
      Math.random() * 0.05,                                // very low recent rate
    ]);
  }
  return data;
}

export interface AnomalyResult {
  event:     LogEvent;
  score:     number;    // 0-1 — closer to 1 = more anomalous
  isAnomaly: boolean;
}

export function detectAnomalies(
  events:     LogEvent[],
  historyMap: Map<string, LogEvent[]>,
  threshold = 0.62,
): AnomalyResult[] {
  if (events.length === 0) return [];

  try {
    const clf = new IsolationForest({ nEstimators: 100 });
    clf.fit(generateNormalData());

    const features  = events.map(e => extractFeatures(e, historyMap.get(e.user_email) ?? []));
    const rawScores = clf.scores(features) as number[];

    return events.map((event, i) => ({
      event,
      score:     rawScores[i] ?? 0.5,
      isAnomaly: (rawScores[i] ?? 0) > threshold,
    }));
  } catch {
    // Heuristic fallback if IF fails
    return events.map(event => {
      const score = Math.min((ACTION_RISK[event.action] ?? 0.3) * 0.7 + (event.user_type === "root" ? 0.4 : 0), 1);
      return { event, score, isAnomaly: score > threshold };
    });
  }
}
