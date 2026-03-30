// frontend/lib/rule-engine.ts
import { RULES, ORG_DOMAIN, OFF_HOURS_START, OFF_HOURS_END, type Rule, type RuleSeverity } from "./config";

export interface LogEvent {
  event_id: string;
  timestamp: string;
  user_email: string;
  user_type: string;
  action: string;
  file_name: string;
  ip_address: string;
  permission_type: string;
}

export interface TriggeredAlert {
  rule_id: string;
  rule_name: string;
  severity: RuleSeverity;
  user_email: string;
  timestamp: string;
  details: string;
  event: LogEvent;
}

export class RuleEngine {
  constructor(private rules: Rule[], private orgDomain: string) {}

  evaluate(event: LogEvent, history: LogEvent[]): TriggeredAlert[] {
    const alerts: TriggeredAlert[] = [];
    for (const rule of this.rules) {
      const [fired, details] = this.checkRule(rule, event, history);
      if (fired) {
        alerts.push(this.buildAlert(rule, event, details));
      }
    }
    return alerts;
  }

  private checkRule(rule: Rule, event: LogEvent, history: LogEvent[]): [boolean, string] {
    switch (rule.type) {
      case "frequency":    return this.checkFrequency(rule, event, history);
      case "single_event": return this.checkSingleEvent(rule, event);
      case "actor_type":   return this.checkActorType(rule, event);
      case "permission":   return this.checkPermission(rule, event);
      case "time":         return this.checkTime(event);
      default:
        throw new Error(`Unhandled rule type: ${(rule as any).type}`);
    }
  }

  private checkFrequency(rule: Rule, event: LogEvent, history: LogEvent[]): [boolean, string] {
    if (event.action !== rule.action) return [false, ""];
    const windowMs = (rule.window_minutes ?? 60) * 60 * 1_000;
    const eventMs  = this.parseTimestamp(event.timestamp).getTime();
    const cutoffMs = eventMs - windowMs;
    const count    = history.filter(
      h => h.action === rule.action && this.parseTimestamp(h.timestamp).getTime() >= cutoffMs
    ).length + 1; // +1 for current event
    const windowMin = rule.window_minutes ?? 60;
    if (count >= (rule.threshold ?? 10)) {
      return [true, `${count} ${rule.action} events in ${windowMin} min`];
    }
    return [false, ""];
  }

  private checkSingleEvent(rule: Rule, event: LogEvent): [boolean, string] {
    if (event.action === rule.action) {
      return [true, `${rule.action} detected`];
    }
    return [false, ""];
  }

  private checkActorType(rule: Rule, event: LogEvent): [boolean, string] {
    if (event.user_type.toLowerCase() === (rule.actor_type ?? "").toLowerCase()) {
      return [true, `${rule.actor_type} account activity detected`];
    }
    return [false, ""];
  }

  private checkPermission(rule: Rule, event: LogEvent): [boolean, string] {
    if (event.action !== (rule.action ?? "PERMISSION_CHANGE")) return [false, ""];
    const perm = (event.permission_type ?? "").toLowerCase();
    if (["public", "anyone", "anyone_with_link"].includes(perm)) {
      return [true, `Permission change: ${event.permission_type}`];
    }
    return [false, ""];
  }

  private parseTimestamp(ts: string): Date {
    // If the timestamp has no timezone indicator, treat it as UTC
    if (!ts.endsWith("Z") && !/[+-]\d{2}:\d{2}$/.test(ts)) {
      return new Date(ts + "Z");
    }
    return new Date(ts);
  }

  private checkTime(event: LogEvent): [boolean, string] {
    const hour = this.parseTimestamp(event.timestamp).getUTCHours();
    const fired = OFF_HOURS_START < OFF_HOURS_END
      ? hour >= OFF_HOURS_START && hour < OFF_HOURS_END
      : hour >= OFF_HOURS_START || hour < OFF_HOURS_END; // wraps midnight
    if (fired) {
      return [true, `Activity at ${String(hour).padStart(2, "0")}:00 UTC (off-hours)`];
    }
    return [false, ""];
  }

  private buildAlert(rule: Rule, event: LogEvent, details: string): TriggeredAlert {
    return {
      rule_id:    rule.id,
      rule_name:  rule.name,
      severity:   rule.severity,
      user_email: event.user_email,
      timestamp:  event.timestamp,
      details: details || `[${rule.id}] ${rule.description} | User: ${event.user_email} | Action: ${event.action} | File: ${event.file_name || "N/A"}`,
      event,
    };
  }
}

export const ruleEngine = new RuleEngine(RULES, ORG_DOMAIN);
