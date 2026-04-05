export interface Stats {
  total_events: number;
  total_alerts: number;
  unacknowledged: number;
  active_users: number;
  by_severity: Record<string, number>;
  by_rule: { rule_id: string; rule_name: string; count: number }[];
  hourly: Record<string, number>;
}

export interface Alert {
  id: string;
  alert_id: string;
  timestamp: string;
  rule_id: string;
  rule_name: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  user_email: string;
  details: string;
  event: unknown;
  acknowledged: boolean;
  // AI layer fields
  anomaly_score:  number  | null;
  ai_verdict:     string  | null;  // "THREAT" | "SAFE" | "UNCERTAIN"
  ai_confidence:  number  | null;
  ai_reasoning:   string  | null;
  ai_action:      string  | null;
  action_taken:   string  | null;
  action_status:  string  | null;  // "SUCCESS" | "FAILED" | "SKIPPED"
  is_anomaly:     boolean | null;
}

export interface LogEntry {
  id: string;
  event_id: string;
  timestamp: string;
  user_email: string;
  action: string;
  file_name: string;
  ip_address: string;
  user_type: string;
  permission_type: string;
  // legacy display fields — undefined when from Prisma
  file_size_mb?: number;
  source?: string;
}

export const SEVERITY_COLOURS: Record<string, string> = {
  CRITICAL: "#dc2626",
  HIGH: "#ea580c",
  MEDIUM: "#ca8a04",
  LOW: "#0891b2",
};

export const SEVERITY_BADGE: Record<string, string> = {
  CRITICAL: "bg-red-100 text-red-700 border-red-200",
  HIGH: "bg-orange-100 text-orange-700 border-orange-200",
  MEDIUM: "bg-yellow-100 text-yellow-700 border-yellow-200",
  LOW: "bg-cyan-100 text-cyan-700 border-cyan-200",
};

export const ACTION_BADGE: Record<string, string> = {
  VIEW:             "bg-slate-100 text-slate-600",
  DOWNLOAD:         "bg-blue-100 text-blue-700",
  UPLOAD:           "bg-green-100 text-green-700",
  DELETE:           "bg-red-100 text-red-700",
  MOVE:             "bg-indigo-100 text-indigo-700",
  LOGIN_FAIL:       "bg-red-100 text-red-700",
  ACCESS_DENIED:    "bg-red-100 text-red-700",
  PERMISSION_CHANGE:"bg-orange-100 text-orange-700",
  LOGGING_DISABLED: "bg-red-100 text-red-800",
  IAM_ESCALATION:   "bg-purple-100 text-purple-700",
  IAM_CREATE_USER:  "bg-yellow-100 text-yellow-700",
};
