import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { AlertTriangle, Brain, Shield, Zap } from "lucide-react";
import type { Alert } from "@/lib/types";
import { SEVERITY_BADGE, SEVERITY_COLOURS } from "@/lib/types";
import { AlertFilters } from "@/components/alert-filters";
import { AcknowledgeButton } from "@/components/acknowledge-button";
import { getAlerts as fetchAlerts } from "@/lib/alert-manager";

const RULES = [
  { id: "AWS-001", name: "Root Account Usage" },
  { id: "AWS-002", name: "CloudTrail Logging Disabled" },
  { id: "AWS-003", name: "IAM Privilege Escalation" },
  { id: "AWS-004", name: "Excessive Access Denied" },
  { id: "AWS-005", name: "S3 Bucket Made Public" },
  { id: "AWS-006", name: "Multiple Failed Console Logins" },
  { id: "AWS-007", name: "Bulk S3 Object Download" },
  { id: "AWS-008", name: "Mass S3 Deletion" },
  { id: "AWS-009", name: "New IAM User / Access Key" },
  { id: "AWS-010", name: "Off-Hours Console Access" },
  { id: "AI-001",  name: "ML Anomaly Detection" },
];

const VERDICT_BADGE: Record<string, string> = {
  THREAT:    "bg-red-100 text-red-700 border-red-200",
  SAFE:      "bg-green-100 text-green-700 border-green-200",
  UNCERTAIN: "bg-yellow-100 text-yellow-700 border-yellow-200",
};

const ACTION_STATUS_BADGE: Record<string, string> = {
  SUCCESS: "bg-green-100 text-green-700 border-green-200",
  FAILED:  "bg-red-100 text-red-700 border-red-200",
  SKIPPED: "bg-slate-100 text-slate-500 border-slate-200",
};

async function getAlerts(severity?: string, rule_id?: string): Promise<Alert[]> {
  return fetchAlerts(500, severity, rule_id) as unknown as Promise<Alert[]>;
}

export default async function AlertsPage({
  searchParams,
}: {
  searchParams: Promise<{ severity?: string; rule_id?: string }>;
}) {
  const { severity, rule_id } = await searchParams;
  const alerts = await getAlerts(severity, rule_id);

  const threats  = alerts.filter(a => a.ai_verdict === "THREAT").length;
  const actions  = alerts.filter(a => a.action_status === "SUCCESS").length;
  const anomalies = alerts.filter(a => a.is_anomaly).length;

  return (
    <div className="flex flex-col gap-6 p-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Alerts</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Three-layer detection: rule engine, Isolation Forest anomaly scoring, and GPT-4.1 verdict. Showing {alerts.length} alerts.
        </p>
      </div>

      {/* AI summary strip */}
      {alerts.length > 0 && (
        <div className="grid grid-cols-3 gap-3">
          <div className="flex items-center gap-2 rounded-lg border bg-red-50 px-4 py-2.5">
            <Brain className="h-4 w-4 text-red-600" />
            <div>
              <p className="text-xs text-muted-foreground">AI Confirmed Threats</p>
              <p className="text-lg font-bold text-red-700">{threats}</p>
            </div>
          </div>
          <div className="flex items-center gap-2 rounded-lg border bg-green-50 px-4 py-2.5">
            <Zap className="h-4 w-4 text-green-600" />
            <div>
              <p className="text-xs text-muted-foreground">AWS Actions Taken</p>
              <p className="text-lg font-bold text-green-700">{actions}</p>
            </div>
          </div>
          <div className="flex items-center gap-2 rounded-lg border bg-purple-50 px-4 py-2.5">
            <Shield className="h-4 w-4 text-purple-600" />
            <div>
              <p className="text-xs text-muted-foreground">ML-Only Anomalies</p>
              <p className="text-lg font-bold text-purple-700">{anomalies}</p>
            </div>
          </div>
        </div>
      )}

      <AlertFilters rules={RULES} selectedSeverity={severity} selectedRule={rule_id} />

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-semibold">Alert Log</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {alerts.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
              <AlertTriangle className="h-8 w-8 mb-2 opacity-30" />
              <p className="text-sm">No alerts match the current filter.</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-36">Timestamp</TableHead>
                  <TableHead className="w-24">Severity</TableHead>
                  <TableHead className="w-44">Rule</TableHead>
                  <TableHead>User</TableHead>
                  <TableHead className="w-28">AI Verdict</TableHead>
                  <TableHead className="w-28">AWS Action</TableHead>
                  <TableHead className="w-24">Status</TableHead>
                  <TableHead className="w-10" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {alerts.map((a) => (
                  <>
                    <TableRow
                      key={a.alert_id}
                      style={{ borderLeft: `3px solid ${SEVERITY_COLOURS[a.severity]}` }}
                    >
                      <TableCell className="font-mono text-xs text-muted-foreground">
                        {a.timestamp?.slice(0, 16)}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className={`text-[10px] px-1.5 ${SEVERITY_BADGE[a.severity]}`}
                        >
                          {a.severity}
                        </Badge>
                        {a.anomaly_score != null && (
                          <p className="text-[10px] text-muted-foreground mt-0.5">
                            anomaly {a.anomaly_score.toFixed(2)}
                          </p>
                        )}
                      </TableCell>
                      <TableCell>
                        <span className="font-mono text-xs bg-muted px-1.5 py-0.5 rounded">
                          {a.rule_id}
                        </span>
                        <p className="text-xs text-muted-foreground mt-0.5">{a.rule_name}</p>
                      </TableCell>
                      <TableCell className="text-sm">{a.user_email}</TableCell>
                      <TableCell>
                        {a.ai_verdict ? (
                          <div className="flex flex-col gap-0.5">
                            <Badge
                              variant="outline"
                              className={`text-[10px] px-1.5 w-fit ${VERDICT_BADGE[a.ai_verdict] ?? ""}`}
                            >
                              {a.ai_verdict}
                            </Badge>
                            {a.ai_confidence != null && (
                              <p className="text-[10px] text-muted-foreground">
                                {Math.round(a.ai_confidence * 100)}% conf.
                              </p>
                            )}
                          </div>
                        ) : (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </TableCell>
                      <TableCell>
                        {a.action_status && a.action_status !== "SKIPPED" ? (
                          <Badge
                            variant="outline"
                            className={`text-[10px] px-1.5 ${ACTION_STATUS_BADGE[a.action_status] ?? ""}`}
                          >
                            {a.action_status === "SUCCESS" ? "✓ " : "✗ "}
                            {a.ai_action?.replace(/_/g, " ")}
                          </Badge>
                        ) : (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </TableCell>
                      <TableCell>
                        {a.acknowledged ? (
                          <Badge variant="outline" className="text-[10px] bg-green-50 text-green-700 border-green-200">
                            Acknowledged
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="text-[10px] bg-yellow-50 text-yellow-700 border-yellow-200">
                            Pending
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell>
                        {!a.acknowledged && <AcknowledgeButton alertId={a.alert_id} />}
                      </TableCell>
                    </TableRow>
                    {/* AI reasoning row */}
                    {a.ai_reasoning && (
                      <TableRow key={`${a.alert_id}-reasoning`} className="bg-muted/30 border-0">
                        <TableCell colSpan={8} className="py-1.5 pl-8 pr-4">
                          <p className="text-xs text-muted-foreground italic whitespace-normal break-words max-w-2xl">
                            <span className="font-medium not-italic text-foreground">AI: </span>
                            {a.ai_reasoning}
                            {a.action_taken && a.action_taken !== "none" && (
                              <span className="ml-2 not-italic font-medium text-green-700">
                                → {a.action_taken}
                              </span>
                            )}
                          </p>
                        </TableCell>
                      </TableRow>
                    )}
                  </>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
