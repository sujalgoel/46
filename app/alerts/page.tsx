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
import { AlertTriangle } from "lucide-react";
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
];

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

  return (
    <div className="flex flex-col gap-6 p-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Alerts</h1>
        <p className="text-sm text-muted-foreground mt-1">
          All triggered rule violations — {alerts.length} shown
        </p>
      </div>

      <AlertFilters rules={RULES} selectedSeverity={severity} selectedRule={rule_id} />

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-semibold">
            Alert Log
          </CardTitle>
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
                  <TableHead>Details</TableHead>
                  <TableHead className="w-28">Status</TableHead>
                  <TableHead className="w-10" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {alerts.map((a) => (
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
                    </TableCell>
                    <TableCell>
                      <span className="font-mono text-xs bg-muted px-1.5 py-0.5 rounded">
                        {a.rule_id}
                      </span>
                      <p className="text-xs text-muted-foreground mt-0.5">{a.rule_name}</p>
                    </TableCell>
                    <TableCell className="text-sm">{a.user_email}</TableCell>
                    <TableCell className="text-xs text-muted-foreground max-w-xs truncate">
                      {a.details}
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
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
