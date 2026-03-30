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
import { Inbox } from "lucide-react";
import type { LogEntry } from "@/lib/types";
import { ACTION_BADGE } from "@/lib/types";
import { LogFilters } from "@/components/log-filters";
import { getLogs as fetchLogs } from "@/lib/alert-manager";

const ACTIONS = [
  "VIEW", "DOWNLOAD", "UPLOAD", "DELETE", "MOVE",
  "LOGIN_FAIL", "ACCESS_DENIED", "PERMISSION_CHANGE",
  "LOGGING_DISABLED", "IAM_ESCALATION", "IAM_CREATE_USER",
];

async function getLogs(action?: string): Promise<LogEntry[]> {
  return fetchLogs(200, action) as unknown as Promise<LogEntry[]>;
}

export default async function LogsPage({
  searchParams,
}: {
  searchParams: Promise<{ action?: string }>;
}) {
  const { action } = await searchParams;
  const logs = await getLogs(action);

  return (
    <div className="flex flex-col gap-6 p-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Audit Logs</h1>
        <p className="text-sm text-muted-foreground mt-1">
          AWS CloudTrail events · {logs.length} records
        </p>
      </div>

      <LogFilters actions={ACTIONS} selectedAction={action} />

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-semibold">Event Log</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {logs.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
              <Inbox className="h-8 w-8 mb-2 opacity-30" />
              <p className="text-sm">No logs yet. Run a simulation from the sidebar.</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-36">Timestamp</TableHead>
                  <TableHead>User</TableHead>
                  <TableHead className="w-36">Action</TableHead>
                  <TableHead>File</TableHead>
                  <TableHead className="w-24">Size (MB)</TableHead>
                  <TableHead className="w-32">IP Address</TableHead>
                  <TableHead className="w-24">Source</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {logs.map((log) => (
                  <TableRow key={log.event_id}>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {log.timestamp?.slice(0, 16)}
                    </TableCell>
                    <TableCell className="text-sm">{log.user_email}</TableCell>
                    <TableCell>
                      <Badge
                        variant="secondary"
                        className={`text-[10px] px-1.5 ${ACTION_BADGE[log.action] ?? ""}`}
                      >
                        {log.action}
                      </Badge>
                    </TableCell>
                    <TableCell
                      className="text-xs text-muted-foreground max-w-[200px] truncate"
                      title={log.file_name}
                    >
                      {log.file_name || "—"}
                    </TableCell>
                    <TableCell className="text-sm">
                      {log.file_size_mb ? log.file_size_mb.toFixed(1) : "—"}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{log.ip_address || "—"}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-[10px]">
                        {log.source}
                      </Badge>
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
