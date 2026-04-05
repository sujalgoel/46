import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Activity, AlertTriangle, Bell, Users } from "lucide-react";
import type { Stats, Alert } from "@/lib/types";
import { SEVERITY_BADGE, SEVERITY_COLOURS } from "@/lib/types";
import { SeverityChart } from "@/components/severity-chart";
import { RuleChart } from "@/components/rule-chart";
import { getStats as fetchStats, getAlerts as fetchAlerts } from "@/lib/alert-manager";

export default async function DashboardPage() {
  const [stats, alerts] = await Promise.all([fetchStats(), fetchAlerts()]);
  const recent = alerts.slice(0, 8);

  const statCards = [
    { title: "Total Events",   value: stats.total_events,    icon: Activity,      colour: "text-blue-400",   bg: "bg-blue-500/10"   },
    { title: "Total Alerts",   value: stats.total_alerts,    icon: AlertTriangle, colour: "text-red-400",    bg: "bg-red-500/10"    },
    { title: "Unacknowledged", value: stats.unacknowledged,  icon: Bell,          colour: "text-orange-400", bg: "bg-orange-500/10" },
    { title: "Active Users",   value: stats.active_users,    icon: Users,         colour: "text-green-400",  bg: "bg-green-500/10"  },
  ];

  return (
    <div className="flex flex-col gap-6 p-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Dashboard</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Real-time AWS CloudTrail intrusion detection · Amity University
        </p>
        <p className="text-xs text-muted-foreground/60 mt-0.5">
          Group 46 · Riya Karagwal &amp; Rhea T. Chakraborty · Guide: Prof. (Dr.) S. K. Dubey
        </p>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
        {statCards.map(({ title, value, icon: Icon, colour, bg }) => (
          <Card key={title}>
            <CardContent className="p-5 flex items-center gap-4">
              <div className={`rounded-xl p-3 ${bg}`}>
                <Icon className={`h-5 w-5 ${colour}`} />
              </div>
              <div>
                <p className="text-3xl font-bold leading-none">{value}</p>
                <p className="text-xs text-muted-foreground mt-1">{title}</p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold">Alerts by Severity</CardTitle>
          </CardHeader>
          <CardContent>
            <SeverityChart data={stats.by_severity} colours={SEVERITY_COLOURS} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold">Alerts by Rule</CardTitle>
          </CardHeader>
          <CardContent>
            <RuleChart data={stats.by_rule} />
          </CardContent>
        </Card>
      </div>

      {/* Recent alerts table */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between pb-3">
          <CardTitle className="text-sm font-semibold">Recent Alerts</CardTitle>
          <a href="/alerts" className="text-xs text-primary underline underline-offset-2">
            View all
          </a>
        </CardHeader>
        <CardContent className="p-0">
          {recent.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <AlertTriangle className="h-8 w-8 mb-2 opacity-30" />
              <p className="text-sm">No alerts yet. Run a simulation from the sidebar.</p>
            </div>
          ) : (
            <div className="divide-y">
              {recent.map((a) => (
                <div
                  key={a.alert_id}
                  className="flex items-start gap-3 px-6 py-3 text-sm"
                  style={{ borderLeft: `3px solid ${SEVERITY_COLOURS[a.severity]}` }}
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${SEVERITY_BADGE[a.severity]}`}>
                        {a.severity}
                      </Badge>
                      <span className="font-mono text-xs text-muted-foreground bg-muted px-1.5 py-0.5 rounded">
                        {a.rule_id}
                      </span>
                      <span className="text-muted-foreground truncate">{a.user_email}</span>
                    </div>
                    <p className="text-muted-foreground text-xs mt-1 line-clamp-1">{a.details}</p>
                  </div>
                  <span className="text-[11px] text-muted-foreground whitespace-nowrap shrink-0">
                    {a.timestamp?.slice(0, 16)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
