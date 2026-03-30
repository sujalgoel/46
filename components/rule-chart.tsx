"use client";

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";

interface Props {
  data: { rule_id: string; rule_name: string; count: number }[];
}

const COLOUR = "#6366f1";

export function RuleChart({ data }: Props) {
  if (data.length === 0) {
    return (
      <div className="flex h-48 items-center justify-center text-sm text-muted-foreground">
        No alert data yet
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={220} style={{ outline: "none" }}>
      <BarChart data={data} layout="vertical" margin={{ left: 0, right: 16 }}>
        <XAxis type="number" tick={{ fontSize: 11 }} />
        <YAxis
          type="category"
          dataKey="rule_id"
          tick={{ fontSize: 11 }}
          width={72}
        />
        <Tooltip
          formatter={(v, _name, p) => [
            v,
            (p as { payload: { rule_name: string } }).payload.rule_name,
          ]}
        />
        <Bar dataKey="count" radius={[0, 4, 4, 0]}>
          {data.map((entry) => (
            <Cell key={entry.rule_id} fill={COLOUR} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
