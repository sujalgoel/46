"use client";

import { PieChart, Pie, Cell, Legend, ResponsiveContainer, Tooltip } from "recharts";

interface Props {
  data: Record<string, number>;
  colours: Record<string, string>;
}

const ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export function SeverityChart({ data, colours }: Props) {
  const chartData = ORDER.filter((s) => (data[s] ?? 0) > 0).map((s) => ({
    name: s,
    value: data[s],
  }));

  if (chartData.length === 0) {
    return (
      <div className="flex h-48 items-center justify-center text-sm text-muted-foreground">
        No alert data yet
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={220}>
      <PieChart style={{ outline: "none" }}>
        <Pie
          data={chartData}
          cx="50%"
          cy="50%"
          innerRadius={55}
          outerRadius={80}
          paddingAngle={3}
          dataKey="value"
        >
          {chartData.map((entry) => (
            <Cell key={entry.name} fill={colours[entry.name]} />
          ))}
        </Pie>
        <Tooltip formatter={(v) => [v, "alerts"]} />
        <Legend iconType="circle" iconSize={8} />
      </PieChart>
    </ResponsiveContainer>
  );
}
