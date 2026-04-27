"use client";

import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#f04060",
  high:     "#f07030",
  medium:   "#f0a830",
  low:      "#50a0f0",
  info:     "#60809a",
};

interface Props {
  data: Record<string, number>;
}

function CustomTooltip({ active, payload }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="card px-3 py-2 text-xs">
      <p className="capitalize text-text-secondary">{payload[0]?.name}</p>
      <p className="text-text-primary font-mono font-semibold">{payload[0]?.value?.toLocaleString()}</p>
    </div>
  );
}

export function SeverityDonut({ data }: Props) {
  const entries = Object.entries(data).map(([name, value]) => ({ name, value }));
  const total = entries.reduce((s, e) => s + e.value, 0);

  return (
    <div className="relative h-full">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={entries}
            cx="50%"
            cy="50%"
            innerRadius="58%"
            outerRadius="80%"
            paddingAngle={2}
            dataKey="value"
          >
            {entries.map((entry) => (
              <Cell
                key={entry.name}
                fill={SEVERITY_COLORS[entry.name] ?? "#60809a"}
                stroke="transparent"
              />
            ))}
          </Pie>
          <Tooltip content={<CustomTooltip />} />
        </PieChart>
      </ResponsiveContainer>
      {/* Center label */}
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
        <span className="text-2xl font-bold font-mono text-text-primary">
          {total >= 1000 ? `${(total / 1000).toFixed(1)}k` : total}
        </span>
        <span className="text-2xs text-text-muted uppercase tracking-wider">total</span>
      </div>
    </div>
  );
}
