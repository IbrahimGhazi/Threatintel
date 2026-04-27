"use client";

import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from "recharts";
import { format, parseISO } from "date-fns";

interface DataPoint {
  date: string;
  count: number;
}

interface Props {
  data: DataPoint[];
}

function CustomTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="card px-3 py-2 text-xs">
      <p className="text-text-muted">{label}</p>
      <p className="text-accent font-mono font-semibold">{payload[0]?.value?.toLocaleString()} indicators</p>
    </div>
  );
}

export function IngestionTimeline({ data }: Props) {
  const formatted = data.map((d) => ({
    ...d,
    label: format(parseISO(d.date), "MMM d"),
  }));

  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={formatted} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
        <defs>
          <linearGradient id="teal-gradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#00c4cc" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#00c4cc" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="#1e2d42" vertical={false} />
        <XAxis
          dataKey="label"
          tick={{ fill: "#506070", fontSize: 10, fontFamily: "Inter" }}
          axisLine={false}
          tickLine={false}
        />
        <YAxis
          tick={{ fill: "#506070", fontSize: 10, fontFamily: "Inter" }}
          axisLine={false}
          tickLine={false}
          tickFormatter={(v) => v >= 1000 ? `${(v / 1000).toFixed(0)}k` : v}
        />
        <Tooltip content={<CustomTooltip />} cursor={{ stroke: "#1e2d42" }} />
        <Area
          type="monotone"
          dataKey="count"
          stroke="#00c4cc"
          strokeWidth={1.5}
          fill="url(#teal-gradient)"
          dot={false}
          activeDot={{ r: 3, fill: "#00c4cc", stroke: "#0f1623", strokeWidth: 2 }}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}
