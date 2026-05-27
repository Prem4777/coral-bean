import type { DashboardMetrics } from "./types";

type Props = {
  breakdown: DashboardMetrics["riskBreakdown"];
};

const rows = [
  { key: "critical" as const, label: "Critical", color: "bg-[#e13052]" },
  { key: "high" as const, label: "High", color: "bg-orange-500" },
  { key: "medium" as const, label: "Medium", color: "bg-amber-500" },
  { key: "low" as const, label: "Low", color: "bg-yellow-400" },
  { key: "unknown" as const, label: "Unknown", color: "bg-white/20" },
];

export function RiskBreakdown({ breakdown }: Props) {
  const total = Object.values(breakdown).reduce((a, b) => a + b, 0);

  return (
    <div className="space-y-3">
      {rows.map(({ key, label, color }) => {
        const count = breakdown[key];
        const pct = total > 0 ? (count / total) * 100 : 0;
        return (
          <div key={key} className="flex items-center gap-4">
            <span className="w-16 font-mono text-[12px] text-white/40">{label}</span>
            <div className="flex-1 h-1 rounded-full bg-white/[0.06] overflow-hidden">
              <div
                className={`h-full rounded-full ${color} transition-all duration-500`}
                style={{ width: `${pct}%` }}
              />
            </div>
            <span className="w-6 text-right font-mono text-[12px] text-white/50">{count}</span>
          </div>
        );
      })}
    </div>
  );
}
