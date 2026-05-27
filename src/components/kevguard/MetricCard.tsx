import type { ReactNode } from "react";

type MetricCardProps = {
  label: string;
  value: string | number;
  tone?: "default" | "danger" | "warning" | "success";
  subtext?: string;
  icon?: ReactNode;
};

const toneStyles: Record<
  NonNullable<MetricCardProps["tone"]>,
  { border: string; label: string; value: string }
> = {
  default: {
    border: "border-[#46464c]",
    label: "text-[#c6c6cd]",
    value: "text-[#d4e4fa]",
  },
  danger: {
    border: "border-[#e13052]/40",
    label: "text-[#e13052]",
    value: "text-[#e13052]",
  },
  warning: {
    border: "border-amber-700/40",
    label: "text-amber-400",
    value: "text-amber-300",
  },
  success: {
    border: "border-[#45dfa4]/30",
    label: "text-[#45dfa4]",
    value: "text-[#45dfa4]",
  },
};

export function MetricCard({
  label,
  value,
  tone = "default",
  subtext,
  icon,
}: MetricCardProps) {
  const styles = toneStyles[tone];

  return (
    <div
      className={`bento-card relative flex h-44 flex-col justify-between overflow-hidden rounded-2xl p-6 ${styles.border}`}
    >
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-white/10 to-transparent" />
      <div className="flex items-start justify-between">
        <span
          className={`font-mono text-[11px] uppercase tracking-[0.12em] ${styles.label}`}
        >
          {label}
        </span>
        {icon && <span className={`opacity-60 ${styles.label}`}>{icon}</span>}
      </div>

      <div className="flex items-baseline gap-2">
        <span
          className={`text-4xl font-semibold leading-none tracking-tight sm:text-[42px] ${styles.value}`}
        >
          {value}
        </span>
      </div>

      {subtext && (
        <span className="font-mono text-[11px] text-[#c6c6cd] opacity-60">
          {subtext}
        </span>
      )}
    </div>
  );
}
