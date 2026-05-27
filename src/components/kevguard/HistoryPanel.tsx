import Link from "next/link";

import type { RecentScan } from "./types";

type Props = {
  scans: RecentScan[];
};

export function HistoryPanel({ scans }: Props) {
  const maxFindings = Math.max(1, ...scans.map((s) => s.findingsCount));

  return (
    <div className="bento-card rounded-lg p-6">
      <div className="mb-4 flex items-center justify-between">
        <h3 className="font-mono text-[11px] uppercase tracking-wider text-[#c6c6cd]">
          Scan History
        </h3>
        <span className="font-mono text-[11px] text-[#c6c6cd] opacity-60">
          Risk trend
        </span>
      </div>

      {scans.length === 0 ? (
        <div className="rounded border border-[#46464c] bg-[#051424] p-4 text-[14px] text-[#c6c6cd]">
          No previous scans yet. Analyze a repository to build history.
        </div>
      ) : (
        <>
          {/* Trend bars */}
          <div className="mb-4 flex h-14 items-end gap-1.5 rounded border border-[#46464c] bg-[#051424] p-3">
            {scans.slice(0, 14).map((s) => (
              <div
                key={s.id}
                className="flex-1 rounded-sm bg-[#45dfa4]/50 transition-all"
                style={{
                  height: `${Math.max(10, Math.round((s.findingsCount / maxFindings) * 100))}%`,
                }}
                title={`${s.owner}/${s.repo}: ${s.findingsCount} findings`}
              />
            ))}
          </div>

          {/* Scan list */}
          <div className="space-y-2">
            {scans.map((scan) => (
              <Link
                key={scan.id}
                href={`/scan/${scan.id}`}
                className="block rounded border border-[#46464c] bg-[#051424] p-3 text-[14px] transition-colors hover:border-[#909097]"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-semibold text-[#d4e4fa]">
                    {scan.owner}/{scan.repo}
                  </span>
                  <span className="font-mono text-[11px] text-[#c6c6cd] opacity-60">
                    {new Date(scan.createdAt).toLocaleString()}
                  </span>
                </div>
                <div className="mt-1 flex items-center gap-3 font-mono text-[11px] text-[#c6c6cd]">
                  <span>Findings: {scan.findingsCount}</span>
                  <span className="opacity-40">·</span>
                  <span className={scan.kevCount > 0 ? "text-[#e13052]" : ""}>
                    KEV: {scan.kevCount}
                  </span>
                  <span className="opacity-40">·</span>
                  <span
                    className={
                      scan.status === "completed"
                        ? "text-[#45dfa4]"
                        : "text-amber-400"
                    }
                  >
                    {scan.status}
                  </span>
                </div>
              </Link>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
