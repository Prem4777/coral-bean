"use client";

import { useEffect, useRef, useState } from "react";

type Props = {
  repoName: string;
};

type ScanLog = (typeof LOG_STEPS)[number];

const LOG_STEPS = [
  { type: "INF", msg: "Repository manifest detected. Parsing dependencies..." },
  { type: "INF", msg: "Fetching OSV vulnerability database..." },
  {
    type: "KEV",
    msg: "Cross-referencing CISA KEV catalog (Active Exploits)...",
  },
  { type: "INF", msg: "Analyzing dependency graph for transitive risks..." },
  { type: "WRN", msg: "Checking for known exploit patterns in packages..." },
  {
    type: "KEV",
    msg: "Correlating CVEs with active exploitation intelligence...",
  },
  { type: "INF", msg: "Generating AI security summary via Gemini..." },
  { type: "INF", msg: "Finalizing threat report..." },
];

const TITLES = [
  "Initialising KEV Audit",
  "Cloning repository...",
  "Mapping dependencies...",
  "Fetching OSV vulnerabilities...",
  "Cross-referencing CISA KEV...",
  "Analyzing attack surface...",
  "Finalizing threat report...",
];

function logColor(type: string) {
  if (type === "KEV") return "text-[#45dfa4]";
  if (type === "WRN") return "text-[#ffb2b7]";
  return "text-[#c6c6cd]";
}

export function ScanningState({ repoName }: Props) {
  const [progress, setProgress] = useState(0);
  const [titleIdx, setTitleIdx] = useState(0);
  const [logs, setLogs] = useState<ScanLog[]>([]);
  const logRef = useRef<HTMLDivElement>(null);
  const timeoutRefs = useRef<number[]>([]);

  useEffect(() => {
    // Progress ticker
    const progressInterval = setInterval(() => {
      setProgress((p) => {
        const next = p + Math.floor(Math.random() * 5) + 1;
        return next >= 100 ? 99 : next; // hold at 99 until done
      });
    }, 900);

    // Title rotation
    const titleInterval = setInterval(() => {
      setTitleIdx((i) => (i + 1 < TITLES.length ? i + 1 : i));
    }, 3500);

    // Log drip
    let logIdx = 0;
    function addLog() {
      if (logIdx < LOG_STEPS.length) {
        const nextLog = LOG_STEPS[logIdx];
        if (nextLog) {
          setLogs((prev) => [...prev, nextLog]);
        }
        logIdx++;
        const timeoutId = window.setTimeout(
          addLog,
          1200 + Math.random() * 1400,
        );
        timeoutRefs.current.push(timeoutId);
      }
    }
    const logTimeout = window.setTimeout(addLog, 600);
    timeoutRefs.current.push(logTimeout);

    return () => {
      clearInterval(progressInterval);
      clearInterval(titleInterval);
      timeoutRefs.current.forEach((timeoutId) => clearTimeout(timeoutId));
      timeoutRefs.current = [];
    };
  }, []);

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [logs]);

  const now = new Date();
  const timeStr = `${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}:${String(now.getSeconds()).padStart(2, "0")}`;

  return (
    <div className="flex flex-1 flex-col items-center justify-center px-8 py-12">
      <div className="w-full max-w-2xl">
        {/* Progress header */}
        <div className="mb-10 w-full">
          <div className="mb-2 flex items-end justify-between">
            <div>
              <h2 className="font-sans text-[24px] font-semibold leading-tight tracking-tight text-[#d4e4fa]">
                {TITLES[titleIdx]}
              </h2>
              <p className="mt-1 font-mono text-[13px] text-[#c6c6cd]">
                {repoName}
              </p>
            </div>
            <span className="font-mono text-[13px] text-[#45dfa4]">
              {progress}%
            </span>
          </div>
          <div className="h-1.5 w-full overflow-hidden rounded-full border border-[#46464c]/30 bg-[#273647]">
            <div
              className="h-full rounded-full bg-[#45dfa4] transition-all duration-700"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>

        {/* Console */}
        <div className="w-full rounded border border-[#46464c] bg-[#010f1f] p-5 shadow-sm">
          <div className="mb-4 flex items-center justify-between border-b border-[#46464c]/50 pb-2">
            <div className="flex items-center gap-2">
              <span className="h-1.5 w-1.5 rounded-full bg-[#45dfa4]" />
              <span className="font-mono text-[11px] font-medium uppercase tracking-wider text-[#d4e4fa]">
                PROCESS_LOG
              </span>
            </div>
            <span className="font-mono text-[10px] text-[#46464c]">
              STABLE_v1.0.4
            </span>
          </div>

          <div
            ref={logRef}
            className="h-64 space-y-1.5 overflow-y-auto font-mono text-[11px] leading-relaxed"
          >
            <div className="flex gap-3 text-[#45dfa4]/70">
              <span className="shrink-0 opacity-50">{timeStr}</span>
              <span>INF: System initializing...</span>
            </div>
            {logs.filter(Boolean).map((log, i) => (
              <div
                key={i}
                className={`flex gap-3 ${logColor(log.type)}`}
                style={{ animation: "fadeIn 0.15s ease-out forwards" }}
              >
                <span className="shrink-0 opacity-40">{timeStr}</span>
                <span className="flex-1">
                  {log.type}: {log.msg}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Insight hint */}
        <div className="mt-8 flex w-full items-center gap-4 rounded border border-[#46464c]/40 bg-[#0d1c2d] p-4">
          <svg
            className="h-5 w-5 shrink-0 text-[#45dfa4]"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={1.5}
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z"
            />
          </svg>
          <p className="text-[14px] text-[#c6c6cd]">
            <span className="font-semibold text-[#45dfa4]">Insight:</span>{" "}
            Cross-referencing dependency graph with{" "}
            <span className="rounded bg-[#273647] px-1 font-mono text-[12px] text-[#d4e4fa]">
              CISA-KEV
            </span>{" "}
            catalog.
          </p>
        </div>
      </div>
    </div>
  );
}
