"use client";

import { useEffect, useMemo, useRef, useState } from "react";

import type { FormEvent } from "react";

import type { FindingsMap } from "./types";

type Message = { role: "user" | "assistant"; text: string };

type Props = {
  findings: FindingsMap;
  repo: string;
};

export function ChatPanel({ findings, repo }: Props) {
  const starter = useMemo<Message[]>(
    () => [
      {
        role: "assistant",
        text: "Analysis complete. Ask me what to fix first, which dependency is most dangerous, or for a short repo risk summary.",
      },
    ],
    [],
  );

  const [messages, setMessages] = useState<Message[]>(starter);
  const [prompt, setPrompt] = useState("");
  const scrollRef = useRef<HTMLDivElement>(null);

  async function sendQuestion(question: string) {
    const trimmed = question.trim();
    if (!trimmed) return;

    setMessages((prev) => [...prev, { role: "user", text: trimmed }]);
    setPrompt("");

    setMessages((prev) => [
      ...prev,
      {
        role: "assistant",
        text: "Thinking through the repo findings...",
      },
    ]);

    try {
      const response = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo, question: trimmed, findings }),
      });

      const data = (await response.json()) as {
        answer?: string;
        error?: string;
      };
      const answer = response.ok
        ? data.answer || "No answer available."
        : data.error || "Chat request failed.";

      setMessages((prev) => {
        const withoutTyping = prev.filter(
          (message) => message.text !== "Thinking through the repo findings...",
        );
        return [...withoutTyping, { role: "assistant", text: answer }];
      });
    } catch {
      setMessages((prev) => {
        const withoutTyping = prev.filter(
          (message) => message.text !== "Thinking through the repo findings...",
        );
        return [
          ...withoutTyping,
          {
            role: "assistant",
            text: "Chat failed. Try again in a moment.",
          },
        ];
      });
    }
  }

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages]);

  function onSend(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    void sendQuestion(prompt);
  }

  const quickActions = [
    { label: "Prioritize Fixes", q: "What should I fix first?" },
    { label: "Risk Profile", q: "Summarize repo risk" },
    { label: "Most Dangerous", q: "Which dependency is most dangerous?" },
  ];

  return (
    <div className="bento-card flex h-105 flex-col overflow-hidden rounded-2xl">
      {/* Header */}
      <div className="flex items-center gap-2 border-b border-[#46464c] bg-[#112130] px-4 py-3">
        <svg
          className="h-4 w-4 text-[#45dfa4]"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={1.5}
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M8.625 12a.375.375 0 11-.75 0 .375.375 0 01.75 0zm0 0H8.25m4.125 0a.375.375 0 11-.75 0 .375.375 0 01.75 0zm0 0H12m4.125 0a.375.375 0 11-.75 0 .375.375 0 01.75 0zm0 0h-.375M21 12c0 4.556-4.03 8.25-9 8.25a9.764 9.764 0 01-2.555-.337A5.972 5.972 0 015.41 20.97a5.969 5.969 0 01-.474-.065 4.48 4.48 0 00.978-2.025c.09-.457-.133-.901-.467-1.226C3.93 16.178 3 14.189 3 12c0-4.556 4.03-8.25 9-8.25s9 3.694 9 8.25z"
          />
        </svg>
        <h4 className="text-[14px] font-semibold text-[#d4e4fa]">
          Chat with Repo
        </h4>
      </div>

      {/* Messages */}
      <div ref={scrollRef} className="flex-1 space-y-3 overflow-y-auto p-4">
        {messages.map((m, idx) => (
          <div
            key={idx}
            className={`flex gap-2 ${m.role === "user" ? "justify-end" : "justify-start"}`}
          >
            <div
              className={`max-w-[85%] rounded border p-3 text-[14px] leading-relaxed ${
                m.role === "user"
                  ? "border-[#46464c] bg-[#273647] text-[#d4e4fa]"
                  : "border-[#46464c] bg-[#051424] text-[#d4e4fa]"
              }`}
            >
              {m.text}
            </div>
          </div>
        ))}
      </div>

      {/* Quick actions + input */}
      <div className="flex flex-col gap-3 border-t border-[#46464c] bg-[#0d1c2d] p-4">
        <div className="flex flex-wrap gap-2">
          {quickActions.map((a) => (
            <button
              key={a.label}
              onClick={() => void sendQuestion(a.q)}
              className="rounded-full border border-[#46464c] px-3 py-1 font-mono text-[10px] uppercase tracking-[0.16em] text-[#c6c6cd] transition-colors hover:border-[#c0c6de] hover:text-[#c0c6de]"
            >
              {a.label}
            </button>
          ))}
        </div>
        <form onSubmit={onSend} className="relative flex">
          <input
            value={prompt}
            onChange={(e) => setPrompt(e.target.value)}
            placeholder="Enter query..."
            className="w-full rounded-xl border border-[#46464c] bg-[#051424] py-2.5 pl-3 pr-10 font-mono text-[13px] text-[#d4e4fa] outline-none placeholder:text-[#46464c] focus:border-[#c0c6de]"
          />
          <button
            type="submit"
            className="absolute right-2 top-1/2 -translate-y-1/2 text-[#c6c6cd] transition-colors hover:text-[#c0c6de]"
          >
            <svg
              className="h-4 w-4"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={2}
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M6 12L3.269 3.126A59.768 59.768 0 0121.485 12 59.77 59.77 0 013.27 20.876L5.999 12zm0 0h7.5"
              />
            </svg>
          </button>
        </form>
      </div>
    </div>
  );
}
