import { NextRequest, NextResponse } from "next/server";

import type { FindingsMap } from "@/components/kevguard/types";
import { generateRepoAgentReply } from "@/lib/repo-agent";

type ChatRequest = {
  repo: string;
  question: string;
  findings: FindingsMap;
};

export async function POST(req: NextRequest) {
  try {
    const body = (await req.json()) as ChatRequest;
    if (!body.question || !body.repo) {
      return NextResponse.json(
        { error: "Invalid chat request" },
        { status: 400 },
      );
    }

    const answer = await generateRepoAgentReply({
      repo: body.repo,
      question: body.question,
      findings: body.findings ?? {},
    });

    return NextResponse.json({ answer });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Chat failed";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
