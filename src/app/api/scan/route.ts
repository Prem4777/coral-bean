import { NextRequest, NextResponse } from "next/server";
import { runScanChain } from "@/lib/langchain";

type ScanRequest = { repoUrl: string };

function parseRepo(url: string) {
  try {
    const u = new URL(url);
    const parts = u.pathname.split("/").filter(Boolean);
    if (parts.length < 2) return null;
    return { owner: parts[0], repo: parts[1] };
  } catch {
    return null;
  }
}

export async function POST(req: NextRequest) {
  const body: ScanRequest = await req.json();
  const encoder = new TextEncoder();

  const stream = new TransformStream();
  const writer = stream.writable.getWriter();

  const writeEvent = async (event: string, data: unknown) => {
    await writer.write(
      encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`),
    );
  };

  void (async () => {
    try {
      const result = await runScanChain(body.repoUrl, (evt) => {
        void writeEvent("progress", evt);
      });

      await writeEvent("result", result);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Scan failed";
      await writeEvent("error", { message });
    } finally {
      await writer.close();
    }
  })();

  try {
    return new NextResponse(stream.readable, {
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache, no-transform",
        Connection: "keep-alive",
      },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Scan failed";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
