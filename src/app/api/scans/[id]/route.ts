import { NextResponse } from "next/server";

import { getScanById } from "@/lib/scan-store";

export async function GET(
  _request: Request,
  context: { params: Promise<{ id: string }> },
) {
  const { id } = await context.params;
  const scan = await getScanById(id);

  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  return NextResponse.json(scan);
}
