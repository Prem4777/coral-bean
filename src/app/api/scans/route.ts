import { NextResponse } from "next/server";

import { listRecentScans } from "@/lib/scan-store";

export async function GET() {
  const scans = await listRecentScans();
  return NextResponse.json({ scans });
}
