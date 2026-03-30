// frontend/app/api/logs/route.ts
import { NextRequest, NextResponse } from "next/server";
import { getLogs } from "@/lib/alert-manager";

export async function GET(req: NextRequest) {
  try {
    const action = req.nextUrl.searchParams.get("action") ?? undefined;
    return NextResponse.json(await getLogs(200, action));
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
