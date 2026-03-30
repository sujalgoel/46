// frontend/app/api/stats/route.ts
import { NextResponse } from "next/server";
import { getStats } from "@/lib/alert-manager";

export async function GET() {
  try {
    return NextResponse.json(await getStats());
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
