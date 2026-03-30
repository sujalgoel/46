// frontend/app/api/clear/route.ts
import { NextResponse } from "next/server";
import { clearAll } from "@/lib/alert-manager";

export async function POST() {
  try {
    await clearAll();
    return NextResponse.json({ status: "cleared" });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
