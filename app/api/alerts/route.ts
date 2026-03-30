// frontend/app/api/alerts/route.ts
import { NextRequest, NextResponse } from "next/server";
import { getAlerts } from "@/lib/alert-manager";

export async function GET(req: NextRequest) {
  try {
    const { searchParams } = req.nextUrl;
    const severity = searchParams.get("severity") ?? undefined;
    const ruleId   = searchParams.get("rule_id")  ?? undefined;
    return NextResponse.json(await getAlerts(500, severity, ruleId));
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
