// frontend/app/api/alerts/[id]/acknowledge/route.ts
import { NextRequest, NextResponse } from "next/server";
import { acknowledgeAlert } from "@/lib/alert-manager";

export async function POST(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    await acknowledgeAlert(id);
    return NextResponse.json({ status: "ok" });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
