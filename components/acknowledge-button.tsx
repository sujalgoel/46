"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Check, Loader2 } from "lucide-react";
import { useRouter } from "next/navigation";

export function AcknowledgeButton({ alertId }: { alertId: string }) {
  const [loading, setLoading] = useState(false);
  const router = useRouter();

  async function handleAck() {
    setLoading(true);
    await fetch(`/api/alerts/${alertId}/acknowledge`, { method: "POST" });
    router.refresh();
    setLoading(false);
  }

  return (
    <Button variant="ghost" size="icon" className="h-7 w-7" onClick={handleAck} disabled={loading}>
      {loading ? (
        <Loader2 className="h-3.5 w-3.5 animate-spin" />
      ) : (
        <Check className="h-3.5 w-3.5 text-green-600" />
      )}
    </Button>
  );
}
