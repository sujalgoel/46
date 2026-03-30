"use client";

import { useState, useEffect, useRef } from "react";
import { Button } from "@/components/ui/button";
import { Play, Trash2, Loader2 } from "lucide-react";
import { useRouter } from "next/navigation";

const STAGES = [
  "Generating events...",
  "Running rule engine...",
  "Writing to MongoDB...",
  "Refreshing dashboard...",
];

export function SimulateButton() {
  const [loading, setLoading]   = useState<"simulate" | "clear" | null>(null);
  const [progress, setProgress] = useState(0);
  const [stage, setStage]       = useState(0);
  const intervalRef             = useRef<ReturnType<typeof setInterval> | null>(null);
  const router                  = useRouter();

  // Advance progress bar gradually while simulating
  useEffect(() => {
    if (loading === "simulate") {
      setProgress(0);
      setStage(0);
      let current = 0;
      intervalRef.current = setInterval(() => {
        current += Math.random() * 4 + 1;
        if (current >= 90) {
          current = 90;
          clearInterval(intervalRef.current!);
        }
        setProgress(current);
        // Advance stage text based on progress
        if (current < 25)  setStage(0);
        else if (current < 55) setStage(1);
        else if (current < 80) setStage(2);
        else               setStage(3);
      }, 200);
    } else {
      if (intervalRef.current) clearInterval(intervalRef.current);
    }
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [loading]);

  async function runSimulate() {
    setLoading("simulate");
    await fetch("/api/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ source: "simulated" }),
    });
    // Snap to 100 then clean up
    setProgress(100);
    setStage(3);
    await new Promise((r) => setTimeout(r, 500));
    router.refresh();
    setLoading(null);
    setProgress(0);
  }

  async function runClear() {
    setLoading("clear");
    await fetch("/api/clear", { method: "POST" });
    router.refresh();
    setLoading(null);
  }

  return (
    <div className="flex flex-col gap-2">
      <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide px-1">
        Simulation
      </p>

      <Button
        size="sm"
        className="w-full justify-start gap-2"
        onClick={runSimulate}
        disabled={loading !== null}
      >
        {loading === "simulate" ? (
          <Loader2 className="h-4 w-4 animate-spin" />
        ) : (
          <Play className="h-4 w-4" />
        )}
        Run Simulation
      </Button>

      {/* Progress bar — only visible while simulating */}
      {loading === "simulate" && (
        <div className="flex flex-col gap-1 px-1">
          <div className="w-full h-1.5 rounded-full bg-muted overflow-hidden">
            <div
              className="h-full rounded-full bg-primary transition-all duration-200 ease-out"
              style={{ width: `${progress}%` }}
            />
          </div>
          <div className="flex items-center justify-between">
            <p className="text-[10px] text-muted-foreground">{STAGES[stage]}</p>
            <p className="text-[10px] text-muted-foreground tabular-nums">
              {Math.min(Math.round(progress), 100)}%
            </p>
          </div>
        </div>
      )}

      <Button
        size="sm"
        variant="outline"
        className="w-full justify-start gap-2"
        onClick={runClear}
        disabled={loading !== null}
      >
        {loading === "clear" ? (
          <Loader2 className="h-4 w-4 animate-spin" />
        ) : (
          <Trash2 className="h-4 w-4" />
        )}
        Clear All Data
      </Button>
    </div>
  );
}
