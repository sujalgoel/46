"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { ChevronDown, X } from "lucide-react";

const ACTION_DOT: Record<string, string> = {
  VIEW:              "bg-slate-400",
  DOWNLOAD:          "bg-blue-500",
  UPLOAD:            "bg-green-500",
  SHARE:             "bg-purple-500",
  DELETE:            "bg-red-500",
  MOVE:              "bg-orange-400",
  RENAME:            "bg-yellow-500",
  LOGIN_FAIL:        "bg-rose-600",
  PERMISSION_CHANGE: "bg-pink-500",
};

const triggerBase =
  "inline-flex h-8 items-center gap-2 rounded-md border border-input bg-background px-3 text-sm font-normal shadow-xs hover:bg-accent hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring transition-colors cursor-pointer";

export function LogFilters({
  actions,
  selectedAction,
}: {
  actions: string[];
  selectedAction?: string;
}) {
  const router = useRouter();
  const searchParams = useSearchParams();

  function update(value: string) {
    const p = new URLSearchParams(searchParams.toString());
    if (!value) p.delete("action");
    else p.set("action", value);
    router.push(`/logs?${p}`);
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      <DropdownMenu>
        <DropdownMenuTrigger
          className={`${triggerBase} ${selectedAction ? "border-foreground/30 bg-accent" : ""}`}
        >
          {selectedAction ? (
            <>
              <span className={`w-2 h-2 rounded-full shrink-0 ${ACTION_DOT[selectedAction] ?? "bg-slate-400"}`} />
              <span className="font-medium">{selectedAction}</span>
            </>
          ) : (
            <span className="text-muted-foreground">Action</span>
          )}
          <ChevronDown className="h-3.5 w-3.5 text-muted-foreground ml-0.5" />
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" className="w-52">
          <DropdownMenuGroup>
            <DropdownMenuLabel>Filter by action</DropdownMenuLabel>
          </DropdownMenuGroup>
          <DropdownMenuSeparator />
          <DropdownMenuRadioGroup
            value={selectedAction ?? ""}
            onValueChange={(v) => update(v === selectedAction ? "" : v)}
          >
            {actions.map((a) => (
              <DropdownMenuRadioItem key={a} value={a}>
                <span className={`w-2 h-2 rounded-full shrink-0 ${ACTION_DOT[a] ?? "bg-slate-400"}`} />
                <span>{a}</span>
              </DropdownMenuRadioItem>
            ))}
          </DropdownMenuRadioGroup>
        </DropdownMenuContent>
      </DropdownMenu>

      {selectedAction && (
        <Button
          variant="ghost"
          size="sm"
          onClick={() => router.push("/logs")}
          className="h-8 gap-1 text-muted-foreground hover:text-foreground px-2"
        >
          <X className="h-3.5 w-3.5" />
          Clear
        </Button>
      )}
    </div>
  );
}
