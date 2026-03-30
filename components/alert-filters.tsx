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

interface Props {
  rules: { id: string; name: string }[];
  selectedSeverity?: string;
  selectedRule?: string;
}

const SEVERITY_DOT: Record<string, string> = {
  CRITICAL: "bg-red-500",
  HIGH:     "bg-orange-500",
  MEDIUM:   "bg-yellow-500",
  LOW:      "bg-blue-400",
};

const SEVERITY_TEXT: Record<string, string> = {
  CRITICAL: "text-red-600",
  HIGH:     "text-orange-500",
  MEDIUM:   "text-yellow-600",
  LOW:      "text-blue-500",
};

const triggerBase =
  "inline-flex h-8 items-center gap-2 rounded-md border border-input bg-background px-3 text-sm font-normal shadow-xs hover:bg-accent hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring transition-colors cursor-pointer";

export function AlertFilters({ rules, selectedSeverity, selectedRule }: Props) {
  const router = useRouter();
  const searchParams = useSearchParams();

  function update(key: string, value: string) {
    const p = new URLSearchParams(searchParams.toString());
    if (!value) p.delete(key);
    else p.set(key, value);
    router.push(`/alerts?${p}`);
  }

  const hasFilter = selectedSeverity || selectedRule;

  return (
    <div className="flex flex-wrap items-center gap-2">

      {/* Severity */}
      <DropdownMenu>
        <DropdownMenuTrigger
          className={`${triggerBase} ${selectedSeverity ? "border-foreground/30 bg-accent" : ""}`}
        >
          {selectedSeverity ? (
            <>
              <span className={`w-2 h-2 rounded-full shrink-0 ${SEVERITY_DOT[selectedSeverity]}`} />
              <span className={`font-medium ${SEVERITY_TEXT[selectedSeverity]}`}>
                {selectedSeverity}
              </span>
            </>
          ) : (
            <span className="text-muted-foreground">Severity</span>
          )}
          <ChevronDown className="h-3.5 w-3.5 text-muted-foreground ml-0.5" />
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" className="w-40">
          <DropdownMenuGroup>
            <DropdownMenuLabel>Filter by severity</DropdownMenuLabel>
          </DropdownMenuGroup>
          <DropdownMenuSeparator />
          <DropdownMenuRadioGroup
            value={selectedSeverity ?? ""}
            onValueChange={(v) => update("severity", v === selectedSeverity ? "" : v)}
          >
            {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => (
              <DropdownMenuRadioItem key={s} value={s}>
                <span className={`w-2 h-2 rounded-full shrink-0 ${SEVERITY_DOT[s]}`} />
                <span className={`font-medium ${SEVERITY_TEXT[s]}`}>{s}</span>
              </DropdownMenuRadioItem>
            ))}
          </DropdownMenuRadioGroup>
        </DropdownMenuContent>
      </DropdownMenu>

      {/* Rule */}
      <DropdownMenu>
        <DropdownMenuTrigger
          className={`${triggerBase} ${selectedRule ? "border-foreground/30 bg-accent" : ""}`}
        >
          {selectedRule ? (
            <>
              <span className="font-mono text-xs bg-muted px-1.5 py-0.5 rounded">
                {selectedRule}
              </span>
              <span className="text-muted-foreground max-w-[110px] truncate text-xs">
                {rules.find((r) => r.id === selectedRule)?.name}
              </span>
            </>
          ) : (
            <span className="text-muted-foreground">Rule</span>
          )}
          <ChevronDown className="h-3.5 w-3.5 text-muted-foreground ml-0.5" />
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" className="w-64">
          <DropdownMenuGroup>
            <DropdownMenuLabel>Filter by rule</DropdownMenuLabel>
          </DropdownMenuGroup>
          <DropdownMenuSeparator />
          <DropdownMenuRadioGroup
            value={selectedRule ?? ""}
            onValueChange={(v) => update("rule_id", v === selectedRule ? "" : v)}
          >
            {rules.map((r) => (
              <DropdownMenuRadioItem key={r.id} value={r.id}>
                <span className="font-mono text-xs bg-muted px-1.5 py-0.5 rounded text-foreground">
                  {r.id}
                </span>
                <span className="text-muted-foreground text-xs">{r.name}</span>
              </DropdownMenuRadioItem>
            ))}
          </DropdownMenuRadioGroup>
        </DropdownMenuContent>
      </DropdownMenu>

      {hasFilter && (
        <Button
          variant="ghost"
          size="sm"
          onClick={() => router.push("/alerts")}
          className="h-8 gap-1 text-muted-foreground hover:text-foreground px-2"
        >
          <X className="h-3.5 w-3.5" />
          Clear
        </Button>
      )}
    </div>
  );
}
