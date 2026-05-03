"use client";

import { Button } from "@/components/ui/button";
import { TimeRange } from "@/lib/types";
import { cn } from "@/lib/utils";

interface TimeRangeSelectorProps {
  value: TimeRange;
  onChange: (range: TimeRange) => void;
}

const ranges: { value: TimeRange; label: string }[] = [
  { value: "1h", label: "1H" },
  { value: "6h", label: "6H" },
  { value: "24h", label: "24H" },
  { value: "7d", label: "7D" },
  { value: "30d", label: "30D" },
];

export function TimeRangeSelector({ value, onChange }: TimeRangeSelectorProps) {
  return (
    <div className="flex gap-1 bg-muted p-1 rounded-lg">
      {ranges.map((range) => (
        <Button
          key={range.value}
          variant={value === range.value ? "secondary" : "ghost"}
          size="sm"
          className={cn(
            "h-7 px-3 text-xs font-medium",
            value === range.value && "bg-background shadow-sm"
          )}
          onClick={() => onChange(range.value)}
        >
          {range.label}
        </Button>
      ))}
    </div>
  );
}
