"use client";

import { useMemo } from "react";
import { HourlyStats } from "@/lib/types";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { format } from "date-fns";

interface ActivityChartProps {
  data: HourlyStats[];
  title?: string;
  description?: string;
  loading?: boolean;
}

export function ActivityChart({ 
  data, 
  title = "Activity",
  description = "Requests over time",
  loading = false,
}: ActivityChartProps) {
  const chartData = useMemo(() => {
    if (!data || data.length === 0) return [];
    
    // Fill in missing hours
    const hourMap = new Map<string, HourlyStats>();
    data.forEach(d => {
      const hourKey = format(new Date(d.hour), "yyyy-MM-dd HH:00");
      hourMap.set(hourKey, d);
    });

    return data.map(d => ({
      hour: format(new Date(d.hour), "HH:mm"),
      date: format(new Date(d.hour), "MMM d"),
      requests: d.total_requests,
      blacklist: d.blacklist_hits,
    }));
  }, [data]);

  const maxValue = useMemo(() => {
    if (chartData.length === 0) return 100;
    return Math.max(...chartData.map(d => d.requests), 100);
  }, [chartData]);

  if (loading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>{title}</CardTitle>
          <CardDescription>{description}</CardDescription>
        </CardHeader>
        <CardContent>
          <Skeleton className="h-[200px] w-full" />
        </CardContent>
      </Card>
    );
  }

  if (chartData.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>{title}</CardTitle>
          <CardDescription>{description}</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-[200px] flex items-center justify-center text-muted-foreground">
            No data available
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="h-[200px] flex items-end gap-1">
          {chartData.map((d, i) => (
            <div key={i} className="flex-1 flex flex-col items-center gap-1">
              <div className="w-full flex flex-col gap-0.5" style={{ height: "160px" }}>
                {/* Blacklist bar (on top) */}
                {d.blacklist > 0 && (
                  <div
                    className="w-full bg-destructive/80 rounded-t-sm"
                    style={{
                      height: `${(d.blacklist / maxValue) * 100}%`,
                      minHeight: d.blacklist > 0 ? "2px" : "0",
                    }}
                    title={`Blacklist: ${d.blacklist}`}
                  />
                )}
                {/* Requests bar */}
                <div
                  className="w-full bg-primary/60 rounded-sm"
                  style={{
                    height: `${((d.requests - d.blacklist) / maxValue) * 100}%`,
                    minHeight: d.requests > 0 ? "2px" : "0",
                  }}
                  title={`Requests: ${d.requests}`}
                />
              </div>
              <span className="text-[10px] text-muted-foreground">
                {i % 4 === 0 ? d.hour : ""}
              </span>
            </div>
          ))}
        </div>
        <div className="flex gap-4 mt-4 justify-center text-sm">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-primary/60 rounded-sm" />
            <span className="text-muted-foreground">Requests</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-destructive/80 rounded-sm" />
            <span className="text-muted-foreground">Blacklist</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
