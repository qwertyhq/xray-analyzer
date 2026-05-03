"use client";

import { useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { HourlyStats } from "@/lib/types";

interface ActivityHeatmapProps {
  data: HourlyStats[];
  title?: string;
  description?: string;
}

// Get color intensity based on value
function getHeatColor(value: number, max: number): string {
  if (max === 0) return "bg-muted/30";
  const intensity = value / max;
  
  if (intensity === 0) return "bg-muted/30";
  if (intensity < 0.25) return "bg-green-500/30";
  if (intensity < 0.5) return "bg-green-500/50";
  if (intensity < 0.75) return "bg-green-500/70";
  return "bg-green-500";
}

function getBlacklistColor(value: number, max: number): string {
  if (max === 0) return "bg-muted/30";
  const intensity = value / max;
  
  if (intensity === 0) return "bg-muted/30";
  if (intensity < 0.25) return "bg-red-500/30";
  if (intensity < 0.5) return "bg-red-500/50";
  if (intensity < 0.75) return "bg-red-500/70";
  return "bg-red-500";
}

export function ActivityHeatmap({ data, title = "Activity Heatmap", description }: ActivityHeatmapProps) {
  const { hourlyData, maxRequests, maxBlacklist } = useMemo(() => {
    // Group by hour of day (0-23)
    const hourlyMap = new Map<number, { requests: number; blacklist: number; count: number }>();
    
    (data || []).forEach((item) => {
      const date = new Date(item.hour);
      const hour = date.getHours();
      
      const existing = hourlyMap.get(hour) || { requests: 0, blacklist: 0, count: 0 };
      hourlyMap.set(hour, {
        requests: existing.requests + item.total_requests,
        blacklist: existing.blacklist + item.blacklist_hits,
        count: existing.count + 1,
      });
    });
    
    // Average the values
    const hourlyData = Array.from({ length: 24 }, (_, i) => {
      const data = hourlyMap.get(i);
      return {
        hour: i,
        requests: data ? Math.round(data.requests / data.count) : 0,
        blacklist: data ? Math.round(data.blacklist / data.count) : 0,
      };
    });
    
    const maxRequests = Math.max(...hourlyData.map(d => d.requests), 1);
    const maxBlacklist = Math.max(...hourlyData.map(d => d.blacklist), 1);
    
    return { hourlyData, maxRequests, maxBlacklist };
  }, [data]);

  const formatHour = (hour: number) => {
    return `${hour.toString().padStart(2, "0")}:00`;
  };

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        {description && (
          <CardDescription className="text-xs">{description}</CardDescription>
        )}
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Requests heatmap */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium text-muted-foreground">Requests by Hour</span>
            <div className="flex items-center gap-1 text-xs text-muted-foreground">
              <span>Low</span>
              <div className="flex gap-0.5">
                <div className="w-3 h-3 rounded-sm bg-green-500/30" />
                <div className="w-3 h-3 rounded-sm bg-green-500/50" />
                <div className="w-3 h-3 rounded-sm bg-green-500/70" />
                <div className="w-3 h-3 rounded-sm bg-green-500" />
              </div>
              <span>High</span>
            </div>
          </div>
          <div className="grid grid-cols-8 sm:grid-cols-12 md:grid-cols-24 gap-1">
            {hourlyData.map((item) => (
              <div
                key={`req-${item.hour}`}
                className={`aspect-square rounded-sm ${getHeatColor(item.requests, maxRequests)} transition-colors cursor-default`}
                title={`${formatHour(item.hour)}: ${item.requests.toLocaleString()} requests`}
              />
            ))}
          </div>
          <div className="flex justify-between mt-1 text-[10px] text-muted-foreground">
            <span>00:00</span>
            <span className="hidden sm:inline">06:00</span>
            <span>12:00</span>
            <span className="hidden sm:inline">18:00</span>
            <span>23:00</span>
          </div>
        </div>

        {/* Blacklist heatmap */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium text-muted-foreground">Blacklist Hits by Hour</span>
            <div className="flex items-center gap-1 text-xs text-muted-foreground">
              <span>Low</span>
              <div className="flex gap-0.5">
                <div className="w-3 h-3 rounded-sm bg-red-500/30" />
                <div className="w-3 h-3 rounded-sm bg-red-500/50" />
                <div className="w-3 h-3 rounded-sm bg-red-500/70" />
                <div className="w-3 h-3 rounded-sm bg-red-500" />
              </div>
              <span>High</span>
            </div>
          </div>
          <div className="grid grid-cols-8 sm:grid-cols-12 md:grid-cols-24 gap-1">
            {hourlyData.map((item) => (
              <div
                key={`bl-${item.hour}`}
                className={`aspect-square rounded-sm ${getBlacklistColor(item.blacklist, maxBlacklist)} transition-colors cursor-default`}
                title={`${formatHour(item.hour)}: ${item.blacklist.toLocaleString()} blacklist hits`}
              />
            ))}
          </div>
          <div className="flex justify-between mt-1 text-[10px] text-muted-foreground">
            <span>00:00</span>
            <span className="hidden sm:inline">06:00</span>
            <span>12:00</span>
            <span className="hidden sm:inline">18:00</span>
            <span>23:00</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
