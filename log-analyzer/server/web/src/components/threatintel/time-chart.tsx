"use client";

import { useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { format, parseISO } from "date-fns";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
  BarChart,
  Bar,
} from "recharts";
import { HourlyThreatStats, DailyThreatStats, TimeStats, ThreatType } from "@/lib/types";
import { threatTypeConfig } from "./config";

interface TimeChartProps {
  data: TimeStats | null;
  loading?: boolean;
}

// Helper to safely get label from threatTypeConfig
const getTypeLabel = (type: string): string => {
  const config = threatTypeConfig[type as ThreatType];
  return config?.label || type;
};

export function TimeChart({ data, loading = false }: TimeChartProps) {
  // Transform hourly data for chart
  const hourlyChartData = useMemo(() => {
    if (!data?.hourly || data.hourly.length === 0) {
      return [];
    }

    // Backend sends aggregated data: { hour, total_count, by_type: {type: count}, unique_users }
    return data.hourly
      .map((stat) => {
        let label = stat.hour;
        try {
          // Parse various ISO formats
          const date = stat.hour.includes("T") ? parseISO(stat.hour) : new Date(stat.hour);
          label = format(date, "HH:mm");
        } catch {
          // Use original if parsing fails
        }
        return {
          hour: stat.hour,
          label,
          total: stat.total_count,
          unique_users: stat.unique_users,
          ...stat.by_type,
        };
      })
      .sort((a, b) => a.hour.localeCompare(b.hour));
  }, [data?.hourly]);

  // Transform daily data for chart
  const dailyChartData = useMemo(() => {
    if (!data?.daily || data.daily.length === 0) {
      return [];
    }

    // Backend sends aggregated data: { day, total_count, by_type: {type: count}, unique_users }
    return data.daily
      .map((stat) => {
        let label = stat.day;
        try {
          const date = stat.day.includes("T") ? parseISO(stat.day) : new Date(stat.day);
          label = format(date, "MMM d");
        } catch {
          // Use original if parsing fails
        }
        return {
          day: stat.day,
          label,
          total: stat.total_count,
          unique_users: stat.unique_users,
          ...stat.by_type,
        };
      })
      .sort((a, b) => a.day.localeCompare(b.day));
  }, [data?.daily]);

  // Get unique threat types for colors
  const threatTypes = useMemo(() => {
    const types = new Set<string>();
    data?.hourly?.forEach((h) => {
      if (h.by_type) {
        Object.keys(h.by_type).forEach((type) => types.add(type));
      }
    });
    data?.daily?.forEach((d) => {
      if (d.by_type) {
        Object.keys(d.by_type).forEach((type) => types.add(type));
      }
    });
    return Array.from(types);
  }, [data]);

  // Color map for threat types
  const colors: Record<string, string> = {
    porn: "hsl(340, 82%, 52%)",       // pink
    gambling: "hsl(32, 98%, 50%)",    // orange
    social: "hsl(212, 96%, 54%)",     // blue
    fakenews: "hsl(262, 83%, 58%)",   // purple
    torrent: "hsl(165, 82%, 51%)",    // teal
    tor: "hsl(0, 84%, 60%)",          // red
    ads: "hsl(48, 96%, 53%)",         // yellow
    malware: "hsl(0, 72%, 51%)",      // dark red
    phishing: "hsl(25, 95%, 53%)",    // dark orange
    c2: "hsl(262, 83%, 38%)",         // dark purple
    botnet: "hsl(142, 71%, 45%)",     // green
    spam: "hsl(197, 71%, 73%)",       // light blue
    default: "hsl(215, 20%, 65%)",    // gray
  };

  const getColor = (type: string) => colors[type] || colors.default;

  if (loading) {
    return (
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Hourly Activity</CardTitle>
          </CardHeader>
          <CardContent>
            <Skeleton className="h-[250px] w-full" />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Daily Activity</CardTitle>
          </CardHeader>
          <CardContent>
            <Skeleton className="h-[250px] w-full" />
          </CardContent>
        </Card>
      </div>
    );
  }

  const hasData = hourlyChartData.length > 0 || dailyChartData.length > 0;

  if (!hasData) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Time Analysis</CardTitle>
          <CardDescription>No time-based data available yet</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center h-[200px] text-muted-foreground">
            Time statistics will appear after matches are recorded
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="grid gap-4 md:grid-cols-2">
      {/* Hourly Chart */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">Hourly Activity (24h)</CardTitle>
          <CardDescription className="text-xs">
            Threat matches per hour by category
          </CardDescription>
        </CardHeader>
        <CardContent className="pt-0">
          <div className="h-[250px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={hourlyChartData} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                <defs>
                  {threatTypes.map((type) => (
                    <linearGradient key={type} id={`color-${type}`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor={getColor(type)} stopOpacity={0.8} />
                      <stop offset="95%" stopColor={getColor(type)} stopOpacity={0.1} />
                    </linearGradient>
                  ))}
                </defs>
                <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                <XAxis 
                  dataKey="label" 
                  tick={{ fontSize: 10 }} 
                  interval="preserveStartEnd"
                  className="text-muted-foreground"
                />
                <YAxis tick={{ fontSize: 10 }} width={30} className="text-muted-foreground" />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "hsl(var(--card))",
                    border: "1px solid hsl(var(--border))",
                    borderRadius: "8px",
                    fontSize: "12px",
                  }}
                  labelStyle={{ color: "hsl(var(--foreground))" }}
                />
                <Legend wrapperStyle={{ fontSize: "10px" }} />
                {threatTypes.map((type) => (
                  <Area
                    key={type}
                    type="monotone"
                    dataKey={type}
                    name={getTypeLabel(type)}
                    stackId="1"
                    stroke={getColor(type)}
                    fill={`url(#color-${type})`}
                  />
                ))}
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>

      {/* Daily Chart */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">Daily Activity (7d)</CardTitle>
          <CardDescription className="text-xs">
            Threat matches per day by category
          </CardDescription>
        </CardHeader>
        <CardContent className="pt-0">
          <div className="h-[250px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={dailyChartData} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                <XAxis 
                  dataKey="label" 
                  tick={{ fontSize: 10 }} 
                  className="text-muted-foreground"
                />
                <YAxis tick={{ fontSize: 10 }} width={30} className="text-muted-foreground" />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "hsl(var(--card))",
                    border: "1px solid hsl(var(--border))",
                    borderRadius: "8px",
                    fontSize: "12px",
                  }}
                  labelStyle={{ color: "hsl(var(--foreground))" }}
                />
                <Legend wrapperStyle={{ fontSize: "10px" }} />
                {threatTypes.map((type) => (
                  <Bar
                    key={type}
                    dataKey={type}
                    name={getTypeLabel(type)}
                    stackId="1"
                    fill={getColor(type)}
                  />
                ))}
              </BarChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
