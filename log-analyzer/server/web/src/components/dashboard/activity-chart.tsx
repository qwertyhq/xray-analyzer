"use client";

import { useMemo } from "react";
import { HourlyStats, TimeRange } from "@/lib/types";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { format } from "date-fns";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";

interface ActivityChartProps {
  data: HourlyStats[];
  title?: string;
  description?: string;
  loading?: boolean;
  timeRange?: TimeRange;
}

export function ActivityChart({ 
  data, 
  title = "Activity",
  description = "Requests over time",
  loading = false,
  timeRange = "24h",
}: ActivityChartProps) {
  const chartData = useMemo(() => {
    if (!data || data.length === 0) {
      return [];
    }

    // Determine label format based on time range
    const isLongRange = timeRange === "7d" || timeRange === "30d";

    // Sort data by hour and format for chart
    return data
      .sort((a, b) => new Date(a.hour).getTime() - new Date(b.hour).getTime())
      .map(d => {
        const date = new Date(d.hour);
        return {
          hour: isLongRange ? format(date, "MMM d") : format(date, "HH:mm"),
          fullDate: format(date, "MMM d, HH:mm"),
          requests: d.total_requests || 0,
          blacklist: d.blacklist_hits || 0,
        };
      });
  }, [data, timeRange]);

  // Calculate tick interval based on data length
  const tickInterval = useMemo(() => {
    const len = chartData.length;
    if (len <= 12) return 0; // Show all
    if (len <= 24) return 3;
    if (len <= 48) return 5;
    if (len <= 168) return 23; // 7 days - show daily
    return Math.floor(len / 10);
  }, [chartData.length]);

  if (loading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>{title}</CardTitle>
          <CardDescription>{description}</CardDescription>
        </CardHeader>
        <CardContent>
          <Skeleton className="h-[300px] w-full" />
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
        <div className="h-[300px] w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart
              data={chartData}
              margin={{ top: 10, right: 10, left: 0, bottom: 0 }}
            >
              <defs>
                <linearGradient id="colorRequests" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="hsl(var(--primary))" stopOpacity={0.8}/>
                  <stop offset="95%" stopColor="hsl(var(--primary))" stopOpacity={0.1}/>
                </linearGradient>
                <linearGradient id="colorBlacklist" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="hsl(var(--destructive))" stopOpacity={0.8}/>
                  <stop offset="95%" stopColor="hsl(var(--destructive))" stopOpacity={0.1}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
              <XAxis 
                dataKey="hour" 
                tick={{ fontSize: 12 }}
                tickLine={false}
                axisLine={false}
                className="text-muted-foreground"
                interval={tickInterval}
              />
              <YAxis 
                tick={{ fontSize: 12 }}
                tickLine={false}
                axisLine={false}
                className="text-muted-foreground"
                tickFormatter={(value) => value >= 1000 ? `${(value / 1000).toFixed(0)}k` : value}
              />
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: "hsl(var(--card))",
                  border: "1px solid hsl(var(--border))",
                  borderRadius: "8px",
                  fontSize: "12px",
                }}
                labelStyle={{ color: "hsl(var(--foreground))" }}
                labelFormatter={(label) => {
                  const item = chartData.find(d => d.hour === label);
                  return item?.fullDate || label;
                }}
                formatter={(value: number, name: string) => [
                  value.toLocaleString(),
                  name === "requests" ? "Requests" : "Blacklist"
                ]}
              />
              <Legend 
                verticalAlign="top"
                height={36}
                formatter={(value) => value === "requests" ? "Requests" : "Blacklist Hits"}
              />
              <Area
                type="monotone"
                dataKey="requests"
                stroke="hsl(var(--primary))"
                fillOpacity={1}
                fill="url(#colorRequests)"
                strokeWidth={2}
              />
              <Area
                type="monotone"
                dataKey="blacklist"
                stroke="hsl(var(--destructive))"
                fillOpacity={1}
                fill="url(#colorBlacklist)"
                strokeWidth={2}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}
