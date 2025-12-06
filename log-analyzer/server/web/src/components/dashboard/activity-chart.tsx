"use client";

import { useMemo } from "react";
import { HourlyStats } from "@/lib/types";
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
}

export function ActivityChart({ 
  data, 
  title = "Activity",
  description = "Requests over time",
  loading = false,
}: ActivityChartProps) {
  const chartData = useMemo(() => {
    // Create a map of existing data by hour
    const hourMap = new Map<string, HourlyStats>();
    if (data && data.length > 0) {
      data.forEach(d => {
        const hourKey = format(new Date(d.hour), "yyyy-MM-dd HH:00");
        hourMap.set(hourKey, d);
      });
    }

    // Generate all hours for the last 24 hours
    const result = [];
    const now = new Date();
    now.setMinutes(0, 0, 0);
    
    for (let i = 23; i >= 0; i--) {
      const hourDate = new Date(now.getTime() - i * 60 * 60 * 1000);
      const hourKey = format(hourDate, "yyyy-MM-dd HH:00");
      const existing = hourMap.get(hourKey);
      
      result.push({
        hour: format(hourDate, "HH:mm"),
        fullDate: format(hourDate, "MMM d, HH:mm"),
        requests: existing?.total_requests || 0,
        blacklist: existing?.blacklist_hits || 0,
      });
    }

    return result;
  }, [data]);

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
                interval="preserveStartEnd"
                tickFormatter={(value, index) => index % 4 === 0 ? value : ""}
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
