"use client";

import { useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { format, parseISO } from "date-fns";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
} from "recharts";
import { TimeStats, ThreatType } from "@/lib/types";
import { threatTypeConfig } from "./config";
import { Clock, Calendar, TrendingUp, Activity } from "lucide-react";

interface TimeChartProps {
  data: TimeStats | null;
  loading?: boolean;
}

// Helper to safely get label from threatTypeConfig
const getTypeLabel = (type: string): string => {
  const config = threatTypeConfig[type as ThreatType];
  return config?.label || type.charAt(0).toUpperCase() + type.slice(1);
};

// Muted color palette with lower saturation
const colors: Record<string, string> = {
  social: "hsla(212, 60%, 55%, 0.7)",
  tiktok: "hsla(340, 55%, 55%, 0.7)",
  porn: "hsla(262, 55%, 60%, 0.7)",
  gambling: "hsla(32, 60%, 55%, 0.7)",
  ads: "hsla(48, 60%, 55%, 0.7)",
  malware: "hsla(0, 50%, 55%, 0.7)",
  phishing: "hsla(25, 60%, 55%, 0.7)",
  torrent: "hsla(165, 50%, 50%, 0.7)",
  tor: "hsla(0, 55%, 55%, 0.7)",
  tracking: "hsla(197, 50%, 55%, 0.7)",
  crypto: "hsla(142, 45%, 50%, 0.7)",
  fakenews: "hsla(280, 45%, 55%, 0.7)",
  drugs: "hsla(45, 55%, 50%, 0.7)",
  abuse: "hsla(15, 55%, 55%, 0.7)",
  fraud: "hsla(350, 55%, 55%, 0.7)",
  default: "hsla(215, 20%, 60%, 0.7)",
};

const getColor = (type: string) => colors[type] || colors.default;

export function TimeChart({ data, loading = false }: TimeChartProps) {
  // Transform hourly data for chart
  const hourlyChartData = useMemo(() => {
    if (!data?.hourly || data.hourly.length === 0) return [];

    return data.hourly
      .map((stat) => {
        let label = stat.hour;
        try {
          const date = stat.hour.includes("T") ? parseISO(stat.hour) : new Date(stat.hour);
          label = format(date, "HH:mm");
        } catch {
          // fallback
        }
        return {
          hour: stat.hour,
          label,
          total: stat.total_count || 0,
          unique_users: stat.unique_users || 0,
          ...stat.by_type,
        };
      })
      .sort((a, b) => a.hour.localeCompare(b.hour));
  }, [data?.hourly]);

  // Transform daily data for chart
  const dailyChartData = useMemo(() => {
    if (!data?.daily || data.daily.length === 0) return [];

    return data.daily
      .map((stat) => {
        let label = stat.day;
        try {
          const date = stat.day.includes("T") ? parseISO(stat.day) : new Date(stat.day);
          label = format(date, "MMM d");
        } catch {
          // fallback
        }
        return {
          day: stat.day,
          label,
          total: stat.total_count || 0,
          unique_users: stat.unique_users || 0,
          ...stat.by_type,
        };
      })
      .sort((a, b) => a.day.localeCompare(b.day));
  }, [data?.daily]);

  // Get threat types sorted by total count
  const threatTypes = useMemo(() => {
    const typeTotals: Record<string, number> = {};
    
    data?.hourly?.forEach((h) => {
      if (h.by_type) {
        Object.entries(h.by_type).forEach(([type, count]) => {
          typeTotals[type] = (typeTotals[type] || 0) + count;
        });
      }
    });

    return Object.entries(typeTotals)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([type]) => type);
  }, [data?.hourly]);

  // Calculate totals for stats
  const totals = useMemo(() => {
    const hourlyTotal = hourlyChartData.reduce((sum, d) => sum + d.total, 0);
    const dailyAvg = dailyChartData.length > 0 
      ? Math.round(dailyChartData.reduce((sum, d) => sum + d.total, 0) / dailyChartData.length)
      : 0;
    const peakHour = hourlyChartData.reduce((max, d) => d.total > max.total ? d : max, { total: 0, label: "-" });
    return { hourlyTotal, dailyAvg, peakHour };
  }, [hourlyChartData, dailyChartData]);

  if (loading) {
    return (
      <div className="space-y-4">
        <div className="grid gap-4 md:grid-cols-3">
          {[1, 2, 3].map(i => <Skeleton key={i} className="h-24" />)}
        </div>
        <div className="grid gap-4 md:grid-cols-2">
          <Skeleton className="h-[300px]" />
          <Skeleton className="h-[300px]" />
        </div>
      </div>
    );
  }

  if (!data || (hourlyChartData.length === 0 && dailyChartData.length === 0)) {
    return (
      <Card className="border-dashed">
        <CardContent className="flex flex-col items-center justify-center h-[200px] text-center">
          <Activity className="h-12 w-12 text-muted-foreground/50 mb-4" />
          <p className="text-muted-foreground">No time-based data available yet</p>
          <p className="text-xs text-muted-foreground/70 mt-1">
            Statistics will appear after threat matches are recorded
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {/* Stats Summary Cards */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card className="bg-gradient-to-br from-blue-500/10 to-blue-600/5 border-blue-500/20">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Clock className="h-4 w-4 text-blue-500" />
              Last 24 Hours
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-blue-600 dark:text-blue-400">
              {totals.hourlyTotal.toLocaleString()}
            </div>
            <p className="text-xs text-muted-foreground">Total matches</p>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-purple-500/10 to-purple-600/5 border-purple-500/20">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Calendar className="h-4 w-4 text-purple-500" />
              Daily Average
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-purple-600 dark:text-purple-400">
              {totals.dailyAvg.toLocaleString()}
            </div>
            <p className="text-xs text-muted-foreground">Matches per day</p>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-orange-500/10 to-orange-600/5 border-orange-500/20">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-orange-500" />
              Peak Hour
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-orange-600 dark:text-orange-400">
              {totals.peakHour.label}
            </div>
            <p className="text-xs text-muted-foreground">
              {totals.peakHour.total.toLocaleString()} matches
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Charts */}
      <div className="grid gap-4 md:grid-cols-2">
        {/* Hourly Chart */}
        <Card>
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-base font-semibold flex items-center gap-2">
                  <Clock className="h-4 w-4" />
                  Hourly Activity
                </CardTitle>
                <CardDescription className="text-xs mt-1">
                  Threat matches by category (24h)
                </CardDescription>
              </div>
              <div className="flex gap-1 flex-wrap justify-end">
                {threatTypes.slice(0, 4).map(type => (
                  <Badge 
                    key={type} 
                    variant="outline" 
                    className="text-[10px] px-1.5 py-0"
                    style={{ borderColor: getColor(type), color: getColor(type) }}
                  >
                    {getTypeLabel(type)}
                  </Badge>
                ))}
              </div>
            </div>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="h-[280px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={hourlyChartData} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
                  <defs>
                    {threatTypes.map((type) => (
                      <linearGradient key={type} id={`gradient-${type}`} x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor={getColor(type)} stopOpacity={0.6} />
                        <stop offset="95%" stopColor={getColor(type)} stopOpacity={0.05} />
                      </linearGradient>
                    ))}
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-muted/50" vertical={false} />
                  <XAxis 
                    dataKey="label" 
                    tick={{ fontSize: 10 }} 
                    tickLine={false}
                    axisLine={false}
                    interval="preserveStartEnd"
                    className="text-muted-foreground"
                  />
                  <YAxis 
                    tick={{ fontSize: 10 }} 
                    tickLine={false}
                    axisLine={false}
                    width={35}
                    tickFormatter={(v) => v >= 1000 ? `${(v/1000).toFixed(0)}k` : v}
                    className="text-muted-foreground"
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "hsl(var(--card))",
                      border: "1px solid hsl(var(--border))",
                      borderRadius: "8px",
                      fontSize: "12px",
                      boxShadow: "0 4px 12px rgba(0,0,0,0.15)",
                    }}
                    labelStyle={{ color: "hsl(var(--foreground))", fontWeight: "bold" }}
                    formatter={(value: number, name: string) => [
                      value.toLocaleString(),
                      getTypeLabel(name)
                    ]}
                  />
                  {threatTypes.map((type, i) => (
                    <Area
                      key={type}
                      type="monotone"
                      dataKey={type}
                      stackId="1"
                      stroke={getColor(type)}
                      fill={`url(#gradient-${type})`}
                      strokeWidth={i === 0 ? 2 : 1}
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
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-base font-semibold flex items-center gap-2">
                  <Calendar className="h-4 w-4" />
                  Daily Activity
                </CardTitle>
                <CardDescription className="text-xs mt-1">
                  Threat matches by category (7d)
                </CardDescription>
              </div>
            </div>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="h-[280px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={dailyChartData} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-muted/50" vertical={false} />
                  <XAxis 
                    dataKey="label" 
                    tick={{ fontSize: 11 }} 
                    tickLine={false}
                    axisLine={false}
                    className="text-muted-foreground"
                  />
                  <YAxis 
                    tick={{ fontSize: 10 }} 
                    tickLine={false}
                    axisLine={false}
                    width={35}
                    tickFormatter={(v) => v >= 1000 ? `${(v/1000).toFixed(0)}k` : v}
                    className="text-muted-foreground"
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "hsl(var(--card))",
                      border: "1px solid hsl(var(--border))",
                      borderRadius: "8px",
                      fontSize: "12px",
                      boxShadow: "0 4px 12px rgba(0,0,0,0.15)",
                    }}
                    labelStyle={{ color: "hsl(var(--foreground))", fontWeight: "bold" }}
                    formatter={(value: number, name: string) => [
                      value.toLocaleString(),
                      getTypeLabel(name)
                    ]}
                  />
                  {threatTypes.map((type) => (
                    <Bar
                      key={type}
                      dataKey={type}
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
    </div>
  );
}
