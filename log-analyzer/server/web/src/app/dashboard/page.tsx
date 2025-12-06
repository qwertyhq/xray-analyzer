"use client";

import { useState } from "react";
import { useApi, useHourlyStatsWithRange, useAnomalies, useBlacklistAnalytics } from "@/hooks/use-api";
import { StatsCards } from "@/components/dashboard/stats-cards";
import { ActivityChart } from "@/components/dashboard/activity-chart";
import { TimeRangeSelector } from "@/components/dashboard/time-range-selector";
import { AnomaliesCard } from "@/components/dashboard/anomalies-card";
import { RecentBlocks } from "@/components/dashboard/recent-blocks";
import { NodesTable } from "@/components/nodes/nodes-table";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { TimeRange } from "@/lib/types";

export default function DashboardPage() {
  const [timeRange, setTimeRange] = useState<TimeRange>("24h");
  const { stats, nodes, loading } = useApi();
  const { stats: hourlyStats, loading: hourlyLoading } = useHourlyStatsWithRange(timeRange);
  const { anomalies, loading: anomaliesLoading } = useAnomalies();
  const { analytics: blacklistAnalytics, loading: blacklistLoading } = useBlacklistAnalytics(timeRange);

  if (loading) {
    return (
      <div className="p-4 md:p-8 space-y-6">
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {[...Array(4)].map((_, i) => (
            <Skeleton key={i} className="h-[120px]" />
          ))}
        </div>
        <Skeleton className="h-[280px]" />
        <div className="grid gap-6 md:grid-cols-2">
          <Skeleton className="h-[300px]" />
          <Skeleton className="h-[300px]" />
        </div>
      </div>
    );
  }

  // Filter only online nodes for dashboard
  const onlineNodes = nodes.filter(n => n.is_connected);

  // Get chart title based on time range
  const chartTitles: Record<TimeRange, string> = {
    "1h": "Activity (Last Hour)",
    "6h": "Activity (Last 6 Hours)",
    "24h": "Activity (Last 24 Hours)",
    "7d": "Activity (Last 7 Days)",
    "30d": "Activity (Last 30 Days)",
    "custom": "Activity",
  };

  return (
    <div className="p-4 md:p-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Dashboard</h2>
          <p className="text-muted-foreground">
            Real-time overview of Xray proxy activity
          </p>
        </div>
        <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
      </div>

      <StatsCards stats={stats} />

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <ActivityChart 
            data={hourlyStats} 
            title={chartTitles[timeRange]}
            description="Requests and blacklist hits over time"
            loading={hourlyLoading}
            timeRange={timeRange}
          />
        </div>
        <AnomaliesCard anomalies={anomalies} loading={anomaliesLoading} />
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Active Nodes</CardTitle>
            <CardDescription>
              {onlineNodes.length} of {nodes.length} nodes online
            </CardDescription>
          </CardHeader>
          <CardContent>
            <NodesTable nodes={onlineNodes} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Blacklist Alerts</CardTitle>
            <CardDescription>
              Recent blocked requests
            </CardDescription>
          </CardHeader>
          <CardContent>
            <RecentBlocks 
              matches={blacklistAnalytics?.recent_matches || []} 
              loading={blacklistLoading}
              limit={10}
            />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
