"use client";

import { useDashboardWebSocket } from "@/hooks/use-websocket";
import { StatsCards } from "@/components/dashboard/stats-cards";
import { ActivityChart } from "@/components/dashboard/activity-chart";
import { AnomaliesCard } from "@/components/dashboard/anomalies-card";
import { RecentBlocks } from "@/components/dashboard/recent-blocks";
import { NodesTable } from "@/components/nodes/nodes-table";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Wifi, WifiOff } from "lucide-react";

export default function DashboardPage() {
  const { stats, nodes, hourly, anomalies, blacklist, connected, loading } = useDashboardWebSocket();

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

  return (
    <div className="p-4 md:p-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Dashboard</h2>
          <p className="text-muted-foreground">
            Real-time overview of Xray proxy activity
          </p>
        </div>
        <Badge 
          variant={connected ? "default" : "destructive"} 
          className="flex items-center gap-1.5"
        >
          {connected ? (
            <>
              <Wifi className="h-3 w-3" />
              Live
            </>
          ) : (
            <>
              <WifiOff className="h-3 w-3" />
              Disconnected
            </>
          )}
        </Badge>
      </div>

      <StatsCards stats={stats} />

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <ActivityChart 
            data={hourly} 
            title="Activity (Last 24 Hours)"
            description="Requests and blacklist hits over time"
            loading={false}
            timeRange="24h"
          />
        </div>
        <AnomaliesCard anomalies={anomalies} loading={false} />
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
              matches={blacklist?.recent_matches || []} 
              loading={false}
              limit={20}
            />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
