"use client";

import { useApi } from "@/hooks/use-api";
import { StatsCards } from "@/components/dashboard/stats-cards";
import { NodesTable } from "@/components/nodes/nodes-table";
import { UsersTable } from "@/components/users/users-table";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";

export default function DashboardPage() {
  const { stats, nodes, users, loading } = useApi();

  if (loading) {
    return (
      <div className="p-4 md:p-8 space-y-6">
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {[...Array(4)].map((_, i) => (
            <Skeleton key={i} className="h-[120px]" />
          ))}
        </div>
        <div className="grid gap-6 md:grid-cols-2">
          <Skeleton className="h-[300px]" />
          <Skeleton className="h-[300px]" />
        </div>
      </div>
    );
  }

  // Filter only online nodes for dashboard
  const onlineNodes = nodes.filter(n => n.is_connected);
  const blacklistUsers = users.filter(u => u.blacklist_hits > 0).slice(0, 10);

  return (
    <div className="p-4 md:p-8 space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Dashboard</h2>
        <p className="text-muted-foreground">
          Real-time overview of Xray proxy activity
        </p>
      </div>

      <StatsCards stats={stats} />

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
              Users accessing blocked destinations
            </CardDescription>
          </CardHeader>
          <CardContent>
            <UsersTable users={blacklistUsers} showBlacklistOnly />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
