"use client";

import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Activity, Server, Users, ShieldAlert } from "lucide-react";

interface StatsCardsProps {
  totalRequests: number;
  totalBlacklist: number;
  nodesConnected: number;
  nodesTotal: number;
}

export function StatsCards({
  totalRequests,
  totalBlacklist,
  nodesConnected,
  nodesTotal,
}: StatsCardsProps) {
  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Total Requests</CardTitle>
          <Activity className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">
            {totalRequests.toLocaleString()}
          </div>
          <p className="text-xs text-muted-foreground">
            Processed log entries
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Blacklist Hits</CardTitle>
          <ShieldAlert className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold text-destructive">
            {totalBlacklist.toLocaleString()}
          </div>
          <p className="text-xs text-muted-foreground">
            Suspicious destinations
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Nodes Connected</CardTitle>
          <Server className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">
            {nodesConnected} / {nodesTotal}
          </div>
          <p className="text-xs text-muted-foreground">
            Active node agents
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Unique Users</CardTitle>
          <Users className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">—</div>
          <p className="text-xs text-muted-foreground">
            Across all nodes
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
