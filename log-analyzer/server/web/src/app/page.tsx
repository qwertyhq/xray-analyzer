"use client";

import { useEffect, useState } from "react";
import { Stats, NodeStats, UserStats } from "@/lib/types";
import { StatsCards } from "@/components/stats-cards";
import { NodesTable } from "@/components/nodes-table";
import { UsersTable } from "@/components/users-table";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

export default function Dashboard() {
  const [stats, setStats] = useState<Stats>({ 
    total_requests: 0, 
    total_blacklist: 0, 
    nodes_total: 0, 
    nodes_connected: 0 
  });
  const [nodes, setNodes] = useState<NodeStats[]>([]);
  const [users, setUsers] = useState<UserStats[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    try {
      const [statsRes, nodesRes, usersRes] = await Promise.all([
        fetch("/api/stats"),
        fetch("/api/nodes"),
        fetch("/api/users/all"),
      ]);
      
      if (statsRes.ok) setStats(await statsRes.json());
      if (nodesRes.ok) setNodes(await nodesRes.json());
      if (usersRes.ok) setUsers(await usersRes.json());
    } catch (error) {
      console.error("Failed to fetch data:", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    // Auto-refresh every 5 seconds
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-muted-foreground">Loading...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <div className="border-b">
        <div className="flex h-16 items-center px-4 md:px-8">
          <h1 className="text-xl font-bold">Xray Log Analyzer</h1>
          <div className="ml-auto flex items-center space-x-4">
            <span className="text-sm text-muted-foreground">
              analyzer.z-hq.com
            </span>
          </div>
        </div>
      </div>

      <main className="p-4 md:p-8 space-y-6">
        <StatsCards
          totalRequests={stats.total_requests}
          totalBlacklist={stats.total_blacklist}
          nodesConnected={stats.nodes_connected}
          nodesTotal={stats.nodes_total}
        />

        <div className="grid gap-6 md:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>Nodes</CardTitle>
              <CardDescription>Connected Xray nodes and their status</CardDescription>
            </CardHeader>
            <CardContent>
              <NodesTable nodes={nodes} />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Blacklist Alerts</CardTitle>
              <CardDescription>Users with suspicious activity</CardDescription>
            </CardHeader>
            <CardContent>
              <UsersTable users={users} showBlacklistOnly />
            </CardContent>
          </Card>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>All Users</CardTitle>
            <CardDescription>Top users by request count</CardDescription>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="all">
              <TabsList>
                <TabsTrigger value="all">All Users</TabsTrigger>
                <TabsTrigger value="blacklist">Blacklist Only</TabsTrigger>
              </TabsList>
              <TabsContent value="all" className="mt-4">
                <UsersTable users={users} />
              </TabsContent>
              <TabsContent value="blacklist" className="mt-4">
                <UsersTable users={users} showBlacklistOnly />
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      </main>
    </div>
  );
}
