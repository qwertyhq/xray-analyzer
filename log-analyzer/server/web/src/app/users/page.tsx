"use client";

import { useWsUsers, useWsStats } from "@/contexts/websocket-context";
import { UsersTable } from "@/components/users/users-table";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Wifi, WifiOff } from "lucide-react";

export default function UsersPage() {
  const { users, loading, connected } = useWsUsers();
  const { stats } = useWsStats();

  if (loading) {
    return (
      <div className="p-4 md:p-8 space-y-6">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-[600px]" />
      </div>
    );
  }

  const blacklistUsers = users.filter(u => u.blacklist_hits > 0);
  const totalRequests = users.reduce((sum, u) => sum + u.total_requests, 0);
  const totalBlacklistHits = users.reduce((sum, u) => sum + u.blacklist_hits, 0);

  return (
    <div className="p-4 md:p-8 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div>
          <h2 className="text-xl sm:text-2xl font-bold tracking-tight">Users</h2>
          <p className="text-sm text-muted-foreground">
            All users across all nodes, sorted by activity
          </p>
        </div>
        <Badge 
          variant={connected ? "default" : "destructive"} 
          className="flex items-center gap-1.5 self-start sm:self-auto"
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

      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Total Users</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{(stats.total_unique_users || users.length).toLocaleString()}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Total Requests</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{totalRequests.toLocaleString()}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-destructive">Flagged Users</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-destructive">{blacklistUsers.length}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-destructive">Blacklist Hits</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-destructive">{totalBlacklistHits}</div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>User Activity</CardTitle>
          <CardDescription>
            Search and filter users by email or node
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="all">
            <TabsList>
              <TabsTrigger value="all">
                All Users
                <Badge variant="secondary" className="ml-2">{users.length}</Badge>
              </TabsTrigger>
              <TabsTrigger value="blacklist">
                Blacklist Only
                <Badge variant="destructive" className="ml-2">{blacklistUsers.length}</Badge>
              </TabsTrigger>
            </TabsList>
            <TabsContent value="all" className="mt-4">
              <UsersTable users={users} showSearch pageSize={25} />
            </TabsContent>
            <TabsContent value="blacklist" className="mt-4">
              <UsersTable users={users} showBlacklistOnly showSearch pageSize={25} />
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
}
