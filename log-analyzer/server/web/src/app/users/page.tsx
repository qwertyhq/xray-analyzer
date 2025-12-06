"use client";

import { useUsers, useApi } from "@/hooks/use-api";
import { UsersTable } from "@/components/users/users-table";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";

export default function UsersPage() {
  const { users, loading } = useUsers();
  const { stats } = useApi();

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
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Users</h2>
        <p className="text-muted-foreground">
          All users across all nodes, sorted by activity
        </p>
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
