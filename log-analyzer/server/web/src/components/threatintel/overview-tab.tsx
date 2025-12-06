"use client";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ThreatMatch, ThreatStats, FeedStatus, CategoryTopUsers } from "@/lib/types";
import { formatDistanceToNow } from "date-fns";
import { threatTypeConfig, sourceLabels } from "./config";
import { UserList } from "./user-list";
import { MatchesTable } from "./matches-table";

interface OverviewTabProps {
  stats: ThreatStats | null;
  feeds: FeedStatus[];
  topUsers: CategoryTopUsers | null;
  threatMatches: ThreatMatch[];
}

export function OverviewTab({ stats, feeds, topUsers, threatMatches }: OverviewTabProps) {
  return (
    <div className="space-y-6">
      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Total Indicators</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {stats?.total_indicators.toLocaleString() || 0}
            </div>
            <p className="text-xs text-muted-foreground">Loaded from feeds</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Total Matches</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-destructive">
              {stats?.total_matches || 0}
            </div>
            <p className="text-xs text-muted-foreground">All time</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Matches (24h)</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-orange-500">
              {stats?.matches_24h || 0}
            </div>
            <p className="text-xs text-muted-foreground">Last 24 hours</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Active Feeds</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-500">
              {feeds.filter((f) => f.status === "ok").length}/{feeds.length}
            </div>
            <p className="text-xs text-muted-foreground">Feeds online</p>
          </CardContent>
        </Card>
      </div>

      {/* Feed Status */}
      <Card>
        <CardHeader>
          <CardTitle>Feed Status</CardTitle>
          <CardDescription>Status of threat intelligence data sources</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Source</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Indicators</TableHead>
                <TableHead>Last Update</TableHead>
                <TableHead>Next Update</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {feeds.map((feed) => (
                <TableRow key={feed.source}>
                  <TableCell className="font-medium">
                    {sourceLabels[feed.source] || feed.source}
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant={feed.status === "ok" ? "default" : "destructive"}
                    >
                      {feed.status}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-right">
                    {feed.indicators.toLocaleString()}
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {feed.last_update
                      ? formatDistanceToNow(new Date(feed.last_update), { addSuffix: true })
                      : "—"}
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {feed.next_update
                      ? formatDistanceToNow(new Date(feed.next_update), { addSuffix: true })
                      : "—"}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Top Users by Content Category */}
      {topUsers && (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {(["porn", "gambling", "social", "fakenews"] as const).map((category) => {
            const users = topUsers[category] || [];
            const config = threatTypeConfig[category];
            const totalCount = users.reduce((sum, u) => sum + u.match_count, 0);
            
            return (
              <Card key={category}>
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className={`p-1.5 rounded-md ${config.color}`}>
                        <span className="text-white">{config.icon}</span>
                      </div>
                      <CardTitle className="text-sm font-medium">{config.label}</CardTitle>
                    </div>
                    {totalCount > 0 && (
                      <span className="text-xl font-bold">{totalCount}</span>
                    )}
                  </div>
                </CardHeader>
                <CardContent className="pt-0">
                  <UserList users={users} />
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {/* Recent Threat Matches (excluding torrent/tor) */}
      <MatchesTable 
        matches={threatMatches} 
        title="Recent Threat Matches"
        description={`Traffic that matched known threat indicators (${threatMatches.length} total)`}
      />
    </div>
  );
}
