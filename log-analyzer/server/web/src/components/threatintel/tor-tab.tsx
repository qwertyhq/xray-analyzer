"use client";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Globe } from "lucide-react";
import { ThreatMatch, FeedStatus, CategoryUserStats } from "@/lib/types";
import Link from "next/link";
import { MatchesTable } from "./matches-table";

interface TorTabProps {
  matches: ThreatMatch[];
  topUsers: CategoryUserStats[];
  feeds: FeedStatus[];
}

export function TorTab({ matches, topUsers, feeds }: TorTabProps) {
  // Sum indicators from all Tor-related feeds
  const totalIndicators = feeds.reduce((sum, f) => sum + (f.indicators || 0), 0);
  // Calculate total detections from topUsers (aggregated stats)
  const totalDetections = topUsers?.reduce((sum, u) => sum + u.match_count, 0) || 0;
  const uniqueUsers = topUsers?.length || 0;

  // Check if we have any data at all
  const hasData = totalDetections > 0 || uniqueUsers > 0 || matches.length > 0;
  
  return (
    <div className="space-y-6">
      {/* Tor Stats */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Globe className="h-4 w-4 text-violet-600" />
              Tor Detections
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-violet-600">
              {totalDetections.toLocaleString()}
            </div>
            <p className="text-xs text-muted-foreground">All time</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Unique Users</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {uniqueUsers}
            </div>
            <p className="text-xs text-muted-foreground">Using Tor</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Exit Nodes Loaded</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {totalIndicators.toLocaleString()}
            </div>
            <p className="text-xs text-muted-foreground">IPs & domains</p>
          </CardContent>
        </Card>
      </div>

      {/* No Data State */}
      {!hasData && (
        <Card>
          <CardContent className="py-12">
            <div className="text-center text-muted-foreground">
              <Globe className="h-12 w-12 mx-auto mb-4 opacity-30" />
              <h3 className="text-lg font-medium mb-2">Нет данных о Tor-активности</h3>
              <p className="text-sm max-w-md mx-auto">
                Пользователи не обращались к exit-нодам Tor сети. 
                Мониторинг активен с {totalIndicators.toLocaleString()} индикаторами.
              </p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Top Tor Users */}
      {hasData && topUsers && topUsers.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Globe className="h-5 w-5 text-violet-600" />
              Top Tor Users
            </CardTitle>
            <CardDescription>Users with most Tor network activity</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {topUsers.map((user, idx) => (
                <div key={user.user_email} className="flex items-start gap-3 p-3 rounded-lg border">
                  <span className={`text-lg font-bold w-6 ${
                    idx === 0 ? "text-yellow-500" :
                    idx === 1 ? "text-gray-400" :
                    idx === 2 ? "text-amber-600" :
                    "text-muted-foreground"
                  }`}>
                    {idx + 1}
                  </span>
                  <div className="flex-1 min-w-0">
                    <Link
                      href={`/users/${encodeURIComponent(user.user_email)}`}
                      className="font-medium hover:underline block truncate"
                    >
                      {user.user_email}
                    </Link>
                    <div className="flex items-center gap-2 mt-1">
                      <Badge variant="secondary">{user.match_count} hits</Badge>
                    </div>
                    {user.domains && user.domains.length > 0 && (
                      <div className="mt-2 text-xs text-muted-foreground">
                        {user.domains.slice(0, 3).map((d, i) => (
                          <span key={d} className="font-mono">
                            {d}{i < Math.min(user.domains.length, 3) - 1 ? ", " : ""}
                          </span>
                        ))}
                        {user.domains.length > 3 && <span> +{user.domains.length - 3} more</span>}
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Tor Matches Table - only show if we have recent matches */}
      {matches.length > 0 && (
        <MatchesTable 
          matches={matches} 
          title="Recent Tor Activity"
          description={`Последние обнаружения Tor-активности (${matches.length} записей)`}
        />
      )}
    </div>
  );
}
