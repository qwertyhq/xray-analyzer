"use client";

import { useParams } from "next/navigation";
import Link from "next/link";
import { useUserDetails } from "@/hooks/use-api";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ArrowLeft, User, Activity, ShieldAlert, Globe, Wifi, AlertTriangle, Gauge } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { isValidDate } from "@/lib/utils/date";
import { UserDestinationsTable } from "@/components/users/user-destinations-table";
import { UserBlacklistMatches } from "@/components/users/user-blacklist-matches";
import { UserIPHistoryTable } from "@/components/users/user-ip-history";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

export default function UserDetailsPage() {
  const params = useParams();
  const email = decodeURIComponent(params.email as string);
  const { details, loading, error } = useUserDetails(email);

  if (loading) {
    return (
      <div className="p-4 md:p-8 space-y-6">
        <Skeleton className="h-8 w-64" />
        <div className="grid gap-4 md:grid-cols-3">
          <Skeleton className="h-[100px]" />
          <Skeleton className="h-[100px]" />
          <Skeleton className="h-[100px]" />
        </div>
        <Skeleton className="h-[400px]" />
      </div>
    );
  }

  if (error || !details) {
    return (
      <div className="p-4 md:p-8">
        <Link href="/users">
          <Button variant="ghost" className="mb-4">
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Users
          </Button>
        </Link>
        <Card>
          <CardContent className="pt-6">
            <p className="text-center text-muted-foreground">
              {error || "User not found"}
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="p-4 md:p-8 space-y-6">
      <div className="flex items-center gap-2 sm:gap-4">
        <Link href="/users">
          <Button variant="ghost" size="icon" className="shrink-0">
            <ArrowLeft className="h-4 w-4" />
          </Button>
        </Link>
        <div className="min-w-0">
          <h2 className="text-lg sm:text-2xl font-bold tracking-tight flex items-center gap-2 truncate">
            <User className="h-5 w-5 sm:h-6 sm:w-6 shrink-0" />
            <span className="truncate">{details.display_name || details.user_email}</span>
          </h2>
          <p className="text-sm text-muted-foreground">
            {details.display_name && details.display_name !== details.user_email && (
              <span className="mr-2 font-mono text-xs">{details.user_email}</span>
            )}
            User activity across {details.nodes.length} node(s)
          </p>
        </div>
      </div>

      <div className="grid gap-4 grid-cols-2 md:grid-cols-5">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-xs sm:text-sm font-medium">Requests</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground hidden sm:block" />
          </CardHeader>
          <CardContent>
            <div className="text-lg sm:text-2xl font-bold">
              {details.total_requests.toLocaleString()}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-xs sm:text-sm font-medium">Blacklist</CardTitle>
            <ShieldAlert className="h-4 w-4 text-muted-foreground hidden sm:block" />
          </CardHeader>
          <CardContent>
            <div className={`text-lg sm:text-2xl font-bold ${details.total_blacklist_hits > 0 ? "text-destructive" : ""}`}>
              {details.total_blacklist_hits}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-xs sm:text-sm font-medium">Threats</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground hidden sm:block" />
          </CardHeader>
          <CardContent>
            <div className={`text-lg sm:text-2xl font-bold ${(details.total_threats ?? 0) > 0 ? "text-orange-500" : ""}`}>
              {details.total_threats ?? 0}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-xs sm:text-sm font-medium">Risk</CardTitle>
            <Gauge className="h-4 w-4 text-muted-foreground hidden sm:block" />
          </CardHeader>
          <CardContent>
            {details.risk_level ? (
              <div className="flex items-baseline gap-2">
                <div className={`text-lg sm:text-2xl font-bold ${
                  details.risk_level === "critical" ? "text-destructive" :
                  details.risk_level === "high" ? "text-orange-500" :
                  details.risk_level === "medium" ? "text-yellow-500" :
                  "text-green-500"
                }`}>
                  {details.risk_score ?? 0}
                </div>
                <span className="text-xs text-muted-foreground uppercase">{details.risk_level}</span>
              </div>
            ) : (
              <div className="text-lg sm:text-2xl font-bold text-muted-foreground">—</div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-xs sm:text-sm font-medium">Nodes</CardTitle>
            <Globe className="h-4 w-4 text-muted-foreground hidden sm:block" />
          </CardHeader>
          <CardContent>
            <div className="text-lg sm:text-2xl font-bold">{details.nodes.length}</div>
          </CardContent>
        </Card>
      </div>

      {details.threats_by_type && Object.keys(details.threats_by_type).length > 0 && (() => {
        // Group threats by category. Aggregate counts come from
        // threats_by_type (full history); recent_threats gives the last N matches
        // per category (subject to the 1000/category recent-matches cap).
        const sortedCats = Object.entries(details.threats_by_type)
          .sort(([, a], [, b]) => b - a)
          .map(([type]) => type);
        const byCat: Record<string, typeof details.recent_threats> = {};
        (details.recent_threats ?? []).forEach(t => {
          (byCat[t.threat_type] ??= []).push(t);
        });
        return (
          <Card>
            <CardHeader>
              <CardTitle className="text-base sm:text-lg flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-orange-500" />
                Threat Intelligence
              </CardTitle>
              <CardDescription className="text-xs sm:text-sm">
                Threats grouped by category. Counts are lifetime (aggregated);
                tables show last 50 recent matches per category.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Tabs defaultValue={sortedCats[0]} className="w-full">
                <TabsList className="flex flex-wrap h-auto justify-start gap-1">
                  {sortedCats.map(cat => (
                    <TabsTrigger key={cat} value={cat} className="font-mono text-xs">
                      <span className="uppercase">{cat}</span>
                      <span className="ml-2 opacity-70">{details.threats_by_type?.[cat] ?? 0}</span>
                    </TabsTrigger>
                  ))}
                </TabsList>
                {sortedCats.map(cat => {
                  const rows = byCat[cat] ?? [];
                  return (
                    <TabsContent key={cat} value={cat} className="mt-4">
                      {rows.length === 0 ? (
                        <p className="text-sm text-muted-foreground py-4">
                          No recent matches in this category (older matches trimmed).
                        </p>
                      ) : (
                        <div className="overflow-x-auto">
                          <Table>
                            <TableHeader>
                              <TableRow>
                                <TableHead className="whitespace-nowrap">Time</TableHead>
                                <TableHead>Destination</TableHead>
                                <TableHead className="hidden md:table-cell">Source</TableHead>
                                <TableHead className="text-right hidden sm:table-cell">Conf</TableHead>
                                <TableHead className="hidden lg:table-cell">Node</TableHead>
                              </TableRow>
                            </TableHeader>
                            <TableBody>
                              {rows.map((t, i) => (
                                <TableRow key={i}>
                                  <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                                    {isValidDate(t.matched_at)
                                      ? formatDistanceToNow(new Date(t.matched_at), { addSuffix: true })
                                      : "—"}
                                  </TableCell>
                                  <TableCell className="font-mono text-xs max-w-[260px] truncate" title={t.destination}>
                                    {t.destination}
                                  </TableCell>
                                  <TableCell className="text-xs text-muted-foreground hidden md:table-cell">
                                    {t.source}
                                  </TableCell>
                                  <TableCell className="text-right hidden sm:table-cell">
                                    <span className={t.confidence >= 90 ? "text-destructive" : t.confidence >= 75 ? "text-orange-500" : ""}>
                                      {t.confidence}
                                    </span>
                                  </TableCell>
                                  <TableCell className="hidden lg:table-cell">
                                    <Badge variant="outline" className="text-xs">{t.node_id}</Badge>
                                  </TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </div>
                      )}
                    </TabsContent>
                  );
                })}
              </Tabs>
            </CardContent>
          </Card>
        );
      })()}

      <Card>
        <CardHeader>
          <CardTitle className="text-base sm:text-lg">Activity by Node</CardTitle>
          <CardDescription className="text-xs sm:text-sm">User statistics per connected node</CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="whitespace-nowrap">Node</TableHead>
                <TableHead className="text-right whitespace-nowrap">Requests</TableHead>
                <TableHead className="text-right whitespace-nowrap">Blacklist</TableHead>
                <TableHead className="text-right whitespace-nowrap hidden sm:table-cell">Destinations</TableHead>
                <TableHead className="whitespace-nowrap hidden md:table-cell">Last Seen</TableHead>
                <TableHead className="whitespace-nowrap hidden lg:table-cell">Last Blocked</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {details.nodes.map((node) => (
                <TableRow key={node.node_id}>
                  <TableCell>
                    <Badge variant="outline" className="whitespace-nowrap">{node.node_id}</Badge>
                  </TableCell>
                  <TableCell className="text-right">
                    {node.total_requests.toLocaleString()}
                  </TableCell>
                  <TableCell className="text-right">
                    {node.blacklist_hits > 0 ? (
                      <Badge variant="destructive">{node.blacklist_hits}</Badge>
                    ) : (
                      <span className="text-muted-foreground">0</span>
                    )}
                  </TableCell>
                  <TableCell className="text-right hidden sm:table-cell">
                    {node.unique_destinations}
                  </TableCell>
                  <TableCell className="text-muted-foreground text-sm hidden md:table-cell whitespace-nowrap">
                    {isValidDate(node.last_seen)
                      ? formatDistanceToNow(new Date(node.last_seen), { addSuffix: true })
                      : "—"
                    }
                  </TableCell>
                  <TableCell className="text-muted-foreground text-sm max-w-[200px] truncate hidden lg:table-cell">
                    {node.last_blacklist_domain || "—"}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base sm:text-lg flex items-center gap-2">
            <Wifi className="h-4 w-4" />
            IP Address History
          </CardTitle>
          <CardDescription className="text-xs sm:text-sm">Last 20 IP addresses used by this user</CardDescription>
        </CardHeader>
        <CardContent>
          <UserIPHistoryTable email={email} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Visited Destinations</CardTitle>
          <CardDescription>Resources visited by this user (sorted by request count)</CardDescription>
        </CardHeader>
        <CardContent>
          <UserDestinationsTable email={email} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-destructive">Blacklist Matches</CardTitle>
          <CardDescription>Blocked requests for this user</CardDescription>
        </CardHeader>
        <CardContent>
          <UserBlacklistMatches email={email} />
        </CardContent>
      </Card>
    </div>
  );
}
