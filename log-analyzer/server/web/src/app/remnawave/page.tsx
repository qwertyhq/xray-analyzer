"use client";

import { useState, useEffect, useCallback, useMemo } from "react";
import { authFetch } from "@/contexts/auth-context";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { PaginationControls, usePagination } from "@/components/ui/data-table";
import { RemnawaveUsersTable } from "@/components/remnawave/remnawave-users-table";
import { AnimatedNumber } from "@/components/ui/animated-number";
import { 
  Users, 
  Smartphone, 
  AlertTriangle, 
  Activity, 
  RefreshCw,
  Server,
  TrendingUp,
  Wifi,
  Clock,
  Globe
} from "lucide-react";
import { useTranslations } from "next-intl";
import { RemnawaveStats, RemnawaveOnlineStats } from "@/lib/types";

export default function RemnavewavePage() {
  const t = useTranslations("remnawave");
  const tCommon = useTranslations("common");
  const [stats, setStats] = useState<RemnawaveStats | null>(null);
  const [onlineStats, setOnlineStats] = useState<RemnawaveOnlineStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);

  const fetchData = useCallback(async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    else setLoading(true);
    
    setError(null);
    
    try {
      const token = localStorage.getItem("auth_token");
      const headers: HeadersInit = {};
      if (token) {
        headers["Authorization"] = `Bearer ${token}`;
      }

      const [statsRes, onlineRes] = await Promise.all([
        authFetch("/api/remnawave/stats", { headers }),
        authFetch("/api/remnawave/online", { headers })
      ]);

      // All endpoints now return JSON even when Remnawave is not configured
      const [statsData, onlineData] = await Promise.all([
        statsRes.ok ? statsRes.json() : { enabled: false },
        onlineRes.ok ? onlineRes.json() : { enabled: false, onlineUsers: [] }
      ]);

      setStats(statsData);
      setOnlineStats(onlineData);
      setLastUpdate(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch data");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    // Auto-refresh every 10 seconds (instant from cache)
    const interval = setInterval(() => fetchData(true), 10 * 1000);
    return () => clearInterval(interval);
  }, [fetchData]);

  // Pagination for online users - must be called before any early returns
  const onlineUsersPagination = usePagination(onlineStats?.onlineUsers ?? []);

  if (loading) {
    return (
      <div className="container mx-auto py-6 px-4 space-y-6">
        <div className="flex justify-between items-center">
          <div>
            <Skeleton className="h-8 w-48 mb-2" />
            <Skeleton className="h-4 w-64" />
          </div>
          <Skeleton className="h-10 w-32" />
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => (
            <Card key={i}>
              <CardHeader className="pb-2">
                <Skeleton className="h-4 w-24" />
              </CardHeader>
              <CardContent>
                <Skeleton className="h-8 w-16" />
              </CardContent>
            </Card>
          ))}
        </div>
        <Card>
          <CardContent className="p-6">
            <Skeleton className="h-96 w-full" />
          </CardContent>
        </Card>
      </div>
    );
  }

  if (error) {
    return (
      <div className="container mx-auto py-6 px-4">
        <Card className="border-destructive">
          <CardHeader>
            <CardTitle className="text-destructive flex items-center gap-2">
              <AlertTriangle className="h-5 w-5" />
              {t("errorTitle")}
            </CardTitle>
            <CardDescription>{error}</CardDescription>
          </CardHeader>
          <CardContent>
            <Button onClick={() => fetchData()}>
              <RefreshCw className="h-4 w-4 mr-2" />
              {t("retry")}
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="container mx-auto py-6 px-4 space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Activity className="h-6 w-6 text-primary" />
            {t("title")}
          </h1>
          <p className="text-muted-foreground">
            {t("description")}
            {lastUpdate && (
              <span className="ml-2 text-xs">
                • {t("updated")} {lastUpdate.toLocaleTimeString()}
              </span>
            )}
            {onlineStats?.lastSync && (
              <span className="ml-2 text-xs text-green-500">
                • {t("syncEveryMinute")}
              </span>
            )}
          </p>
        </div>
        <Button 
          variant="outline" 
          onClick={() => fetchData(true)}
          disabled={refreshing}
        >
          <RefreshCw className={`h-4 w-4 mr-2 ${refreshing ? 'animate-spin' : ''}`} />
          {t("refresh")}
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Online Now - Featured Card */}
        <Card className="border-green-500/50 bg-green-500/5">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Wifi className="h-4 w-4 text-green-500" />
              {t("onlineNow")}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-green-500">
              <AnimatedNumber value={onlineStats?.now ?? 0} />
            </div>
            <div className="flex gap-2 mt-2 text-xs text-muted-foreground">
              <span>{t("mins15")} <AnimatedNumber value={onlineStats?.recent ?? 0} /></span>
              <span>•</span>
              <span>{t("hour1")} <AnimatedNumber value={onlineStats?.lastHour ?? 0} /></span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Users className="h-4 w-4 text-muted-foreground" />
              {t("totalUsers")}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              <AnimatedNumber value={stats?.totalUsers ?? 0} />
            </div>
            <div className="flex gap-2 mt-2">
              <Badge variant="default" className="bg-green-500 text-xs">
                Active: <AnimatedNumber value={stats?.activeUsers ?? 0} />
              </Badge>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Smartphone className="h-4 w-4 text-muted-foreground" />
              {t("hwidDevices")}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              <AnimatedNumber value={stats?.hwidStats?.totalDevices ?? 0} />
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              {t("unique")} <AnimatedNumber value={stats?.hwidStats?.uniqueUsers ?? 0} />
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Server className="h-4 w-4 text-muted-foreground" />
              {t("platforms")}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-1">
              {stats?.hwidStats?.platformBreakdown ? (
                Object.entries(stats.hwidStats.platformBreakdown)
                  .sort(([,a], [,b]) => b - a)
                  .slice(0, 3)
                  .map(([platform, count]) => (
                    <div key={platform} className="flex justify-between text-sm">
                      <span className="text-muted-foreground">{platform || "Unknown"}</span>
                      <span className="font-medium">{count}</span>
                    </div>
                  ))
              ) : (
                <span className="text-sm text-muted-foreground">{t("noData")}</span>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main Content */}
      <Tabs defaultValue="online" className="space-y-4">
        <TabsList>
          <TabsTrigger value="online" className="flex items-center gap-2">
            <Wifi className="h-4 w-4" />
            {t("tabOnline")}
            {onlineStats && onlineStats.now > 0 && (
              <Badge variant="default" className="ml-1 bg-green-500">
                {onlineStats.now}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="users" className="flex items-center gap-2">
            <Users className="h-4 w-4" />
            {t("tabUsers")}
          </TabsTrigger>
          <TabsTrigger value="analytics" className="flex items-center gap-2">
            <TrendingUp className="h-4 w-4" />
            {t("tabAnalytics")}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="online" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Wifi className="h-5 w-5 text-green-500" />
                {t("onlineUsersTitle")}
              </CardTitle>
              <CardDescription>
                {t("onlineUsersDesc")}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {/* Online Stats Summary */}
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
                <div className="text-center p-3 bg-green-500/10 rounded-lg">
                  <div className="text-2xl font-bold text-green-500">{onlineStats?.now ?? 0}</div>
                  <div className="text-xs text-muted-foreground">{t("now5min")}</div>
                </div>
                <div className="text-center p-3 bg-muted/50 rounded-lg">
                  <div className="text-2xl font-bold">{onlineStats?.recent ?? 0}</div>
                  <div className="text-xs text-muted-foreground">{t("last15min")}</div>
                </div>
                <div className="text-center p-3 bg-muted/50 rounded-lg">
                  <div className="text-2xl font-bold">{onlineStats?.lastHour ?? 0}</div>
                  <div className="text-xs text-muted-foreground">{t("lastHour")}</div>
                </div>
                <div className="text-center p-3 bg-muted/50 rounded-lg">
                  <div className="text-2xl font-bold">{onlineStats?.last24h ?? 0}</div>
                  <div className="text-xs text-muted-foreground">{t("last24h")}</div>
                </div>
                <div className="text-center p-3 bg-muted/50 rounded-lg">
                  <div className="text-2xl font-bold text-muted-foreground">{onlineStats?.neverOnline ?? 0}</div>
                  <div className="text-xs text-muted-foreground">{t("neverOnline")}</div>
                </div>
              </div>

              {/* Online Users Table */}
              {onlineStats?.onlineUsers && onlineStats.onlineUsers.length > 0 ? (
                <>
                <div className="max-h-[600px] overflow-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>{t("userColumn")}</TableHead>
                      <TableHead>{t("statusColumn")}</TableHead>
                      <TableHead>{t("lastActivityColumn")}</TableHead>
                      <TableHead>{t("nodeColumn")}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {onlineUsersPagination.paginatedData.map((user) => (
                      <TableRow key={user.uuid}>
                        <TableCell>
                          <div className="space-y-1">
                            <div className="font-medium flex items-center gap-2">
                              <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span>
                              {user.username}
                            </div>
                            {user.email && (
                              <div className="text-xs text-muted-foreground">{user.email}</div>
                            )}
                            {user.parsedRealName && (
                              <div className="text-xs text-muted-foreground">{user.parsedRealName}</div>
                            )}
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge variant={user.status === "ACTIVE" ? "default" : "secondary"}
                                 className={user.status === "ACTIVE" ? "bg-green-500" : ""}>
                            {user.status}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <Clock className="h-3 w-3 text-muted-foreground" />
                            <span className="text-sm">
                              {user.minutesAgo === 0 ? tCommon("justNow") : tCommon("minutesAgo", { count: user.minutesAgo })}
                            </span>
                          </div>
                        </TableCell>
                        <TableCell>
                          {user.lastConnectedNode ? (
                            <div className="flex items-center gap-2">
                              <Globe className="h-3 w-3 text-muted-foreground" />
                              <span className="text-sm">{user.lastConnectedNode}</span>
                              {user.countryCode && (
                                <Badge variant="outline" className="text-xs">
                                  {user.countryCode}
                                </Badge>
                              )}
                            </div>
                          ) : (
                            <span className="text-muted-foreground">—</span>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                </div>
                <PaginationControls {...onlineUsersPagination} />
                </>
              ) : (
                <div className="text-center py-8 text-muted-foreground">
                  <Wifi className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>{t("noOnlineUsers")}</p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="users" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Users className="h-5 w-5" />
                {t("remnawaveUsers")}
              </CardTitle>
              <CardDescription>
                {t("remnawaveUsersDesc")}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <RemnawaveUsersTable />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="analytics" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Traffic Stats */}
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">{t("trafficUsage")}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground">{t("totalTraffic")}</span>
                    <span className="font-medium">
                      {stats?.totalTrafficUsed
                        ? `${(stats.totalTrafficUsed / (1024 * 1024 * 1024)).toFixed(2)} GB`
                        : tCommon("notAvailable")
                      }
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground">{t("avgPerUser")}</span>
                    <span className="font-medium">
                      {stats?.totalTrafficUsed && stats?.activeUsers
                        ? `${(stats.totalTrafficUsed / stats.activeUsers / (1024 * 1024 * 1024)).toFixed(2)} GB`
                        : tCommon("notAvailable")
                      }
                    </span>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Status Distribution */}
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">{t("statusDistribution")}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <div className="flex justify-between items-center">
                    <Badge variant="default" className="bg-green-500">ACTIVE</Badge>
                    <span className="font-medium">{stats?.activeUsers ?? 0}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <Badge variant="secondary">DISABLED</Badge>
                    <span className="font-medium">{stats?.disabledUsers ?? 0}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <Badge variant="default" className="bg-orange-500">LIMITED</Badge>
                    <span className="font-medium">{stats?.limitedUsers ?? 0}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <Badge variant="destructive">EXPIRED</Badge>
                    <span className="font-medium">{stats?.expiredUsers ?? 0}</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Online Activity */}
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">{t("onlineActivity")}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground">{t("lastHourLabel")}</span>
                    <span className="font-medium text-green-500">
                      {stats?.onlineLastHour ?? "—"}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground">{t("last24hLabel")}</span>
                    <span className="font-medium">
                      {stats?.onlineLast24h ?? "—"}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground">{t("neverOnlineLabel")}</span>
                    <span className="font-medium text-muted-foreground">
                      {stats?.neverOnline ?? "—"}
                    </span>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Device Limits */}
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">{t("deviceLimits")}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground">{t("withHwidLimit")}</span>
                    <span className="font-medium">
                      {stats?.usersWithHwidLimit ?? "—"}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground">{t("totalDevices")}</span>
                    <span className="font-medium">
                      {stats?.hwidStats?.totalDevices ?? "—"}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground">{t("avgDevices")}</span>
                    <span className="font-medium">
                      {stats?.hwidStats?.totalDevices && stats?.hwidStats?.uniqueUsers
                        ? (stats.hwidStats.totalDevices / stats.hwidStats.uniqueUsers).toFixed(1)
                        : "—"
                      }
                    </span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
