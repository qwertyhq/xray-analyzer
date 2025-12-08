"use client";

import { useState, useEffect, useCallback } from "react";
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
import { RemnawaveUsersTable } from "@/components/remnawave/remnawave-users-table";
import { RemnawaveAbuseTable } from "@/components/remnawave/remnawave-abuse-table";
import { 
  Users, 
  Smartphone, 
  AlertTriangle, 
  Activity, 
  RefreshCw,
  Server,
  Shield,
  TrendingUp,
  Wifi,
  Clock,
  Globe
} from "lucide-react";
import { RemnawaveStats, RemnawaveAbuseUser, RemnawaveOnlineStats } from "@/lib/types";

export default function RemnavewavePage() {
  const [stats, setStats] = useState<RemnawaveStats | null>(null);
  const [onlineStats, setOnlineStats] = useState<RemnawaveOnlineStats | null>(null);
  const [abuseUsers, setAbuseUsers] = useState<RemnawaveAbuseUser[]>([]);
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

      const [statsRes, abuseRes, onlineRes] = await Promise.all([
        fetch("/api/remnawave/stats", { headers }),
        fetch("/api/remnawave/abuse", { headers }),
        fetch("/api/remnawave/online", { headers })
      ]);

      // All endpoints now return JSON even when Remnawave is not configured
      const [statsData, abuseData, onlineData] = await Promise.all([
        statsRes.ok ? statsRes.json() : { enabled: false },
        abuseRes.ok ? abuseRes.json() : { enabled: false, users: [] },
        onlineRes.ok ? onlineRes.json() : { enabled: false, onlineUsers: [] }
      ]);

      setStats(statsData);
      setAbuseUsers(abuseData.users || []);
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
    // Auto-refresh every 1 minute for more accurate online stats
    const interval = setInterval(() => fetchData(true), 60 * 1000);
    return () => clearInterval(interval);
  }, [fetchData]);

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
              Ошибка подключения к Remnawave
            </CardTitle>
            <CardDescription>{error}</CardDescription>
          </CardHeader>
          <CardContent>
            <Button onClick={() => fetchData()}>
              <RefreshCw className="h-4 w-4 mr-2" />
              Повторить
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  const highRiskCount = abuseUsers.filter(u => u.excessDevices >= 3).length;
  const mediumRiskCount = abuseUsers.filter(u => u.excessDevices === 2).length;
  const lowRiskCount = abuseUsers.filter(u => u.excessDevices === 1).length;

  return (
    <div className="container mx-auto py-6 px-4 space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Activity className="h-6 w-6 text-primary" />
            Remnawave Analytics
          </h1>
          <p className="text-muted-foreground">
            Расширенная аналитика на основе данных Remnawave API
            {lastUpdate && (
              <span className="ml-2 text-xs">
                • Обновлено: {lastUpdate.toLocaleTimeString()}
              </span>
            )}
            {onlineStats?.lastSync && (
              <span className="ml-2 text-xs text-green-500">
                • Синхронизация каждую минуту
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
          Обновить
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Online Now - Featured Card */}
        <Card className="border-green-500/50 bg-green-500/5">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Wifi className="h-4 w-4 text-green-500" />
              Онлайн сейчас
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-green-500">{onlineStats?.now ?? 0}</div>
            <div className="flex gap-2 mt-2 text-xs text-muted-foreground">
              <span>15 мин: {onlineStats?.recent ?? 0}</span>
              <span>•</span>
              <span>1ч: {onlineStats?.lastHour ?? 0}</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Users className="h-4 w-4 text-muted-foreground" />
              Всего пользователей
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.totalUsers ?? 0}</div>
            <div className="flex gap-2 mt-2">
              <Badge variant="default" className="bg-green-500 text-xs">
                Active: {stats?.activeUsers ?? 0}
              </Badge>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Smartphone className="h-4 w-4 text-muted-foreground" />
              HWID устройств
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.hwidStats?.totalDevices ?? 0}</div>
            <p className="text-xs text-muted-foreground mt-1">
              Уникальных: {stats?.hwidStats?.uniqueUsers ?? 0}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-muted-foreground" />
              Подозрительные
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-orange-500">{abuseUsers.length}</div>
            <div className="flex gap-1 mt-2 flex-wrap">
              {highRiskCount > 0 && (
                <Badge variant="destructive" className="text-xs">
                  High: {highRiskCount}
                </Badge>
              )}
              {mediumRiskCount > 0 && (
                <Badge variant="default" className="bg-orange-500 text-xs">
                  Medium: {mediumRiskCount}
                </Badge>
              )}
              {lowRiskCount > 0 && (
                <Badge variant="secondary" className="text-xs">
                  Low: {lowRiskCount}
                </Badge>
              )}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Server className="h-4 w-4 text-muted-foreground" />
              Платформы
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
                <span className="text-sm text-muted-foreground">Нет данных</span>
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
            Онлайн
            {onlineStats && onlineStats.now > 0 && (
              <Badge variant="default" className="ml-1 bg-green-500">
                {onlineStats.now}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="abuse" className="flex items-center gap-2">
            <Shield className="h-4 w-4" />
            Abuse Detection
            {abuseUsers.length > 0 && (
              <Badge variant="destructive" className="ml-1">
                {abuseUsers.length}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="users" className="flex items-center gap-2">
            <Users className="h-4 w-4" />
            Пользователи
          </TabsTrigger>
          <TabsTrigger value="analytics" className="flex items-center gap-2">
            <TrendingUp className="h-4 w-4" />
            Аналитика
          </TabsTrigger>
        </TabsList>

        <TabsContent value="online" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Wifi className="h-5 w-5 text-green-500" />
                Онлайн пользователи (Remnawave)
              </CardTitle>
              <CardDescription>
                Точная статистика онлайн из Remnawave API. 
                Данные обновляются каждую минуту и более точны, чем статистика на основе логов.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {/* Online Stats Summary */}
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
                <div className="text-center p-3 bg-green-500/10 rounded-lg">
                  <div className="text-2xl font-bold text-green-500">{onlineStats?.now ?? 0}</div>
                  <div className="text-xs text-muted-foreground">Сейчас (5 мин)</div>
                </div>
                <div className="text-center p-3 bg-muted/50 rounded-lg">
                  <div className="text-2xl font-bold">{onlineStats?.recent ?? 0}</div>
                  <div className="text-xs text-muted-foreground">За 15 минут</div>
                </div>
                <div className="text-center p-3 bg-muted/50 rounded-lg">
                  <div className="text-2xl font-bold">{onlineStats?.lastHour ?? 0}</div>
                  <div className="text-xs text-muted-foreground">За час</div>
                </div>
                <div className="text-center p-3 bg-muted/50 rounded-lg">
                  <div className="text-2xl font-bold">{onlineStats?.last24h ?? 0}</div>
                  <div className="text-xs text-muted-foreground">За 24 часа</div>
                </div>
                <div className="text-center p-3 bg-muted/50 rounded-lg">
                  <div className="text-2xl font-bold text-muted-foreground">{onlineStats?.neverOnline ?? 0}</div>
                  <div className="text-xs text-muted-foreground">Никогда</div>
                </div>
              </div>

              {/* Online Users Table */}
              {onlineStats?.onlineUsers && onlineStats.onlineUsers.length > 0 ? (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Пользователь</TableHead>
                      <TableHead>Статус</TableHead>
                      <TableHead>Последняя активность</TableHead>
                      <TableHead>Нода</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {onlineStats.onlineUsers.map((user) => (
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
                              {user.minutesAgo === 0 ? "Только что" : `${user.minutesAgo} мин назад`}
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
              ) : (
                <div className="text-center py-8 text-muted-foreground">
                  <Wifi className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>Нет онлайн пользователей за последние 15 минут</p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="abuse" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-orange-500" />
                HWID Abuse Detection
              </CardTitle>
              <CardDescription>
                Пользователи с превышением лимита устройств по HWID. 
                Данные основаны на реальных идентификаторах устройств, 
                а не IP-адресах.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <RemnawaveAbuseTable users={abuseUsers} />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="users" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Users className="h-5 w-5" />
                Пользователи Remnawave
              </CardTitle>
              <CardDescription>
                Полный список пользователей с данными HWID, 
                историей подключений и информацией из Note.
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
                <CardTitle className="text-lg">Использование трафика</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground">Общий трафик</span>
                    <span className="font-medium">
                      {stats?.totalTrafficUsed 
                        ? `${(stats.totalTrafficUsed / (1024 * 1024 * 1024)).toFixed(2)} GB`
                        : "N/A"
                      }
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground">Средний на пользователя</span>
                    <span className="font-medium">
                      {stats?.totalTrafficUsed && stats?.activeUsers
                        ? `${(stats.totalTrafficUsed / stats.activeUsers / (1024 * 1024 * 1024)).toFixed(2)} GB`
                        : "N/A"
                      }
                    </span>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Status Distribution */}
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">Распределение статусов</CardTitle>
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
                <CardTitle className="text-lg">Активность онлайн</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground">За последний час</span>
                    <span className="font-medium text-green-500">
                      {stats?.onlineLastHour ?? "—"}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground">За последние 24 часа</span>
                    <span className="font-medium">
                      {stats?.onlineLast24h ?? "—"}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground">Никогда не онлайн</span>
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
                <CardTitle className="text-lg">Лимиты устройств</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground">С HWID лимитом</span>
                    <span className="font-medium">
                      {stats?.usersWithHwidLimit ?? "—"}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground">Превышают лимит</span>
                    <span className="font-medium text-orange-500">
                      {abuseUsers.length}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground">Ср. устройств</span>
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
