"use client";

import { useState, useEffect, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
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
  TrendingUp
} from "lucide-react";
import { RemnawaveStats, RemnawaveAbuseUser } from "@/lib/types";

export default function RemnavewavePage() {
  const [stats, setStats] = useState<RemnawaveStats | null>(null);
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

      const [statsRes, abuseRes] = await Promise.all([
        fetch("/api/remnawave/stats", { headers }),
        fetch("/api/remnawave/abuse", { headers })
      ]);

      if (!statsRes.ok) {
        throw new Error(`Stats fetch failed: ${statsRes.status}`);
      }
      if (!abuseRes.ok) {
        throw new Error(`Abuse fetch failed: ${abuseRes.status}`);
      }

      const [statsData, abuseData] = await Promise.all([
        statsRes.json(),
        abuseRes.json()
      ]);

      setStats(statsData);
      setAbuseUsers(abuseData.users || []);
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
    // Auto-refresh every 5 minutes
    const interval = setInterval(() => fetchData(true), 5 * 60 * 1000);
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
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
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
              <Badge variant="secondary" className="text-xs">
                Disabled: {stats?.disabledUsers ?? 0}
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
              Уникальных пользователей: {stats?.hwidStats?.uniqueUsers ?? 0}
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
      <Tabs defaultValue="abuse" className="space-y-4">
        <TabsList>
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
