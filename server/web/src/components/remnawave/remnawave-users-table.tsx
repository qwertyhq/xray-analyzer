"use client";

import { useState, useEffect, useCallback } from "react";
import { useTranslations } from "next-intl";
import { authFetch } from "@/contexts/auth-context";
import { formatDistanceToNow } from "date-fns";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Users,
  Smartphone,
  RefreshCw,
  Search,
  AlertTriangle,
  CheckCircle,
  Clock,
  Ban,
  UserX,
  ChevronLeft,
  ChevronRight,
  Phone,
  AtSign,
  User,
} from "lucide-react";
import { RemnawaveStats, RemnawaveUser } from "@/lib/types";

// Format bytes to human readable
function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

// Get status badge
function getStatusBadge(status: string) {
  switch (status) {
    case "ACTIVE":
      return <Badge variant="default" className="bg-green-500"><CheckCircle className="w-3 h-3 mr-1" />Active</Badge>;
    case "DISABLED":
      return <Badge variant="destructive"><Ban className="w-3 h-3 mr-1" />Disabled</Badge>;
    case "LIMITED":
      return <Badge variant="secondary" className="bg-yellow-500 text-black"><AlertTriangle className="w-3 h-3 mr-1" />Limited</Badge>;
    case "EXPIRED":
      return <Badge variant="outline"><Clock className="w-3 h-3 mr-1" />Expired</Badge>;
    default:
      return <Badge variant="outline">{status}</Badge>;
  }
}

export function RemnawaveUsersTable() {
  const t = useTranslations("remnawaveUsersTable");
  const [stats, setStats] = useState<RemnawaveStats | null>(null);
  const [users, setUsers] = useState<RemnawaveUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [abuseFilter, setAbuseFilter] = useState<string>("all");
  const [minDevices, setMinDevices] = useState<number>(0);
  const [sortBy, setSortBy] = useState<"username" | "devices" | "traffic" | "online">("username");
  const [page, setPage] = useState(1);
  const pageSize = 25;

  const fetchData = useCallback(async () => {
    try {
      const [statsRes, usersRes] = await Promise.all([
        authFetch("/api/remnawave/stats"),
        authFetch("/api/remnawave/users"),
      ]);

      if (statsRes.ok) {
        setStats(await statsRes.json());
      }
      if (usersRes.ok) {
        setUsers(await usersRes.json());
      }
    } catch (error) {
      console.error("Failed to fetch Remnawave data:", error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    // Refresh every 5 minutes
    const interval = setInterval(fetchData, 5 * 60 * 1000);
    return () => clearInterval(interval);
  }, [fetchData]);

  // Filter and sort users
  const filteredUsers = users
    .filter((u) => {
      // Search filter
      if (search) {
        const searchLower = search.toLowerCase();
        const matches =
          u.username.toLowerCase().includes(searchLower) ||
          u.email?.toLowerCase().includes(searchLower) ||
          u.parsed_real_name?.toLowerCase().includes(searchLower) ||
          u.parsed_phone?.includes(search) ||
          u.parsed_telegram_user?.toLowerCase().includes(searchLower);
        if (!matches) return false;
      }

      // Status filter
      if (statusFilter !== "all" && u.status !== statusFilter) {
        return false;
      }

      // Abuse filter
      if (abuseFilter === "exceeds" && !u.hwid_exceeds_limit) {
        return false;
      }

      // Min devices filter
      if (minDevices > 0 && (u.hwid_device_count || 0) < minDevices) {
        return false;
      }

      return true;
    })
    .sort((a, b) => {
      switch (sortBy) {
        case "devices":
          return (b.hwid_device_count || 0) - (a.hwid_device_count || 0);
        case "traffic":
          return (b.used_traffic_bytes || 0) - (a.used_traffic_bytes || 0);
        case "online":
          const aTime = a.online_at ? new Date(a.online_at).getTime() : 0;
          const bTime = b.online_at ? new Date(b.online_at).getTime() : 0;
          return bTime - aTime;
        case "username":
        default:
          return a.username.localeCompare(b.username);
      }
    });

  // Pagination
  const totalPages = Math.ceil(filteredUsers.length / pageSize);
  const paginatedUsers = filteredUsers.slice(
    (page - 1) * pageSize,
    page * pageSize
  );

  // Reset page when filters change
  useEffect(() => {
    setPage(1);
  }, [search, statusFilter, abuseFilter, minDevices, sortBy]);

  if (loading) {
    return (
      <div className="space-y-4">
        <div className="grid gap-4 grid-cols-2 lg:grid-cols-4">
          {[...Array(4)].map((_, i) => (
            <Skeleton key={i} className="h-24" />
          ))}
        </div>
        <Skeleton className="h-[600px]" />
      </div>
    );
  }

  if (!stats?.enabled) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <UserX className="h-5 w-5" />
            Remnawave Not Configured
          </CardTitle>
          <CardDescription>
            Remnawave integration is not enabled. Configure REMNAWAVE_URL and
            REMNAWAVE_API_TOKEN environment variables to enable.
          </CardDescription>
        </CardHeader>
      </Card>
    );
  }

  // Calculate stats
  const activeUsers = users.filter((u) => u.status === "ACTIVE").length;
  const abusersCount = users.filter((u) => u.hwid_exceeds_limit).length;
  const totalDevices = stats.hwidStats?.totalDevices ?? 0;

  return (
    <div className="space-y-4">
      {/* Stats Cards */}
      <div className="grid gap-4 grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Users className="h-4 w-4 text-muted-foreground" />
              Total Users
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.totalUsers}</div>
            <p className="text-xs text-muted-foreground">
              {activeUsers} active
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Smartphone className="h-4 w-4 text-muted-foreground" />
              HWID Devices
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{totalDevices}</div>
            <p className="text-xs text-muted-foreground">
              {(totalDevices / Math.max(stats.totalUsers, 1)).toFixed(1)} avg per user
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-destructive" />
              HWID Abusers
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-destructive">{abusersCount}</div>
            <p className="text-xs text-muted-foreground">
              exceeding device limit
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <RefreshCw className="h-4 w-4 text-muted-foreground" />
              Last Sync
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-lg font-bold">
              {stats.lastSync
                ? formatDistanceToNow(new Date(stats.lastSync), { addSuffix: true })
                : "Never"}
            </div>
            <Button
              variant="ghost"
              size="sm"
              className="mt-1 h-7 px-2"
              onClick={fetchData}
            >
              <RefreshCw className="h-3 w-3 mr-1" />
              Refresh
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div className="flex-1 min-w-[200px]">
          <div className="relative">
            <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder={t("searchPlaceholder")}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-8"
            />
          </div>
        </div>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-[130px]">
            <SelectValue placeholder={t("statusFilter")} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t("allStatuses")}</SelectItem>
            <SelectItem value="ACTIVE">Active</SelectItem>
            <SelectItem value="DISABLED">Disabled</SelectItem>
            <SelectItem value="LIMITED">Limited</SelectItem>
            <SelectItem value="EXPIRED">Expired</SelectItem>
          </SelectContent>
        </Select>
        <Select value={abuseFilter} onValueChange={setAbuseFilter}>
          <SelectTrigger className="w-[150px]">
            <SelectValue placeholder={t("abuseFilter")} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t("allAbuse")}</SelectItem>
            <SelectItem value="exceeds">{t("exceedsLimit")}</SelectItem>
          </SelectContent>
        </Select>
        <Select value={String(minDevices)} onValueChange={(v) => setMinDevices(Number(v))}>
          <SelectTrigger className="w-[130px]">
            <SelectValue placeholder={t("devicesFilter")} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="0">{t("allDevices")}</SelectItem>
            <SelectItem value="2">≥ 2 {t("devicesFilter").toLowerCase()}</SelectItem>
            <SelectItem value="3">≥ 3 {t("devicesFilter").toLowerCase()}</SelectItem>
            <SelectItem value="5">≥ 5 {t("devicesFilter").toLowerCase()}</SelectItem>
          </SelectContent>
        </Select>
        <Select value={sortBy} onValueChange={(v) => setSortBy(v as typeof sortBy)}>
          <SelectTrigger className="w-[150px]">
            <SelectValue placeholder={t("sortBy")} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="username">{t("sortByName")}</SelectItem>
            <SelectItem value="devices">{t("sortByDevices")}</SelectItem>
            <SelectItem value="traffic">{t("sortByTraffic")}</SelectItem>
            <SelectItem value="online">{t("sortByOnline")}</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Results count */}
      <p className="text-sm text-muted-foreground">
        {t("showing", { shown: paginatedUsers.length, total: filteredUsers.length })}
      </p>

      {/* Users Table */}
      <Card>
        <div className="max-h-[600px] overflow-y-auto scrollbar-thin">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>User</TableHead>
              <TableHead>Status</TableHead>
              <TableHead className="text-right">Traffic</TableHead>
              <TableHead className="text-right">Devices</TableHead>
              <TableHead>Contact Info</TableHead>
              <TableHead>Last Online</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {paginatedUsers.map((user) => (
              <TableRow
                key={user.uuid}
                className={user.hwid_exceeds_limit ? "bg-destructive/10" : ""}
              >
                <TableCell>
                  <div className="space-y-1">
                    <div className="font-medium">{user.username}</div>
                    {user.email && (
                      <div className="text-xs text-muted-foreground">
                        {user.email}
                      </div>
                    )}
                    {user.parsed_real_name && (
                      <div className="text-xs flex items-center gap-1">
                        <User className="h-3 w-3" />
                        {user.parsed_real_name}
                      </div>
                    )}
                    {user.tag && (
                      <Badge variant="outline" className="text-xs">
                        {user.tag}
                      </Badge>
                    )}
                  </div>
                </TableCell>
                <TableCell>{getStatusBadge(user.status)}</TableCell>
                <TableCell className="text-right">
                  <div className="space-y-1">
                    <div>{formatBytes(user.used_traffic_bytes)}</div>
                    {user.traffic_limit_bytes > 0 && (
                      <>
                        <div className="text-xs text-muted-foreground">
                          / {formatBytes(user.traffic_limit_bytes)}
                        </div>
                        <div className="w-full bg-secondary rounded-full h-1.5">
                          <div
                            className={`h-1.5 rounded-full ${
                              user.traffic_percent > 90
                                ? "bg-destructive"
                                : user.traffic_percent > 70
                                ? "bg-yellow-500"
                                : "bg-green-500"
                            }`}
                            style={{
                              width: `${Math.min(user.traffic_percent, 100)}%`,
                            }}
                          />
                        </div>
                      </>
                    )}
                  </div>
                </TableCell>
                <TableCell className="text-right">
                  <div className="space-y-1">
                    <div
                      className={
                        user.hwid_exceeds_limit ? "text-destructive font-bold" : ""
                      }
                    >
                      {user.hwid_device_count}
                      {user.hwid_device_limit && (
                        <span className="text-muted-foreground">
                          /{user.hwid_device_limit}
                        </span>
                      )}
                    </div>
                    {user.hwid_exceeds_limit && (
                      <Badge variant="destructive" className="text-xs">
                        <AlertTriangle className="h-3 w-3 mr-1" />
                        Exceeded
                      </Badge>
                    )}
                  </div>
                </TableCell>
                <TableCell>
                  <div className="space-y-1 text-xs">
                    {user.parsed_phone && (
                      <div className="flex items-center gap-1">
                        <Phone className="h-3 w-3 text-muted-foreground" />
                        {user.parsed_phone}
                      </div>
                    )}
                    {user.parsed_telegram_user && (
                      <div className="flex items-center gap-1">
                        <AtSign className="h-3 w-3 text-muted-foreground" />
                        {user.parsed_telegram_user}
                      </div>
                    )}
                    {user.telegram_id && !user.parsed_telegram_user && (
                      <div className="text-muted-foreground">
                        TG ID: {user.telegram_id}
                      </div>
                    )}
                  </div>
                </TableCell>
                <TableCell>
                  {user.online_at ? (
                    <div className="text-sm">
                      {formatDistanceToNow(new Date(user.online_at), {
                        addSuffix: true,
                      })}
                    </div>
                  ) : (
                    <span className="text-muted-foreground">Never</span>
                  )}
                  {user.last_connected_node && (
                    <div className="text-xs text-muted-foreground">
                      {user.last_connected_node}
                    </div>
                  )}
                </TableCell>
              </TableRow>
            ))}
            {paginatedUsers.length === 0 && (
              <TableRow>
                <TableCell colSpan={6} className="text-center text-muted-foreground">
                  {t("noUsers")}
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
        </div>
      </Card>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <p className="text-sm text-muted-foreground">
            {t("page", { page, total: totalPages })}
          </p>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
            >
              <ChevronLeft className="h-4 w-4" />
              {t("prev")}
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
            >
              {t("next")}
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}