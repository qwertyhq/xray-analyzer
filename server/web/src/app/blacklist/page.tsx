"use client";

import { useState, useEffect, useMemo } from "react";
import { authFetch } from "@/contexts/auth-context";
import Link from "next/link";
import { useWsBlacklist } from "@/contexts/websocket-context";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Input } from "@/components/ui/input";
import { TimeRangeSelector } from "@/components/dashboard/time-range-selector";
import { IPInfoBadge } from "@/components/ui/ip-info-badge";
import { StatCard, StatCardGrid } from "@/components/threatintel/stat-card";
import { PaginationControls, usePagination } from "@/components/ui/data-table";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ShieldAlert, Globe, Users, TrendingUp, ExternalLink, Wifi, WifiOff, Search } from "lucide-react";
import { useTranslations } from "next-intl";
import { format } from "date-fns";
import { TimeRange, BlacklistAnalytics } from "@/lib/types";
import { isValidDate } from "@/lib/utils/date";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

export default function BlacklistPage() {
  const t = useTranslations("blacklist");
  const tCommon = useTranslations("common");
  const [timeRange, setTimeRange] = useState<TimeRange>("24h");
  const { blacklist: wsBlacklist, loading: wsLoading, connected } = useWsBlacklist();
  const [httpAnalytics, setHttpAnalytics] = useState<BlacklistAnalytics | null>(null);
  const [httpLoading, setHttpLoading] = useState(false);
  const [domainSearch, setDomainSearch] = useState("");
  const [matchSearch, setMatchSearch] = useState("");
  const [nodeFilter, setNodeFilter] = useState<string>("all");
  const [selectedDomains, setSelectedDomains] = useState<Set<string>>(new Set());
  const [userDomainSearch, setUserDomainSearch] = useState("");

  // For 24h, use WebSocket; for other ranges, fetch via HTTP
  const use24hWebSocket = timeRange === "24h";
  const analytics = use24hWebSocket ? wsBlacklist : httpAnalytics;
  const loading = use24hWebSocket ? wsLoading : httpLoading;

  // Fetch analytics for non-24h ranges via HTTP
  useEffect(() => {
    if (use24hWebSocket) return;

    const fetchAnalytics = async () => {
      setHttpLoading(true);
      try {
        const res = await authFetch(`/api/blacklist/analytics?period=${timeRange}`);
        if (res.ok) {
          setHttpAnalytics(await res.json());
        }
      } catch {
        // ignore
      } finally {
        setHttpLoading(false);
      }
    };

    fetchAnalytics();
    const interval = setInterval(fetchAnalytics, 10000);
    return () => clearInterval(interval);
  }, [timeRange, use24hWebSocket]);

  // Get unique nodes from recent matches for filter
  const uniqueNodes = useMemo(() => {
    const nodes = new Set<string>();
    analytics?.recent_matches?.forEach(m => {
      if (m.node_id) nodes.add(m.node_id);
    });
    return Array.from(nodes).sort();
  }, [analytics?.recent_matches]);

  // Filter domains by search
  const filteredDomains = useMemo(() => {
    if (!domainSearch.trim()) return analytics?.top_domains || [];
    const search = domainSearch.toLowerCase();
    return (analytics?.top_domains || []).filter(d => 
      d.domain.toLowerCase().includes(search)
    );
  }, [analytics?.top_domains, domainSearch]);

  // Filter recent matches
  const filteredMatches = useMemo(() => {
    let matches = analytics?.recent_matches || [];
    
    if (matchSearch.trim()) {
      const search = matchSearch.toLowerCase();
      matches = matches.filter(m => 
        m.destination.toLowerCase().includes(search) ||
        m.source_ip?.toLowerCase().includes(search) ||
        m.matched_rule?.toLowerCase().includes(search)
      );
    }
    
    if (nodeFilter !== "all") {
      matches = matches.filter(m => m.node_id === nodeFilter);
    }
    
    return matches;
  }, [analytics?.recent_matches, matchSearch, nodeFilter]);

  // All unique domains for filter
  const allDomains = useMemo(() => {
    return (analytics?.top_domains || []).map(d => d.domain).sort();
  }, [analytics?.top_domains]);

  // Users filtered by selected domains
  const usersByDomains = useMemo(() => {
    if (selectedDomains.size === 0) return [];
    
    const matches = analytics?.recent_matches || [];
    const userMap = new Map<string, {
      user_email: string;
      username: string;
      domains: Set<string>;
      hit_count: number;
      last_ip: string;
    }>();
    
    matches.forEach(m => {
      if (!selectedDomains.has(m.destination)) return;
      if (!m.user_email) return;
      
      const existing = userMap.get(m.user_email);
      if (existing) {
        existing.domains.add(m.destination);
        existing.hit_count++;
        if (m.source_ip) existing.last_ip = m.source_ip;
      } else {
        // Try to find username from top_users
        const topUser = analytics?.top_users?.find(u => u.user_email === m.user_email);
        userMap.set(m.user_email, {
          user_email: m.user_email,
          username: topUser?.username || m.user_email,
          domains: new Set([m.destination]),
          hit_count: 1,
          last_ip: m.source_ip || "",
        });
      }
    });
    
    return Array.from(userMap.values())
      .map(u => ({ ...u, domains: Array.from(u.domains) }))
      .sort((a, b) => b.hit_count - a.hit_count);
  }, [analytics?.recent_matches, analytics?.top_users, selectedDomains]);

  // Filter domains for the domain selector
  const filteredDomainSelector = useMemo(() => {
    if (!userDomainSearch.trim()) return allDomains.slice(0, 50);
    const search = userDomainSearch.toLowerCase();
    return allDomains.filter(d => d.toLowerCase().includes(search)).slice(0, 50);
  }, [allDomains, userDomainSearch]);

  // Pagination for tables - must be called before any early returns
  const domainsPagination = usePagination(filteredDomains, 15);
  const topUsersPagination = usePagination(analytics?.top_users || [], 15);
  const matchesPagination = usePagination(filteredMatches, 20);
  const usersByDomainsPagination = usePagination(usersByDomains, 15);

  if (loading || !analytics) {
    return (
      <div className="p-4 md:p-8 space-y-6">
        <Skeleton className="h-8 w-48" />
        <div className="grid gap-4 md:grid-cols-4">
          {[...Array(4)].map((_, i) => (
            <Skeleton key={i} className="h-[100px]" />
          ))}
        </div>
        <Skeleton className="h-[400px]" />
      </div>
    );
  }

  const timeLabels: Record<TimeRange, string> = {
    "1h": t("timeLastHour"),
    "6h": t("timeLast6Hours"),
    "24h": t("timeLast24Hours"),
    "7d": t("timeLast7Days"),
    "30d": t("timeLast30Days"),
    "custom": t("timeCustom"),
  };

  // Prepare chart data
  const chartData = analytics.hourly_stats?.filter(h => isValidDate(h.hour)).map((h) => ({
    hour: format(new Date(h.hour), "HH:mm"),
    hits: h.hit_count,
  })) || [];

  return (
    <div className="p-4 md:p-8 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl sm:text-2xl font-bold tracking-tight flex items-center gap-2">
            <ShieldAlert className="h-5 w-5 sm:h-6 sm:w-6 text-destructive" />
            {t("title")}
          </h2>
          <p className="text-sm text-muted-foreground">
            {t("description")}
          </p>
        </div>
        <div className="flex items-center gap-2 sm:gap-3">
          <Badge 
            variant={connected ? "default" : "destructive"} 
            className="flex items-center gap-1.5"
          >
            {connected ? (
              <>
                <Wifi className="h-3 w-3" />
                {tCommon("live")}
              </>
            ) : (
              <>
                <WifiOff className="h-3 w-3" />
                {tCommon("disconnected")}
              </>
            )}
          </Badge>
          <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
        </div>
      </div>

      {/* Stats Cards */}
      <StatCardGrid columns={4}>
        <StatCard
          label={t("totalHits")}
          value={analytics.total_hits.toLocaleString()}
          subValue={timeLabels[timeRange]}
          icon={<TrendingUp className="h-4 w-4" />}
          variant="danger"
        />
        <StatCard
          label={t("uniqueUsers")}
          value={analytics.unique_users}
          subValue={t("accessedBlocked")}
          icon={<Users className="h-4 w-4" />}
          variant="muted"
        />
        <StatCard
          label={t("uniqueDomains")}
          value={analytics.unique_domains}
          subValue={t("blockedDestinations")}
          icon={<Globe className="h-4 w-4" />}
          variant="muted"
        />
        <StatCard
          label={t("avgPerUser")}
          value={analytics.unique_users > 0
            ? (analytics.total_hits / analytics.unique_users).toFixed(1)
            : "0"}
          subValue={t("hitsPerUser")}
          icon={<ShieldAlert className="h-4 w-4" />}
          variant="muted"
        />
      </StatCardGrid>

      {/* Hourly Chart */}
      {chartData.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>{t("hitsOverTime")}</CardTitle>
            <CardDescription>{t("hourlyDist")}</CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={250}>
              <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="colorHits" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="hsl(var(--muted-foreground))" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="hsl(var(--muted-foreground))" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                <XAxis dataKey="hour" className="text-xs" tick={{ fill: 'hsl(var(--muted-foreground))' }} />
                <YAxis className="text-xs" tick={{ fill: 'hsl(var(--muted-foreground))' }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'hsl(var(--card))',
                    border: '1px solid hsl(var(--border))',
                    borderRadius: '8px',
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="hits"
                  stroke="hsl(var(--muted-foreground))"
                  fillOpacity={1}
                  fill="url(#colorHits)"
                  name="Hits"
                />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      )}

      {/* Tabs for different views */}
      <Tabs defaultValue="domains" className="space-y-4">
        <div className="overflow-x-auto -mx-4 px-4 md:mx-0 md:px-0">
          <TabsList className="w-max md:w-auto">
            <TabsTrigger value="domains" className="text-xs sm:text-sm whitespace-nowrap">
              {t("topDomains")}
              {analytics.top_domains?.length > 0 && (
                <Badge variant="secondary" className="ml-1 sm:ml-2">
                  {analytics.top_domains.length}
                </Badge>
              )}
            </TabsTrigger>
            <TabsTrigger value="users" className="text-xs sm:text-sm whitespace-nowrap">
              {t("topUsers")}
              {analytics.top_users?.length > 0 && (
                <Badge variant="secondary" className="ml-1 sm:ml-2">
                  {analytics.top_users.length}
                </Badge>
              )}
            </TabsTrigger>
            <TabsTrigger value="by-domain" className="text-xs sm:text-sm whitespace-nowrap">
              🔍 {t("byDomain")}
              {selectedDomains.size > 0 && (
                <Badge variant="default" className="ml-1 sm:ml-2">
                  {selectedDomains.size}
                </Badge>
              )}
            </TabsTrigger>
            <TabsTrigger value="recent" className="text-xs sm:text-sm whitespace-nowrap">
              {t("recentMatches")}
              {analytics.recent_matches?.length > 0 && (
                <Badge variant="secondary" className="ml-1 sm:ml-2">
                  {analytics.recent_matches.length}
                </Badge>
              )}
            </TabsTrigger>
          </TabsList>
        </div>

        {/* Top Domains Tab */}
        <TabsContent value="domains">
          <Card>
            <CardHeader>
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                <div>
                  <CardTitle>{t("mostAccessedDomains")}</CardTitle>
                  <CardDescription>
                    {t("domainsByHits")}
                  </CardDescription>
                </div>
                <div className="relative w-full sm:w-64">
                  <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                  <Input
                    placeholder={t("searchDomains")}
                    value={domainSearch}
                    onChange={(e) => setDomainSearch(e.target.value)}
                    className="pl-8"
                  />
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="overflow-auto max-h-[500px] border rounded-md">
              <Table>
                <TableHeader className="sticky top-0 bg-background z-10">
                  <TableRow>
                    <TableHead className="w-[40px]">{t("rank")}</TableHead>
                    <TableHead className="whitespace-nowrap">{t("domain")}</TableHead>
                    <TableHead className="whitespace-nowrap hidden md:table-cell">{t("matchedRule")}</TableHead>
                    <TableHead className="text-right whitespace-nowrap">{t("hits")}</TableHead>
                    <TableHead className="text-right whitespace-nowrap hidden sm:table-cell">{t("users")}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {domainsPagination.paginatedData.map((domain, idx) => (
                    <TableRow key={domain.domain}>
                      <TableCell className="text-muted-foreground">{domainsPagination.startIndex + idx + 1}</TableCell>
                      <TableCell className="font-mono text-xs sm:text-sm max-w-[150px] sm:max-w-[300px] truncate">
                        {domain.domain}
                      </TableCell>
                      <TableCell className="text-muted-foreground text-sm hidden md:table-cell">
                        {domain.matched_rule}
                      </TableCell>
                      <TableCell className="text-right">
                        <Badge variant="secondary">{domain.hit_count}</Badge>
                      </TableCell>
                      <TableCell className="text-right hidden sm:table-cell">{domain.unique_users}</TableCell>
                    </TableRow>
                  ))}
                  {domainsPagination.paginatedData.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={5} className="text-center text-muted-foreground">
                        {domainSearch ? t("noDomainsSearch") : t("noDomainsPeriod")}
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
              </div>
              <PaginationControls {...domainsPagination} />
            </CardContent>
          </Card>
        </TabsContent>

        {/* Top Users Tab */}
        <TabsContent value="users">
          <Card>
            <CardHeader>
              <CardTitle>{t("usersAccessingBlocked")}</CardTitle>
              <CardDescription>
                {t("usersByHits")}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="overflow-auto max-h-[500px] border rounded-md">
              <Table>
                <TableHeader className="sticky top-0 bg-background z-10">
                  <TableRow>
                    <TableHead className="w-[40px]">{t("rank")}</TableHead>
                    <TableHead className="whitespace-nowrap">{t("user")}</TableHead>
                    <TableHead className="whitespace-nowrap hidden lg:table-cell">{t("lastIp")}</TableHead>
                    <TableHead className="text-right whitespace-nowrap">{t("hits")}</TableHead>
                    <TableHead className="text-right whitespace-nowrap hidden sm:table-cell">{t("uniqueDomains")}</TableHead>
                    <TableHead className="hidden md:table-cell">{t("topBlockedDomains")}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {topUsersPagination.paginatedData.map((user, idx) => (
                    <TableRow key={user.user_email}>
                      <TableCell className="text-muted-foreground">{topUsersPagination.startIndex + idx + 1}</TableCell>
                      <TableCell className="font-medium max-w-[120px] sm:max-w-none">
                        <Link 
                          href={`/users/${encodeURIComponent(user.user_email)}`}
                          className="hover:underline text-primary flex items-center gap-1 truncate"
                        >
                          <span className="truncate">{user.username || user.user_email}</span>
                          <ExternalLink className="h-3 w-3 flex-shrink-0" />
                        </Link>
                      </TableCell>
                      <TableCell className="hidden lg:table-cell">
                        {user.last_ip ? (
                          <IPInfoBadge ip={user.last_ip} />
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </TableCell>
                      <TableCell className="text-right">
                        <Badge variant="destructive">{user.hit_count}</Badge>
                      </TableCell>
                      <TableCell className="text-right hidden sm:table-cell">{user.unique_domains}</TableCell>
                      <TableCell className="max-w-[300px] hidden md:table-cell">
                        <div className="flex flex-wrap gap-1">
                          {user.top_domains?.slice(0, 3).map((domain) => (
                            <Badge key={domain} variant="outline" className="text-xs truncate max-w-[150px]">
                              {domain}
                            </Badge>
                          ))}
                          {user.top_domains && user.top_domains.length > 3 && (
                            <Badge variant="outline" className="text-xs">
                              +{user.top_domains.length - 3}
                            </Badge>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                  {topUsersPagination.paginatedData.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center text-muted-foreground">
                        {t("noUsersHits")}
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
              </div>
              <PaginationControls {...topUsersPagination} />
            </CardContent>
          </Card>
        </TabsContent>

        {/* Users by Domain Tab */}
        <TabsContent value="by-domain">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                🔍 {t("whoVisitsDomains")}
              </CardTitle>
              <CardDescription>
                {t("selectDomainsFilter")}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Domain selector */}
              <div className="space-y-3">
                <div className="flex flex-col sm:flex-row gap-2">
                  <div className="relative flex-1">
                    <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                    <Input
                      placeholder={t("searchDomain")}
                      value={userDomainSearch}
                      onChange={(e) => setUserDomainSearch(e.target.value)}
                      className="pl-8"
                    />
                  </div>
                  {selectedDomains.size > 0 && (
                    <Badge 
                      variant="destructive" 
                      className="cursor-pointer self-start sm:self-auto"
                      onClick={() => setSelectedDomains(new Set())}
                    >
                      {t("resetFilter", { count: selectedDomains.size })}
                    </Badge>
                  )}
                </div>
                
                {/* Quick domain selection */}
                <div className="flex flex-wrap gap-1.5 max-h-[200px] overflow-y-auto p-2 border rounded-md bg-muted/30">
                  {filteredDomainSelector.length === 0 ? (
                    <span className="text-muted-foreground text-sm p-2">{t("noDomainsDisplay")}</span>
                  ) : (
                    filteredDomainSelector.map(domain => (
                      <Badge
                        key={domain}
                        variant={selectedDomains.has(domain) ? "default" : "outline"}
                        className="cursor-pointer text-xs truncate max-w-[200px] hover:bg-primary/80 transition-colors"
                        onClick={() => {
                          const newSet = new Set(selectedDomains);
                          if (newSet.has(domain)) {
                            newSet.delete(domain);
                          } else {
                            newSet.add(domain);
                          }
                          setSelectedDomains(newSet);
                        }}
                      >
                        {domain}
                      </Badge>
                    ))
                  )}
                </div>
              </div>

              {/* Results */}
              {selectedDomains.size === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <Globe className="h-12 w-12 mx-auto mb-2 opacity-50" />
                  <p>{t("selectDomains")}</p>
                </div>
              ) : (
                <>
                  <div className="text-sm text-muted-foreground">
                    {t("foundUsers", { count: usersByDomains.length })}
                  </div>
                  <div className="overflow-auto max-h-[400px] border rounded-md">
                    <Table>
                      <TableHeader className="sticky top-0 bg-background z-10">
                        <TableRow>
                          <TableHead className="w-[40px]">{t("rank")}</TableHead>
                          <TableHead className="whitespace-nowrap">{t("user")}</TableHead>
                          <TableHead className="whitespace-nowrap hidden lg:table-cell">{t("lastIp")}</TableHead>
                          <TableHead className="text-right whitespace-nowrap">{t("hits")}</TableHead>
                          <TableHead className="hidden md:table-cell">{t("visitedDomains")}</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {usersByDomainsPagination.paginatedData.map((user, idx) => (
                          <TableRow key={user.user_email}>
                            <TableCell className="text-muted-foreground">
                              {usersByDomainsPagination.startIndex + idx + 1}
                            </TableCell>
                            <TableCell className="font-medium">
                              <Link 
                                href={`/users/${encodeURIComponent(user.user_email)}`}
                                className="hover:underline text-primary flex items-center gap-1"
                              >
                                <span className="truncate max-w-[150px]">{user.username}</span>
                                <ExternalLink className="h-3 w-3 flex-shrink-0" />
                              </Link>
                            </TableCell>
                            <TableCell className="hidden lg:table-cell">
                              {user.last_ip ? (
                                <IPInfoBadge ip={user.last_ip} />
                              ) : (
                                <span className="text-muted-foreground">—</span>
                              )}
                            </TableCell>
                            <TableCell className="text-right">
                              <Badge variant="destructive">{user.hit_count}</Badge>
                            </TableCell>
                            <TableCell className="max-w-[300px] hidden md:table-cell">
                              <div className="flex flex-wrap gap-1">
                                {user.domains.slice(0, 3).map((domain) => (
                                  <Badge key={domain} variant="outline" className="text-xs truncate max-w-[150px]">
                                    {domain}
                                  </Badge>
                                ))}
                                {user.domains.length > 3 && (
                                  <Badge variant="outline" className="text-xs">
                                    +{user.domains.length - 3}
                                  </Badge>
                                )}
                              </div>
                            </TableCell>
                          </TableRow>
                        ))}
                        {usersByDomainsPagination.paginatedData.length === 0 && (
                          <TableRow>
                            <TableCell colSpan={5} className="text-center text-muted-foreground">
                              {t("noUsersSelectedDomains")}
                            </TableCell>
                          </TableRow>
                        )}
                      </TableBody>
                    </Table>
                  </div>
                  <PaginationControls {...usersByDomainsPagination} />
                </>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Recent Matches Tab */}
        <TabsContent value="recent">
          <Card>
            <CardHeader>
              <div className="flex flex-col gap-4">
                <div>
                  <CardTitle>{t("recentMatchesTitle")}</CardTitle>
                  <CardDescription>
                    {t("last100")}
                  </CardDescription>
                </div>
                <div className="flex flex-col sm:flex-row gap-2">
                  <div className="relative flex-1 sm:max-w-xs">
                    <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                    <Input
                      placeholder={t("searchMatchPlaceholder")}
                      value={matchSearch}
                      onChange={(e) => setMatchSearch(e.target.value)}
                      className="pl-8"
                    />
                  </div>
                  {uniqueNodes.length > 0 && (
                    <Select value={nodeFilter} onValueChange={setNodeFilter}>
                      <SelectTrigger className="w-full sm:w-[180px]">
                        <SelectValue placeholder={t("filterByNode")} />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">{t("allNodes")}</SelectItem>
                        {uniqueNodes.map(node => (
                          <SelectItem key={node} value={node}>{node}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  )}
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="overflow-auto max-h-[500px] border rounded-md">
              <Table>
                <TableHeader className="sticky top-0 bg-background z-10">
                  <TableRow>
                    <TableHead className="whitespace-nowrap">{t("time")}</TableHead>
                    <TableHead className="whitespace-nowrap hidden sm:table-cell">{t("node")}</TableHead>
                    <TableHead className="whitespace-nowrap hidden lg:table-cell">{t("sourceIp")}</TableHead>
                    <TableHead className="whitespace-nowrap">{t("destination")}</TableHead>
                    <TableHead className="whitespace-nowrap hidden md:table-cell">{t("matchedRule")}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {matchesPagination.paginatedData.map((match, idx) => (
                    <TableRow key={idx}>
                      <TableCell className="text-muted-foreground text-xs sm:text-sm whitespace-nowrap">
                        {isValidDate(match.timestamp)
                          ? format(new Date(match.timestamp), "HH:mm:ss")
                          : "—"
                        }
                      </TableCell>
                      <TableCell className="hidden sm:table-cell">
                        <Badge variant="outline">{match.node_id}</Badge>
                      </TableCell>
                      <TableCell className="font-mono text-sm hidden lg:table-cell">
                        {match.source_ip}
                      </TableCell>
                      <TableCell className="font-mono text-xs sm:text-sm max-w-[150px] sm:max-w-[250px] truncate">
                        {match.destination}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground max-w-[150px] truncate hidden md:table-cell">
                        {match.matched_rule}
                      </TableCell>
                    </TableRow>
                  ))}
                  {matchesPagination.paginatedData.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={5} className="text-center text-muted-foreground">
                        {matchSearch || nodeFilter !== "all"
                          ? t("noMatchesFilters")
                          : t("noMatchesPeriod")}
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
              </div>
              <PaginationControls {...matchesPagination} />
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
