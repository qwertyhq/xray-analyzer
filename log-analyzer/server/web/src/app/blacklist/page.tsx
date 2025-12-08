"use client";

import { useState, useEffect, useMemo } from "react";
import Link from "next/link";
import { useWsBlacklist } from "@/contexts/websocket-context";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Input } from "@/components/ui/input";
import { TimeRangeSelector } from "@/components/dashboard/time-range-selector";
import { IPInfoBadge } from "@/components/ui/ip-info-badge";
import { SubscriptionAbuseTable } from "@/components/users/subscription-abuse-table";
import { StatCard, StatCardGrid } from "@/components/threatintel/stat-card";
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
import { ShieldAlert, Globe, Users, TrendingUp, ExternalLink, Wifi, WifiOff, UserX, Search } from "lucide-react";
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
  const [timeRange, setTimeRange] = useState<TimeRange>("24h");
  const { blacklist: wsBlacklist, loading: wsLoading, connected } = useWsBlacklist();
  const [httpAnalytics, setHttpAnalytics] = useState<BlacklistAnalytics | null>(null);
  const [httpLoading, setHttpLoading] = useState(false);
  const [domainSearch, setDomainSearch] = useState("");
  const [matchSearch, setMatchSearch] = useState("");
  const [nodeFilter, setNodeFilter] = useState<string>("all");

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
        const res = await fetch(`/api/blacklist/analytics?period=${timeRange}`);
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
    "1h": "Last Hour",
    "6h": "Last 6 Hours",
    "24h": "Last 24 Hours",
    "7d": "Last 7 Days",
    "30d": "Last 30 Days",
    "custom": "Custom",
  };

  // Prepare chart data
  const chartData = analytics.hourly_stats?.filter(h => isValidDate(h.hour)).map((h) => ({
    hour: format(new Date(h.hour), "HH:mm"),
    hits: h.hit_count,
  })) || [];

  // Get unique nodes from recent matches for filter
  const uniqueNodes = useMemo(() => {
    const nodes = new Set<string>();
    analytics.recent_matches?.forEach(m => {
      if (m.node_id) nodes.add(m.node_id);
    });
    return Array.from(nodes).sort();
  }, [analytics.recent_matches]);

  // Filter domains by search
  const filteredDomains = useMemo(() => {
    if (!domainSearch.trim()) return analytics.top_domains || [];
    const search = domainSearch.toLowerCase();
    return (analytics.top_domains || []).filter(d => 
      d.domain.toLowerCase().includes(search)
    );
  }, [analytics.top_domains, domainSearch]);

  // Filter recent matches
  const filteredMatches = useMemo(() => {
    let matches = analytics.recent_matches || [];
    
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
  }, [analytics.recent_matches, matchSearch, nodeFilter]);

  return (
    <div className="p-4 md:p-8 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl sm:text-2xl font-bold tracking-tight flex items-center gap-2">
            <ShieldAlert className="h-5 w-5 sm:h-6 sm:w-6 text-destructive" />
            Blacklist Analytics
          </h2>
          <p className="text-sm text-muted-foreground">
            Detailed analysis of blocked resource access
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
                Live
              </>
            ) : (
              <>
                <WifiOff className="h-3 w-3" />
                Disconnected
              </>
            )}
          </Badge>
          <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
        </div>
      </div>

      {/* Stats Cards */}
      <StatCardGrid columns={4}>
        <StatCard
          label="Total Hits"
          value={analytics.total_hits.toLocaleString()}
          subValue={timeLabels[timeRange]}
          icon={<TrendingUp className="h-4 w-4" />}
          variant="danger"
        />
        <StatCard
          label="Unique Users"
          value={analytics.unique_users}
          subValue="Accessed blocked resources"
          icon={<Users className="h-4 w-4" />}
          variant="muted"
        />
        <StatCard
          label="Unique Domains"
          value={analytics.unique_domains}
          subValue="Blocked destinations"
          icon={<Globe className="h-4 w-4" />}
          variant="muted"
        />
        <StatCard
          label="Avg per User"
          value={analytics.unique_users > 0 
            ? (analytics.total_hits / analytics.unique_users).toFixed(1) 
            : "0"}
          subValue="Hits per user"
          icon={<ShieldAlert className="h-4 w-4" />}
          variant="muted"
        />
      </StatCardGrid>

      {/* Hourly Chart */}
      {chartData.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Blacklist Hits Over Time</CardTitle>
            <CardDescription>Hourly distribution of blocked requests</CardDescription>
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
              Top Domains
              {analytics.top_domains?.length > 0 && (
                <Badge variant="secondary" className="ml-1 sm:ml-2">
                  {analytics.top_domains.length}
                </Badge>
              )}
            </TabsTrigger>
            <TabsTrigger value="users" className="text-xs sm:text-sm whitespace-nowrap">
              Top Users
              {analytics.top_users?.length > 0 && (
                <Badge variant="secondary" className="ml-1 sm:ml-2">
                  {analytics.top_users.length}
                </Badge>
              )}
            </TabsTrigger>
            <TabsTrigger value="abuse" className="text-xs sm:text-sm whitespace-nowrap">
              <UserX className="h-3 w-3 mr-1" />
              Subscription Abuse
            </TabsTrigger>
            <TabsTrigger value="recent" className="text-xs sm:text-sm whitespace-nowrap">
              Recent Matches
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
                  <CardTitle>Most Accessed Blocked Domains</CardTitle>
                  <CardDescription>
                    Domains sorted by total hits across all users
                  </CardDescription>
                </div>
                <div className="relative w-full sm:w-64">
                  <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                  <Input
                    placeholder="Search domains..."
                    value={domainSearch}
                    onChange={(e) => setDomainSearch(e.target.value)}
                    className="pl-8"
                  />
                </div>
              </div>
            </CardHeader>
            <CardContent className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[40px]">#</TableHead>
                    <TableHead className="whitespace-nowrap">Domain</TableHead>
                    <TableHead className="whitespace-nowrap hidden md:table-cell">Matched Rule</TableHead>
                    <TableHead className="text-right whitespace-nowrap">Hits</TableHead>
                    <TableHead className="text-right whitespace-nowrap hidden sm:table-cell">Users</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredDomains.map((domain, idx) => (
                    <TableRow key={domain.domain}>
                      <TableCell className="text-muted-foreground">{idx + 1}</TableCell>
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
                  {filteredDomains.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={5} className="text-center text-muted-foreground">
                        {domainSearch ? "No domains match your search" : "No blocked domains in this period"}
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Top Users Tab */}
        <TabsContent value="users">
          <Card>
            <CardHeader>
              <CardTitle>Users Accessing Blocked Resources</CardTitle>
              <CardDescription>
                Users sorted by number of blacklist hits
              </CardDescription>
            </CardHeader>
            <CardContent className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[40px]">#</TableHead>
                    <TableHead className="whitespace-nowrap">User</TableHead>
                    <TableHead className="whitespace-nowrap hidden lg:table-cell">Last IP</TableHead>
                    <TableHead className="text-right whitespace-nowrap">Hits</TableHead>
                    <TableHead className="text-right whitespace-nowrap hidden sm:table-cell">Domains</TableHead>
                    <TableHead className="hidden md:table-cell">Top Blocked Domains</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {analytics.top_users?.map((user, idx) => (
                    <TableRow key={user.user_email}>
                      <TableCell className="text-muted-foreground">{idx + 1}</TableCell>
                      <TableCell className="font-medium max-w-[120px] sm:max-w-none">
                        <Link 
                          href={`/users/${encodeURIComponent(user.user_email)}`}
                          className="hover:underline text-primary flex items-center gap-1 truncate"
                        >
                          <span className="truncate">{user.user_email}</span>
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
                  {(!analytics.top_users || analytics.top_users.length === 0) && (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center text-muted-foreground">
                        No users with blacklist hits in this period
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Subscription Abuse Tab */}
        <TabsContent value="abuse">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <UserX className="h-5 w-5 text-destructive" />
                Subscription Abuse Detection
              </CardTitle>
              <CardDescription>
                Users with multiple unique IP addresses - potential account sharing
              </CardDescription>
            </CardHeader>
            <CardContent>
              <SubscriptionAbuseTable defaultPeriod={timeRange} />
            </CardContent>
          </Card>
        </TabsContent>

        {/* Recent Matches Tab */}
        <TabsContent value="recent">
          <Card>
            <CardHeader>
              <div className="flex flex-col gap-4">
                <div>
                  <CardTitle>Recent Blacklist Matches</CardTitle>
                  <CardDescription>
                    Last 100 blocked requests
                  </CardDescription>
                </div>
                <div className="flex flex-col sm:flex-row gap-2">
                  <div className="relative flex-1 sm:max-w-xs">
                    <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                    <Input
                      placeholder="Search destination, IP, rule..."
                      value={matchSearch}
                      onChange={(e) => setMatchSearch(e.target.value)}
                      className="pl-8"
                    />
                  </div>
                  {uniqueNodes.length > 0 && (
                    <Select value={nodeFilter} onValueChange={setNodeFilter}>
                      <SelectTrigger className="w-full sm:w-[180px]">
                        <SelectValue placeholder="Filter by node" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All Nodes</SelectItem>
                        {uniqueNodes.map(node => (
                          <SelectItem key={node} value={node}>{node}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  )}
                </div>
              </div>
            </CardHeader>
            <CardContent className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="whitespace-nowrap">Time</TableHead>
                    <TableHead className="whitespace-nowrap hidden sm:table-cell">Node</TableHead>
                    <TableHead className="whitespace-nowrap hidden lg:table-cell">Source IP</TableHead>
                    <TableHead className="whitespace-nowrap">Destination</TableHead>
                    <TableHead className="whitespace-nowrap hidden md:table-cell">Matched Rule</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredMatches.map((match, idx) => (
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
                  {filteredMatches.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={5} className="text-center text-muted-foreground">
                        {matchSearch || nodeFilter !== "all" 
                          ? "No matches found with current filters" 
                          : "No blacklist matches in this period"}
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
