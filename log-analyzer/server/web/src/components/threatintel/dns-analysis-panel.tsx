"use client";

import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
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
import { 
  Globe, 
  Shield, 
  TrendingUp, 
  TrendingDown, 
  Minus,
  AlertTriangle,
  RefreshCw,
  Server,
  Users,
  Activity,
  Ban
} from "lucide-react";
import { 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  BarChart,
  Bar,
  Cell,
  Legend
} from "recharts";
import { DNSAnalysisSummary, RiskLevel } from "@/lib/types";
import { formatDistanceToNow } from "date-fns";
import { StatCard, StatCardGrid } from "./stat-card";

interface DNSAnalysisPanelProps {
  data: DNSAnalysisSummary | null;
  loading?: boolean;
  onRefresh?: () => void;
}

const riskColors: Record<RiskLevel, string> = {
  low: "hsla(142, 45%, 50%, 0.8)",      // green muted
  medium: "hsla(48, 55%, 55%, 0.8)",    // yellow muted
  high: "hsla(25, 55%, 55%, 0.8)",      // orange muted
  critical: "hsla(0, 50%, 55%, 0.8)",   // red muted
};

// Muted chart colors
const CHART_COLORS = [
  "hsla(262, 50%, 58%, 0.75)",   // purple muted
  "hsla(142, 45%, 50%, 0.75)",   // green muted
  "hsla(48, 55%, 55%, 0.75)",    // yellow muted
  "hsla(25, 55%, 55%, 0.75)",    // orange muted
  "hsla(197, 45%, 55%, 0.75)",   // cyan muted
  "hsla(340, 50%, 55%, 0.75)",   // pink muted
  "hsla(212, 55%, 55%, 0.75)",   // blue muted
];

// Tooltip style for dark theme readability
const tooltipStyle = {
  contentStyle: {
    backgroundColor: "rgb(24, 24, 27)",
    border: "1px solid rgb(63, 63, 70)",
    borderRadius: "8px",
    fontSize: "12px",
    boxShadow: "0 4px 12px rgba(0,0,0,0.4)",
    color: "rgb(250, 250, 250)",
  },
  labelStyle: { color: "rgb(250, 250, 250)", fontWeight: "bold" as const },
  itemStyle: { color: "rgb(212, 212, 216)" },
};

// Return the appropriate icon component based on trend direction
function getTrendIcon(direction: string) {
  switch (direction) {
    case "up":
      return <TrendingUp className="h-4 w-4 text-red-500" />;
    case "down":
      return <TrendingDown className="h-4 w-4 text-emerald-500" />;
    default:
      return <Minus className="h-4 w-4 text-muted-foreground" />;
  }
}

export function DNSAnalysisPanel({ data, loading = false, onRefresh }: DNSAnalysisPanelProps) {
  const [activeView, setActiveView] = useState<"overview" | "domains" | "users">("overview");

  if (loading) {
    return (
      <div className="space-y-4">
        <div className="grid gap-4 md:grid-cols-4">
          {[1, 2, 3, 4].map(i => <Skeleton key={i} className="h-24 rounded-xl" />)}
        </div>
        <Card>
          <CardContent className="pt-6">
            <Skeleton className="h-64 w-full" />
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!data) {
    return (
      <Card className="border-dashed">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-muted-foreground">
            <Globe className="h-5 w-5" />
            DNS Analysis
          </CardTitle>
          <CardDescription>No DNS analysis data available</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col items-center justify-center h-[150px] text-muted-foreground gap-2">
            <Server className="h-12 w-12 opacity-20" />
            <p className="text-center">DNS analysis data will appear<br/>after queries are processed</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  const stats = data.query_stats;
  const trendIcon = getTrendIcon(data.trend_direction);

  // Prepare chart data
  const hourlyData = stats?.hourly_stats?.map(h => ({
    hour: h.hour.split("T")[1] || h.hour,
    total: h.total_queries,
    blocked: h.blocked_queries,
  })) || [];

  const dailyData = stats?.daily_stats?.map(d => ({
    day: d.day.slice(5), // MM-DD format
    total: d.total_queries,
    blocked: d.blocked_queries,
  })) || [];

  const categoryData = Object.entries(data.category_breakdown || {})
    .slice(0, 8)
    .map(([name, value]) => ({ name, value }));

  return (
    <div className="space-y-4">
      {/* Stats Cards */}
      <StatCardGrid columns={4}>
        <StatCard
          icon={<Server className="h-4 w-4" />}
          label="Total Queries"
          value={stats?.total_queries || 0}
          subValue="Last 30 days"
          variant="info"
        />
        <StatCard
          icon={<Ban className="h-4 w-4" />}
          label="Blocked Queries"
          value={stats?.blocked_queries || 0}
          subValue="Threats blocked"
          variant="danger"
        />
        <StatCard
          icon={<Shield className="h-4 w-4" />}
          label="Block Rate"
          value={`${(stats?.block_rate || 0).toFixed(1)}%`}
          subValue="Blocked / Total"
          variant="warning"
        />
        <StatCard
          icon={<AlertTriangle className="h-4 w-4" />}
          label="Bad Domains"
          value={stats?.unique_domains_bad || 0}
          subValue="Unique threats"
          variant="muted"
        />
      </StatCardGrid>

      {/* Main Card */}
      <Card className="border shadow-sm">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Globe className="h-5 w-5 text-muted-foreground" />
                DNS Analysis
                <Badge variant="outline" className="ml-2 flex items-center gap-1">
                  {trendIcon}
                  <span>
                    {data.trend_direction === "up" ? "Increasing" :
                     data.trend_direction === "down" ? "Decreasing" : "Stable"}
                  </span>
                </Badge>
              </CardTitle>
              <CardDescription>
                DNS query analysis and threat detection
              </CardDescription>
            </div>
            <div className="flex gap-2">
              <div className="flex rounded-lg border overflow-hidden">
                {(["overview", "domains", "users"] as const).map(view => (
                  <Button
                    key={view}
                    variant={activeView === view ? "secondary" : "ghost"}
                    size="sm"
                    className="rounded-none"
                    onClick={() => setActiveView(view)}
                  >
                    {view === "overview" ? "Overview" : view === "domains" ? "Domains" : "Users"}
                  </Button>
                ))}
              </div>
              {onRefresh && (
                <Button variant="outline" size="sm" onClick={onRefresh}>
                  <RefreshCw className="h-4 w-4" />
                </Button>
              )}
            </div>
          </div>
        </CardHeader>

        <CardContent>
          {activeView === "overview" && (
            <div className="space-y-6">
              {/* Charts */}
              <div className="grid gap-4 md:grid-cols-2">
              {/* Daily Trend */}
              <Card className="border">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium">Daily Trend (30 days)</CardTitle>
                </CardHeader>
                <CardContent className="pt-0">
                  <div className="h-[250px] w-full">
                    {dailyData.length > 0 ? (
                      <ResponsiveContainer width="100%" height="100%">
                        <AreaChart data={dailyData} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                          <defs>
                            <linearGradient id="colorTotal" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor="hsla(262, 50%, 60%, 0.6)" stopOpacity={0.6} />
                              <stop offset="95%" stopColor="hsla(262, 50%, 60%, 0.1)" stopOpacity={0.05} />
                            </linearGradient>
                            <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor="hsla(0, 50%, 58%, 0.6)" stopOpacity={0.6} />
                              <stop offset="95%" stopColor="hsla(0, 50%, 58%, 0.1)" stopOpacity={0.05} />
                            </linearGradient>
                          </defs>
                          <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                          <XAxis
                            dataKey="day"
                            tick={{ fontSize: 10 }}
                            interval="preserveStartEnd"
                            className="text-muted-foreground"
                          />
                          <YAxis tick={{ fontSize: 10 }} width={40} className="text-muted-foreground" />
                          <Tooltip
                            contentStyle={tooltipStyle.contentStyle}
                            labelStyle={tooltipStyle.labelStyle}
                            itemStyle={tooltipStyle.itemStyle}
                            cursor={{ stroke: "rgba(63, 63, 70, 0.5)", strokeWidth: 1 }}
                          />
                          <Legend wrapperStyle={{ fontSize: "10px" }} />
                          <Area
                            type="monotone"
                            dataKey="total"
                            stroke="hsla(262, 50%, 60%, 0.8)"
                            fill="url(#colorTotal)"
                            name="Total"
                          />
                          <Area
                            type="monotone"
                            dataKey="blocked"
                            stroke="hsla(0, 50%, 58%, 0.8)"
                            fill="url(#colorBlocked)"
                            name="Blocked"
                          />
                        </AreaChart>
                      </ResponsiveContainer>
                    ) : (
                      <div className="flex flex-col items-center justify-center h-full text-muted-foreground">
                        <Activity className="h-8 w-8 opacity-30 mb-2" />
                        <p className="text-sm">No daily data available</p>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>

              {/* Category Breakdown */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium">Category Breakdown</CardTitle>
                </CardHeader>
                <CardContent className="pt-0">
                  <div className="h-[250px] w-full">
                    {categoryData.length > 0 ? (
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={categoryData} margin={{ top: 10, right: 20, left: 10, bottom: 5 }}>
                          <CartesianGrid strokeDasharray="3 3" className="stroke-muted/30" vertical={false} />
                          <XAxis 
                            dataKey="name" 
                            tick={{ fontSize: 10 }}
                            interval={0}
                            angle={-25}
                            textAnchor="end"
                            height={50}
                          />
                          <YAxis 
                            tick={{ fontSize: 10 }}
                            tickFormatter={(value) => value.toLocaleString()}
                          />
                          <Tooltip
                            contentStyle={tooltipStyle.contentStyle}
                            labelStyle={tooltipStyle.labelStyle}
                            itemStyle={tooltipStyle.itemStyle}
                            cursor={{ fill: "rgba(63, 63, 70, 0.3)" }}
                            formatter={(value: number, name: string) => [`${value.toLocaleString()} queries`, name]}
                          />
                          <Bar dataKey="value" radius={[4, 4, 0, 0]} name="Queries">
                            {categoryData.map((_, index) => (
                              <Cell key={`cell-${index}`} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                            ))}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    ) : (
                      <div className="flex flex-col items-center justify-center h-full text-muted-foreground">
                        <Globe className="h-8 w-8 opacity-30 mb-2" />
                        <p className="text-sm">No category data available</p>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Hourly Activity */}
            {hourlyData.length > 0 && (
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium">Hourly Activity (24h)</CardTitle>
                </CardHeader>
                <CardContent className="pt-0">
                  <div className="h-[200px] w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={hourlyData} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                        <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                        <XAxis
                          dataKey="hour"
                          tick={{ fontSize: 10 }}
                          interval="preserveStartEnd"
                          className="text-muted-foreground"
                        />
                        <YAxis tick={{ fontSize: 10 }} width={40} className="text-muted-foreground" />
                        <Tooltip
                          contentStyle={tooltipStyle.contentStyle}
                          labelStyle={tooltipStyle.labelStyle}
                          itemStyle={tooltipStyle.itemStyle}
                          cursor={{ fill: "rgba(63, 63, 70, 0.3)" }}
                        />
                        <Legend wrapperStyle={{ fontSize: "10px" }} />
                        <Bar dataKey="total" fill="hsla(262, 50%, 60%, 0.7)" name="Total" radius={[2, 2, 0, 0]} />
                        <Bar dataKey="blocked" fill="hsla(0, 50%, 58%, 0.7)" name="Blocked" radius={[2, 2, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        )}

        {activeView === "domains" && (
          <div className="space-y-4">
            <h3 className="text-lg font-semibold">Top Blocked Domains</h3>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Domain</TableHead>
                  <TableHead className="text-right">Hits</TableHead>
                  <TableHead className="text-right">Users</TableHead>
                  <TableHead>Categories</TableHead>
                  <TableHead>Last Seen</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(data.top_bad_domains || []).map((domain, idx) => (
                  <TableRow key={idx}>
                    <TableCell className="font-mono text-xs">{domain.domain}</TableCell>
                    <TableCell className="text-right font-medium">{domain.total_hits}</TableCell>
                    <TableCell className="text-right">{domain.unique_users}</TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {(domain.threat_types || []).slice(0, 3).map((type, i) => (
                          <Badge key={i} variant="outline" className="text-xs">
                            {type}
                          </Badge>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {domain.last_seen ? formatDistanceToNow(new Date(domain.last_seen), { addSuffix: true }) : "N/A"}
                    </TableCell>
                  </TableRow>
                ))}
                {(!data.top_bad_domains || data.top_bad_domains.length === 0) && (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center text-muted-foreground">
                      No blocked domains recorded
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        )}

        {activeView === "users" && (
          <div className="space-y-4">
            <h3 className="text-lg font-semibold">Top Users by Blocked DNS</h3>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>User</TableHead>
                  <TableHead className="text-right">Total</TableHead>
                  <TableHead className="text-right">Blocked</TableHead>
                  <TableHead className="text-right">Block Rate</TableHead>
                  <TableHead>Risk</TableHead>
                  <TableHead>Top Domains</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(data.top_users_by_dns || []).map((user, idx) => (
                  <TableRow key={idx}>
                    <TableCell className="font-medium">{user.user_email}</TableCell>
                    <TableCell className="text-right">{user.total_queries.toLocaleString()}</TableCell>
                    <TableCell className="text-right text-red-600">{user.blocked_queries.toLocaleString()}</TableCell>
                    <TableCell className="text-right">{user.block_rate.toFixed(1)}%</TableCell>
                    <TableCell>
                      <Badge 
                        variant="outline"
                        style={{ 
                          color: riskColors[user.risk_level],
                          borderColor: riskColors[user.risk_level]
                        }}
                      >
                        {user.risk_level}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {(user.top_domains || []).slice(0, 2).map((d, i) => (
                          <Badge key={i} variant="secondary" className="text-xs font-mono">
                            {d.length > 20 ? d.slice(0, 20) + "..." : d}
                          </Badge>
                        ))}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
                {(!data.top_users_by_dns || data.top_users_by_dns.length === 0) && (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center text-muted-foreground">
                      No user DNS data available
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
    </Card>
    </div>
  );
}
