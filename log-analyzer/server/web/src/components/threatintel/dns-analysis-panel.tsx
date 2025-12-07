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
  PieChart,
  Pie,
  Cell,
  Legend
} from "recharts";
import { DNSAnalysisSummary, RiskLevel } from "@/lib/types";
import { formatDistanceToNow } from "date-fns";

interface DNSAnalysisPanelProps {
  data: DNSAnalysisSummary | null;
  loading?: boolean;
  onRefresh?: () => void;
}

const riskColors: Record<RiskLevel, string> = {
  low: "#22c55e",
  medium: "#eab308",
  high: "#f97316",
  critical: "#ef4444",
};

const CHART_COLORS = ["#8884d8", "#82ca9d", "#ffc658", "#ff7300", "#00C49F", "#FFBB28", "#FF8042"];

const trendIcons = {
  up: <TrendingUp className="h-4 w-4 text-red-500" />,
  down: <TrendingDown className="h-4 w-4 text-green-500" />,
  stable: <Minus className="h-4 w-4 text-gray-500" />,
};

export function DNSAnalysisPanel({ data, loading = false, onRefresh }: DNSAnalysisPanelProps) {
  const [activeView, setActiveView] = useState<"overview" | "domains" | "users">("overview");

  if (loading) {
    return (
      <Card>
        <CardHeader>
          <Skeleton className="h-6 w-48" />
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="grid gap-4 md:grid-cols-4">
              {[1, 2, 3, 4].map(i => <Skeleton key={i} className="h-24 w-full" />)}
            </div>
            <Skeleton className="h-64 w-full" />
          </div>
        </CardContent>
      </Card>
    );
  }

  if (!data) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Globe className="h-5 w-5" />
            DNS Analysis
          </CardTitle>
          <CardDescription>No DNS analysis data available</CardDescription>
        </CardHeader>
      </Card>
    );
  }

  const stats = data.query_stats;
  const trend = trendIcons[data.trend_direction] || trendIcons.stable;

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
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Globe className="h-5 w-5" />
              DNS Analysis
              <Badge variant="outline" className="ml-2">
                {trend}
                {data.trend_direction === "up" ? "Increasing" : 
                 data.trend_direction === "down" ? "Decreasing" : "Stable"}
              </Badge>
            </CardTitle>
            <CardDescription>
              DNS query analysis and threat detection
            </CardDescription>
          </div>
          <div className="flex gap-2">
            <div className="flex rounded-md border">
              {(["overview", "domains", "users"] as const).map(view => (
                <Button
                  key={view}
                  variant={activeView === view ? "secondary" : "ghost"}
                  size="sm"
                  className="rounded-none first:rounded-l-md last:rounded-r-md"
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
            {/* Stats Cards */}
            <div className="grid gap-4 md:grid-cols-4">
              <Card>
                <CardContent className="pt-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-2xl font-bold">
                        {(stats?.total_queries || 0).toLocaleString()}
                      </div>
                      <div className="text-xs text-muted-foreground">Total Queries (30d)</div>
                    </div>
                    <Server className="h-8 w-8 text-blue-500 opacity-50" />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="pt-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-2xl font-bold text-red-600">
                        {(stats?.blocked_queries || 0).toLocaleString()}
                      </div>
                      <div className="text-xs text-muted-foreground">Blocked Queries</div>
                    </div>
                    <Ban className="h-8 w-8 text-red-500 opacity-50" />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="pt-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-2xl font-bold text-orange-600">
                        {(stats?.block_rate || 0).toFixed(1)}%
                      </div>
                      <div className="text-xs text-muted-foreground">Block Rate</div>
                    </div>
                    <Shield className="h-8 w-8 text-orange-500 opacity-50" />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="pt-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-2xl font-bold">
                        {stats?.unique_domains_bad || 0}
                      </div>
                      <div className="text-xs text-muted-foreground">Bad Domains</div>
                    </div>
                    <AlertTriangle className="h-8 w-8 text-yellow-500 opacity-50" />
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Charts */}
            <div className="grid gap-4 md:grid-cols-2">
              {/* Daily Trend */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium">Daily Trend (30 days)</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={dailyData}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="day" tick={{ fontSize: 10 }} />
                        <YAxis tick={{ fontSize: 10 }} />
                        <Tooltip />
                        <Area 
                          type="monotone" 
                          dataKey="total" 
                          stackId="1"
                          stroke="#8884d8" 
                          fill="#8884d8" 
                          fillOpacity={0.3}
                          name="Total"
                        />
                        <Area 
                          type="monotone" 
                          dataKey="blocked" 
                          stackId="2"
                          stroke="#ef4444" 
                          fill="#ef4444"
                          fillOpacity={0.5}
                          name="Blocked"
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </CardContent>
              </Card>

              {/* Category Breakdown */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium">Category Breakdown</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={categoryData}
                          cx="50%"
                          cy="50%"
                          labelLine={false}
                          outerRadius={80}
                          fill="#8884d8"
                          dataKey="value"
                          label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                        >
                          {categoryData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip />
                      </PieChart>
                    </ResponsiveContainer>
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
                <CardContent>
                  <div className="h-48">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={hourlyData}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="hour" tick={{ fontSize: 10 }} />
                        <YAxis tick={{ fontSize: 10 }} />
                        <Tooltip />
                        <Bar dataKey="total" fill="#8884d8" name="Total" />
                        <Bar dataKey="blocked" fill="#ef4444" name="Blocked" />
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
  );
}
