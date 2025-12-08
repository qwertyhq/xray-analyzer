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
  low: "hsl(142, 71%, 45%)",      // green
  medium: "hsl(48, 96%, 53%)",    // yellow
  high: "hsl(25, 95%, 53%)",      // orange
  critical: "hsl(0, 84%, 60%)",   // red
};

// Theme-aware chart colors using HSL
const CHART_COLORS = [
  "hsl(262, 83%, 58%)",   // purple (primary)
  "hsl(142, 71%, 45%)",   // green
  "hsl(48, 96%, 53%)",    // yellow
  "hsl(25, 95%, 53%)",    // orange
  "hsl(197, 71%, 53%)",   // cyan
  "hsl(340, 82%, 52%)",   // pink
  "hsl(212, 96%, 54%)",   // blue
];

// Return the appropriate icon component based on trend direction
function getTrendIcon(direction: string) {
  switch (direction) {
    case "up":
      return <TrendingUp className="h-4 w-4 text-red-500" />;
    case "down":
      return <TrendingDown className="h-4 w-4 text-green-500" />;
    default:
      return <Minus className="h-4 w-4 text-muted-foreground" />;
  }
}

// Gradient stat card component
interface GradientStatCardProps {
  icon: React.ReactNode;
  label: string;
  value: string | number;
  subValue?: string;
  gradient: string;
}

function GradientStatCard({ icon, label, value, subValue, gradient }: GradientStatCardProps) {
  return (
    <div className={`relative overflow-hidden rounded-xl p-4 ${gradient}`}>
      <div className="absolute top-0 right-0 w-20 h-20 opacity-10">
        <div className="w-full h-full rounded-full bg-white transform translate-x-4 -translate-y-4" />
      </div>
      <div className="relative z-10">
        <div className="flex items-center gap-2 text-white/90 mb-2">
          {icon}
          <span className="text-xs font-medium uppercase tracking-wider">{label}</span>
        </div>
        <div className="text-2xl font-bold text-white">{value}</div>
        {subValue && (
          <div className="text-xs text-white/70 mt-1">{subValue}</div>
        )}
      </div>
    </div>
  );
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
      {/* Gradient Stats Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <GradientStatCard
          icon={<Server className="h-4 w-4" />}
          label="Total Queries"
          value={(stats?.total_queries || 0).toLocaleString()}
          subValue="Last 30 days"
          gradient="bg-gradient-to-br from-blue-500 to-blue-600"
        />
        <GradientStatCard
          icon={<Ban className="h-4 w-4" />}
          label="Blocked Queries"
          value={(stats?.blocked_queries || 0).toLocaleString()}
          subValue="Threats blocked"
          gradient="bg-gradient-to-br from-red-500 to-red-600"
        />
        <GradientStatCard
          icon={<Shield className="h-4 w-4" />}
          label="Block Rate"
          value={`${(stats?.block_rate || 0).toFixed(1)}%`}
          subValue="Blocked / Total"
          gradient="bg-gradient-to-br from-amber-500 to-amber-600"
        />
        <GradientStatCard
          icon={<AlertTriangle className="h-4 w-4" />}
          label="Bad Domains"
          value={stats?.unique_domains_bad || 0}
          subValue="Unique threats"
          gradient="bg-gradient-to-br from-violet-500 to-violet-600"
        />
      </div>

      {/* Main Card */}
      <Card className="border-0 shadow-md">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Globe className="h-5 w-5 text-blue-500" />
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
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium">Daily Trend (30 days)</CardTitle>
                </CardHeader>
                <CardContent className="pt-0">
                  <div className="h-[250px] w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={dailyData} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                        <defs>
                          <linearGradient id="colorTotal" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="hsl(262, 83%, 58%)" stopOpacity={0.8} />
                            <stop offset="95%" stopColor="hsl(262, 83%, 58%)" stopOpacity={0.1} />
                          </linearGradient>
                          <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="hsl(0, 84%, 60%)" stopOpacity={0.8} />
                            <stop offset="95%" stopColor="hsl(0, 84%, 60%)" stopOpacity={0.1} />
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
                          contentStyle={{
                            backgroundColor: "hsl(var(--card))",
                            border: "1px solid hsl(var(--border))",
                            borderRadius: "8px",
                            fontSize: "12px",
                          }}
                          labelStyle={{ color: "hsl(var(--foreground))" }}
                        />
                        <Legend wrapperStyle={{ fontSize: "10px" }} />
                        <Area
                          type="monotone"
                          dataKey="total"
                          stroke="hsl(262, 83%, 58%)"
                          fill="url(#colorTotal)"
                          name="Total"
                        />
                        <Area
                          type="monotone"
                          dataKey="blocked"
                          stroke="hsl(0, 84%, 60%)"
                          fill="url(#colorBlocked)"
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
                <CardContent className="pt-0">
                  <div className="h-[250px] w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={categoryData}
                          cx="50%"
                          cy="50%"
                          labelLine={false}
                          outerRadius={80}
                          innerRadius={40}
                          fill="hsl(262, 83%, 58%)"
                          dataKey="value"
                          label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                          paddingAngle={2}
                        >
                          {categoryData.map((_, index) => (
                            <Cell key={`cell-${index}`} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip
                          contentStyle={{
                            backgroundColor: "hsl(var(--card))",
                            border: "1px solid hsl(var(--border))",
                            borderRadius: "8px",
                            fontSize: "12px",
                          }}
                          labelStyle={{ color: "hsl(var(--foreground))" }}
                        />
                        <Legend wrapperStyle={{ fontSize: "10px" }} />
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
                          contentStyle={{
                            backgroundColor: "hsl(var(--card))",
                            border: "1px solid hsl(var(--border))",
                            borderRadius: "8px",
                            fontSize: "12px",
                          }}
                          labelStyle={{ color: "hsl(var(--foreground))" }}
                        />
                        <Legend wrapperStyle={{ fontSize: "10px" }} />
                        <Bar dataKey="total" fill="hsl(262, 83%, 58%)" name="Total" radius={[2, 2, 0, 0]} />
                        <Bar dataKey="blocked" fill="hsl(0, 84%, 60%)" name="Blocked" radius={[2, 2, 0, 0]} />
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
