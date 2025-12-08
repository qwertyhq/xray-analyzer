"use client";

import { useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
  PieChart,
  Pie,
  Legend,
} from "recharts";
import { GeoSummary, ThreatType } from "@/lib/types";
import { threatTypeConfig } from "./config";
import { Globe, MapPin, Users, AlertTriangle, TrendingUp, Shield, Target } from "lucide-react";

interface GeoChartProps {
  data: GeoSummary | null;
  loading?: boolean;
}

// Flag emoji from country code
const getFlag = (countryCode: string): string => {
  if (!countryCode || countryCode.length !== 2) return "🌍";
  const codePoints = countryCode
    .toUpperCase()
    .split("")
    .map((char) => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
};

// Modern color palette with gradients
const countryColors = [
  "#6366f1", // indigo
  "#8b5cf6", // violet
  "#06b6d4", // cyan
  "#10b981", // emerald
  "#f59e0b", // amber
  "#ef4444", // red
  "#ec4899", // pink
  "#14b8a6", // teal
  "#f97316", // orange
  "#84cc16", // lime
];

// Get label for threat type
const getTypeLabel = (type: string): string => {
  const config = threatTypeConfig[type as ThreatType];
  return config?.label || type;
};

// Gradient stat card component
interface StatCardProps {
  icon: React.ReactNode;
  label: string;
  value: string | number;
  subValue?: string;
  gradient: string;
}

function StatCard({ icon, label, value, subValue, gradient }: StatCardProps) {
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

export function GeoChart({ data, loading = false }: GeoChartProps) {
  // Transform data for bar chart
  const barData = useMemo(() => {
    if (!data?.top_countries?.length) return [];
    return data.top_countries.slice(0, 8).map((c, i) => ({
      name: `${getFlag(c.country_code)} ${c.country_code}`,
      fullName: c.country_name,
      matches: c.total_matches,
      users: c.unique_users,
      topThreat: c.top_threat,
      color: countryColors[i % countryColors.length],
    }));
  }, [data]);

  // Transform data for pie chart
  const pieData = useMemo(() => {
    if (!data?.top_countries?.length) return [];
    const total = data.top_countries.reduce((sum, c) => sum + c.total_matches, 0);
    return data.top_countries.slice(0, 6).map((c, i) => ({
      name: c.country_code,
      fullName: c.country_name,
      value: c.total_matches,
      percent: ((c.total_matches / total) * 100).toFixed(1),
      color: countryColors[i % countryColors.length],
    }));
  }, [data]);

  // Calculate total stats
  const stats = useMemo(() => {
    if (!data?.top_countries?.length) return null;
    const totalMatches = data.top_countries.reduce((sum, c) => sum + c.total_matches, 0);
    const totalUsers = data.top_countries.reduce((sum, c) => sum + c.unique_users, 0);
    const topCountry = data.top_countries[0];
    return { totalMatches, totalUsers, topCountry };
  }, [data]);

  if (loading) {
    return (
      <div className="space-y-4">
        <div className="grid gap-4 md:grid-cols-4">
          {[...Array(4)].map((_, i) => (
            <Skeleton key={i} className="h-24 rounded-xl" />
          ))}
        </div>
        <div className="grid gap-4 md:grid-cols-2">
          <Card>
            <CardContent className="pt-6">
              <Skeleton className="h-[280px] w-full" />
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <Skeleton className="h-[280px] w-full" />
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  if (!data || !data.top_countries?.length) {
    return (
      <Card className="border-dashed">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-muted-foreground">
            <Globe className="h-5 w-5" />
            Geographic Analysis
          </CardTitle>
          <CardDescription>No geographic data available yet</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col items-center justify-center h-[200px] text-muted-foreground gap-2">
            <MapPin className="h-12 w-12 opacity-20" />
            <p className="text-center">Geographic statistics will appear after<br/>threat matches with IP data are recorded</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {/* Gradient Stats Summary */}
      <div className="grid gap-4 md:grid-cols-4">
        <StatCard
          icon={<Globe className="h-4 w-4" />}
          label="Countries"
          value={data.total_countries}
          subValue="Unique countries detected"
          gradient="bg-gradient-to-br from-blue-500 to-blue-600"
        />
        <StatCard
          icon={<Target className="h-4 w-4" />}
          label="Total Matches"
          value={stats?.totalMatches.toLocaleString() || "0"}
          subValue="Across all countries"
          gradient="bg-gradient-to-br from-violet-500 to-violet-600"
        />
        <StatCard
          icon={<Users className="h-4 w-4" />}
          label="Users Affected"
          value={stats?.totalUsers.toLocaleString() || "0"}
          subValue="Unique users with threats"
          gradient="bg-gradient-to-br from-emerald-500 to-emerald-600"
        />
        <StatCard
          icon={<TrendingUp className="h-4 w-4" />}
          label="Top Source"
          value={stats?.topCountry ? `${getFlag(stats.topCountry.country_code)} ${stats.topCountry.country_code}` : "N/A"}
          subValue={stats?.topCountry ? `${stats.topCountry.total_matches.toLocaleString()} matches` : "No data"}
          gradient="bg-gradient-to-br from-amber-500 to-amber-600"
        />
      </div>

      {/* Charts */}
      <div className="grid gap-4 md:grid-cols-2">
        {/* Bar Chart */}
        <Card className="border-0 shadow-md">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Shield className="h-4 w-4 text-indigo-500" />
              Matches by Country
            </CardTitle>
            <CardDescription className="text-xs">Top countries by threat detections</CardDescription>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="h-[280px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={barData} layout="vertical" margin={{ top: 5, right: 30, left: 50, bottom: 5 }}>
                  <defs>
                    {barData.map((entry, index) => (
                      <linearGradient key={`gradient-${index}`} id={`barGradient-${index}`} x1="0" y1="0" x2="1" y2="0">
                        <stop offset="0%" stopColor={entry.color} stopOpacity={0.8} />
                        <stop offset="100%" stopColor={entry.color} stopOpacity={1} />
                      </linearGradient>
                    ))}
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-muted/30" horizontal={false} />
                  <XAxis 
                    type="number" 
                    tick={{ fontSize: 10 }}
                    tickFormatter={(value) => value.toLocaleString()}
                  />
                  <YAxis 
                    type="category" 
                    dataKey="name" 
                    tick={{ fontSize: 12 }} 
                    width={55}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "hsl(var(--card))",
                      border: "1px solid hsl(var(--border))",
                      borderRadius: "12px",
                      fontSize: "12px",
                      boxShadow: "0 4px 12px rgba(0,0,0,0.15)",
                    }}
                    formatter={(value: number, name: string) => [value.toLocaleString(), "Matches"]}
                    labelFormatter={(label) => {
                      const item = barData.find(d => d.name === label);
                      return item?.fullName || label;
                    }}
                  />
                  <Bar dataKey="matches" radius={[0, 6, 6, 0]}>
                    {barData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={`url(#barGradient-${index})`} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        {/* Pie Chart */}
        <Card className="border-0 shadow-md">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Globe className="h-4 w-4 text-violet-500" />
              Distribution
            </CardTitle>
            <CardDescription className="text-xs">Share of threats by country</CardDescription>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="h-[280px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <defs>
                    {pieData.map((entry, index) => (
                      <linearGradient key={`pieGradient-${index}`} id={`pieGradient-${index}`} x1="0" y1="0" x2="1" y2="1">
                        <stop offset="0%" stopColor={entry.color} stopOpacity={0.9} />
                        <stop offset="100%" stopColor={entry.color} stopOpacity={1} />
                      </linearGradient>
                    ))}
                  </defs>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={90}
                    paddingAngle={3}
                    dataKey="value"
                    strokeWidth={2}
                    stroke="hsl(var(--background))"
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={`url(#pieGradient-${index})`} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "hsl(var(--card))",
                      border: "1px solid hsl(var(--border))",
                      borderRadius: "12px",
                      fontSize: "12px",
                      boxShadow: "0 4px 12px rgba(0,0,0,0.15)",
                    }}
                    formatter={(value: number) => [value.toLocaleString(), "Matches"]}
                  />
                  <Legend 
                    formatter={(value) => {
                      const item = pieData.find(d => d.name === value);
                      return `${getFlag(value)} ${item?.fullName || value}`;
                    }}
                    wrapperStyle={{ fontSize: "11px" }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Country Details Table */}
      <Card className="border-0 shadow-md">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <MapPin className="h-4 w-4 text-cyan-500" />
            Country Details
          </CardTitle>
          <CardDescription className="text-xs">Detailed breakdown by country</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {data.top_countries.slice(0, 10).map((country, i) => (
              <div
                key={country.country_code}
                className="flex items-center justify-between p-3 rounded-xl bg-gradient-to-r from-muted/50 to-transparent hover:from-muted transition-all"
              >
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-full bg-gradient-to-br from-muted to-muted/50 flex items-center justify-center text-xl shadow-sm">
                    {getFlag(country.country_code)}
                  </div>
                  <div>
                    <div className="font-medium text-sm">{country.country_name}</div>
                    <div className="text-xs text-muted-foreground flex items-center gap-2">
                      <span className="flex items-center gap-1">
                        <Users className="h-3 w-3" />
                        {country.unique_users} users
                      </span>
                      <span className="text-muted-foreground/50">•</span>
                      <Badge variant="secondary" className="text-[10px] px-1.5 py-0">
                        {getTypeLabel(country.top_threat)}
                      </Badge>
                    </div>
                  </div>
                </div>
                <div className="text-right">
                  <div className="font-bold text-lg">{country.total_matches.toLocaleString()}</div>
                  <div className="text-xs text-muted-foreground">matches</div>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
