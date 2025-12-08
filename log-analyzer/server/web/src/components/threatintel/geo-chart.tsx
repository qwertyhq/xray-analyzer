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

// Muted color palette
const countryColors = [
  "hsla(240, 45%, 60%, 0.75)", // indigo muted
  "hsla(270, 40%, 60%, 0.75)", // violet muted
  "hsla(185, 45%, 50%, 0.75)", // cyan muted
  "hsla(155, 40%, 50%, 0.75)", // emerald muted
  "hsla(38, 50%, 55%, 0.75)",  // amber muted
  "hsla(0, 50%, 55%, 0.75)",   // red muted
  "hsla(330, 45%, 55%, 0.75)", // pink muted
  "hsla(170, 40%, 50%, 0.75)", // teal muted
  "hsla(25, 50%, 55%, 0.75)",  // orange muted
  "hsla(80, 40%, 50%, 0.75)",  // lime muted
];

// Common tooltip style for dark theme
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
      name: c.country_code,
      fullName: c.country_name,
      matches: c.total_matches,
      users: c.unique_users,
      topThreat: c.top_threat,
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
      {/* Matches by Country Chart */}
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
                  width={40}
                  tickFormatter={(value) => value}
                />
                <Tooltip
                  contentStyle={tooltipStyle.contentStyle}
                  labelStyle={tooltipStyle.labelStyle}
                  itemStyle={tooltipStyle.itemStyle}
                  cursor={{ fill: "rgba(63, 63, 70, 0.3)" }}
                  formatter={(value: number) => [value.toLocaleString(), "Matches"]}
                  labelFormatter={(label) => {
                    const item = barData.find(d => d.name === label);
                    return item?.fullName || label;
                  }}
                />
                <Bar dataKey="matches" radius={[0, 6, 6, 0]}>
                  {barData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
