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
} from "recharts";
import { GeoSummary, ThreatType } from "@/lib/types";
import { threatTypeConfig } from "./config";
import { Globe, MapPin, Users, AlertTriangle } from "lucide-react";

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

// Color palette for countries
const countryColors = [
  "hsl(221, 83%, 53%)", // blue
  "hsl(262, 83%, 58%)", // purple  
  "hsl(142, 71%, 45%)", // green
  "hsl(32, 98%, 50%)",  // orange
  "hsl(340, 82%, 52%)", // pink
  "hsl(197, 71%, 73%)", // light blue
  "hsl(48, 96%, 53%)",  // yellow
  "hsl(0, 84%, 60%)",   // red
  "hsl(165, 82%, 51%)", // teal
  "hsl(25, 95%, 53%)",  // dark orange
];

// Get label for threat type
const getTypeLabel = (type: string): string => {
  const config = threatTypeConfig[type as ThreatType];
  return config?.label || type;
};

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

  if (loading) {
    return (
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Geographic Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <Skeleton className="h-[250px] w-full" />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Top Countries</CardTitle>
          </CardHeader>
          <CardContent>
            <Skeleton className="h-[250px] w-full" />
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!data || !data.top_countries?.length) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Globe className="h-5 w-5" />
            Geographic Analysis
          </CardTitle>
          <CardDescription>No geographic data available yet</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center h-[200px] text-muted-foreground">
            Geographic statistics will appear after threat matches with IP data are recorded
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {/* Stats Summary */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Globe className="h-4 w-4 text-blue-500" />
              Countries
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{data.total_countries}</div>
            <p className="text-xs text-muted-foreground">Unique countries detected</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <MapPin className="h-4 w-4 text-green-500" />
              Top Country
            </CardTitle>
          </CardHeader>
          <CardContent>
            {data.top_countries[0] && (
              <>
                <div className="text-2xl font-bold">
                  {getFlag(data.top_countries[0].country_code)} {data.top_countries[0].country_name}
                </div>
                <p className="text-xs text-muted-foreground">
                  {data.top_countries[0].total_matches.toLocaleString()} matches
                </p>
              </>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-orange-500" />
              Most Common Threat
            </CardTitle>
          </CardHeader>
          <CardContent>
            {data.top_countries[0] && (
              <>
                <div className="text-2xl font-bold">
                  {getTypeLabel(data.top_countries[0].top_threat)}
                </div>
                <p className="text-xs text-muted-foreground">
                  In {data.top_countries[0].country_name}
                </p>
              </>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Charts */}
      <div className="grid gap-4 md:grid-cols-2">
        {/* Bar Chart */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Matches by Country</CardTitle>
            <CardDescription className="text-xs">Top countries by threat matches</CardDescription>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="h-[250px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={barData} layout="vertical" margin={{ top: 5, right: 20, left: 40, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-muted" horizontal={false} />
                  <XAxis type="number" tick={{ fontSize: 10 }} />
                  <YAxis 
                    type="category" 
                    dataKey="name" 
                    tick={{ fontSize: 11 }} 
                    width={50}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "hsl(var(--card))",
                      border: "1px solid hsl(var(--border))",
                      borderRadius: "8px",
                      fontSize: "12px",
                    }}
                  />
                  <Bar dataKey="matches" radius={[0, 4, 4, 0]}>
                    {barData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        {/* Pie Chart */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Distribution</CardTitle>
            <CardDescription className="text-xs">Share of matches by country</CardDescription>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="h-[250px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={80}
                    paddingAngle={2}
                    dataKey="value"
                    label={({ name, percent }) => `${getFlag(name)} ${percent}%`}
                    labelLine={false}
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "hsl(var(--card))",
                      border: "1px solid hsl(var(--border))",
                      borderRadius: "8px",
                      fontSize: "12px",
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Country Details Table */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">Country Details</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {data.top_countries.slice(0, 10).map((country, i) => (
              <div
                key={country.country_code}
                className="flex items-center justify-between p-2 rounded-lg bg-muted/50"
              >
                <div className="flex items-center gap-3">
                  <span className="text-xl">{getFlag(country.country_code)}</span>
                  <div>
                    <div className="font-medium text-sm">{country.country_name}</div>
                    <div className="text-xs text-muted-foreground flex items-center gap-1">
                      <Users className="h-3 w-3" />
                      {country.unique_users} users
                    </div>
                  </div>
                </div>
                <div className="text-right">
                  <div className="font-bold">{country.total_matches.toLocaleString()}</div>
                  <Badge variant="outline" className="text-xs">
                    {getTypeLabel(country.top_threat)}
                  </Badge>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
