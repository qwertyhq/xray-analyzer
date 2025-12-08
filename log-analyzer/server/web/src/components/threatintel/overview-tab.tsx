"use client";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ThreatMatch, ThreatStats, FeedStatus, CategoryTopUsers, TimeStats, GeoSummary, AnomalySummary, UserRiskSummary, DNSAnalysisSummary, ReportSummary, ReportConfig } from "@/lib/types";
import { formatDistanceToNow } from "date-fns";
import { threatTypeConfig, sourceLabels } from "./config";
import { UserList } from "./user-list";
import { MatchesTable } from "./matches-table";
import { TimeChart } from "./time-chart";
import { GeoChart } from "./geo-chart";
import { AnomalyPanel } from "./anomaly-panel";
import { RiskProfilePanel } from "./risk-profile-panel";
import { DNSAnalysisPanel } from "./dns-analysis-panel";
import { ReportsPanel } from "./reports-panel";
import { Database, AlertTriangle, Clock, Radio, TrendingUp, Shield } from "lucide-react";

interface OverviewTabProps {
  stats: ThreatStats | null;
  feeds: FeedStatus[];
  topUsers: CategoryTopUsers | null;
  threatMatches: ThreatMatch[];
  timeStats: TimeStats | null;
  geoStats: GeoSummary | null;
  anomalies: AnomalySummary | null;
  riskProfiles: UserRiskSummary | null;
  dnsAnalysis: DNSAnalysisSummary | null;
  reports: ReportSummary | null;
  onRiskRefresh?: () => void;
  onDnsRefresh?: () => void;
  onReportsRefresh?: () => void;
  onGenerateReport?: (config: ReportConfig) => Promise<void>;
  onDeleteReport?: (id: string) => Promise<void>;
}

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

export function OverviewTab({ stats, feeds, topUsers, threatMatches, timeStats, geoStats, anomalies, riskProfiles, dnsAnalysis, reports, onRiskRefresh, onDnsRefresh, onReportsRefresh, onGenerateReport, onDeleteReport }: OverviewTabProps) {
  const activeFeeds = feeds.filter((f) => f.status === "ok").length;
  
  return (
    <div className="space-y-6">
      {/* Gradient Stats Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <StatCard
          icon={<Database className="h-4 w-4" />}
          label="Total Indicators"
          value={stats?.total_indicators.toLocaleString() || "0"}
          subValue="Loaded from feeds"
          gradient="bg-gradient-to-br from-blue-500 to-blue-600"
        />
        <StatCard
          icon={<AlertTriangle className="h-4 w-4" />}
          label="Total Matches"
          value={stats?.total_matches?.toLocaleString() || "0"}
          subValue="All time detections"
          gradient="bg-gradient-to-br from-red-500 to-red-600"
        />
        <StatCard
          icon={<Clock className="h-4 w-4" />}
          label="Matches (24h)"
          value={stats?.matches_24h?.toLocaleString() || "0"}
          subValue="Last 24 hours"
          gradient="bg-gradient-to-br from-amber-500 to-amber-600"
        />
        <StatCard
          icon={<Radio className="h-4 w-4" />}
          label="Active Feeds"
          value={`${activeFeeds}/${feeds.length}`}
          subValue="Feeds online"
          gradient="bg-gradient-to-br from-emerald-500 to-emerald-600"
        />
      </div>

      {/* Time-based Charts */}
      <TimeChart data={timeStats} />

      {/* Geographic Analysis */}
      <GeoChart data={geoStats} />

      {/* Feed Status */}
      <Card className="border-0 shadow-md">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-blue-500" />
            Feed Status
          </CardTitle>
          <CardDescription>Status of threat intelligence data sources</CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="whitespace-nowrap">Source</TableHead>
                <TableHead className="whitespace-nowrap">Status</TableHead>
                <TableHead className="text-right whitespace-nowrap hidden sm:table-cell">Indicators</TableHead>
                <TableHead className="whitespace-nowrap hidden md:table-cell">Last Update</TableHead>
                <TableHead className="whitespace-nowrap hidden lg:table-cell">Next Update</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {feeds.map((feed) => (
                <TableRow key={feed.source} className="hover:bg-muted/50 transition-colors">
                  <TableCell className="font-medium text-xs sm:text-sm">
                    {sourceLabels[feed.source] || feed.source}
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant={feed.status === "ok" ? "default" : "destructive"}
                      className={feed.status === "ok" ? "bg-emerald-500 hover:bg-emerald-600" : ""}
                    >
                      {feed.status === "ok" ? "✓ Online" : feed.status}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-right hidden sm:table-cell font-mono">
                    {feed.indicators.toLocaleString()}
                  </TableCell>
                  <TableCell className="text-muted-foreground hidden md:table-cell text-sm">
                    {feed.last_update
                      ? formatDistanceToNow(new Date(feed.last_update), { addSuffix: true })
                      : "—"}
                  </TableCell>
                  <TableCell className="text-muted-foreground hidden lg:table-cell text-sm">
                    {feed.next_update
                      ? formatDistanceToNow(new Date(feed.next_update), { addSuffix: true })
                      : "—"}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Top Users by Content Category */}
      {topUsers && (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {(["porn", "gambling", "social", "fakenews", "torrent", "tor"] as const).map((category) => {
            const users = topUsers[category] || [];
            const config = threatTypeConfig[category];
            const totalCount = users.reduce((sum, u) => sum + u.match_count, 0);
            
            return (
              <Card key={category} className="overflow-hidden">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className={`p-1.5 rounded-md ${config.color}`}>
                        <span className="text-white">{config.icon}</span>
                      </div>
                      <CardTitle className="text-sm font-medium">{config.label}</CardTitle>
                    </div>
                    {totalCount > 0 && (
                      <span className="text-xl font-bold">{totalCount}</span>
                    )}
                  </div>
                </CardHeader>
                <CardContent className="pt-0">
                  <UserList users={users} />
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {/* Anomaly Detection Panel */}
      <AnomalyPanel data={anomalies} />

      {/* User Risk Profiles Panel */}
      <RiskProfilePanel data={riskProfiles} onRefresh={onRiskRefresh} />

      {/* DNS Analysis Panel */}
      <DNSAnalysisPanel data={dnsAnalysis} onRefresh={onDnsRefresh} />

      {/* Reports & Exports Panel */}
      <ReportsPanel 
        reports={reports}
        onGenerate={onGenerateReport || (async () => {})}
        onRefresh={onReportsRefresh || (() => {})}
        onDelete={onDeleteReport}
      />

      {/* Recent Matches (all types) */}
      <MatchesTable 
        matches={threatMatches} 
        title="Recent Matches"
        description={`Last ${threatMatches.length} detected connections (max 20 stored)`}
      />
    </div>
  );
}
