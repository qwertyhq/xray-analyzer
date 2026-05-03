"use client";

import { useState, useEffect, useMemo, useCallback } from "react";
import { authFetch } from "@/contexts/auth-context";
import { useWebSocket, useWsThreatIntel } from "@/contexts/websocket-context";
import { useThreatIntelData } from "@/hooks/use-threat-intel-data";
import { StatsCards } from "@/components/dashboard/stats-cards";
import { ActivityChart } from "@/components/dashboard/activity-chart";
import { AnomaliesCard } from "@/components/dashboard/anomalies-card";
import { RecentBlocks } from "@/components/dashboard/recent-blocks";
import { NodesTable } from "@/components/nodes/nodes-table";
import { ThreatIntelCard } from "@/components/threatintel/threat-intel-card";
import { QuickActions } from "@/components/dashboard/quick-actions";
import { SystemHealth } from "@/components/dashboard/system-health";
import { ActivityHeatmap } from "@/components/dashboard/activity-heatmap";
import { GeoMap, CityData } from "@/components/dashboard/geo-map";
import { TopOffenders } from "@/components/dashboard/top-offenders";
import { RealTimeFeed, FeedEvent, EventType } from "@/components/dashboard/real-time-feed";
import { TrafficDistribution } from "@/components/dashboard/traffic-distribution";
import { PeriodComparison } from "@/components/dashboard/period-comparison";
import { AlertsSummary, Alert } from "@/components/dashboard/alerts-summary";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Wifi, WifiOff } from "lucide-react";
import { useTranslations } from "next-intl";
import { BlacklistMatchInfo, StatsAnomaly } from "@/lib/types";

export default function DashboardPage() {
  const t = useTranslations();
  const tThreat = useTranslations("threatIntel");
  const { stats, nodes, hourly, anomalies, blacklist, connected, loading } = useWebSocket();
  const { threatIntel } = useWsThreatIntel();
  // HTTP-polled copy as a fallback: WS may take up to 10s to push the first
  // threatintel frame after (re)connect, and the feed loader itself can be
  // slow on cold start. The HTTP endpoint reads the same stats and
  // guarantees SystemHealth sees live numbers within a refresh interval.
  const { stats: tiStatsHTTP } = useThreatIntelData();
  
  // State for additional data
  const [geoData, setGeoData] = useState<Array<{ country: string; country_code: string; count: number; users: number }>>([]);
  const [cityData, setCityData] = useState<CityData[]>([]);
  const [topOffenders, setTopOffenders] = useState<Array<{ user_email: string; blacklist_hits: number; risk_score?: number }>>([]);
  const [feedEvents, setFeedEvents] = useState<FeedEvent[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [dbAlerts, setDbAlerts] = useState<Alert[]>([]);
  const [remnawaveStatus, setRemnawaveStatus] = useState<"online" | "offline" | "unknown">("unknown");
  const [remnawaveEnabled, setRemnawaveEnabled] = useState<boolean>(true);
  const [remnawaveLastSync, setRemnawaveLastSync] = useState<string | undefined>();
  const [onlineHistory, setOnlineHistory] = useState<Array<{hour: string; online_users: number}>>([]);
  // HTTP fallback for core stats. WS broadcast skips ticks under SQLite
  // write contention; falling back to /api/stats (which is Redis-cached)
  // keeps the Dashboard cards populated even while the WS queue drains.
  const [statsHTTP, setStatsHTTP] = useState<typeof stats | null>(null);
  
  // Fetch additional dashboard data.
  // All 6 endpoints are independent → Promise.all. Previously they ran
  // sequentially so a single slow one (usually threatintel/geo-stats on a
  // cold cache) bottlenecked every other card's first paint.
  useEffect(() => {
    const safeJson = async (url: string) => {
      try {
        const res = await authFetch(url);
        if (!res.ok) return null;
        return await res.json();
      } catch {
        return null;
      }
    };

    const fetchDashboardData = async () => {
      const [geo, cities, offenders, online, remna, alerts, coreStats] = await Promise.all([
        safeJson("/api/threatintel/geo-stats?type=connections&limit=50"),
        safeJson("/api/threatintel/geo-stats?type=cities&limit=200"),
        safeJson("/api/users"),
        safeJson("/api/online-history?since=24h"),
        safeJson("/api/remnawave/stats"),
        safeJson("/api/alerts?limit=20"),
        safeJson("/api/stats"),
      ]);
      if (coreStats) {
        setStatsHTTP(coreStats);
      }

      if (geo?.top_countries) {
        setGeoData(
          geo.top_countries.map((c: { country_code: string; country_name: string; total_matches: number; unique_users: number }) => ({
            country: c.country_name || c.country_code,
            country_code: c.country_code,
            count: c.total_matches,
            users: c.unique_users,
          })),
        );
      }

      if (cities?.cities) {
        setCityData(
          cities.cities.map((c: { city: string; country_code: string; country_name: string; latitude: number; longitude: number; connections: number; unique_users: number }) => ({
            city: c.city,
            country: c.country_name || c.country_code,
            country_code: c.country_code,
            count: c.connections,
            users: c.unique_users,
            latitude: c.latitude,
            longitude: c.longitude,
          })),
        );
      }

      if (Array.isArray(offenders)) {
        const topUsers = offenders
          .filter((u: { blacklist_hits: number }) => u.blacklist_hits > 0)
          .slice(0, 5)
          .map((u: { username: string; blacklist_hits: number }) => ({
            user_email: u.username,
            blacklist_hits: u.blacklist_hits,
          }));
        setTopOffenders(topUsers);
      }

      if (online?.points) {
        setOnlineHistory(online.points);
      }

      if (remna) {
        setRemnawaveEnabled(remna.enabled ?? false);
        if (remna.enabled) {
          setRemnawaveStatus(remna.totalUsers > 0 ? "online" : "offline");
          setRemnawaveLastSync(remna.lastSync);
        } else {
          setRemnawaveStatus("offline");
        }
      } else {
        setRemnawaveEnabled(false);
        setRemnawaveStatus("offline");
      }

      if (Array.isArray(alerts)) {
        const mappedAlerts: Alert[] = alerts.map((a: { id: number; type: string; user_email: string; destination: string; count: number; message: string; created_at: string; sent: boolean }) => ({
          id: `db-${a.id}`,
          title: a.type === "blacklist_threshold" ? `🚨 ${t("nav.blacklist")}: ${a.user_email}` : `⚠️ ${a.type}`,
          description: a.destination ? `${a.count}x → ${a.destination}` : `${a.count} ${t("blacklist.hits").toLowerCase()}`,
          severity: a.count >= 10 ? "critical" as const : a.count >= 5 ? "high" as const : "medium" as const,
          timestamp: a.created_at,
          read: a.sent,
          link: `/users/${encodeURIComponent(a.user_email)}`,
        }));
        setDbAlerts(mappedAlerts);
      }
    };

    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 30000);
    return () => clearInterval(interval);
  }, []);

  // Convert blacklist matches to feed events
  useEffect(() => {
    const newEvents: FeedEvent[] = [];
    
    // Add blacklist events
    blacklist?.recent_matches?.slice(0, 10).forEach((match: BlacklistMatchInfo, index: number) => {
      newEvents.push({
        id: `bl-${match.timestamp}-${index}`,
        type: "blacklist_hit" as EventType,
        message: `Blocked: ${match.destination}`,
        details: match.display_name || match.user_email,
        timestamp: match.timestamp,
        severity: "warning",
      });
    });
    
    // Add threat intel events
    threatIntel.matches?.slice(0, 10).forEach((match) => {
      newEvents.push({
        id: `ti-${match.id}`,
        type: "threat_match" as EventType,
        message: `Threat: ${match.destination}`,
        details: `${match.threat_type} - ${match.username || match.user_email}`,
        timestamp: match.matched_at,
        severity: "error",
      });
    });
    
    // Add anomaly events
    anomalies?.slice(0, 5).forEach((anomaly: StatsAnomaly) => {
      newEvents.push({
        id: `an-${anomaly.hour}-${anomaly.type}`,
        type: "anomaly" as EventType,
        message: anomaly.message,
        details: anomaly.user_email,
        timestamp: anomaly.hour,
        severity: "warning",
      });
    });
    
    // Sort by timestamp
    newEvents.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    
    setFeedEvents(newEvents.slice(0, 50));
  }, [blacklist?.recent_matches, threatIntel.matches, anomalies]);

  // Generate alerts from threat intel categories + merge with database alerts
  useEffect(() => {
    const newAlerts: Alert[] = [];
    const topUsers = threatIntel.topUsers;

    // Category labels and severity config
    const categoryConfig: Record<string, { label: string; severity: "critical" | "high" | "medium"; icon: string }> = {
      tor: { label: "🌐 Tor", severity: "critical", icon: "🌐" },
      torrent: { label: "📥 Torrent", severity: "high", icon: "📥" },
      porn: { label: `🔞 ${tThreat("categories.porn")}`, severity: "high", icon: "🔞" },
      gambling: { label: `🎰 ${tThreat("categories.gambling")}`, severity: "high", icon: "🎰" },
      malware: { label: "🦠 Malware", severity: "critical", icon: "🦠" },
    };

    // Generate alerts for recent users in each category (if topUsers available)
    if (topUsers) {
      const categories = ["tor", "torrent", "porn", "gambling", "malware"] as const;
      
      categories.forEach(category => {
        const users = topUsers[category] || [];
        const config = categoryConfig[category];
        
        // Take last 3 users from each category
        users.slice(0, 3).forEach((user, idx) => {
          const displayName = user.username || user.user_email;
          const domains = user.domains?.slice(0, 2).join(", ") || "";
          
          newAlerts.push({
            id: `threat-${category}-${user.user_email}-${idx}`,
            title: `${config.label}: ${displayName}`,
            description: domains ? `→ ${domains}` : `${user.match_count} ${t("blacklist.hits").toLowerCase()}`,
            severity: config.severity,
            timestamp: new Date().toISOString(), // Recent activity
            read: false,
            link: `/users/${encodeURIComponent(user.user_email)}`,
          });
        });
      });
    }

    // Add database alerts
    newAlerts.push(...dbAlerts);
    
    // Sort by severity (critical first, then high), then by timestamp
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    newAlerts.sort((a, b) => {
      const sevDiff = severityOrder[a.severity] - severityOrder[b.severity];
      if (sevDiff !== 0) return sevDiff;
      return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
    });
    
    // Remove duplicates by id and limit
    const seen = new Set<string>();
    const uniqueAlerts = newAlerts.filter(a => {
      if (seen.has(a.id)) return false;
      seen.add(a.id);
      return true;
    });
    
    setAlerts(uniqueAlerts.slice(0, 20));
  }, [threatIntel.topUsers, dbAlerts]);

  // Quick action handlers
  const handleSyncRemnawave = useCallback(async () => {
    try {
      const token = localStorage.getItem("auth_token");
      await authFetch("/api/remnawave/sync", {
        method: "POST",
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
    } catch (error) {
      console.error("Sync failed:", error);
    }
  }, []);

  const handleRefreshBlacklist = useCallback(async () => {
    try {
      const token = localStorage.getItem("auth_token");
      await authFetch("/api/threatintel/refresh", {
        method: "POST",
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
    } catch (error) {
      console.error("Refresh failed:", error);
    }
  }, []);

  const handleExportReport = useCallback(async () => {
    window.open("/api/threatintel/reports?format=html&type=summary", "_blank");
  }, []);

  const handleMarkAlertRead = useCallback((id: string) => {
    setAlerts(prev => prev.map(a => a.id === id ? { ...a, read: true } : a));
  }, []);

  const handleMarkAllAlertsRead = useCallback(() => {
    setAlerts(prev => prev.map(a => ({ ...a, read: true })));
  }, []);

  // Calculate period comparison stats (mock previous day as 90% of current for demo)
  const periodStats = useMemo(() => ({
    requests: { 
      current: stats.total_requests, 
      previous: Math.round(stats.total_requests * 0.85) 
    },
    blacklistHits: { 
      current: stats.total_blacklist, 
      previous: Math.round(stats.total_blacklist * 1.1) 
    },
    uniqueUsers: { 
      current: stats.total_unique_users, 
      previous: Math.round(stats.total_unique_users * 0.95) 
    },
    onlineUsers: { 
      current: stats.online_users, 
      previous: Math.round(stats.online_users * 0.9) 
    },
  }), [stats]);

  // Filter only online nodes for dashboard
  const onlineNodes = useMemo(() => nodes.filter(n => n.is_connected), [nodes]);

  if (loading) {
    return (
      <div className="p-4 md:p-8 space-y-6">
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
          {[...Array(5)].map((_, i) => (
            <Skeleton key={i} className="h-[120px]" />
          ))}
        </div>
        <Skeleton className="h-[280px]" />
        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
          <Skeleton className="h-[300px]" />
          <Skeleton className="h-[300px]" />
          <Skeleton className="h-[300px]" />
        </div>
      </div>
    );
  }

  return (
    <div className="p-4 md:p-8 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div>
          <h2 className="text-xl sm:text-2xl font-bold tracking-tight">{t("dashboard.title")}</h2>
          <p className="text-sm text-muted-foreground">
            {t("dashboard.description")}
          </p>
        </div>
        <Badge 
          variant={connected ? "default" : "destructive"} 
          className="flex items-center gap-1.5 self-start sm:self-auto"
        >
          {connected ? (
            <>
              <Wifi className="h-3 w-3" />
              {t("common.live")}
            </>
          ) : (
            <>
              <WifiOff className="h-3 w-3" />
              {t("common.disconnected")}
            </>
          )}
        </Badge>
      </div>

      {/* Stats Cards — prefer live WS state, but fall back to HTTP so the
          dashboard keeps showing numbers even if the broadcast is stalled.
          Each field is picked independently so a partial WS update still
          shows the freshest value available. */}
      <StatsCards
        stats={{
          total_requests: stats?.total_requests || statsHTTP?.total_requests || 0,
          total_blacklist: stats?.total_blacklist || statsHTTP?.total_blacklist || 0,
          nodes_total: stats?.nodes_total || statsHTTP?.nodes_total || 0,
          nodes_connected: stats?.nodes_connected ?? statsHTTP?.nodes_connected ?? 0,
          total_unique_users: stats?.total_unique_users || statsHTTP?.total_unique_users || 0,
          online_users: stats?.online_users || statsHTTP?.online_users || 0,
        }}
      />

      {/* Row 2: Quick Actions + System Health + Period Comparison + Alerts */}
      <div className="grid gap-4 grid-cols-1 sm:grid-cols-2 lg:grid-cols-4">
        <QuickActions 
          onSyncRemnawave={handleSyncRemnawave}
          onRefreshBlacklist={handleRefreshBlacklist}
          onExportReport={handleExportReport}
          problemUsersCount={topOffenders.filter(u => (u.risk_score || 0) >= 50).length}
        />
        <SystemHealth 
          remnawaveStatus={remnawaveStatus}
          remnawaveEnabled={remnawaveEnabled}
          remnawaveLastSync={remnawaveLastSync}
          threatIntelIndicators={threatIntel.stats?.total_indicators ?? tiStatsHTTP?.total_indicators ?? null}
          threatIntelLastUpdate={threatIntel.stats?.last_updated ?? tiStatsHTTP?.last_updated}
          websocketConnected={connected}
        />
        <PeriodComparison stats={periodStats} periodLabel={t("dashboard.vsYesterday")} />
        <AlertsSummary 
          alerts={alerts}
          onMarkRead={handleMarkAlertRead}
          onMarkAllRead={handleMarkAllAlertsRead}
        />
      </div>

      {/* Row 3: Activity Chart + Anomalies */}
      <div className="grid gap-4 grid-cols-1 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <ActivityChart
            data={hourly}
            onlineHistory={onlineHistory}
            title={t("dashboard.activityTitle")}
            description={t("dashboard.activityDesc")}
            loading={false}
            timeRange="24h"
          />
        </div>
        <AnomaliesCard anomalies={anomalies} loading={false} />
      </div>

      {/* Row 4: Heatmap + Traffic Distribution + Top Offenders */}
      <div className="grid gap-4 grid-cols-1 md:grid-cols-2 lg:grid-cols-3">
        <ActivityHeatmap
          data={hourly}
          title={t("activityHeatmap.title")}
          description={t("activityHeatmap.description")}
        />
        <TrafficDistribution nodes={nodes} title={t("trafficDistribution.title")} />
        <TopOffenders users={topOffenders} title={t("topOffenders.title")} />
      </div>

      {/* Row 5: Geo Distribution (larger) + Real-time Feed */}
      <div className="grid gap-4 grid-cols-1 md:grid-cols-2">
        <GeoMap data={geoData} cityData={cityData} title={t("geoMap.title")} mode="cities" />
        <RealTimeFeed events={feedEvents} title={t("realTimeFeed.title")} />
      </div>

      {/* Row 6: Threat Intel (full width) */}
      <div className="grid gap-6">
        <ThreatIntelCard />
      </div>

      {/* Row 7: Nodes + Blacklist Alerts */}
      <div className="grid gap-4 grid-cols-1 md:grid-cols-2">
        <Card className="overflow-hidden">
          <CardHeader className="pb-3">
            <CardTitle>{t("dashboard.activeNodes")}</CardTitle>
            <CardDescription>
              {t("dashboard.activeNodesDesc", { online: onlineNodes.length, total: nodes.length })}
            </CardDescription>
          </CardHeader>
          <CardContent className="max-h-[400px] overflow-y-auto scrollbar-thin">
            <NodesTable nodes={onlineNodes} />
          </CardContent>
        </Card>

        <Card className="overflow-hidden">
          <CardHeader className="pb-3">
            <CardTitle>{t("dashboard.blacklistAlerts")}</CardTitle>
            <CardDescription>
              {t("dashboard.recentBlocked")}
            </CardDescription>
          </CardHeader>
          <CardContent className="max-h-[400px] overflow-y-auto scrollbar-thin">
            <RecentBlocks 
              matches={blacklist?.recent_matches || []} 
              loading={false}
              limit={10}
            />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
