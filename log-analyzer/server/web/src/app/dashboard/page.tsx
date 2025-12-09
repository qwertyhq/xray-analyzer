"use client";

import { useState, useEffect, useMemo, useCallback } from "react";
import { useWebSocket, useWsThreatIntel } from "@/contexts/websocket-context";
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
import { AIChat } from "@/components/dashboard/ai-chat";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Wifi, WifiOff } from "lucide-react";
import { BlacklistMatchInfo, StatsAnomaly } from "@/lib/types";

export default function DashboardPage() {
  const { stats, nodes, hourly, anomalies, blacklist, connected, loading } = useWebSocket();
  const { threatIntel } = useWsThreatIntel();
  
  // State for additional data
  const [geoData, setGeoData] = useState<Array<{ country: string; country_code: string; count: number; users: number }>>([]);
  const [cityData, setCityData] = useState<CityData[]>([]);
  const [topOffenders, setTopOffenders] = useState<Array<{ user_email: string; blacklist_hits: number; risk_score?: number }>>([]);
  const [feedEvents, setFeedEvents] = useState<FeedEvent[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [remnawaveStatus, setRemnawaveStatus] = useState<"online" | "offline" | "unknown">("unknown");
  const [remnawaveLastSync, setRemnawaveLastSync] = useState<string | undefined>();
  
  // Fetch additional dashboard data
  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        const token = localStorage.getItem("auth_token");
        const headers: HeadersInit = {};
        if (token) {
          headers["Authorization"] = `Bearer ${token}`;
        }

        // Fetch geo stats (use type=connections to get ALL connections, not just threats)
        const geoRes = await fetch("/api/threatintel/geo-stats?type=connections&limit=50", { headers });
        if (geoRes.ok) {
          const data = await geoRes.json();
          // Transform top_countries to match GeoMap format
          const countries = data.top_countries?.map((c: { country_code: string; country_name: string; total_matches: number; unique_users: number }) => ({
            country: c.country_name || c.country_code,
            country_code: c.country_code,
            count: c.total_matches,
            users: c.unique_users,
          })) || [];
          setGeoData(countries);
        }

        // Fetch city-level geo stats with coordinates
        const citiesRes = await fetch("/api/threatintel/geo-stats?type=cities&limit=200", { headers });
        if (citiesRes.ok) {
          const data = await citiesRes.json();
          const cities: CityData[] = data.cities?.map((c: { city: string; country_code: string; country_name: string; latitude: number; longitude: number; connections: number; unique_users: number }) => ({
            city: c.city,
            country: c.country_name || c.country_code,
            country_code: c.country_code,
            count: c.connections,
            users: c.unique_users,
            latitude: c.latitude,
            longitude: c.longitude,
          })) || [];
          setCityData(cities);
        }

        // Fetch top offenders (API returns array directly, sorted by blacklist_hits)
        const offendersRes = await fetch("/api/users", { headers });
        if (offendersRes.ok) {
          const data = await offendersRes.json();
          // Filter users with blacklist hits and take top 5
          const topUsers = (data || [])
            .filter((u: { blacklist_hits: number }) => u.blacklist_hits > 0)
            .slice(0, 5)
            .map((u: { user_email: string; blacklist_hits: number }) => ({
              user_email: u.user_email,
              blacklist_hits: u.blacklist_hits,
            }));
          setTopOffenders(topUsers);
        }

        // Check Remnawave status
        const remnawaveRes = await fetch("/api/remnawave/stats", { headers });
        if (remnawaveRes.ok) {
          const data = await remnawaveRes.json();
          setRemnawaveStatus(data.total_users > 0 ? "online" : "offline");
          setRemnawaveLastSync(data.last_sync);
        } else {
          setRemnawaveStatus("offline");
        }
      } catch (error) {
        console.error("Failed to fetch dashboard data:", error);
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
        details: match.user_email,
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
        details: `${match.threat_type} - ${match.user_email}`,
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

  // Generate alerts from anomalies
  useEffect(() => {
    const newAlerts: Alert[] = anomalies?.slice(0, 10).map((anomaly: StatsAnomaly, index: number) => ({
      id: `alert-${anomaly.hour}-${anomaly.type}-${index}`,
      title: anomaly.message,
      description: anomaly.user_email,
      severity: anomaly.deviation > 10 ? "critical" : anomaly.deviation > 5 ? "high" : "medium",
      timestamp: anomaly.hour,
      read: false,
    } as Alert)) || [];
    
    setAlerts(newAlerts);
  }, [anomalies]);

  // Quick action handlers
  const handleSyncRemnawave = useCallback(async () => {
    try {
      const token = localStorage.getItem("auth_token");
      await fetch("/api/remnawave/sync", {
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
      await fetch("/api/threatintel/refresh", {
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
          <h2 className="text-xl sm:text-2xl font-bold tracking-tight">Dashboard</h2>
          <p className="text-sm text-muted-foreground">
            Real-time overview of Xray proxy activity
          </p>
        </div>
        <Badge 
          variant={connected ? "default" : "destructive"} 
          className="flex items-center gap-1.5 self-start sm:self-auto"
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
      </div>

      {/* Stats Cards */}
      <StatsCards stats={stats} />

      {/* Row 2: Quick Actions + System Health + Period Comparison + Alerts */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <QuickActions 
          onSyncRemnawave={handleSyncRemnawave}
          onRefreshBlacklist={handleRefreshBlacklist}
          onExportReport={handleExportReport}
          problemUsersCount={topOffenders.filter(u => (u.risk_score || 0) >= 50).length}
        />
        <SystemHealth 
          remnawaveStatus={remnawaveStatus}
          remnawaveLastSync={remnawaveLastSync}
          threatIntelIndicators={threatIntel.stats?.total_indicators || 0}
          threatIntelLastUpdate={threatIntel.stats?.last_updated}
          websocketConnected={connected}
        />
        <PeriodComparison stats={periodStats} periodLabel="vs yesterday" />
        <AlertsSummary 
          alerts={alerts}
          onMarkRead={handleMarkAlertRead}
          onMarkAllRead={handleMarkAllAlertsRead}
        />
      </div>

      {/* Row 3: Activity Chart + Anomalies */}
      <div className="grid gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <ActivityChart 
            data={hourly} 
            title="Activity (Last 24 Hours)"
            description="Requests and blacklist hits over time"
            loading={false}
            timeRange="24h"
          />
        </div>
        <AnomaliesCard anomalies={anomalies} loading={false} />
      </div>

      {/* Row 4: Heatmap + Traffic Distribution + Top Offenders */}
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
        <ActivityHeatmap 
          data={hourly} 
          title="Activity Heatmap"
          description="Average activity by hour of day"
        />
        <TrafficDistribution nodes={nodes} title="Traffic by Node" />
        <TopOffenders users={topOffenders} title="Top Offenders" />
      </div>

      {/* Row 5: Geo Distribution (larger) + Real-time Feed */}
      <div className="grid gap-6 md:grid-cols-2">
        <GeoMap data={geoData} cityData={cityData} title="Geographic Distribution" mode="cities" />
        <RealTimeFeed events={feedEvents} title="Real-time Feed" />
      </div>

      {/* Row 6: AI Chat + Threat Intel */}
      <div className="grid gap-6 md:grid-cols-2">
        <AIChat />
        <ThreatIntelCard />
      </div>

      {/* Row 7: Nodes + Blacklist Alerts */}
      <div className="grid gap-6 md:grid-cols-2">
        <Card className="overflow-hidden">
          <CardHeader className="pb-3">
            <CardTitle>Active Nodes</CardTitle>
            <CardDescription>
              {onlineNodes.length} of {nodes.length} nodes online
            </CardDescription>
          </CardHeader>
          <CardContent className="max-h-[400px] overflow-y-auto scrollbar-thin">
            <NodesTable nodes={onlineNodes} />
          </CardContent>
        </Card>

        <Card className="overflow-hidden">
          <CardHeader className="pb-3">
            <CardTitle>Blacklist Alerts</CardTitle>
            <CardDescription>
              Recent blocked requests
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
