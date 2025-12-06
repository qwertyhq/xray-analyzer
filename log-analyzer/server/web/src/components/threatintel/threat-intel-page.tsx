"use client";

import { useState, useEffect } from "react";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ShieldAlert, RefreshCw, Download, Globe } from "lucide-react";
import { FeedStatus } from "@/lib/types";
import { useWsThreatIntel } from "@/contexts/websocket-context";
import { OverviewTab } from "./overview-tab";
import { TorrentTab } from "./torrent-tab";
import { TorTab } from "./tor-tab";

export function ThreatIntelPage() {
  const { threatIntel, loading: wsLoading, connected } = useWsThreatIntel();
  
  const [feeds, setFeeds] = useState<FeedStatus[]>([]);
  const [apiLoading, setApiLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("overview");

  // Fetch feeds status (not in WebSocket)
  const fetchFeeds = async () => {
    try {
      const feedsRes = await fetch("/api/threatintel/feeds");
      if (feedsRes.ok) setFeeds((await feedsRes.json()) || []);
    } catch {
      // ignore
    } finally {
      setApiLoading(false);
    }
  };

  useEffect(() => {
    fetchFeeds();
    const interval = setInterval(fetchFeeds, 60000);
    return () => clearInterval(interval);
  }, []);

  const stats = threatIntel.stats;
  const matches = threatIntel.matches || [];
  const topUsers = threatIntel.topUsers;
  const loading = wsLoading && apiLoading;

  // Filter matches by type
  // Content/P2P categories that go to separate tabs or are non-threat
  const contentCategories = ["torrent", "tor", "porn", "gambling", "social", "fakenews", "tiktok", "ads", "tracking", "redirect"];
  const torrentMatches = matches.filter(m => m.threat_type === "torrent");
  const torMatches = matches.filter(m => m.threat_type === "tor");
  // Threat matches = everything except content categories
  const threatMatches = matches.filter(m => !contentCategories.includes(m.threat_type));

  if (loading) {
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

  return (
    <div className="p-4 md:p-8 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl sm:text-2xl font-bold tracking-tight flex items-center gap-2">
            <ShieldAlert className="h-5 w-5 sm:h-6 sm:w-6 text-destructive" />
            Threat Intelligence
          </h2>
          <p className="text-sm text-muted-foreground">
            Real-time threat detection from open source feeds
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <Badge variant={connected ? "default" : "secondary"} className="flex items-center gap-1.5">
            <span className={`h-2 w-2 rounded-full ${connected ? "bg-green-400 animate-pulse" : "bg-gray-400"}`} />
            {connected ? "Live" : "Offline"}
          </Badge>
          <Badge variant="outline" className="flex items-center gap-1.5">
            <RefreshCw className="h-3 w-3" />
            <span className="hidden sm:inline">Feeds every</span> 6h
          </Badge>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="grid w-full grid-cols-3 max-w-md">
          <TabsTrigger value="overview" className="flex items-center gap-1 sm:gap-2 text-xs sm:text-sm">
            <ShieldAlert className="h-3.5 w-3.5 sm:h-4 sm:w-4" />
            <span className="hidden sm:inline">Обзор</span>
            <span className="sm:hidden">Обзор</span>
          </TabsTrigger>
          <TabsTrigger value="torrent" className="flex items-center gap-1 sm:gap-2 text-xs sm:text-sm">
            <Download className="h-3.5 w-3.5 sm:h-4 sm:w-4" />
            <span className="hidden xs:inline">Торренты</span>
            {torrentMatches.length > 0 && (
              <Badge variant="secondary" className="ml-1 text-xs h-5 px-1.5">{torrentMatches.length}</Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="tor" className="flex items-center gap-1 sm:gap-2 text-xs sm:text-sm">
            <Globe className="h-3.5 w-3.5 sm:h-4 sm:w-4" />
            Tor
            {torMatches.length > 0 && (
              <Badge variant="secondary" className="ml-1 text-xs h-5 px-1.5">{torMatches.length}</Badge>
            )}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="mt-6">
          <OverviewTab 
            stats={stats}
            feeds={feeds}
            topUsers={topUsers}
            threatMatches={threatMatches}
          />
        </TabsContent>

        <TabsContent value="torrent" className="mt-6">
          <TorrentTab 
            matches={torrentMatches}
            topUsers={topUsers?.torrent || []}
            feed={feeds.find(f => f.source === "torrent-trackers")}
          />
        </TabsContent>

        <TabsContent value="tor" className="mt-6">
          <TorTab 
            matches={torMatches}
            topUsers={topUsers?.tor || []}
            feed={feeds.find(f => f.source === "tor-exit-nodes")}
          />
        </TabsContent>
      </Tabs>
    </div>
  );
}
