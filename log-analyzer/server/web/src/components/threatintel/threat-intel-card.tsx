"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ShieldAlert, Bug, Crosshair, Fish, Bot, Skull, Activity, RefreshCw, Heart, Dice1, Users, Newspaper, Download, Globe } from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ThreatMatch, ThreatStats, FeedStatus, ThreatType, ThreatSource, CategoryTopUsers, CategoryUserStats } from "@/lib/types";
import { format, formatDistanceToNow } from "date-fns";
import Link from "next/link";
import { useWsThreatIntel } from "@/contexts/websocket-context";

const threatTypeConfig: Record<ThreatType, { icon: React.ReactNode; color: string; label: string }> = {
  malware: { icon: <Bug className="h-4 w-4" />, color: "bg-red-500", label: "Malware" },
  c2: { icon: <Crosshair className="h-4 w-4" />, color: "bg-purple-500", label: "C2 Server" },
  phishing: { icon: <Fish className="h-4 w-4" />, color: "bg-orange-500", label: "Phishing" },
  botnet: { icon: <Bot className="h-4 w-4" />, color: "bg-pink-500", label: "Botnet" },
  ransomware: { icon: <Skull className="h-4 w-4" />, color: "bg-red-700", label: "Ransomware" },
  adware: { icon: <Activity className="h-4 w-4" />, color: "bg-yellow-500", label: "Adware" },
  tracker: { icon: <Activity className="h-4 w-4" />, color: "bg-gray-500", label: "Tracker" },
  // Content categories
  porn: { icon: <Heart className="h-4 w-4" />, color: "bg-pink-600", label: "Порно" },
  gambling: { icon: <Dice1 className="h-4 w-4" />, color: "bg-emerald-600", label: "Казино" },
  social: { icon: <Users className="h-4 w-4" />, color: "bg-blue-500", label: "Соц.сети" },
  fakenews: { icon: <Newspaper className="h-4 w-4" />, color: "bg-amber-600", label: "Фейки" },
  // P2P
  torrent: { icon: <Download className="h-4 w-4" />, color: "bg-cyan-600", label: "Торрент" },
  // Anonymization
  tor: { icon: <Globe className="h-4 w-4" />, color: "bg-violet-600", label: "Tor" },
};

const sourceLabels: Record<ThreatSource, string> = {
  urlhaus: "URLhaus",
  feodo: "Feodo Tracker",
  threatfox: "ThreatFox",
  sslbl: "SSL Blacklist",
  stevenblack: "StevenBlack",
  // Content category blocklists
  "porn-blocklist": "Porn Blocklist",
  "gambling-blocklist": "Gambling Blocklist",
  "social-blocklist": "Social Blocklist",
  "fakenews-blocklist": "FakeNews Blocklist",
  // P2P
  "torrent-trackers": "Torrent Trackers",
  // Anonymization
  "tor-exit-nodes": "Tor Exit Nodes",
};

interface ThreatIntelCardProps {
  className?: string;
}

export function ThreatIntelCard({ className }: ThreatIntelCardProps) {
  const { threatIntel, loading } = useWsThreatIntel();
  const { stats, matches } = threatIntel;

  if (loading) {
    return (
      <Card className={className}>
        <CardHeader>
          <Skeleton className="h-6 w-48" />
        </CardHeader>
        <CardContent>
          <Skeleton className="h-[200px]" />
        </CardContent>
      </Card>
    );
  }

  if (!stats) {
    return (
      <Card className={className}>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldAlert className="h-5 w-5 text-muted-foreground" />
            Threat Intelligence
          </CardTitle>
          <CardDescription>Service not available</CardDescription>
        </CardHeader>
      </Card>
    );
  }

  return (
    <Card className={className}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ShieldAlert className="h-5 w-5 text-destructive" />
          Threat Intelligence
        </CardTitle>
        <CardDescription>
          {stats.total_indicators.toLocaleString()} indicators loaded • {stats.matches_24h} matches (24h)
        </CardDescription>
      </CardHeader>
      <CardContent>
        {matches.length > 0 ? (
          <div className="space-y-3 max-h-[300px] overflow-y-auto">
            {matches.map((match) => {
              const config = threatTypeConfig[match.threat_type] || threatTypeConfig.malware;
              return (
                <div
                  key={match.id}
                  className="flex items-start gap-3 p-2 rounded-lg bg-muted/50 border border-destructive/20"
                >
                  <div className={`p-1.5 rounded ${config.color} text-white`}>
                    {config.icon}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <Badge variant="destructive" className="text-xs">
                        {config.label}
                      </Badge>
                      <Badge variant="outline" className="text-xs">
                        {match.confidence}%
                      </Badge>
                      <span className="text-xs text-muted-foreground">
                        {sourceLabels[match.source]}
                      </span>
                    </div>
                    <p className="text-sm font-mono truncate mt-1">{match.destination}</p>
                    <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
                      <Link
                        href={`/users/${encodeURIComponent(match.user_email)}`}
                        className="hover:underline"
                      >
                        {match.user_email}
                      </Link>
                      <span>•</span>
                      <span>{formatDistanceToNow(new Date(match.matched_at), { addSuffix: true })}</span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="text-center py-8 text-muted-foreground">
            <ShieldAlert className="h-12 w-12 mx-auto mb-2 opacity-20" />
            <p>No threat matches detected</p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// Full page component for threat intel
export function ThreatIntelPage() {
  // Use WebSocket for real-time stats, matches, and top users
  const { threatIntel, loading: wsLoading, connected } = useWsThreatIntel();
  
  // Feeds fetched via API (status doesn't change often)
  const [feeds, setFeeds] = useState<FeedStatus[]>([]);
  const [apiLoading, setApiLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [activeTab, setActiveTab] = useState("overview");
  const pageSize = 20;

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
    // Refresh feeds every 60 seconds
    const interval = setInterval(fetchFeeds, 60000);
    return () => clearInterval(interval);
  }, []);

  // Get data from WebSocket
  const stats = threatIntel.stats;
  const matches = threatIntel.matches || [];
  const topUsers = threatIntel.topUsers;
  const loading = wsLoading && apiLoading;

  // Filter matches by type
  const torrentMatches = matches.filter(m => m.threat_type === "torrent");
  const torMatches = matches.filter(m => m.threat_type === "tor");
  const threatMatches = matches.filter(m => !["torrent", "tor", "porn", "gambling", "social", "fakenews"].includes(m.threat_type));

  // Pagination based on active tab
  const getFilteredMatches = () => {
    switch (activeTab) {
      case "torrent": return torrentMatches;
      case "tor": return torMatches;
      default: return threatMatches;
    }
  };
  
  const filteredMatches = getFilteredMatches();
  const totalPages = Math.ceil(filteredMatches.length / pageSize);
  const paginatedMatches = filteredMatches.slice((page - 1) * pageSize, page * pageSize);

  // Reset page when switching tabs
  useEffect(() => {
    setPage(1);
  }, [activeTab]);

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
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <ShieldAlert className="h-6 w-6 text-destructive" />
            Threat Intelligence
          </h2>
          <p className="text-muted-foreground">
            Real-time threat detection from open source feeds
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant={connected ? "default" : "secondary"} className="flex items-center gap-1.5">
            <span className={`h-2 w-2 rounded-full ${connected ? "bg-green-400 animate-pulse" : "bg-gray-400"}`} />
            {connected ? "Live" : "Offline"}
          </Badge>
          <Badge variant="outline" className="flex items-center gap-1.5">
            <RefreshCw className="h-3 w-3" />
            Feeds every 6h
          </Badge>
        </div>
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="grid w-full grid-cols-3 max-w-md">
          <TabsTrigger value="overview" className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4" />
            Обзор
          </TabsTrigger>
          <TabsTrigger value="torrent" className="flex items-center gap-2">
            <Download className="h-4 w-4" />
            Торренты
            {torrentMatches.length > 0 && (
              <Badge variant="secondary" className="ml-1 text-xs">{torrentMatches.length}</Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="tor" className="flex items-center gap-2">
            <Globe className="h-4 w-4" />
            Tor
            {torMatches.length > 0 && (
              <Badge variant="secondary" className="ml-1 text-xs">{torMatches.length}</Badge>
            )}
          </TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-6 mt-6">
          {/* Stats Cards */}
          <div className="grid gap-4 md:grid-cols-4">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Total Indicators</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {stats?.total_indicators.toLocaleString() || 0}
                </div>
                <p className="text-xs text-muted-foreground">Loaded from feeds</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Total Matches</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-destructive">
                  {stats?.total_matches || 0}
                </div>
                <p className="text-xs text-muted-foreground">All time</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Matches (24h)</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-orange-500">
                  {stats?.matches_24h || 0}
                </div>
                <p className="text-xs text-muted-foreground">Last 24 hours</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Active Feeds</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-green-500">
                  {feeds.filter((f) => f.status === "ok").length}/{feeds.length}
                </div>
                <p className="text-xs text-muted-foreground">Feeds online</p>
              </CardContent>
            </Card>
          </div>

          {/* Feed Status */}
          <Card>
            <CardHeader>
              <CardTitle>Feed Status</CardTitle>
              <CardDescription>Status of threat intelligence data sources</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Source</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="text-right">Indicators</TableHead>
                    <TableHead>Last Update</TableHead>
                    <TableHead>Next Update</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {feeds.map((feed) => (
                    <TableRow key={feed.source}>
                      <TableCell className="font-medium">
                        {sourceLabels[feed.source] || feed.source}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={feed.status === "ok" ? "default" : "destructive"}
                        >
                          {feed.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        {feed.indicators.toLocaleString()}
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {feed.last_update
                          ? formatDistanceToNow(new Date(feed.last_update), { addSuffix: true })
                          : "—"}
                      </TableCell>
                      <TableCell className="text-muted-foreground">
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
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
              {(["porn", "gambling", "social", "fakenews"] as const).map((category) => {
                const users = topUsers[category] || [];
                const config = threatTypeConfig[category];
                const totalCount = users.reduce((sum, u) => sum + u.match_count, 0);
                
                return (
                  <Card key={category}>
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

          {/* Recent Threat Matches (excluding torrent/tor) */}
          <MatchesTable 
            matches={threatMatches} 
            title="Recent Threat Matches"
            description={`Traffic that matched known threat indicators (${threatMatches.length} total)`}
          />
        </TabsContent>

        {/* Torrent Tab */}
        <TabsContent value="torrent" className="space-y-6 mt-6">
          {/* Torrent Stats */}
          <div className="grid gap-4 md:grid-cols-3">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <Download className="h-4 w-4 text-cyan-600" />
                  Torrent Detections
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-cyan-600">
                  {torrentMatches.length}
                </div>
                <p className="text-xs text-muted-foreground">All time</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Unique Users</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {new Set(torrentMatches.map(m => m.user_email)).size}
                </div>
                <p className="text-xs text-muted-foreground">Using torrents</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Indicators Loaded</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {feeds.find(f => f.source === "torrent-trackers")?.indicators.toLocaleString() || 0}
                </div>
                <p className="text-xs text-muted-foreground">Trackers & sites</p>
              </CardContent>
            </Card>
          </div>

          {/* Top Torrent Users */}
          {topUsers?.torrent && topUsers.torrent.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Download className="h-5 w-5 text-cyan-600" />
                  Top Torrent Users
                </CardTitle>
                <CardDescription>Users with most torrent activity</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                  {topUsers.torrent.map((user, idx) => (
                    <div key={user.user_email} className="flex items-start gap-3 p-3 rounded-lg border">
                      <span className={`text-lg font-bold w-6 ${
                        idx === 0 ? "text-yellow-500" :
                        idx === 1 ? "text-gray-400" :
                        idx === 2 ? "text-amber-600" :
                        "text-muted-foreground"
                      }`}>
                        {idx + 1}
                      </span>
                      <div className="flex-1 min-w-0">
                        <Link
                          href={`/users/${encodeURIComponent(user.user_email)}`}
                          className="font-medium hover:underline block truncate"
                        >
                          {user.user_email}
                        </Link>
                        <div className="flex items-center gap-2 mt-1">
                          <Badge variant="secondary">{user.match_count} hits</Badge>
                        </div>
                        {user.domains && user.domains.length > 0 && (
                          <div className="mt-2 text-xs text-muted-foreground">
                            {user.domains.slice(0, 3).map((d, i) => (
                              <span key={d} className="font-mono">
                                {d}{i < Math.min(user.domains.length, 3) - 1 ? ", " : ""}
                              </span>
                            ))}
                            {user.domains.length > 3 && <span> +{user.domains.length - 3} more</span>}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Torrent Matches Table */}
          <MatchesTable 
            matches={torrentMatches} 
            title="Torrent Activity"
            description={`Detected torrent tracker and site connections (${torrentMatches.length} total)`}
          />
        </TabsContent>

        {/* Tor Tab */}
        <TabsContent value="tor" className="space-y-6 mt-6">
          {/* Tor Stats */}
          <div className="grid gap-4 md:grid-cols-3">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <Globe className="h-4 w-4 text-violet-600" />
                  Tor Detections
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-violet-600">
                  {torMatches.length}
                </div>
                <p className="text-xs text-muted-foreground">All time</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Unique Users</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {new Set(torMatches.map(m => m.user_email)).size}
                </div>
                <p className="text-xs text-muted-foreground">Using Tor</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Exit Nodes Loaded</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {feeds.find(f => f.source === "tor-exit-nodes")?.indicators.toLocaleString() || 0}
                </div>
                <p className="text-xs text-muted-foreground">IPs & domains</p>
              </CardContent>
            </Card>
          </div>

          {/* Top Tor Users */}
          {topUsers?.tor && topUsers.tor.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Globe className="h-5 w-5 text-violet-600" />
                  Top Tor Users
                </CardTitle>
                <CardDescription>Users with most Tor network activity</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                  {topUsers.tor.map((user, idx) => (
                    <div key={user.user_email} className="flex items-start gap-3 p-3 rounded-lg border">
                      <span className={`text-lg font-bold w-6 ${
                        idx === 0 ? "text-yellow-500" :
                        idx === 1 ? "text-gray-400" :
                        idx === 2 ? "text-amber-600" :
                        "text-muted-foreground"
                      }`}>
                        {idx + 1}
                      </span>
                      <div className="flex-1 min-w-0">
                        <Link
                          href={`/users/${encodeURIComponent(user.user_email)}`}
                          className="font-medium hover:underline block truncate"
                        >
                          {user.user_email}
                        </Link>
                        <div className="flex items-center gap-2 mt-1">
                          <Badge variant="secondary">{user.match_count} hits</Badge>
                        </div>
                        {user.domains && user.domains.length > 0 && (
                          <div className="mt-2 text-xs text-muted-foreground">
                            {user.domains.slice(0, 3).map((d, i) => (
                              <span key={d} className="font-mono">
                                {d}{i < Math.min(user.domains.length, 3) - 1 ? ", " : ""}
                              </span>
                            ))}
                            {user.domains.length > 3 && <span> +{user.domains.length - 3} more</span>}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Tor Matches Table */}
          <MatchesTable 
            matches={torMatches} 
            title="Tor Activity"
            description={`Detected Tor network connections (${torMatches.length} total)`}
          />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// Helper component for user list
function UserList({ users }: { users: CategoryUserStats[] }) {
  if (users.length === 0) {
    return (
      <div className="py-6 text-center text-sm text-muted-foreground">
        Нет данных
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {users.map((user, idx) => (
        <div key={user.user_email} className="flex items-start gap-2.5">
          <span className={`text-sm font-medium w-4 ${
            idx === 0 ? "text-yellow-500" :
            idx === 1 ? "text-gray-400" :
            idx === 2 ? "text-amber-600" :
            "text-muted-foreground"
          }`}>
            {idx + 1}.
          </span>
          
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between gap-2">
              <Link
                href={`/users/${encodeURIComponent(user.user_email)}`}
                className="text-sm hover:underline truncate"
                title={user.user_email}
              >
                {user.user_email}
              </Link>
              <Badge variant="secondary" className="text-xs font-mono">
                {user.match_count}
              </Badge>
            </div>
            
            {user.domains && user.domains.length > 0 && (
              <div className="mt-1 text-xs text-muted-foreground truncate" title={user.domains.join(", ")}>
                {user.domains.slice(0, 2).join(", ")}
                {user.domains.length > 2 && ` +${user.domains.length - 2}`}
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

// Helper component for matches table
function MatchesTable({ matches, title, description }: { matches: ThreatMatch[], title: string, description: string }) {
  const [page, setPage] = useState(1);
  const pageSize = 20;
  const totalPages = Math.ceil(matches.length / pageSize);
  const paginatedMatches = matches.slice((page - 1) * pageSize, page * pageSize);

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>{title}</CardTitle>
            <CardDescription>{description}</CardDescription>
          </div>
          {totalPages > 1 && (
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="px-3 py-1 text-sm border rounded hover:bg-muted disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Prev
              </button>
              <span className="text-sm text-muted-foreground">
                Page {page} of {totalPages}
              </span>
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                className="px-3 py-1 text-sm border rounded hover:bg-muted disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Next
              </button>
            </div>
          )}
        </div>
      </CardHeader>
      <CardContent className="max-h-[500px] overflow-y-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Time</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>User</TableHead>
              <TableHead>Destination</TableHead>
              <TableHead>Source</TableHead>
              <TableHead className="text-right">Confidence</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {paginatedMatches.map((match) => {
              const config = threatTypeConfig[match.threat_type] || threatTypeConfig.malware;
              return (
                <TableRow key={match.id}>
                  <TableCell className="text-muted-foreground whitespace-nowrap">
                    {format(new Date(match.matched_at), "MMM d, HH:mm")}
                  </TableCell>
                  <TableCell>
                    <Badge className={`${config.color} text-white`}>
                      {config.label}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Link
                      href={`/users/${encodeURIComponent(match.user_email)}`}
                      className="hover:underline text-primary"
                    >
                      {match.user_email}
                    </Link>
                  </TableCell>
                  <TableCell className="font-mono text-sm max-w-[250px] truncate">
                    {match.destination}
                  </TableCell>
                  <TableCell className="text-muted-foreground text-sm">
                    {sourceLabels[match.source] || match.source}
                  </TableCell>
                  <TableCell className="text-right">
                    <Badge
                      variant={match.confidence >= 80 ? "destructive" : "secondary"}
                    >
                      {match.confidence}%
                    </Badge>
                  </TableCell>
                </TableRow>
              );
            })}
            {matches.length === 0 && (
              <TableRow>
                <TableCell colSpan={6} className="text-center text-muted-foreground py-8">
                  No matches detected
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}
