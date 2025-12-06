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
import { ShieldAlert, Bug, Crosshair, Fish, Bot, Skull, Activity, RefreshCw } from "lucide-react";
import { ThreatMatch, ThreatStats, FeedStatus, ThreatType, ThreatSource } from "@/lib/types";
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
};

const sourceLabels: Record<ThreatSource, string> = {
  urlhaus: "URLhaus",
  feodo: "Feodo Tracker",
  threatfox: "ThreatFox",
  sslbl: "SSL Blacklist",
  stevenblack: "StevenBlack",
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
  const [stats, setStats] = useState<ThreatStats | null>(null);
  const [matches, setMatches] = useState<ThreatMatch[]>([]);
  const [feeds, setFeeds] = useState<FeedStatus[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const pageSize = 20;

  const fetchData = async () => {
    try {
      const [statsRes, matchesRes, feedsRes] = await Promise.all([
        fetch("/api/threatintel/stats"),
        fetch("/api/threatintel/matches?limit=500"),
        fetch("/api/threatintel/feeds"),
      ]);

      if (statsRes.ok) setStats(await statsRes.json());
      if (matchesRes.ok) setMatches((await matchesRes.json()) || []);
      if (feedsRes.ok) setFeeds((await feedsRes.json()) || []);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, []);

  // Pagination
  const totalPages = Math.ceil(matches.length / pageSize);
  const paginatedMatches = matches.slice((page - 1) * pageSize, page * pageSize);

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
        <Badge variant="outline" className="flex items-center gap-1.5">
          <RefreshCw className="h-3 w-3" />
          Updates every 6h
        </Badge>
      </div>

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

      {/* Recent Matches */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Recent Threat Matches</CardTitle>
              <CardDescription>
                Traffic that matched known threat indicators ({matches.length} total)
              </CardDescription>
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
                      {sourceLabels[match.source]}
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
                    No threat matches detected
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Indicators by Type */}
      {stats && Object.keys(stats.indicators_by_type).length > 0 && (
        <div className="grid gap-4 md:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>Indicators by Type</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {Object.entries(stats.indicators_by_type).map(([type, count]) => {
                  const config = threatTypeConfig[type as ThreatType];
                  return (
                    <div key={type} className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        {config?.icon}
                        <span className="capitalize">{config?.label || type}</span>
                      </div>
                      <span className="font-mono">{count.toLocaleString()}</span>
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Indicators by Source</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {Object.entries(stats.indicators_by_source).map(([source, count]) => (
                  <div key={source} className="flex items-center justify-between">
                    <span>{sourceLabels[source as ThreatSource] || source}</span>
                    <span className="font-mono">{count.toLocaleString()}</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
