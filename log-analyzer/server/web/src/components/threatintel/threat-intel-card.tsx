"use client";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ShieldAlert } from "lucide-react";
import { useWsThreatIntel } from "@/contexts/websocket-context";
import { formatDistanceToNow } from "date-fns";
import Link from "next/link";
import { threatTypeConfig, sourceLabels } from "./config";

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
    <Card className={`${className} overflow-hidden`}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ShieldAlert className="h-5 w-5 text-muted-foreground" />
          Threat Intelligence
        </CardTitle>
        <CardDescription>
          {stats.total_indicators.toLocaleString()} indicators loaded • {stats.matches_24h} matches (24h)
        </CardDescription>
      </CardHeader>
      <CardContent>
        {matches.length > 0 ? (
          <>
            <div className="flex items-center justify-between mb-3">
              <span className="text-sm font-medium">Recent Matches</span>
              <Badge variant="secondary" className="text-xs">
                {matches.length} latest
              </Badge>
            </div>
            <div className="space-y-2 max-h-[400px] overflow-y-auto pr-1">
              {matches.map((match) => {
                const config = threatTypeConfig[match.threat_type] || threatTypeConfig.malware;
                return (
                  <div
                    key={match.id}
                    className="flex items-start gap-3 p-2 rounded-lg bg-muted/50 border border-destructive/20 overflow-hidden"
                  >
                    <div className={`p-1.5 rounded ${config.color} text-white shrink-0`}>
                      {config.icon}
                    </div>
                    <div className="flex-1 min-w-0 overflow-hidden">
                      <div className="flex items-center gap-2 flex-wrap">
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
                      <p className="text-sm font-mono truncate mt-1 max-w-full">{match.destination}</p>
                      <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
                        <Link
                          href={`/users/${encodeURIComponent(match.user_email)}`}
                          className="hover:underline truncate"
                        >
                          {match.user_email}
                        </Link>
                        <span>•</span>
                        <span className="whitespace-nowrap">{formatDistanceToNow(new Date(match.matched_at), { addSuffix: true })}</span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </>
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
