"use client";

import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { BlacklistMatchInfo } from "@/lib/types";
import { format } from "date-fns";

// Check if date is valid (not zero time or year 1)
function isValidDate(dateStr: string): boolean {
  if (!dateStr) return false;
  const date = new Date(dateStr);
  return !isNaN(date.getTime()) && date.getFullYear() > 2000;
}

interface RecentBlocksProps {
  matches: BlacklistMatchInfo[];
  loading?: boolean;
  limit?: number;
}

export function RecentBlocks({ matches, loading, limit = 10 }: RecentBlocksProps) {
  if (loading) {
    return (
      <div className="space-y-3">
        {[...Array(5)].map((_, i) => (
          <Skeleton key={i} className="h-16" />
        ))}
      </div>
    );
  }

  if (!matches || matches.length === 0) {
    return (
      <div className="text-center text-muted-foreground py-8">
        No recent blocks
      </div>
    );
  }

  const displayMatches = matches.slice(0, limit);

  return (
    <div className="space-y-2">
      {displayMatches.map((match, idx) => (
        <div
          key={idx}
          className="flex items-start justify-between p-3 rounded-lg border bg-card hover:bg-accent/50 transition-colors"
        >
          <div className="space-y-1 min-w-0 flex-1">
            <div className="flex items-center gap-2">
              {match.user_email ? (
                <Link
                  href={`/users/${encodeURIComponent(match.user_email)}`}
                  className="font-medium text-sm text-primary hover:underline truncate"
                >
                  {match.user_email}
                </Link>
              ) : (
                <span className="font-medium text-sm text-muted-foreground">Unknown</span>
              )}
              <Badge variant="outline" className="text-xs shrink-0">
                {match.node_id}
              </Badge>
            </div>
            <p className="text-sm text-destructive font-mono truncate" title={match.destination}>
              {match.destination}
            </p>
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <span className="font-mono">{match.source_ip}</span>
              <span>•</span>
              <span>{match.matched_rule}</span>
            </div>
          </div>
          <div className="text-xs text-muted-foreground shrink-0 ml-2">
            {isValidDate(match.timestamp)
              ? format(new Date(match.timestamp), "HH:mm:ss")
              : "—"
            }
          </div>
        </div>
      ))}
    </div>
  );
}
