"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
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
import { BlacklistMatchInfo } from "@/lib/types";
import { format } from "date-fns";
import { isValidDate } from "@/lib/utils/date";
import { cn } from "@/lib/utils";

interface RecentBlocksProps {
  matches: BlacklistMatchInfo[];
  loading?: boolean;
  limit?: number;
}

// Generate unique key for a match
function getMatchKey(match: BlacklistMatchInfo): string {
  return `${match.timestamp}-${match.user_email}-${match.destination}-${match.node_id}`;
}

export function RecentBlocks({ matches, loading, limit = 10 }: RecentBlocksProps) {
  const [newKeys, setNewKeys] = useState<Set<string>>(new Set());
  const prevMatchesRef = useRef<Set<string>>(new Set());
  const isFirstRender = useRef(true);

  useEffect(() => {
    if (!matches || matches.length === 0) return;

    const currentKeys = matches.slice(0, limit).map(getMatchKey);
    const currentSet = new Set(currentKeys);
    
    // Skip animation on first render
    if (isFirstRender.current) {
      isFirstRender.current = false;
      prevMatchesRef.current = currentSet;
      return;
    }

    // Find new items that weren't in the previous list
    const newItems = currentKeys.filter(key => !prevMatchesRef.current.has(key));

    if (newItems.length > 0) {
      setNewKeys(new Set(newItems));
      
      // Clear highlight after animation
      const timer = setTimeout(() => {
        setNewKeys(new Set());
      }, 2000);

      // Update previous keys
      prevMatchesRef.current = currentSet;
      
      return () => clearTimeout(timer);
    }

    // Always update previous keys
    prevMatchesRef.current = currentSet;
  }, [matches, limit]);

  if (loading) {
    return (
      <div className="space-y-3">
        {[...Array(5)].map((_, i) => (
          <Skeleton key={i} className="h-10" />
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
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>User</TableHead>
          <TableHead>Node</TableHead>
          <TableHead>Destination</TableHead>
          <TableHead>Time</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {displayMatches.map((match, idx) => {
          const key = getMatchKey(match);
          const isNew = newKeys.has(key);
          
          return (
            <TableRow 
              key={key}
              className={cn(
                "transition-all duration-500",
                isNew && "animate-fade-in-row animate-pulse-border"
              )}
            >
              <TableCell className="font-medium">
                {match.user_email ? (
                  <Link
                    href={`/users/${encodeURIComponent(match.user_email)}`}
                    className="text-primary hover:underline"
                  >
                    {match.user_email}
                  </Link>
                ) : (
                  <span className="text-muted-foreground">Unknown</span>
                )}
              </TableCell>
              <TableCell>
                <Badge variant="outline">{match.node_id}</Badge>
              </TableCell>
              <TableCell className={cn(
                "font-mono text-sm max-w-[200px] truncate",
                isNew ? "text-destructive font-semibold" : "text-destructive"
              )}>
                {match.destination}
              </TableCell>
              <TableCell className={cn(
                "text-sm",
                isNew ? "text-foreground font-medium" : "text-muted-foreground"
              )}>
                {isValidDate(match.timestamp)
                  ? format(new Date(match.timestamp), "HH:mm:ss")
                  : "—"
                }
              </TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}
