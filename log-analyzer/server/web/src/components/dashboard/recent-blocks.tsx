"use client";

import { useMemo } from "react";
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

interface RecentBlocksProps {
  matches: BlacklistMatchInfo[];
  loading?: boolean;
  limit?: number;
}

// Generate unique key for a match
function getMatchKey(match: BlacklistMatchInfo, index: number): string {
  return `${match.timestamp}-${match.display_name || match.user_email || ''}-${match.destination}-${match.node_id}-${index}`;
}

export function RecentBlocks({ matches, loading, limit = 12 }: RecentBlocksProps) {
  // Sort matches by timestamp (newest first) and limit
  const sortedMatches = useMemo(() => {
    if (!matches || matches.length === 0) return [];
    
    return [...matches]
      .filter(m => isValidDate(m.timestamp))
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
      .slice(0, limit);
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

  return (
    <div className="overflow-x-auto">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="whitespace-nowrap">User</TableHead>
            <TableHead className="whitespace-nowrap hidden sm:table-cell">Node</TableHead>
            <TableHead className="whitespace-nowrap hidden md:table-cell">Destination</TableHead>
            <TableHead className="whitespace-nowrap">Time</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {sortedMatches.map((match, index) => (
            <TableRow key={getMatchKey(match, index)}>
              <TableCell className="font-medium max-w-[100px] sm:max-w-none">
                {(match.display_name || match.user_email) ? (
                  <Link
                    href={`/users/${encodeURIComponent(match.user_email || match.display_name || '')}`}
                    className="text-primary hover:underline truncate block"
                  >
                    {match.display_name || match.user_email}
                  </Link>
                ) : (
                  <span className="text-muted-foreground">Unknown</span>
                )}
              </TableCell>
              <TableCell className="hidden sm:table-cell">
                <Badge variant="outline">{match.node_id}</Badge>
              </TableCell>
              <TableCell className="font-mono text-xs sm:text-sm max-w-[150px] sm:max-w-[200px] truncate text-destructive hidden md:table-cell">
                {match.destination}
              </TableCell>
              <TableCell className="text-xs sm:text-sm text-muted-foreground whitespace-nowrap">
                {isValidDate(match.timestamp)
                  ? format(new Date(match.timestamp), "HH:mm:ss")
                  : "—"
                }
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
