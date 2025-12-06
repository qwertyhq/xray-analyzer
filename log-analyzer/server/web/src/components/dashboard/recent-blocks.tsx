"use client";

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
        {displayMatches.map((match, idx) => (
          <TableRow key={idx}>
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
            <TableCell className="text-destructive font-mono text-sm max-w-[200px] truncate">
              {match.destination}
            </TableCell>
            <TableCell className="text-muted-foreground text-sm">
              {isValidDate(match.timestamp)
                ? format(new Date(match.timestamp), "HH:mm:ss")
                : "—"
              }
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
