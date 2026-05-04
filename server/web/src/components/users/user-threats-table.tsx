"use client";

import { useState, useEffect, useCallback } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { isValidDate } from "@/lib/utils/date";
import { authFetch } from "@/contexts/auth-context";
import { TimeRange, UserThreatInfo } from "@/lib/types";

interface PaginatedThreatsResponse {
  matches: UserThreatInfo[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

interface UserThreatsTableProps {
  email: string;
  threatType: string;
}

export function UserThreatsTable({ email, threatType }: UserThreatsTableProps) {
  const [data, setData] = useState<PaginatedThreatsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [period, setPeriod] = useState<TimeRange>("24h");
  const pageSize = 20;

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const res = await authFetch(
        `/api/users/${encodeURIComponent(email)}/threats?type=${encodeURIComponent(threatType)}&page=${page}&page_size=${pageSize}&period=${period}`
      );
      if (res.ok) {
        const json = await res.json();
        setData(json);
      }
    } catch (error) {
      console.error("Failed to fetch threat matches:", error);
    } finally {
      setLoading(false);
    }
  }, [email, threatType, page, period]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  useEffect(() => {
    setPage(1);
  }, [period, threatType]);

  if (loading && !data) {
    return (
      <div className="space-y-3">
        {[...Array(5)].map((_, i) => (
          <Skeleton key={i} className="h-10" />
        ))}
      </div>
    );
  }

  if (!data || data.matches.length === 0) {
    return (
      <div className="space-y-3">
        <div className="flex items-center justify-end">
          <Select value={period} onValueChange={(v) => setPeriod(v as TimeRange)}>
            <SelectTrigger className="w-[120px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="1h">Last hour</SelectItem>
              <SelectItem value="6h">Last 6h</SelectItem>
              <SelectItem value="24h">Last 24h</SelectItem>
              <SelectItem value="7d">Last 7 days</SelectItem>
              <SelectItem value="30d">Last 30 days</SelectItem>
              <SelectItem value="all">All time</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <p className="text-sm text-muted-foreground py-4 text-center">No threat matches in the selected period</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <span className="text-sm text-muted-foreground">{data.total} matches</span>
        <Select value={period} onValueChange={(v) => setPeriod(v as TimeRange)}>
          <SelectTrigger className="w-[120px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="1h">Last hour</SelectItem>
            <SelectItem value="6h">Last 6h</SelectItem>
            <SelectItem value="24h">Last 24h</SelectItem>
            <SelectItem value="7d">Last 7 days</SelectItem>
            <SelectItem value="30d">Last 30 days</SelectItem>
            <SelectItem value="all">All time</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div className="max-h-[400px] overflow-y-auto overflow-x-auto scrollbar-thin">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="whitespace-nowrap">Time</TableHead>
              <TableHead>Destination</TableHead>
              <TableHead className="hidden md:table-cell">Source</TableHead>
              <TableHead className="text-right hidden sm:table-cell">Conf</TableHead>
              <TableHead className="hidden lg:table-cell">Node</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.matches.map((row, i) => (
              <TableRow key={i}>
                <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                  {isValidDate(row.matched_at)
                    ? formatDistanceToNow(new Date(row.matched_at), { addSuffix: true })
                    : "—"}
                </TableCell>
                <TableCell className="font-mono text-xs max-w-[260px] truncate" title={row.destination}>
                  {row.destination}
                </TableCell>
                <TableCell className="text-xs text-muted-foreground hidden md:table-cell">
                  {row.source}
                </TableCell>
                <TableCell className="text-right hidden sm:table-cell">
                  <span className={row.confidence >= 90 ? "text-destructive" : row.confidence >= 75 ? "text-orange-500" : ""}>
                    {row.confidence}
                  </span>
                </TableCell>
                <TableCell className="hidden lg:table-cell">
                  <Badge variant="outline" className="text-xs">{row.node_id}</Badge>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      {data.total_pages > 1 && (
        <div className="flex items-center justify-between pt-2">
          <span className="text-sm text-muted-foreground">
            Page {data.page} of {data.total_pages}
          </span>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1 || loading}>
              <ChevronLeft className="h-4 w-4" />
              Previous
            </Button>
            <Button variant="outline" size="sm" onClick={() => setPage(p => Math.min(data.total_pages, p + 1))} disabled={page >= data.total_pages || loading}>
              Next
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
