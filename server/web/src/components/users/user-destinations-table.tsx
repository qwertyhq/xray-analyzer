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
import { ChevronLeft, ChevronRight, Globe } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { isValidDate } from "@/lib/utils/date";
import { authFetch } from "@/contexts/auth-context";
import { UserDestinationsResponse, TimeRange } from "@/lib/types";

interface UserDestinationsTableProps {
  email: string;
}

export function UserDestinationsTable({ email }: UserDestinationsTableProps) {
  const [data, setData] = useState<UserDestinationsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [period, setPeriod] = useState<TimeRange>("24h");
  const pageSize = 20;

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const res = await authFetch(
        `/api/users/${encodeURIComponent(email)}/destinations?page=${page}&page_size=${pageSize}&period=${period}`
      );
      if (res.ok) {
        const json = await res.json();
        setData(json);
      }
    } catch (error) {
      console.error("Failed to fetch destinations:", error);
    } finally {
      setLoading(false);
    }
  }, [email, page, period, pageSize]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  useEffect(() => {
    setPage(1);
  }, [period]);

  if (loading && !data) {
    return (
      <div className="space-y-3">
        {[...Array(5)].map((_, i) => (
          <Skeleton key={i} className="h-10" />
        ))}
      </div>
    );
  }

  if (!data || data.destinations.length === 0) {
    return (
      <div className="text-center text-muted-foreground py-8">
        No destinations found for the selected period
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Globe className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm text-muted-foreground">
            {data.total} destinations
          </span>
        </div>
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
          </SelectContent>
        </Select>
      </div>

      <div className="max-h-[400px] overflow-y-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Destination</TableHead>
              <TableHead>Node</TableHead>
              <TableHead className="text-right">Requests</TableHead>
              <TableHead>Last Visit</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.destinations.map((dest, idx) => (
              <TableRow key={`${dest.destination}-${dest.node_id}-${idx}`}>
                <TableCell className="font-mono text-sm max-w-[300px] truncate">
                  {dest.destination}
                </TableCell>
                <TableCell>
                  <Badge variant="outline">{dest.node_id}</Badge>
                </TableCell>
                <TableCell className="text-right font-medium">
                  {dest.request_count.toLocaleString()}
                </TableCell>
                <TableCell className="text-muted-foreground text-sm">
                  {isValidDate(dest.last_seen)
                    ? formatDistanceToNow(new Date(dest.last_seen), { addSuffix: true })
                    : "—"
                  }
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
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page === 1 || loading}
            >
              <ChevronLeft className="h-4 w-4" />
              Previous
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage(p => Math.min(data.total_pages, p + 1))}
              disabled={page >= data.total_pages || loading}
            >
              Next
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
