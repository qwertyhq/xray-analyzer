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
import { ChevronLeft, ChevronRight, AlertTriangle } from "lucide-react";
import { format, formatDistanceToNow } from "date-fns";
import { isValidDate } from "@/lib/utils/date";
import { PaginatedAlertsResponse } from "@/lib/types";

interface UserAlertsTableProps {
  email: string;
}

export function UserAlertsTable({ email }: UserAlertsTableProps) {
  const [data, setData] = useState<PaginatedAlertsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const pageSize = 15;

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(
        `/api/users/${encodeURIComponent(email)}/alerts?page=${page}&page_size=${pageSize}`
      );
      if (res.ok) {
        const json = await res.json();
        setData(json);
      }
    } catch (error) {
      console.error("Failed to fetch alerts:", error);
    } finally {
      setLoading(false);
    }
  }, [email, page, pageSize]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  if (loading && !data) {
    return (
      <div className="space-y-3">
        {[...Array(5)].map((_, i) => (
          <Skeleton key={i} className="h-10" />
        ))}
      </div>
    );
  }

  if (!data || data.alerts.length === 0) {
    return (
      <div className="text-center text-muted-foreground py-8">
        No alerts for this user
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <AlertTriangle className="h-4 w-4 text-destructive" />
        <span className="text-sm text-muted-foreground">
          {data.total} total alerts
        </span>
      </div>

      <div className="max-h-[400px] overflow-y-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Time</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Node</TableHead>
              <TableHead>Message</TableHead>
              <TableHead>Status</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.alerts.map((alert) => (
              <TableRow key={alert.id}>
                <TableCell className="text-sm whitespace-nowrap">
                  {isValidDate(alert.created_at) ? (
                    <span title={format(new Date(alert.created_at), "PPpp")}>
                      {formatDistanceToNow(new Date(alert.created_at), { addSuffix: true })}
                    </span>
                  ) : "—"}
                </TableCell>
                <TableCell>
                  <Badge variant="destructive">{alert.type}</Badge>
                </TableCell>
                <TableCell>
                  <Badge variant="outline">{alert.node_id}</Badge>
                </TableCell>
                <TableCell className="max-w-[300px] truncate text-sm">
                  {alert.message}
                </TableCell>
                <TableCell>
                  {alert.sent ? (
                    <Badge variant="secondary">Sent</Badge>
                  ) : (
                    <Badge variant="outline">Pending</Badge>
                  )}
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
