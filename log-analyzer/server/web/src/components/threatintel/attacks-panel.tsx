"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { authFetch } from "@/contexts/auth-context";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Swords, RefreshCw, Target, Crosshair, Check } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { StatCard, StatCardGrid } from "./stat-card";

// Incident = one attack detection. Shape mirrors /api/threatintel/attacks.
type AttackDetails = {
  port?: string;
  unique_ips?: number;
  unique_destinations?: number;
  target_subnet?: string;
  window_minutes?: number;
};

type Attack = {
  id: string;
  type: string;
  severity: "low" | "medium" | "high" | "critical";
  user_email: string;
  username?: string;
  description: string;
  details?: AttackDetails | Record<string, unknown>;
  detected_at: string;
  resolved: boolean;
};

const severityBadge: Record<string, string> = {
  low: "bg-blue-500/15 text-blue-700 dark:text-blue-300 border-blue-500/30",
  medium: "bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30",
  high: "bg-orange-500/15 text-orange-700 dark:text-orange-300 border-orange-500/30",
  critical: "bg-red-500/15 text-red-700 dark:text-red-300 border-red-500/30",
};

const typeLabel: Record<string, { label: string; icon: React.ReactNode }> = {
  port_scan: { label: "Port scan", icon: <Crosshair className="h-3.5 w-3.5" /> },
  abuse_port_flood: { label: "Brute-force / flood", icon: <Swords className="h-3.5 w-3.5" /> },
  burst_scan: { label: "Burst scan", icon: <Target className="h-3.5 w-3.5" /> },
};

const SINCE_OPTIONS = [
  { value: "1h", label: "1h" },
  { value: "6h", label: "6h" },
  { value: "24h", label: "24h" },
  { value: "7d", label: "7 days" },
];

export function AttacksPanel() {
  const [since, setSince] = useState("24h");
  const [attacks, setAttacks] = useState<Attack[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [resolvingIds, setResolvingIds] = useState<Set<string>>(new Set());

  const fetchAttacks = useCallback(async () => {
    setLoading(true);
    try {
      const res = await authFetch(`/api/threatintel/attacks?since=${since}&limit=200`);
      if (!res.ok) {
        console.error("attacks fetch failed:", res.status);
        setAttacks([]);
        return;
      }
      const json = await res.json();
      setAttacks(json.attacks || []);
    } catch (err) {
      console.error("attacks fetch error:", err);
      setAttacks([]);
    } finally {
      setLoading(false);
    }
  }, [since]);

  useEffect(() => {
    fetchAttacks();
    const t = setInterval(fetchAttacks, 60_000);
    return () => clearInterval(t);
  }, [fetchAttacks]);

  const resolve = async (id: string) => {
    setResolvingIds((prev) => new Set(prev).add(id));
    try {
      await authFetch(`/api/threatintel/anomalies?id=${encodeURIComponent(id)}`, { method: "DELETE" });
      setAttacks((prev) => (prev || []).filter((a) => a.id !== id));
    } finally {
      setResolvingIds((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    }
  };

  const list = attacks || [];
  const critical = list.filter((a) => a.severity === "critical").length;
  const high = list.filter((a) => a.severity === "high").length;
  const uniqUsers = new Set(list.map((a) => a.user_email)).size;
  const uniqScans = list.filter((a) => a.type === "port_scan").length;
  const uniqFloods = list.filter((a) => a.type === "abuse_port_flood").length;

  if (loading && attacks === null) {
    return (
      <div className="space-y-4">
        <div className="grid gap-4 md:grid-cols-4">
          {[...Array(4)].map((_, i) => (
            <Skeleton key={i} className="h-24 rounded-xl" />
          ))}
        </div>
        <Skeleton className="h-[400px] rounded-xl" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <StatCardGrid columns={4}>
        <StatCard
          icon={<Swords className="h-4 w-4" />}
          label="Active attacks"
          value={list.length}
          subValue={`${since} window`}
          variant={list.length > 0 ? "danger" : "muted"}
          highlight={list.length > 0}
        />
        <StatCard
          icon={<Target className="h-4 w-4" />}
          label="Critical + High"
          value={critical + high}
          subValue={`${critical} crit · ${high} high`}
          variant="warning"
        />
        <StatCard
          icon={<Crosshair className="h-4 w-4" />}
          label="Port scans"
          value={uniqScans}
          subValue={`${uniqFloods} brute-force floods`}
          variant="info"
        />
        <StatCard
          icon={<Swords className="h-4 w-4" />}
          label="Distinct attackers"
          value={uniqUsers}
          subValue="Unique users"
          variant="info"
        />
      </StatCardGrid>

      <Card className="border shadow-sm">
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div>
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Swords className="h-4 w-4 text-muted-foreground" />
                Attacks originating from VPN clients
              </CardTitle>
              <CardDescription className="text-xs">
                Only hostile patterns (port scan / brute-force). CDN / normal browsing is filtered out.
              </CardDescription>
            </div>
            <div className="flex items-center gap-2">
              <Select value={since} onValueChange={setSince}>
                <SelectTrigger className="w-[120px] h-8">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SINCE_OPTIONS.map((o) => (
                    <SelectItem key={o.value} value={o.value}>
                      {o.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button variant="outline" size="sm" onClick={fetchAttacks} className="gap-1">
                <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
                Refresh
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {list.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-[240px] text-muted-foreground">
              <div className="w-16 h-16 rounded-full bg-emerald-100 dark:bg-emerald-900/30 flex items-center justify-center mb-3">
                <Swords className="h-8 w-8 text-emerald-500" />
              </div>
              <p className="text-sm font-medium">No attacks in the last {since}</p>
              <p className="text-xs">Scanning / brute-force detectors haven't fired</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[120px]">When</TableHead>
                    <TableHead className="w-[170px]">Type</TableHead>
                    <TableHead className="w-[200px]">User</TableHead>
                    <TableHead>Target</TableHead>
                    <TableHead className="w-[110px]">Severity</TableHead>
                    <TableHead className="w-[90px] text-right">Action</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {list.map((a) => {
                    const t = typeLabel[a.type] ?? { label: a.type, icon: null };
                    const details = (a.details ?? {}) as AttackDetails;
                    const target =
                      details.target_subnet && details.port
                        ? `${details.target_subnet} : ${details.port}  (${details.unique_ips ?? "?"} IPs)`
                        : details.port
                          ? `port ${details.port} (${details.unique_destinations ?? "?"} dests)`
                          : a.description;
                    const shownUser = a.username && a.username !== a.user_email
                      ? `${a.username}  ·  #${a.user_email}`
                      : `#${a.user_email}`;
                    return (
                      <TableRow key={a.id}>
                        <TableCell className="text-xs text-muted-foreground">
                          {formatDistanceToNow(new Date(a.detected_at), { addSuffix: true })}
                        </TableCell>
                        <TableCell>
                          <span className="inline-flex items-center gap-1.5 text-xs">
                            {t.icon}
                            {t.label}
                          </span>
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          <Link
                            href={`/users/${encodeURIComponent(a.user_email)}`}
                            className="hover:underline text-primary"
                          >
                            {shownUser}
                          </Link>
                        </TableCell>
                        <TableCell className="font-mono text-xs">{target}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className={severityBadge[a.severity] ?? ""}>
                            {a.severity}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right">
                          <Button
                            size="sm"
                            variant="ghost"
                            disabled={resolvingIds.has(a.id)}
                            onClick={() => resolve(a.id)}
                            className="h-7 px-2"
                          >
                            <Check className="h-3.5 w-3.5" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
