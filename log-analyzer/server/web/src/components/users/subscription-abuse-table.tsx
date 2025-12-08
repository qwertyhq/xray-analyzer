"use client";

import { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Users, Globe, ExternalLink, ChevronDown, AlertTriangle, RefreshCw, Server, Smartphone, Monitor, Trash2, Loader2 } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { SubscriptionAbuse, TimeRange } from "@/lib/types";
import { isValidDate } from "@/lib/utils/date";

// Country flag emoji from country code
function getFlagEmoji(countryCode: string): string {
  if (!countryCode || countryCode.length !== 2) return "🌍";
  return String.fromCodePoint(
    ...[...countryCode.toUpperCase()].map(c => 0x1F1E6 - 65 + c.charCodeAt(0))
  );
}

// Get abuse score color
function getScoreVariant(score: number): "destructive" | "secondary" | "outline" {
  if (score >= 70) return "destructive";
  if (score >= 40) return "secondary";
  return "outline";
}

interface SubscriptionAbuseTableProps {
  defaultPeriod?: TimeRange;
  defaultMinIPs?: number;
}

export function SubscriptionAbuseTable({ 
  defaultPeriod = "24h",
  defaultMinIPs = 3
}: SubscriptionAbuseTableProps) {
  const [abusers, setAbusers] = useState<SubscriptionAbuse[]>([]);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [clearingHwid, setClearingHwid] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [period, setPeriod] = useState<TimeRange>(defaultPeriod);
  const [minIPs, setMinIPs] = useState(defaultMinIPs);
  const [expandedUsers, setExpandedUsers] = useState<Set<string>>(new Set());

  const fetchData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await fetch(`/api/blacklist/abuse?period=${period}&min_ips=${minIPs}`);
      if (!res.ok) throw new Error("Failed to fetch data");
      const data = await res.json();
      // Sort by abuse_score descending
      const sorted = (data || []).sort((a: SubscriptionAbuse, b: SubscriptionAbuse) => 
        (b.abuse_score || 0) - (a.abuse_score || 0)
      );
      setAbusers(sorted);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }, [period, minIPs]);

  // Force sync HWID data from Remnawave
  const handleForceSync = useCallback(async () => {
    try {
      setSyncing(true);
      const res = await fetch("/api/remnawave/sync", { method: "POST" });
      if (!res.ok) throw new Error("Failed to sync");
      // Refetch data after sync
      await fetchData();
    } catch (err) {
      console.error("Sync failed:", err);
    } finally {
      setSyncing(false);
    }
  }, [fetchData]);

  // Clear HWID devices for a user
  const handleClearHwid = useCallback(async (userUuid: string) => {
    setClearingHwid(userUuid);
    try {
      const response = await fetch("/api/remnawave/hwid-clear", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userUuid }),
      });

      if (!response.ok) {
        const error = await response.text();
        throw new Error(error || "Failed to clear HWID");
      }

      // Refresh data after clearing
      await fetchData();
    } catch (error) {
      console.error("Failed to clear HWID:", error);
      alert(`Ошибка: ${error instanceof Error ? error.message : "Не удалось очистить HWID"}`);
    } finally {
      setClearingHwid(null);
    }
  }, [fetchData]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const toggleExpanded = (email: string) => {
    setExpandedUsers(prev => {
      const next = new Set(prev);
      if (next.has(email)) {
        next.delete(email);
      } else {
        next.add(email);
      }
      return next;
    });
  };

  if (loading && abusers.length === 0) {
    return (
      <div className="space-y-3">
        {[...Array(5)].map((_, i) => (
          <Skeleton key={i} className="h-16 w-full" />
        ))}
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center py-8 text-muted-foreground gap-2">
        <AlertTriangle className="h-8 w-8 opacity-50" />
        <p>Failed to load data: {error}</p>
        <Button variant="outline" size="sm" onClick={fetchData}>
          <RefreshCw className="h-4 w-4 mr-2" />
          Retry
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-2 justify-between">
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Users className="h-4 w-4" />
          <span>{abusers.length} suspicious users found</span>
        </div>
        <div className="flex gap-2">
          <Select value={period} onValueChange={(v) => setPeriod(v as TimeRange)}>
            <SelectTrigger className="w-[130px]">
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
          <Select value={String(minIPs)} onValueChange={(v) => setMinIPs(Number(v))}>
            <SelectTrigger className="w-[100px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="2">≥ 2 IPs</SelectItem>
              <SelectItem value="3">≥ 3 IPs</SelectItem>
              <SelectItem value="5">≥ 5 IPs</SelectItem>
              <SelectItem value="10">≥ 10 IPs</SelectItem>
            </SelectContent>
          </Select>
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="outline"
                  size="icon"
                  onClick={handleForceSync}
                  disabled={syncing}
                >
                  <RefreshCw className={`h-4 w-4 ${syncing ? "animate-spin" : ""}`} />
                </Button>
              </TooltipTrigger>
              <TooltipContent>
                <p>Sync HWID data from Remnawave</p>
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        </div>
      </div>

      {abusers.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
          <Users className="h-12 w-12 opacity-20 mb-3" />
          <p className="text-lg font-medium">No suspicious activity detected</p>
          <p className="text-sm">No users with {minIPs}+ unique IPs in the selected period</p>
        </div>
      ) : (
        <div className="space-y-2">
          {abusers.map((abuser) => (
            <Collapsible
              key={abuser.user_email}
              open={expandedUsers.has(abuser.user_email)}
              onOpenChange={() => toggleExpanded(abuser.user_email)}
            >
              <div className="border rounded-lg">
                <CollapsibleTrigger asChild>
                  <div className="flex items-center justify-between p-4 cursor-pointer hover:bg-muted/50 transition-colors">
                    <div className="flex items-center gap-3 min-w-0">
                      {/* Abuse Score Circle */}
                      <TooltipProvider>
                        <Tooltip>
                          <TooltipTrigger>
                            <div className={`flex items-center justify-center w-10 h-10 rounded-full font-bold text-sm ${
                              abuser.abuse_score >= 70 
                                ? "bg-destructive/20 text-destructive" 
                                : abuser.abuse_score >= 40 
                                  ? "bg-amber-500/20 text-amber-600 dark:text-amber-400"
                                  : "bg-muted text-muted-foreground"
                            }`}>
                              {abuser.abuse_score || 0}
                            </div>
                          </TooltipTrigger>
                          <TooltipContent>
                            <p>Abuse Score: {abuser.abuse_score || 0}/100</p>
                            <p className="text-xs text-muted-foreground">Based on IP, Node, HWID diversity</p>
                          </TooltipContent>
                        </Tooltip>
                      </TooltipProvider>
                      <div className="min-w-0">
                        <Link 
                          href={`/users/${encodeURIComponent(abuser.user_email)}`}
                          className="font-medium hover:underline text-primary flex items-center gap-1"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <span className="truncate">{abuser.username || abuser.user_email}</span>
                          <ExternalLink className="h-3 w-3 flex-shrink-0" />
                        </Link>
                        <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm text-muted-foreground">
                          <span>{abuser.total_requests.toLocaleString()} requests</span>
                          <span>•</span>
                          <span className="flex items-center gap-1">
                            <Globe className="h-3 w-3" />
                            {abuser.unique_countries} countries
                          </span>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 sm:gap-3">
                      {/* Stat badges */}
                      <div className="hidden sm:flex gap-1.5">
                        <TooltipProvider>
                          <Tooltip>
                            <TooltipTrigger>
                              <Badge variant="outline" className="gap-1">
                                <Monitor className="h-3 w-3" />
                                {abuser.unique_ips}
                              </Badge>
                            </TooltipTrigger>
                            <TooltipContent>Unique IPs</TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                        <TooltipProvider>
                          <Tooltip>
                            <TooltipTrigger>
                              <Badge variant="outline" className="gap-1">
                                <Server className="h-3 w-3" />
                                {abuser.unique_nodes || 0}
                              </Badge>
                            </TooltipTrigger>
                            <TooltipContent>Unique Nodes</TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                        {(abuser.unique_hwids || 0) > 0 && (
                          <TooltipProvider>
                            <Tooltip>
                              <TooltipTrigger>
                                <Badge variant="outline" className="gap-1">
                                  <Smartphone className="h-3 w-3" />
                                  {abuser.unique_hwids}
                                </Badge>
                              </TooltipTrigger>
                              <TooltipContent>HWID Devices</TooltipContent>
                            </Tooltip>
                          </TooltipProvider>
                        )}
                      </div>
                      {/* Country flags */}
                      <div className="hidden md:flex gap-1">
                        {abuser.countries?.slice(0, 3).map((cc) => (
                          <TooltipProvider key={cc}>
                            <Tooltip>
                              <TooltipTrigger>
                                <span className="text-lg">{getFlagEmoji(cc)}</span>
                              </TooltipTrigger>
                              <TooltipContent>{cc}</TooltipContent>
                            </Tooltip>
                          </TooltipProvider>
                        ))}
                        {(abuser.countries?.length || 0) > 3 && (
                          <Badge variant="secondary" className="text-xs">
                            +{abuser.countries.length - 3}
                          </Badge>
                        )}
                      </div>
                      <ChevronDown 
                        className={`h-4 w-4 text-muted-foreground transition-transform ${
                          expandedUsers.has(abuser.user_email) ? "rotate-180" : ""
                        }`} 
                      />
                    </div>
                  </div>
                </CollapsibleTrigger>
                <CollapsibleContent>
                  <div className="px-4 pb-4 pt-0 space-y-4">
                    {/* Nodes list */}
                    {abuser.nodes && abuser.nodes.length > 0 && (
                      <div className="flex flex-wrap gap-1.5">
                        <span className="text-sm text-muted-foreground mr-1">Nodes:</span>
                        {abuser.nodes.map((node) => (
                          <Badge key={node} variant="secondary" className="text-xs">
                            {node}
                          </Badge>
                        ))}
                      </div>
                    )}
                    
                    {/* HWID devices */}
                    {abuser.hwids && abuser.hwids.length > 0 && (
                      <div className="flex flex-wrap gap-1.5">
                        <span className="text-sm text-muted-foreground mr-1">Devices:</span>
                        {abuser.hwids.map((hwid) => (
                          <TooltipProvider key={hwid.hwid}>
                            <Tooltip>
                              <TooltipTrigger>
                                <Badge variant="outline" className="text-xs gap-1">
                                  <Smartphone className="h-3 w-3" />
                                  {hwid.platform || "Unknown"}
                                  {hwid.device_model && ` (${hwid.device_model})`}
                                </Badge>
                              </TooltipTrigger>
                              <TooltipContent>
                                <p className="font-mono text-xs">{hwid.hwid.slice(0, 16)}...</p>
                              </TooltipContent>
                            </Tooltip>
                          </TooltipProvider>
                        ))}
                        {/* Clear HWID button */}
                        {abuser.user_uuid && (
                          <AlertDialog>
                            <AlertDialogTrigger asChild>
                              <Button
                                variant="ghost"
                                size="sm"
                                className="text-destructive hover:text-destructive hover:bg-destructive/10 ml-2"
                                onClick={(e) => e.stopPropagation()}
                                disabled={clearingHwid === abuser.user_uuid}
                              >
                                {clearingHwid === abuser.user_uuid ? (
                                  <Loader2 className="h-3 w-3 animate-spin" />
                                ) : (
                                  <Trash2 className="h-3 w-3" />
                                )}
                                <span className="ml-1">Clear</span>
                              </Button>
                            </AlertDialogTrigger>
                            <AlertDialogContent onClick={(e) => e.stopPropagation()}>
                              <AlertDialogHeader>
                                <AlertDialogTitle>Очистить HWID устройства?</AlertDialogTitle>
                                <AlertDialogDescription>
                                  Будут удалены все {abuser.unique_hwids} устройств пользователя{" "}
                                  <span className="font-medium text-foreground">{abuser.username || abuser.user_email}</span>.
                                  Пользователю придётся заново подключить устройства.
                                </AlertDialogDescription>
                              </AlertDialogHeader>
                              <AlertDialogFooter>
                                <AlertDialogCancel>Отмена</AlertDialogCancel>
                                <AlertDialogAction
                                  className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                                onClick={() => handleClearHwid(abuser.user_uuid!)}
                              >
                                Очистить HWID
                                </AlertDialogAction>
                              </AlertDialogFooter>
                            </AlertDialogContent>
                          </AlertDialog>
                        )}
                      </div>
                    )}

                    {/* IP table */}
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>IP Address</TableHead>
                          <TableHead>Location</TableHead>
                          <TableHead className="hidden sm:table-cell">Node</TableHead>
                          <TableHead className="text-right">Requests</TableHead>
                          <TableHead className="hidden md:table-cell">Last Seen</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {abuser.ips?.map((ip, idx) => (
                          <TableRow key={`${ip.ip}-${idx}`}>
                            <TableCell className="font-mono text-sm">
                              <span className="inline-flex items-center gap-1.5">
                                <span>{getFlagEmoji(ip.country_code)}</span>
                                <span>{ip.ip}</span>
                              </span>
                            </TableCell>
                            <TableCell className="text-sm">
                              {ip.country_code || "—"}
                              {ip.city && <span className="text-muted-foreground"> • {ip.city}</span>}
                            </TableCell>
                            <TableCell className="hidden sm:table-cell">
                              {ip.node_id ? (
                                <Badge variant="outline" className="text-xs">{ip.node_id}</Badge>
                              ) : "—"}
                            </TableCell>
                            <TableCell className="text-right">
                              <Badge variant="secondary">{ip.request_count.toLocaleString()}</Badge>
                            </TableCell>
                            <TableCell className="text-muted-foreground text-sm hidden md:table-cell">
                              {isValidDate(ip.last_seen)
                                ? formatDistanceToNow(new Date(ip.last_seen), { addSuffix: true })
                                : "—"}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                </CollapsibleContent>
              </div>
            </Collapsible>
          ))}
        </div>
      )}
    </div>
  );
}
