"use client";

import { useState, useEffect, useCallback, useMemo } from "react";
import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Users,
  Globe,
  ExternalLink,
  ChevronDown,
  AlertTriangle,
  RefreshCw,
  Server,
  Smartphone,
  Monitor,
  Trash2,
  Loader2,
  Search,
  Shield,
  Activity,
  TrendingUp,
  MapPin,
  Clock,
  UserX,
  AlertCircle,
  CheckCircle2,
  XCircle,
  Phone,
  User,
} from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { SubscriptionAbuse, RemnawaveAbuseUser, TimeRange } from "@/lib/types";
import { isValidDate } from "@/lib/utils/date";

// Country flag emoji from country code
function getFlagEmoji(countryCode: string): string {
  if (!countryCode || countryCode.length !== 2) return "🌍";
  return String.fromCodePoint(
    ...[...countryCode.toUpperCase()].map(c => 0x1F1E6 - 65 + c.charCodeAt(0))
  );
}

// Platform icons
function getPlatformIcon(platform: string): string {
  const p = platform?.toLowerCase() || "";
  if (p.includes("ios") || p.includes("iphone") || p.includes("ipad")) return "🍎";
  if (p.includes("android")) return "🤖";
  if (p.includes("windows")) return "🪟";
  if (p.includes("mac") || p.includes("macos")) return "🍎";
  if (p.includes("linux")) return "🐧";
  return "📱";
}

// Risk level helpers
function getRiskLevel(score: number): "critical" | "high" | "medium" | "low" | "clean" {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  if (score >= 20) return "low";
  return "clean";
}

function getRiskColor(level: string): string {
  switch (level) {
    case "critical": return "text-red-600 bg-red-500/10 border-red-500/30";
    case "high": return "text-orange-600 bg-orange-500/10 border-orange-500/30";
    case "medium": return "text-yellow-600 bg-yellow-500/10 border-yellow-500/30";
    case "low": return "text-blue-600 bg-blue-500/10 border-blue-500/30";
    default: return "text-green-600 bg-green-500/10 border-green-500/30";
  }
}

function getRiskLabel(level: string): string {
  switch (level) {
    case "critical": return "Критический";
    case "high": return "Высокий";
    case "medium": return "Средний";
    case "low": return "Низкий";
    default: return "Чистый";
  }
}

interface CombinedAbuseUser {
  // Common fields
  user_email: string;
  username?: string;
  uuid?: string;
  
  // IP-based abuse data
  unique_ips: number;
  unique_countries: number;
  unique_nodes: number;
  total_requests: number;
  countries?: Array<{ country: string; country_code: string; count: number }>;
  ips?: Array<{ ip: string; country?: string; country_code?: string; requests: number; last_seen: string }>;
  
  // HWID-based abuse data
  unique_hwids: number;
  hwid_devices?: Array<{
    hwid: string;
    platform?: string;
    deviceModel?: string;
    osVersion?: string;
  }>;
  device_limit?: number;
  excess_devices?: number;
  
  // Combined score
  abuse_score: number;
  risk_factors: string[];
  
  // Metadata
  last_activity?: string;
  status?: string;
  parsedNote?: {
    real_name?: string;
    phone?: string;
    telegram_user?: string;
  };
}

interface AbuseStats {
  totalSuspicious: number;
  criticalRisk: number;
  highRisk: number;
  mediumRisk: number;
  lowRisk: number;
  totalUniqueIPs: number;
  totalUniqueHWIDs: number;
  avgAbuseScore: number;
  topCountries: Array<{ country: string; country_code: string; count: number }>;
}

interface SubscriptionAbuseAnalyticsProps {
  defaultPeriod?: TimeRange;
  /** If provided, use these instead of fetching */
  ipAbuseData?: SubscriptionAbuse[];
  /** If provided, use these instead of fetching */
  hwidAbuseData?: RemnawaveAbuseUser[];
  /** Callback when HWID is cleared */
  onHwidCleared?: () => void;
}

export function SubscriptionAbuseAnalytics({ 
  defaultPeriod = "24h",
  ipAbuseData,
  hwidAbuseData,
  onHwidCleared
}: SubscriptionAbuseAnalyticsProps) {
  const [ipAbusers, setIpAbusers] = useState<SubscriptionAbuse[]>(ipAbuseData || []);
  const [hwidAbusers, setHwidAbusers] = useState<RemnawaveAbuseUser[]>(hwidAbuseData || []);
  const [loading, setLoading] = useState(!ipAbuseData && !hwidAbuseData);
  const [syncing, setSyncing] = useState(false);
  const [clearingHwid, setClearingHwid] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [period, setPeriod] = useState<TimeRange>(defaultPeriod);
  const [minIPs, setMinIPs] = useState(3);
  const [search, setSearch] = useState("");
  const [sortBy, setSortBy] = useState<"score" | "ips" | "hwids" | "requests">("score");
  const [riskFilter, setRiskFilter] = useState<string>("all");
  const [hwidFilter, setHwidFilter] = useState<"all" | "exceeded" | "at_limit" | "with_hwid">("all");
  const [expandedUsers, setExpandedUsers] = useState<Set<string>>(new Set());
  
  // Track if data is provided externally
  const isExternalData = ipAbuseData !== undefined || hwidAbuseData !== undefined;

  // Update state when props change (external data mode)
  useEffect(() => {
    if (ipAbuseData !== undefined) {
      setIpAbusers(ipAbuseData);
    }
  }, [ipAbuseData]);

  useEffect(() => {
    if (hwidAbuseData !== undefined) {
      setHwidAbusers(hwidAbuseData);
    }
  }, [hwidAbuseData]);

  const fetchData = useCallback(async () => {
    // Skip fetching if data is provided externally
    if (isExternalData) {
      setLoading(false);
      return;
    }
    
    try {
      setLoading(true);
      setError(null);
      
      const token = localStorage.getItem("auth_token");
      const headers: HeadersInit = {};
      if (token) {
        headers["Authorization"] = `Bearer ${token}`;
      }

      const [ipRes, hwidRes] = await Promise.all([
        fetch(`/api/blacklist/abuse?period=${period}&min_ips=${minIPs}`, { headers }),
        fetch("/api/remnawave/abuse", { headers }),
      ]);

      if (!ipRes.ok && ipRes.status !== 404) {
        throw new Error("Failed to fetch IP abuse data");
      }

      const [ipData, hwidData] = await Promise.all([
        ipRes.ok ? ipRes.json() : [],
        hwidRes.ok ? hwidRes.json() : { users: [] },
      ]);

      setIpAbusers(ipData || []);
      setHwidAbusers(hwidData.users || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }, [period, minIPs, isExternalData]);

  useEffect(() => {
    if (!isExternalData) {
      fetchData();
    } else {
      setLoading(false);
    }
  }, [fetchData, isExternalData]);

  // Force sync HWID data
  const handleForceSync = useCallback(async () => {
    try {
      setSyncing(true);
      const res = await fetch("/api/remnawave/sync", { method: "POST" });
      if (!res.ok) throw new Error("Failed to sync");
      if (isExternalData && onHwidCleared) {
        onHwidCleared();
      } else {
        await fetchData();
      }
    } catch (err) {
      console.error("Sync failed:", err);
    } finally {
      setSyncing(false);
    }
  }, [fetchData, isExternalData, onHwidCleared]);

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
        throw new Error(await response.text() || "Failed to clear HWID");
      }

      if (isExternalData && onHwidCleared) {
        onHwidCleared();
      } else {
        await fetchData();
      }
    } catch (error) {
      console.error("Failed to clear HWID:", error);
      alert(`Ошибка: ${error instanceof Error ? error.message : "Не удалось очистить HWID"}`);
    } finally {
      setClearingHwid(null);
    }
  }, [fetchData, isExternalData, onHwidCleared]);

  // Combine IP and HWID abuse data
  const combinedAbusers = useMemo((): CombinedAbuseUser[] => {
    const userMap = new Map<string, CombinedAbuseUser>();
    // Secondary index by username for merging
    const usernameIndex = new Map<string, string>(); // username -> map key

    // First, add IP-based abusers
    for (const ipAbuser of ipAbusers) {
      const email = ipAbuser.user_email.toLowerCase();
      const username = ipAbuser.username?.toLowerCase() || "";
      
      // Transform countries from string[] to proper format
      const countriesFormatted = ipAbuser.countries?.map((c) => ({
        country: c,
        country_code: c,
        count: 1,
      })) || [];
      
      // Transform ips from AbuseIPInfo[] to proper format
      const ipsFormatted = ipAbuser.ips?.map((ip) => ({
        ip: ip.ip,
        country: ip.city,
        country_code: ip.country_code,
        requests: ip.request_count,
        last_seen: ip.last_seen,
      })) || [];
      
      // Transform hwids if present
      const hwidsFormatted = ipAbuser.hwids?.map((h) => ({
        hwid: h.hwid,
        platform: h.platform,
        deviceModel: undefined,
        osVersion: undefined,
      })) || [];
      
      userMap.set(email, {
        user_email: ipAbuser.user_email,
        username: ipAbuser.username,
        uuid: ipAbuser.user_uuid,
        unique_ips: ipAbuser.unique_ips,
        unique_countries: ipAbuser.unique_countries,
        unique_nodes: ipAbuser.unique_nodes || 0,
        total_requests: ipAbuser.total_requests,
        countries: countriesFormatted,
        ips: ipsFormatted,
        unique_hwids: ipAbuser.unique_hwids || 0,
        hwid_devices: hwidsFormatted,
        abuse_score: ipAbuser.abuse_score || 0,
        risk_factors: [],
        last_activity: ipAbuser.last_seen,
      });
      
      // Index by username for HWID merge lookup
      if (username) {
        usernameIndex.set(username, email);
      }
    }

    // Then, merge HWID-based abusers
    for (const hwidAbuser of hwidAbusers) {
      const hwidUsername = hwidAbuser.username?.toLowerCase() || "";
      const hwidEmail = hwidAbuser.email?.toLowerCase() || "";
      
      // Try to find existing entry by username first, then by email
      let existingKey = usernameIndex.get(hwidUsername) || userMap.has(hwidEmail) ? hwidEmail : null;
      const existing = existingKey ? userMap.get(existingKey) : null;

      if (existing) {
        // Merge HWID data into existing record
        existing.uuid = hwidAbuser.uuid;
        existing.unique_hwids = Math.max(existing.unique_hwids, hwidAbuser.deviceCount);
        existing.hwid_devices = hwidAbuser.devices;
        existing.device_limit = hwidAbuser.deviceLimit;
        existing.excess_devices = hwidAbuser.excessDevices;
        existing.status = hwidAbuser.status;
        existing.parsedNote = hwidAbuser.parsedNote;
        if (hwidAbuser.lastActivity) {
          existing.last_activity = hwidAbuser.lastActivity;
        }
      } else {
        // Add as new entry - use username as key since no IP data match found
        const newKey = hwidUsername || hwidEmail;
        userMap.set(newKey, {
          user_email: hwidAbuser.email || hwidAbuser.username || "",
          username: hwidAbuser.username,
          uuid: hwidAbuser.uuid,
          unique_ips: 0,
          unique_countries: 0,
          unique_nodes: 0,
          total_requests: 0,
          unique_hwids: hwidAbuser.deviceCount,
          hwid_devices: hwidAbuser.devices,
          device_limit: hwidAbuser.deviceLimit,
          excess_devices: hwidAbuser.excessDevices,
          abuse_score: 0,
          risk_factors: [],
          last_activity: hwidAbuser.lastActivity,
          status: hwidAbuser.status,
          parsedNote: hwidAbuser.parsedNote,
        });
      }
    }

    // Calculate combined abuse scores
    const result = Array.from(userMap.values()).map(user => {
      const factors: string[] = [];
      let score = user.abuse_score;

      // IP factors
      if (user.unique_ips >= 10) {
        factors.push(`${user.unique_ips} уникальных IP`);
        score = Math.max(score, 60);
      } else if (user.unique_ips >= 5) {
        factors.push(`${user.unique_ips} IP адресов`);
        score = Math.max(score, 40);
      }

      // Country factors
      if (user.unique_countries >= 5) {
        factors.push(`${user.unique_countries} стран`);
        score += 20;
      } else if (user.unique_countries >= 3) {
        factors.push(`${user.unique_countries} страны`);
        score += 10;
      }

      // Node factors
      if (user.unique_nodes >= 5) {
        factors.push(`${user.unique_nodes} нод`);
        score += 15;
      }

      // HWID excess
      if (user.excess_devices && user.excess_devices > 0) {
        factors.push(`Превышение HWID лимита на ${user.excess_devices}`);
        score += 25 + (user.excess_devices * 10);
      } else if (user.device_limit && user.unique_hwids >= user.device_limit) {
        factors.push("На пределе HWID");
        score += 15;
      }

      // High request volume
      if (user.total_requests >= 10000) {
        factors.push(`${user.total_requests.toLocaleString()} запросов`);
        score += 10;
      }

      return {
        ...user,
        abuse_score: Math.min(score, 100),
        risk_factors: factors,
      };
    });

    return result;
  }, [ipAbusers, hwidAbusers]);

  // Calculate statistics
  const stats = useMemo((): AbuseStats => {
    const users = combinedAbusers;
    const countryMap = new Map<string, { code: string; count: number }>();

    for (const user of users) {
      if (user.countries) {
        for (const c of user.countries) {
          const existing = countryMap.get(c.country_code);
          if (existing) {
            existing.count += c.count;
          } else {
            countryMap.set(c.country_code, { code: c.country_code, count: c.count });
          }
        }
      }
    }

    const topCountries = Array.from(countryMap.entries())
      .map(([country_code, { count }]) => ({ country: country_code, country_code, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    return {
      totalSuspicious: users.length,
      criticalRisk: users.filter(u => u.abuse_score >= 80).length,
      highRisk: users.filter(u => u.abuse_score >= 60 && u.abuse_score < 80).length,
      mediumRisk: users.filter(u => u.abuse_score >= 40 && u.abuse_score < 60).length,
      lowRisk: users.filter(u => u.abuse_score >= 20 && u.abuse_score < 40).length,
      totalUniqueIPs: users.reduce((sum, u) => sum + u.unique_ips, 0),
      totalUniqueHWIDs: users.reduce((sum, u) => sum + u.unique_hwids, 0),
      avgAbuseScore: users.length > 0 
        ? Math.round(users.reduce((sum, u) => sum + u.abuse_score, 0) / users.length)
        : 0,
      topCountries,
    };
  }, [combinedAbusers]);

  // Filter and sort
  const filteredAbusers = useMemo(() => {
    let result = [...combinedAbusers];

    // Search filter
    if (search.trim()) {
      const searchLower = search.toLowerCase();
      result = result.filter(a =>
        a.user_email.toLowerCase().includes(searchLower) ||
        a.username?.toLowerCase().includes(searchLower)
      );
    }

    // Risk filter - only filter if not "all"
    if (riskFilter !== "all") {
      result = result.filter(a => getRiskLevel(a.abuse_score) === riskFilter);
    }

    // HWID filter - additional filter, not exclusive
    if (hwidFilter !== "all") {
      result = result.filter(a => {
        switch (hwidFilter) {
          case "exceeded":
            return a.excess_devices && a.excess_devices > 0;
          case "at_limit":
            return a.device_limit && a.unique_hwids >= a.device_limit && !(a.excess_devices && a.excess_devices > 0);
          case "with_hwid":
            return a.unique_hwids > 0;
          default:
            return true;
        }
      });
    }

    // Sort with composite criteria - primary by selected, secondary by score
    result.sort((a, b) => {
      let diff = 0;
      switch (sortBy) {
        case "ips":
          diff = b.unique_ips - a.unique_ips;
          if (diff === 0) diff = b.abuse_score - a.abuse_score;
          if (diff === 0) diff = b.unique_hwids - a.unique_hwids;
          break;
        case "hwids":
          diff = b.unique_hwids - a.unique_hwids;
          if (diff === 0) diff = b.abuse_score - a.abuse_score;
          if (diff === 0) diff = b.unique_ips - a.unique_ips;
          break;
        case "requests":
          diff = b.total_requests - a.total_requests;
          if (diff === 0) diff = b.abuse_score - a.abuse_score;
          break;
        default: // score
          diff = b.abuse_score - a.abuse_score;
          if (diff === 0) diff = b.unique_ips - a.unique_ips;
          if (diff === 0) diff = b.unique_hwids - a.unique_hwids;
      }
      return diff;
    });

    return result;
  }, [combinedAbusers, search, riskFilter, hwidFilter, sortBy]);

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

  if (loading && combinedAbusers.length === 0) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => (
            <Skeleton key={i} className="h-24" />
          ))}
        </div>
        <Skeleton className="h-[400px]" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-muted-foreground gap-4">
        <AlertTriangle className="h-12 w-12 opacity-50" />
        <p className="text-lg">Не удалось загрузить данные: {error}</p>
        <Button variant="outline" onClick={fetchData}>
          <RefreshCw className="h-4 w-4 mr-2" />
          Повторить
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Stats Overview */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <UserX className="h-4 w-4 text-red-500" />
              Подозрительных
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.totalSuspicious}</div>
            <p className="text-xs text-muted-foreground">пользователей</p>
          </CardContent>
        </Card>

        <Card className={stats.criticalRisk > 0 ? "border-red-500/50" : ""}>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <AlertCircle className="h-4 w-4 text-red-600" />
              Критический
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">{stats.criticalRisk}</div>
            <p className="text-xs text-muted-foreground">score ≥80</p>
          </CardContent>
        </Card>

        <Card className={stats.highRisk > 0 ? "border-orange-500/50" : ""}>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-orange-600" />
              Высокий
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-orange-600">{stats.highRisk}</div>
            <p className="text-xs text-muted-foreground">score 60-79</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Shield className="h-4 w-4 text-yellow-600" />
              Средний
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-yellow-600">{stats.mediumRisk}</div>
            <p className="text-xs text-muted-foreground">score 40-59</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Monitor className="h-4 w-4 text-muted-foreground" />
              Уникальных IP
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.totalUniqueIPs}</div>
            <p className="text-xs text-muted-foreground">адресов</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Smartphone className="h-4 w-4 text-muted-foreground" />
              HWID устройств
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.totalUniqueHWIDs}</div>
            <p className="text-xs text-muted-foreground">устройств</p>
          </CardContent>
        </Card>
      </div>

      {/* Average Score and Top Countries */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Средний Abuse Score</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-4">
              <div className={`text-3xl font-bold ${
                stats.avgAbuseScore >= 60 ? "text-red-600" :
                stats.avgAbuseScore >= 40 ? "text-orange-600" :
                stats.avgAbuseScore >= 20 ? "text-yellow-600" :
                "text-green-600"
              }`}>
                {stats.avgAbuseScore}
              </div>
              <div className="flex-1">
                <Progress 
                  value={stats.avgAbuseScore} 
                  className="h-2"
                />
                <p className="text-xs text-muted-foreground mt-1">из 100</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Globe className="h-4 w-4" />
              Топ стран
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {stats.topCountries.map((c) => (
                <Badge key={c.country_code} variant="outline" className="gap-1">
                  {getFlagEmoji(c.country_code)} {c.country_code}
                  <span className="text-muted-foreground">({c.count})</span>
                </Badge>
              ))}
              {stats.topCountries.length === 0 && (
                <span className="text-sm text-muted-foreground">Нет данных о странах</span>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Filters */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <CardTitle>Подозрительные пользователи</CardTitle>
              <CardDescription>
                Объединённый анализ по IP адресам и HWID устройствам
              </CardDescription>
            </div>
            <div className="flex items-center gap-2">
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
                  <TooltipContent>Синхронизировать HWID из Remnawave</TooltipContent>
                </Tooltip>
              </TooltipProvider>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Search and Filters */}
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Поиск по email или username..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-8"
              />
            </div>
            <Select value={period} onValueChange={(v) => setPeriod(v as TimeRange)}>
              <SelectTrigger className="w-[110px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="1h">1 час</SelectItem>
                <SelectItem value="6h">6 часов</SelectItem>
                <SelectItem value="24h">24 часа</SelectItem>
                <SelectItem value="7d">7 дней</SelectItem>
                <SelectItem value="30d">30 дней</SelectItem>
              </SelectContent>
            </Select>
            <Select value={String(minIPs)} onValueChange={(v) => setMinIPs(Number(v))}>
              <SelectTrigger className="w-[95px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="2">≥ 2 IP</SelectItem>
                <SelectItem value="3">≥ 3 IP</SelectItem>
                <SelectItem value="5">≥ 5 IP</SelectItem>
                <SelectItem value="10">≥ 10 IP</SelectItem>
              </SelectContent>
            </Select>
            <Select value={riskFilter} onValueChange={setRiskFilter}>
              <SelectTrigger className="w-[130px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Все риски</SelectItem>
                <SelectItem value="critical">Критический</SelectItem>
                <SelectItem value="high">Высокий</SelectItem>
                <SelectItem value="medium">Средний</SelectItem>
                <SelectItem value="low">Низкий</SelectItem>
              </SelectContent>
            </Select>
            <Select value={hwidFilter} onValueChange={(v) => setHwidFilter(v as typeof hwidFilter)}>
              <SelectTrigger className="w-[145px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Все HWID</SelectItem>
                <SelectItem value="exceeded">Превышен лимит</SelectItem>
                <SelectItem value="at_limit">На лимите</SelectItem>
                <SelectItem value="with_hwid">С HWID</SelectItem>
              </SelectContent>
            </Select>
            <Select value={sortBy} onValueChange={(v) => setSortBy(v as typeof sortBy)}>
              <SelectTrigger className="w-[130px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="score">По риску</SelectItem>
                <SelectItem value="ips">По кол-ву IP</SelectItem>
                <SelectItem value="hwids">По кол-ву HWID</SelectItem>
                <SelectItem value="requests">По запросам</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* Results count */}
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Users className="h-4 w-4" />
            <span>Показано {filteredAbusers.length} из {combinedAbusers.length} пользователей</span>
          </div>

          {/* Users List */}
          {filteredAbusers.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <CheckCircle2 className="h-12 w-12 opacity-20 mb-3" />
              <p className="text-lg font-medium">Подозрительная активность не обнаружена</p>
              <p className="text-sm">
                {search ? "Нет пользователей по вашему запросу" : `Нет пользователей с ${minIPs}+ IP адресами`}
              </p>
            </div>
          ) : (
            <div className="space-y-2 max-h-[600px] overflow-y-auto pr-1">
              {filteredAbusers.map((user) => {
                const riskLevel = getRiskLevel(user.abuse_score);
                const isExpanded = expandedUsers.has(user.user_email);

                return (
                  <Collapsible
                    key={user.user_email}
                    open={isExpanded}
                    onOpenChange={() => toggleExpanded(user.user_email)}
                  >
                    <div className="border rounded-lg">
                      <CollapsibleTrigger asChild>
                        <div className="flex items-center justify-between p-4 cursor-pointer hover:bg-muted/50 transition-colors">
                          <div className="flex items-center gap-3 min-w-0">
                            {/* Abuse Score Circle */}
                            <TooltipProvider>
                              <Tooltip>
                                <TooltipTrigger>
                                  <div className={`flex items-center justify-center w-12 h-12 rounded-full font-bold text-sm border ${getRiskColor(riskLevel)}`}>
                                    {user.abuse_score}
                                  </div>
                                </TooltipTrigger>
                                <TooltipContent className="max-w-xs">
                                  <p className="font-medium">Abuse Score: {user.abuse_score}/100</p>
                                  {user.risk_factors.length > 0 && (
                                    <ul className="text-xs mt-1 space-y-0.5">
                                      {user.risk_factors.map((f, i) => (
                                        <li key={i}>• {f}</li>
                                      ))}
                                    </ul>
                                  )}
                                </TooltipContent>
                              </Tooltip>
                            </TooltipProvider>

                            <div className="min-w-0">
                              <Link
                                href={`/users/${encodeURIComponent(user.user_email)}`}
                                className="font-medium hover:underline text-primary flex items-center gap-1"
                                onClick={(e) => e.stopPropagation()}
                              >
                                <span className="truncate">{user.username || user.user_email}</span>
                                <ExternalLink className="h-3 w-3 flex-shrink-0" />
                              </Link>
                              <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm text-muted-foreground">
                                {user.total_requests > 0 && (
                                  <span>{user.total_requests.toLocaleString()} req</span>
                                )}
                                {user.unique_countries > 0 && (
                                  <>
                                    <span>•</span>
                                    <span className="flex items-center gap-1">
                                      <Globe className="h-3 w-3" />
                                      {user.unique_countries} стран
                                    </span>
                                  </>
                                )}
                                {user.parsedNote?.real_name && (
                                  <>
                                    <span>•</span>
                                    <span>{user.parsedNote.real_name}</span>
                                  </>
                                )}
                              </div>
                            </div>
                          </div>

                          <div className="flex items-center gap-2 sm:gap-3">
                            {/* Stats badges */}
                            <div className="hidden sm:flex gap-1.5">
                              <TooltipProvider>
                                <Tooltip>
                                  <TooltipTrigger>
                                    <Badge variant="outline" className="gap-1">
                                      <Monitor className="h-3 w-3" />
                                      {user.unique_ips}
                                    </Badge>
                                  </TooltipTrigger>
                                  <TooltipContent>Unique IPs</TooltipContent>
                                </Tooltip>
                              </TooltipProvider>

                              {user.unique_hwids > 0 && (
                                <TooltipProvider>
                                  <Tooltip>
                                    <TooltipTrigger>
                                      <Badge 
                                        variant={user.excess_devices && user.excess_devices > 0 ? "destructive" : "outline"} 
                                        className="gap-1"
                                      >
                                        <Smartphone className="h-3 w-3" />
                                        {user.unique_hwids}
                                        {user.device_limit && `/${user.device_limit}`}
                                      </Badge>
                                    </TooltipTrigger>
                                    <TooltipContent>
                                      HWID устройств
                                      {user.excess_devices && user.excess_devices > 0 && ` (превышение на ${user.excess_devices})`}
                                    </TooltipContent>
                                  </Tooltip>
                                </TooltipProvider>
                              )}

                              {user.unique_nodes > 0 && (
                                <TooltipProvider>
                                  <Tooltip>
                                    <TooltipTrigger>
                                      <Badge variant="outline" className="gap-1">
                                        <Server className="h-3 w-3" />
                                        {user.unique_nodes}
                                      </Badge>
                                    </TooltipTrigger>
                                    <TooltipContent>Unique Nodes</TooltipContent>
                                  </Tooltip>
                                </TooltipProvider>
                              )}
                            </div>

                            {/* Risk Badge */}
                            <Badge variant="outline" className={getRiskColor(riskLevel)}>
                              {getRiskLabel(riskLevel)}
                            </Badge>

                            {/* Clear HWID button */}
                            {user.uuid && (
                              <AlertDialog>
                                <AlertDialogTrigger asChild>
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    className="text-destructive hover:text-destructive hover:bg-destructive/10"
                                    onClick={(e) => e.stopPropagation()}
                                    disabled={clearingHwid === user.uuid}
                                  >
                                    {clearingHwid === user.uuid ? (
                                      <Loader2 className="h-4 w-4 animate-spin" />
                                    ) : (
                                      <Trash2 className="h-4 w-4" />
                                    )}
                                  </Button>
                                </AlertDialogTrigger>
                                <AlertDialogContent onClick={(e) => e.stopPropagation()}>
                                  <AlertDialogHeader>
                                    <AlertDialogTitle>Очистить HWID устройства?</AlertDialogTitle>
                                    <AlertDialogDescription>
                                      Будут удалены все устройства пользователя{" "}
                                      <span className="font-medium text-foreground">{user.username || user.user_email}</span>.
                                      Пользователю придётся заново подключить устройства.
                                    </AlertDialogDescription>
                                  </AlertDialogHeader>
                                  <AlertDialogFooter>
                                    <AlertDialogCancel>Отмена</AlertDialogCancel>
                                    <AlertDialogAction
                                      className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                                      onClick={() => user.uuid && handleClearHwid(user.uuid)}
                                    >
                                      Очистить HWID
                                    </AlertDialogAction>
                                  </AlertDialogFooter>
                                </AlertDialogContent>
                              </AlertDialog>
                            )}

                            <ChevronDown className={`h-4 w-4 transition-transform ${isExpanded ? "rotate-180" : ""}`} />
                          </div>
                        </div>
                      </CollapsibleTrigger>

                      <CollapsibleContent>
                        <div className="border-t p-4 bg-muted/30 space-y-4">
                          {/* Contact Info */}
                          {user.parsedNote && (user.parsedNote.phone || user.parsedNote.telegram_user) && (
                            <div className="flex flex-wrap gap-4 text-sm">
                              {user.parsedNote.phone && (
                                <div className="flex items-center gap-1">
                                  <Phone className="h-4 w-4 text-muted-foreground" />
                                  {user.parsedNote.phone}
                                </div>
                              )}
                              {user.parsedNote.telegram_user && (
                                <div className="flex items-center gap-1">
                                  <span className="text-muted-foreground">@</span>
                                  {user.parsedNote.telegram_user}
                                </div>
                              )}
                            </div>
                          )}

                          {/* Risk Factors */}
                          {user.risk_factors.length > 0 && (
                            <div>
                              <div className="text-sm font-medium mb-2 flex items-center gap-2">
                                <AlertTriangle className="h-4 w-4 text-orange-500" />
                                Факторы риска
                              </div>
                              <div className="flex flex-wrap gap-2">
                                {user.risk_factors.map((factor, i) => (
                                  <Badge key={i} variant="outline" className="text-orange-600 border-orange-500/30">
                                    {factor}
                                  </Badge>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* IPs */}
                          {user.ips && user.ips.length > 0 && (
                            <div>
                              <div className="text-sm font-medium mb-2 flex items-center gap-2">
                                <Monitor className="h-4 w-4" />
                                IP адреса ({user.ips.length})
                              </div>
                              <div className="grid gap-2 max-h-48 overflow-y-auto">
                                {user.ips.slice(0, 10).map((ip) => (
                                  <div
                                    key={ip.ip}
                                    className="text-xs bg-background p-2 rounded border flex flex-wrap justify-between gap-2"
                                  >
                                    <span className="font-mono">{ip.ip}</span>
                                    <div className="flex items-center gap-2">
                                      {ip.country_code && (
                                        <span>{getFlagEmoji(ip.country_code)} {ip.country_code}</span>
                                      )}
                                      <Badge variant="secondary" className="text-xs">{ip.requests} req</Badge>
                                      {ip.last_seen && isValidDate(ip.last_seen) && (
                                        <span className="text-muted-foreground">
                                          {formatDistanceToNow(new Date(ip.last_seen), { addSuffix: true })}
                                        </span>
                                      )}
                                    </div>
                                  </div>
                                ))}
                                {user.ips.length > 10 && (
                                  <p className="text-xs text-muted-foreground">
                                    ... и ещё {user.ips.length - 10} IP адресов
                                  </p>
                                )}
                              </div>
                            </div>
                          )}

                          {/* HWID Devices */}
                          {user.hwid_devices && user.hwid_devices.length > 0 && (
                            <div>
                              <div className="text-sm font-medium mb-2 flex items-center gap-2">
                                <Smartphone className="h-4 w-4" />
                                HWID устройства ({user.hwid_devices.length})
                                {user.device_limit && (
                                  <span className="text-muted-foreground font-normal">
                                    / лимит: {user.device_limit}
                                  </span>
                                )}
                              </div>
                              <div className="grid gap-2">
                                {user.hwid_devices.map((device) => (
                                  <div
                                    key={device.hwid}
                                    className="text-xs bg-background p-3 rounded border grid grid-cols-2 md:grid-cols-4 gap-2"
                                  >
                                    <div>
                                      <span className="text-muted-foreground">HWID:</span>
                                      <span className="ml-1 font-mono">{device.hwid.slice(0, 16)}...</span>
                                    </div>
                                    <div>
                                      <span className="text-muted-foreground">Platform:</span>
                                      <span className="ml-1">{getPlatformIcon(device.platform || "")} {device.platform || "Unknown"}</span>
                                    </div>
                                    <div>
                                      <span className="text-muted-foreground">Model:</span>
                                      <span className="ml-1">{device.deviceModel || "—"}</span>
                                    </div>
                                    <div>
                                      <span className="text-muted-foreground">OS:</span>
                                      <span className="ml-1">{device.osVersion || "—"}</span>
                                    </div>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Countries */}
                          {user.countries && user.countries.length > 0 && (
                            <div>
                              <div className="text-sm font-medium mb-2 flex items-center gap-2">
                                <Globe className="h-4 w-4" />
                                Страны ({user.countries.length})
                              </div>
                              <div className="flex flex-wrap gap-2">
                                {user.countries.map((c) => (
                                  <Badge key={c.country_code} variant="outline" className="gap-1">
                                    {getFlagEmoji(c.country_code)} {c.country}
                                    <span className="text-muted-foreground">({c.count})</span>
                                  </Badge>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Last Activity */}
                          {user.last_activity && isValidDate(user.last_activity) && (
                            <div className="text-xs text-muted-foreground flex items-center gap-1">
                              <Clock className="h-3 w-3" />
                              Последняя активность: {formatDistanceToNow(new Date(user.last_activity), { addSuffix: true })}
                            </div>
                          )}
                        </div>
                      </CollapsibleContent>
                    </div>
                  </Collapsible>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
