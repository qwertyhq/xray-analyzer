"use client";

import { useState } from "react";
import { authFetch } from "@/contexts/auth-context";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { 
  AlertTriangle, 
  TrendingUp, 
  Moon, 
  UserPlus, 
  Globe, 
  Zap,
  MapPin,
  Check,
  RefreshCw,
  Shield
} from "lucide-react";
import { AnomalySummary, Anomaly, AnomalyType, AnomalySeverity } from "@/lib/types";
import { formatDistanceToNow } from "date-fns";
import { StatCard, StatCardGrid } from "./stat-card";

interface AnomalyPanelProps {
  data: AnomalySummary | null;
  loading?: boolean;
  onResolve?: (id: string) => void;
  onRefresh?: () => void;
}

// Config for anomaly types
const anomalyTypeConfig: Record<AnomalyType, { icon: React.ReactNode; label: string; color: string }> = {
  activity_spike: { 
    icon: <TrendingUp className="h-4 w-4" />, 
    label: "Activity Spike", 
    color: "text-amber-600 dark:text-amber-400" 
  },
  night_activity: { 
    icon: <Moon className="h-4 w-4" />, 
    label: "Night Activity", 
    color: "text-violet-600 dark:text-violet-400" 
  },
  new_user_high_vol: { 
    icon: <UserPlus className="h-4 w-4" />, 
    label: "New User High Volume", 
    color: "text-blue-600 dark:text-blue-400" 
  },
  geo_anomaly: { 
    icon: <Globe className="h-4 w-4" />, 
    label: "Geo Anomaly", 
    color: "text-emerald-600 dark:text-emerald-400" 
  },
  threat_burst: { 
    icon: <Zap className="h-4 w-4" />, 
    label: "Threat Burst", 
    color: "text-red-600 dark:text-red-400" 
  },
  multiple_countries: { 
    icon: <MapPin className="h-4 w-4" />, 
    label: "Multiple Countries", 
    color: "text-pink-600 dark:text-pink-400" 
  },
  blacklist_spike: { 
    icon: <AlertTriangle className="h-4 w-4" />, 
    label: "Blacklist Spike", 
    color: "text-red-600 dark:text-red-400" 
  },
  traffic_spike: { 
    icon: <TrendingUp className="h-4 w-4" />, 
    label: "Traffic Spike", 
    color: "text-amber-600 dark:text-amber-400" 
  },
  user_spike: { 
    icon: <UserPlus className="h-4 w-4" />, 
    label: "User Spike", 
    color: "text-blue-600 dark:text-blue-400" 
  },
  user_blacklist_spike: { 
    icon: <AlertTriangle className="h-4 w-4" />, 
    label: "User Blacklist Spike", 
    color: "text-red-600 dark:text-red-400" 
  },
};

// Config for severity
const severityConfig: Record<AnomalySeverity, { color: string; bgColor: string }> = {
  low: { color: "text-blue-600 dark:text-blue-400", bgColor: "bg-blue-500/10 border-blue-500/20" },
  medium: { color: "text-amber-600 dark:text-amber-400", bgColor: "bg-amber-500/10 border-amber-500/20" },
  high: { color: "text-orange-600 dark:text-orange-400", bgColor: "bg-orange-500/10 border-orange-500/20" },
  critical: { color: "text-red-600 dark:text-red-400", bgColor: "bg-red-500/10 border-red-500/20" },
};

export function AnomalyPanel({ data, loading = false, onResolve, onRefresh }: AnomalyPanelProps) {
  const [resolving, setResolving] = useState<string | null>(null);

  const handleResolve = async (id: string) => {
    setResolving(id);
    try {
      await authFetch(`/api/threatintel/anomalies?id=${id}`, { method: "DELETE" });
      onResolve?.(id);
    } finally {
      setResolving(null);
    }
  };

  if (loading) {
    return (
      <div className="space-y-4">
        <div className="grid gap-4 md:grid-cols-4">
          {[...Array(4)].map((_, i) => (
            <Skeleton key={i} className="h-24 rounded-xl" />
          ))}
        </div>
        <Card>
          <CardContent className="pt-6">
            <Skeleton className="h-[300px] w-full" />
          </CardContent>
        </Card>
      </div>
    );
  }

  const hasAnomalies = data && data.total_anomalies > 0;

  return (
    <div className="space-y-4">
      {/* Summary Cards */}
      <StatCardGrid columns={4}>
        <StatCard
          icon={<AlertTriangle className="h-4 w-4" />}
          label="Active Anomalies"
          value={data?.total_anomalies || 0}
          subValue="Requiring attention"
          variant={hasAnomalies ? "warning" : "muted"}
          highlight={hasAnomalies ?? false}
        />
        <StatCard
          icon={<Zap className="h-4 w-4" />}
          label="Critical"
          value={data?.by_severity?.critical || 0}
          subValue="High priority"
          variant="danger"
        />
        <StatCard
          icon={<TrendingUp className="h-4 w-4" />}
          label="High Severity"
          value={data?.by_severity?.high || 0}
          subValue="Needs review"
          variant="warning"
        />
        <StatCard
          icon={<Shield className="h-4 w-4" />}
          label="Affected Users"
          value={data?.affected_users || 0}
          subValue="Unique users"
          variant="info"
        />
      </StatCardGrid>

      {/* Anomaly List */}
      <Card className="border shadow-sm">
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-muted-foreground" />
                Recent Anomalies
              </CardTitle>
              <CardDescription className="text-xs">
                Detected behavioral anomalies
              </CardDescription>
            </div>
            {onRefresh && (
              <Button variant="outline" size="sm" onClick={onRefresh} className="gap-1">
                <RefreshCw className="h-4 w-4" />
                Run Detection
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent>
          {!hasAnomalies ? (
            <div className="flex flex-col items-center justify-center h-[200px] text-muted-foreground">
              <div className="w-16 h-16 rounded-full bg-emerald-100 dark:bg-emerald-900/30 flex items-center justify-center mb-3">
                <Shield className="h-8 w-8 text-emerald-500" />
              </div>
              <p className="text-sm font-medium">No anomalies detected</p>
              <p className="text-xs">System is operating normally</p>
            </div>
          ) : (
            <div className="space-y-3">
              {data?.recent_anomalies?.map((anomaly) => {
                const typeConfig = anomalyTypeConfig[anomaly.type] || anomalyTypeConfig.activity_spike;
                const sevConfig = severityConfig[anomaly.severity] || severityConfig.medium;
                
                return (
                  <div
                    key={anomaly.id}
                    className={`p-4 rounded-xl border ${sevConfig.bgColor} hover:shadow-md transition-all`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex items-start gap-3">
                        <div className={`mt-0.5 p-2 rounded-lg bg-background/80 ${typeConfig.color}`}>
                          {typeConfig.icon}
                        </div>
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <span className="font-medium text-sm">{typeConfig.label}</span>
                            <Badge 
                              variant="outline" 
                              className={`text-xs ${sevConfig.color}`}
                            >
                              {anomaly.severity}
                            </Badge>
                          </div>
                          <p className="text-sm text-muted-foreground">
                            {anomaly.description}
                          </p>
                          {anomaly.user_email && (
                            <p className="text-xs text-muted-foreground">
                              User: <span className="font-mono bg-muted px-1 rounded">{anomaly.user_email}</span>
                            </p>
                          )}
                          <p className="text-xs text-muted-foreground">
                            {formatDistanceToNow(new Date(anomaly.detected_at), { addSuffix: true })}
                          </p>
                        </div>
                      </div>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleResolve(anomaly.id)}
                        disabled={resolving === anomaly.id}
                        className="text-emerald-600 hover:text-emerald-700 hover:bg-emerald-100"
                      >
                        {resolving === anomaly.id ? (
                          <RefreshCw className="h-4 w-4 animate-spin" />
                        ) : (
                          <Check className="h-4 w-4" />
                        )}
                      </Button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Type Distribution */}
      {hasAnomalies && data?.by_type && Object.keys(data.by_type).length > 0 && (
        <Card className="border shadow-sm">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-muted-foreground" />
              Anomaly Types
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
              {Object.entries(data.by_type).map(([type, count]) => {
                const config = anomalyTypeConfig[type as AnomalyType] || anomalyTypeConfig.activity_spike;
                return (
                  <div
                    key={type}
                    className="flex items-center gap-2 p-3 rounded-xl bg-gradient-to-r from-muted/50 to-transparent hover:from-muted transition-all"
                  >
                    <div className={`p-1.5 rounded-lg bg-background ${config.color}`}>
                      {config.icon}
                    </div>
                    <span className="text-sm flex-1">{config.label}</span>
                    <Badge variant="secondary" className="font-bold">
                      {count}
                    </Badge>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
