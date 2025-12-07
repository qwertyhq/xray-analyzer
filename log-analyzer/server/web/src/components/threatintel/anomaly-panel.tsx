"use client";

import { useState } from "react";
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
    color: "text-orange-500" 
  },
  night_activity: { 
    icon: <Moon className="h-4 w-4" />, 
    label: "Night Activity", 
    color: "text-purple-500" 
  },
  new_user_high_vol: { 
    icon: <UserPlus className="h-4 w-4" />, 
    label: "New User High Volume", 
    color: "text-blue-500" 
  },
  geo_anomaly: { 
    icon: <Globe className="h-4 w-4" />, 
    label: "Geo Anomaly", 
    color: "text-green-500" 
  },
  threat_burst: { 
    icon: <Zap className="h-4 w-4" />, 
    label: "Threat Burst", 
    color: "text-red-500" 
  },
  multiple_countries: { 
    icon: <MapPin className="h-4 w-4" />, 
    label: "Multiple Countries", 
    color: "text-pink-500" 
  },
  blacklist_spike: { 
    icon: <AlertTriangle className="h-4 w-4" />, 
    label: "Blacklist Spike", 
    color: "text-red-500" 
  },
  traffic_spike: { 
    icon: <TrendingUp className="h-4 w-4" />, 
    label: "Traffic Spike", 
    color: "text-orange-500" 
  },
  user_spike: { 
    icon: <UserPlus className="h-4 w-4" />, 
    label: "User Spike", 
    color: "text-blue-500" 
  },
  user_blacklist_spike: { 
    icon: <AlertTriangle className="h-4 w-4" />, 
    label: "User Blacklist Spike", 
    color: "text-red-500" 
  },
};

// Config for severity
const severityConfig: Record<AnomalySeverity, { color: string; bgColor: string }> = {
  low: { color: "text-blue-600", bgColor: "bg-blue-100 dark:bg-blue-900/30" },
  medium: { color: "text-yellow-600", bgColor: "bg-yellow-100 dark:bg-yellow-900/30" },
  high: { color: "text-orange-600", bgColor: "bg-orange-100 dark:bg-orange-900/30" },
  critical: { color: "text-red-600", bgColor: "bg-red-100 dark:bg-red-900/30" },
};

export function AnomalyPanel({ data, loading = false, onResolve, onRefresh }: AnomalyPanelProps) {
  const [resolving, setResolving] = useState<string | null>(null);

  const handleResolve = async (id: string) => {
    setResolving(id);
    try {
      await fetch(`/api/threatintel/anomalies?id=${id}`, { method: "DELETE" });
      onResolve?.(id);
    } finally {
      setResolving(null);
    }
  };

  if (loading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Anomaly Detection</CardTitle>
        </CardHeader>
        <CardContent>
          <Skeleton className="h-[300px] w-full" />
        </CardContent>
      </Card>
    );
  }

  const hasAnomalies = data && data.total_anomalies > 0;

  return (
    <div className="space-y-4">
      {/* Summary Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card className={hasAnomalies ? "border-orange-500/50" : ""}>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <AlertTriangle className={`h-4 w-4 ${hasAnomalies ? "text-orange-500" : "text-muted-foreground"}`} />
              Active Anomalies
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className={`text-2xl font-bold ${hasAnomalies ? "text-orange-500" : ""}`}>
              {data?.total_anomalies || 0}
            </div>
            <p className="text-xs text-muted-foreground">Requiring attention</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Zap className="h-4 w-4 text-red-500" />
              Critical
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-500">
              {data?.by_severity?.critical || 0}
            </div>
            <p className="text-xs text-muted-foreground">High priority</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-orange-500" />
              High
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-orange-500">
              {data?.by_severity?.high || 0}
            </div>
            <p className="text-xs text-muted-foreground">Needs review</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Shield className="h-4 w-4 text-blue-500" />
              Affected Users
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {data?.affected_users || 0}
            </div>
            <p className="text-xs text-muted-foreground">Unique users</p>
          </CardContent>
        </Card>
      </div>

      {/* Anomaly List */}
      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-sm font-medium">Recent Anomalies</CardTitle>
              <CardDescription className="text-xs">
                Detected behavioral anomalies
              </CardDescription>
            </div>
            {onRefresh && (
              <Button variant="outline" size="sm" onClick={onRefresh}>
                <RefreshCw className="h-4 w-4 mr-1" />
                Run Detection
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent>
          {!hasAnomalies ? (
            <div className="flex flex-col items-center justify-center h-[200px] text-muted-foreground">
              <Shield className="h-12 w-12 mb-2 text-green-500" />
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
                    className={`p-3 rounded-lg border ${sevConfig.bgColor}`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex items-start gap-3">
                        <div className={`mt-0.5 ${typeConfig.color}`}>
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
                              User: <span className="font-mono">{anomaly.user_email}</span>
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
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Anomaly Types</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
              {Object.entries(data.by_type).map(([type, count]) => {
                const config = anomalyTypeConfig[type as AnomalyType] || anomalyTypeConfig.activity_spike;
                return (
                  <div
                    key={type}
                    className="flex items-center gap-2 p-2 rounded-lg bg-muted/50"
                  >
                    <span className={config.color}>{config.icon}</span>
                    <span className="text-sm">{config.label}</span>
                    <Badge variant="secondary" className="ml-auto">
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
