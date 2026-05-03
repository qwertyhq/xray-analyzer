"use client";

import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { 
  Activity, 
  Server, 
  Shield, 
  Database,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Loader2
} from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { useTranslations } from "next-intl";

interface ServiceStatus {
  name: string;
  status: "online" | "offline" | "warning" | "loading";
  lastUpdate?: string;
  details?: string;
}

interface SystemHealthProps {
  remnawaveStatus?: "online" | "offline" | "unknown";
  remnawaveEnabled?: boolean;
  remnawaveLastSync?: string;
  threatIntelLastUpdate?: string;
  // null/undefined = still loading (no data yet). 0 = service reports 0 indicators
  // (real warning). >0 = healthy.
  threatIntelIndicators?: number | null;
  databaseStatus?: "online" | "offline";
  websocketConnected?: boolean;
}

export function SystemHealth({
  remnawaveStatus = "unknown",
  remnawaveEnabled = true,
  remnawaveLastSync,
  threatIntelLastUpdate,
  threatIntelIndicators,
  databaseStatus = "online",
  websocketConnected = true,
}: SystemHealthProps) {
  const t = useTranslations("systemHealth");

  // Remnawave not configured is not a system problem
  const remnawaveEffectiveStatus = !remnawaveEnabled ? "warning" : remnawaveStatus === "unknown" ? "loading" : remnawaveStatus;
  const remnawaveDetails = !remnawaveEnabled
    ? t("remnaNotConfigured")
    : remnawaveStatus === "online"
      ? t("remnaConnected")
      : remnawaveStatus === "offline"
        ? t("remnaNotAvailable")
        : t("remnaChecking");

  const services: ServiceStatus[] = [
    {
      name: t("websocket"),
      status: websocketConnected ? "online" : "offline",
      details: websocketConnected ? t("wsOnline") : t("wsOffline"),
    },
    {
      name: t("remnawave"),
      status: remnawaveEffectiveStatus,
      lastUpdate: remnawaveLastSync,
      details: remnawaveDetails,
    },
    {
      name: t("threatIntel"),
      // null/undefined = haven't received any stats yet — show "loading" not "warning".
      // Only flag warning when we KNOW indicator count is zero.
      status:
        threatIntelIndicators == null
          ? "loading"
          : threatIntelIndicators > 0
            ? "online"
            : "warning",
      lastUpdate: threatIntelLastUpdate,
      details:
        threatIntelIndicators == null
          ? t("threatLoading")
          : threatIntelIndicators > 0
            ? t("threatIndicators", { count: threatIntelIndicators.toLocaleString() })
            : t("threatNoIndicators"),
    },
    {
      name: t("database"),
      status: databaseStatus,
      details: databaseStatus === "online" ? t("dbOnline") : t("dbOffline"),
    },
  ];

  const statusIcon = (status: ServiceStatus["status"]) => {
    switch (status) {
      case "online":
        return <CheckCircle className="h-3.5 w-3.5 text-green-500" />;
      case "offline":
        return <XCircle className="h-3.5 w-3.5 text-red-500" />;
      case "warning":
        return <AlertTriangle className="h-3.5 w-3.5 text-yellow-500" />;
      case "loading":
        return <Loader2 className="h-3.5 w-3.5 text-muted-foreground animate-spin" />;
    }
  };

  const statusBadge = (status: ServiceStatus["status"]) => {
    switch (status) {
      case "online":
        return <Badge variant="outline" className="bg-green-500/10 text-green-600 border-green-500/30 text-xs">{t("statusOnline")}</Badge>;
      case "offline":
        return <Badge variant="outline" className="bg-red-500/10 text-red-600 border-red-500/30 text-xs">{t("statusOffline")}</Badge>;
      case "warning":
        return <Badge variant="outline" className="bg-yellow-500/10 text-yellow-600 border-yellow-500/30 text-xs">{t("statusWarning")}</Badge>;
      case "loading":
        return <Badge variant="outline" className="text-xs">{t("statusLoading")}</Badge>;
    }
  };

  const overallStatus = services.every(s => s.status === "online") 
    ? "healthy" 
    : services.some(s => s.status === "offline") 
      ? "degraded" 
      : "warning";

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Activity className="h-4 w-4 text-blue-500" />
            {t("title")}
          </CardTitle>
          <Badge
            variant="outline"
            className={
              overallStatus === "healthy"
                ? "bg-green-500/10 text-green-600 border-green-500/30"
                : overallStatus === "degraded"
                  ? "bg-red-500/10 text-red-600 border-red-500/30"
                  : "bg-yellow-500/10 text-yellow-600 border-yellow-500/30"
            }
          >
            {overallStatus === "healthy" ? t("allOperational") : overallStatus === "degraded" ? t("degraded") : t("warning")}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {services.map((service) => (
          <div 
            key={service.name} 
            className="flex items-center justify-between py-1.5 border-b border-border/50 last:border-0"
          >
            <div className="flex items-center gap-2">
              {statusIcon(service.status)}
              <div>
                <span className="text-sm font-medium">{service.name}</span>
                <p className="text-xs text-muted-foreground">{service.details}</p>
              </div>
            </div>
            <div className="text-right">
              {statusBadge(service.status)}
              {service.lastUpdate && (
                <p className="text-[10px] text-muted-foreground mt-0.5">
                  {formatDistanceToNow(new Date(service.lastUpdate), { addSuffix: true })}
                </p>
              )}
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
