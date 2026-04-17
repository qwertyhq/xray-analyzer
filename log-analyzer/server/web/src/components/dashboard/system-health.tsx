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
  // Remnawave not configured is not a system problem
  const remnawaveEffectiveStatus = !remnawaveEnabled ? "warning" : remnawaveStatus === "unknown" ? "loading" : remnawaveStatus;
  const remnawaveDetails = !remnawaveEnabled 
    ? "Not configured" 
    : remnawaveStatus === "online" 
      ? "Connected" 
      : remnawaveStatus === "offline" 
        ? "Not available" 
        : "Checking...";

  const services: ServiceStatus[] = [
    {
      name: "WebSocket",
      status: websocketConnected ? "online" : "offline",
      details: websocketConnected ? "Real-time updates active" : "Reconnecting...",
    },
    {
      name: "Remnawave API",
      status: remnawaveEffectiveStatus,
      lastUpdate: remnawaveLastSync,
      details: remnawaveDetails,
    },
    {
      name: "Threat Intel",
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
          ? "Loading feeds..."
          : threatIntelIndicators > 0
            ? `${threatIntelIndicators.toLocaleString()} indicators`
            : "No indicators loaded",
    },
    {
      name: "Database",
      status: databaseStatus,
      details: databaseStatus === "online" ? "SQLite operational" : "Connection error",
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
        return <Badge variant="outline" className="bg-green-500/10 text-green-600 border-green-500/30 text-xs">Online</Badge>;
      case "offline":
        return <Badge variant="outline" className="bg-red-500/10 text-red-600 border-red-500/30 text-xs">Offline</Badge>;
      case "warning":
        return <Badge variant="outline" className="bg-yellow-500/10 text-yellow-600 border-yellow-500/30 text-xs">Warning</Badge>;
      case "loading":
        return <Badge variant="outline" className="text-xs">Loading</Badge>;
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
            System Health
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
            {overallStatus === "healthy" ? "All Systems Operational" : overallStatus === "degraded" ? "Degraded" : "Warning"}
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
