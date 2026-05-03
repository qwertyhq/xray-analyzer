"use client";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Bell, AlertTriangle, ShieldAlert, Info, X, CheckCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useState } from "react";
import { useTranslations } from "next-intl";
import Link from "next/link";

export type AlertSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface Alert {
  id: string;
  title: string;
  description?: string;
  severity: AlertSeverity;
  timestamp: string;
  read: boolean;
  link?: string;
}

interface AlertsSummaryProps {
  alerts: Alert[];
  onMarkRead?: (id: string) => void;
  onMarkAllRead?: () => void;
}

const severityConfig: Record<AlertSeverity, { 
  icon: React.ReactNode; 
  color: string;
  label: string;
}> = {
  critical: {
    icon: <ShieldAlert className="h-4 w-4" />,
    color: "text-red-600 bg-red-500/10 border-red-500/30",
    label: "Critical",
  },
  high: {
    icon: <AlertTriangle className="h-4 w-4" />,
    color: "text-orange-600 bg-orange-500/10 border-orange-500/30",
    label: "High",
  },
  medium: {
    icon: <AlertTriangle className="h-4 w-4" />,
    color: "text-yellow-600 bg-yellow-500/10 border-yellow-500/30",
    label: "Medium",
  },
  low: {
    icon: <Info className="h-4 w-4" />,
    color: "text-blue-600 bg-blue-500/10 border-blue-500/30",
    label: "Low",
  },
  info: {
    icon: <Info className="h-4 w-4" />,
    color: "text-muted-foreground bg-muted border-border",
    label: "Info",
  },
};

export function AlertsSummary({ alerts, onMarkRead, onMarkAllRead }: AlertsSummaryProps) {
  const t = useTranslations("alerts");
  const unreadCount = alerts.filter(a => !a.read).length;
  const criticalCount = alerts.filter(a => a.severity === "critical" && !a.read).length;
  const highCount = alerts.filter(a => a.severity === "high" && !a.read).length;
  
  const displayAlerts = alerts.slice(0, 5);

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Bell className="h-4 w-4 text-yellow-500" />
            {t("title")}
            {unreadCount > 0 && (
              <Badge variant="destructive" className="h-5 px-1.5 text-xs">
                {unreadCount}
              </Badge>
            )}
          </CardTitle>
          {unreadCount > 0 && onMarkAllRead && (
            <Button 
              variant="ghost" 
              size="sm" 
              className="h-7 text-xs"
              onClick={onMarkAllRead}
            >
              <CheckCircle className="h-3 w-3 mr-1" />
              {t("markAllRead")}
            </Button>
          )}
        </div>
        
        {/* Severity summary badges */}
        {(criticalCount > 0 || highCount > 0) && (
          <div className="flex gap-2 mt-2">
            {criticalCount > 0 && (
              <Badge variant="outline" className={severityConfig.critical.color}>
                {criticalCount} Critical
              </Badge>
            )}
            {highCount > 0 && (
              <Badge variant="outline" className={severityConfig.high.color}>
                {highCount} High
              </Badge>
            )}
          </div>
        )}
      </CardHeader>
      <CardContent>
        {alerts.length === 0 ? (
          <div className="text-center py-6 text-muted-foreground">
            <CheckCircle className="h-8 w-8 mx-auto mb-2 opacity-30 text-green-500" />
            <p className="text-sm">{t("noAlerts")}</p>
            <p className="text-xs mt-1">{t("allRunning")}</p>
          </div>
        ) : (
          <div className="space-y-2 max-h-[280px] overflow-y-auto scrollbar-thin pr-1">
            {displayAlerts.map((alert) => {
              const config = severityConfig[alert.severity];
              const baseClassName = `flex items-start gap-2 p-2 rounded-lg border transition-all ${
                config.color
              } ${!alert.read ? "ring-1 ring-primary/20" : "opacity-70"}`;
              
              const content = (
                <>
                  <div className="mt-0.5">{config.icon}</div>
                  <div className="flex-1 min-w-0">
                    <p className={`text-xs font-medium ${!alert.read ? "" : "text-muted-foreground"}`}>
                      {alert.title}
                    </p>
                    {alert.description && (
                      <p className="text-[10px] text-muted-foreground truncate mt-0.5">
                        {alert.description}
                      </p>
                    )}
                  </div>
                  {onMarkRead && !alert.read && (
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-5 w-5 shrink-0"
                      onClick={(e) => {
                        e.preventDefault();
                        e.stopPropagation();
                        onMarkRead(alert.id);
                      }}
                    >
                      <X className="h-3 w-3" />
                    </Button>
                  )}
                </>
              );
              
              if (alert.link) {
                return (
                  <Link
                    key={alert.id}
                    href={alert.link}
                    className={`${baseClassName} hover:opacity-80 cursor-pointer block`}
                  >
                    {content}
                  </Link>
                );
              }
              
              return (
                <div key={alert.id} className={baseClassName}>
                  {content}
                </div>
              );
            })}
          </div>
        )}
        
        {alerts.length > 5 && (
          <p className="text-xs text-muted-foreground text-center mt-2">
            +{alerts.length - 5} {t("title").toLowerCase()}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
