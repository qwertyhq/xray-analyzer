"use client";

import { useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { TrendingUp, TrendingDown, Minus, Activity, ShieldAlert, Users, Server } from "lucide-react";
import { useTranslations } from "next-intl";

interface PeriodStat {
  label: string;
  current: number;
  previous: number;
  icon: React.ReactNode;
  format?: "number" | "percentage";
}

interface PeriodComparisonProps {
  stats: {
    requests: { current: number; previous: number };
    blacklistHits: { current: number; previous: number };
    uniqueUsers: { current: number; previous: number };
    onlineUsers: { current: number; previous: number };
  };
  periodLabel?: string;
}

function formatChange(current: number, previous: number): { value: string; trend: "up" | "down" | "same" } {
  if (previous === 0) {
    if (current > 0) return { value: "+100%", trend: "up" };
    return { value: "0%", trend: "same" };
  }
  
  const change = ((current - previous) / previous) * 100;
  const trend = change > 0 ? "up" : change < 0 ? "down" : "same";
  const absChange = Math.abs(change);
  
  if (absChange >= 1000) {
    return { value: `${change > 0 ? "+" : ""}${(change / 100).toFixed(0)}x`, trend };
  }
  
  return { value: `${change > 0 ? "+" : ""}${change.toFixed(1)}%`, trend };
}

function TrendIcon({ trend }: { trend: "up" | "down" | "same" }) {
  if (trend === "up") return <TrendingUp className="h-3.5 w-3.5" />;
  if (trend === "down") return <TrendingDown className="h-3.5 w-3.5" />;
  return <Minus className="h-3.5 w-3.5" />;
}

function TrendBadge({ trend, value, inverted = false }: { trend: "up" | "down" | "same"; value: string; inverted?: boolean }) {
  // For metrics like blacklist hits, "up" is bad (red), "down" is good (green)
  // For metrics like users/requests, "up" is good (green), "down" is bad (red)
  const isPositive = inverted ? trend === "down" : trend === "up";
  const isNegative = inverted ? trend === "up" : trend === "down";
  
  return (
    <Badge 
      variant="outline" 
      className={`flex items-center gap-1 text-xs ${
        isPositive ? "text-green-600 border-green-500/30 bg-green-500/10" :
        isNegative ? "text-red-600 border-red-500/30 bg-red-500/10" :
        "text-muted-foreground"
      }`}
    >
      <TrendIcon trend={trend} />
      {value}
    </Badge>
  );
}

export function PeriodComparison({ stats, periodLabel }: PeriodComparisonProps) {
  const t = useTranslations("periodComparison");

  const comparisons = useMemo(() => [
    {
      label: t("requests"),
      shortLabel: "Req",
      iconType: "activity" as const,
      current: stats.requests.current,
      previous: stats.requests.previous,
    },
    {
      label: t("blacklistHits"),
      shortLabel: "Blackli...",
      iconType: "shield" as const,
      current: stats.blacklistHits.current,
      previous: stats.blacklistHits.previous,
      inverted: true, // Lower is better
    },
    {
      label: t("uniqueUsers"),
      shortLabel: "Uniq...",
      iconType: "users" as const,
      current: stats.uniqueUsers.current,
      previous: stats.uniqueUsers.previous,
    },
    {
      label: t("onlineNow"),
      shortLabel: "Onli...",
      iconType: "server" as const,
      current: stats.onlineUsers.current,
      previous: stats.onlineUsers.previous,
    },
  // eslint-disable-next-line react-hooks/exhaustive-deps
  ], [stats]);

  const getIcon = (type: string) => {
    switch (type) {
      case "activity": return <Activity className="h-4 w-4 text-blue-500" />;
      case "shield": return <ShieldAlert className="h-4 w-4 text-red-500" />;
      case "users": return <Users className="h-4 w-4 text-green-500" />;
      case "server": return <Server className="h-4 w-4 text-purple-500" />;
      default: return null;
    }
  };

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-medium flex items-center justify-between">
          <span>{t("title")}</span>
          <Badge variant="secondary" className="text-xs font-normal">
            {periodLabel}
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="pb-4">
        <div className="grid grid-cols-1 gap-2">
          {comparisons.map((item) => {
            const { value, trend } = formatChange(item.current, item.previous);
            return (
              <div 
                key={item.label}
                className="flex items-center gap-2 p-2 rounded-lg bg-muted/50"
              >
                {getIcon(item.iconType)}
                <div className="flex-1 min-w-0">
                  <p className="text-xs text-muted-foreground">{item.label}</p>
                  <p className="text-sm font-semibold">{item.current.toLocaleString()}</p>
                </div>
                <TrendBadge trend={trend} value={value} inverted={item.inverted} />
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}
