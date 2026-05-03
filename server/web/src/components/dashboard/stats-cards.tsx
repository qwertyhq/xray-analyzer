"use client";

import { useEffect, useRef, useState } from "react";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Activity, Server, Users, ShieldAlert, UserCheck } from "lucide-react";
import { useTranslations } from "next-intl";
import { Stats } from "@/lib/types";
import { cn } from "@/lib/utils";

interface StatsCardsProps {
  stats: Stats;
}

// Animated counter component
function AnimatedNumber({ 
  value, 
  className,
  duration = 500 
}: { 
  value: number; 
  className?: string;
  duration?: number;
}) {
  const [displayValue, setDisplayValue] = useState(value);
  const [isAnimating, setIsAnimating] = useState(false);
  const prevValue = useRef(value);

  useEffect(() => {
    if (prevValue.current === value) return;
    
    const diff = value - prevValue.current;
    const startValue = prevValue.current;
    const startTime = Date.now();
    
    setIsAnimating(true);
    
    const animate = () => {
      const elapsed = Date.now() - startTime;
      const progress = Math.min(elapsed / duration, 1);
      
      // Easing function
      const eased = 1 - Math.pow(1 - progress, 3);
      
      const current = Math.round(startValue + diff * eased);
      setDisplayValue(current);
      
      if (progress < 1) {
        requestAnimationFrame(animate);
      } else {
        setIsAnimating(false);
        prevValue.current = value;
      }
    };
    
    requestAnimationFrame(animate);
    prevValue.current = value;
  }, [value, duration]);

  return (
    <span className={cn(
      "transition-colors duration-300",
      isAnimating && "text-primary",
      className
    )}>
      {displayValue.toLocaleString()}
    </span>
  );
}

// Stat card with change indicator
function StatCard({
  title,
  value,
  icon: Icon,
  description,
  valueClassName,
  suffix,
}: {
  title: string;
  value: number;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
  valueClassName?: string;
  suffix?: React.ReactNode;
}) {
  const [prevValue, setPrevValue] = useState(value);
  const [trend, setTrend] = useState<"up" | "down" | null>(null);

  useEffect(() => {
    if (value !== prevValue) {
      setTrend(value > prevValue ? "up" : "down");
      setPrevValue(value);
      
      const timer = setTimeout(() => setTrend(null), 2000);
      return () => clearTimeout(timer);
    }
  }, [value, prevValue]);

  return (
    <Card className={cn(
      "transition-all duration-300",
      trend === "up" && "ring-2 ring-green-500/50",
      trend === "down" && "ring-2 ring-destructive/50"
    )}>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        <Icon className={cn(
          "h-4 w-4 transition-colors duration-300",
          trend ? "text-primary" : "text-muted-foreground"
        )} />
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold flex items-baseline gap-1">
          <AnimatedNumber value={value} className={valueClassName} />
          {suffix}
          {trend && (
            <span className={cn(
              "text-xs ml-1 animate-in fade-in",
              trend === "up" ? "text-green-500" : "text-destructive"
            )}>
              {trend === "up" ? "↑" : "↓"}
            </span>
          )}
        </div>
        <p className="text-xs text-muted-foreground">
          {description}
        </p>
      </CardContent>
    </Card>
  );
}

export function StatsCards({ stats }: StatsCardsProps) {
  const t = useTranslations("stats");

  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
      <StatCard
        title={t("totalRequests")}
        value={stats.total_requests}
        icon={Activity}
        description={t("processedLogs")}
      />

      <StatCard
        title={t("blacklistHits")}
        value={stats.total_blacklist}
        icon={ShieldAlert}
        description={t("suspiciousDestinations")}
        valueClassName="text-destructive"
      />

      <Card className="transition-all duration-300">
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">{t("nodes")}</CardTitle>
          <Server className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">
            <AnimatedNumber value={stats.nodes_connected} className="text-green-500" />
            <span className="text-sm font-normal text-muted-foreground">
              {" "}/ {stats.nodes_total}
            </span>
          </div>
          <p className="text-xs text-muted-foreground">
            {t("nodesOnlineTotal")}
          </p>
        </CardContent>
      </Card>

      <StatCard
        title={t("onlineUsers")}
        value={stats.online_users || 0}
        icon={UserCheck}
        description={t("activeLastMinute")}
        valueClassName="text-green-500"
      />

      <StatCard
        title={t("totalUsers")}
        value={stats.total_unique_users || 0}
        icon={Users}
        description={t("acrossAllNodes")}
      />
    </div>
  );
}
