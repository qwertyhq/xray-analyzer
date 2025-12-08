"use client";

import { useRef, useEffect, useState } from "react";
import { StatsAnomaly } from "@/lib/types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, TrendingUp, User } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import Link from "next/link";
import { isValidDate } from "@/lib/utils/date";

interface AnomaliesCardProps {
  anomalies: StatsAnomaly[];
  loading?: boolean;
}

const anomalyIcons = {
  blacklist_spike: AlertTriangle,
  traffic_spike: TrendingUp,
  user_spike: User,
};

const anomalyColors = {
  blacklist_spike: "destructive",
  traffic_spike: "secondary",
  user_spike: "default",
} as const;

// Генерируем уникальный ключ для аномалии
function getAnomalyKey(anomaly: StatsAnomaly): string {
  return `${anomaly.type}-${anomaly.hour}-${anomaly.user_email || "global"}-${anomaly.deviation}`;
}

export function AnomaliesCard({ anomalies, loading }: AnomaliesCardProps) {
  const prevAnomaliesRef = useRef<Set<string>>(new Set());
  const [newAnomalyKeys, setNewAnomalyKeys] = useState<Set<string>>(new Set());

  useEffect(() => {
    const currentKeys = new Set(anomalies.map(getAnomalyKey));
    const newKeys = new Set<string>();

    // Находим новые аномалии
    currentKeys.forEach((key) => {
      if (!prevAnomaliesRef.current.has(key)) {
        newKeys.add(key);
      }
    });

    if (newKeys.size > 0) {
      setNewAnomalyKeys(newKeys);

      // Убираем подсветку через 2 секунды
      const timer = setTimeout(() => {
        setNewAnomalyKeys(new Set());
      }, 2000);

      return () => clearTimeout(timer);
    }

    // Обновляем предыдущее состояние
    prevAnomaliesRef.current = currentKeys;
  }, [anomalies]);

  // Обновляем ref после каждого рендера
  useEffect(() => {
    prevAnomaliesRef.current = new Set(anomalies.map(getAnomalyKey));
  }, [anomalies]);

  if (loading) {
    return (
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <AlertTriangle className="h-4 w-4" />
            Anomalies
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="animate-pulse space-y-3">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-12 bg-muted rounded" />
            ))}
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="overflow-hidden">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm sm:text-base flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 flex-shrink-0" />
          Anomalies
          {anomalies.length > 0 && (
            <Badge variant="destructive" className="ml-auto">
              {anomalies.length}
            </Badge>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {anomalies.length === 0 ? (
          <p className="text-sm text-muted-foreground text-center py-4">
            No anomalies detected
          </p>
        ) : (
          <div className="space-y-3 max-h-[350px] overflow-y-auto scrollbar-thin pr-1">
            {anomalies.map((anomaly) => {
              const Icon = anomalyIcons[anomaly.type] || AlertTriangle;
              const color = anomalyColors[anomaly.type] || "default";
              const key = getAnomalyKey(anomaly);
              const isNew = newAnomalyKeys.has(key);
              
              return (
                <div
                  key={key}
                  className={`flex items-start gap-3 p-3 rounded-lg border bg-card transition-all duration-300 ${
                    isNew ? "animate-fade-in-row ring-2 ring-orange-500 ring-offset-1" : ""
                  }`}
                >
                  <div className="flex-shrink-0 mt-0.5">
                    <Badge variant={color} className={`h-6 w-6 p-0 flex items-center justify-center ${
                      isNew ? "animate-pulse" : ""
                    }`}>
                      <Icon className="h-3 w-3" />
                    </Badge>
                  </div>
                  <div className="flex-1 min-w-0 overflow-hidden">
                    <p className="text-xs sm:text-sm font-medium truncate max-w-full">
                      {anomaly.message}
                    </p>
                    <div className="flex items-center gap-2 mt-1">
                      {anomaly.user_email && (
                        <Link
                          href={`/users/${encodeURIComponent(anomaly.user_email)}`}
                          className="text-xs text-primary hover:underline"
                        >
                          {anomaly.user_email}
                        </Link>
                      )}
                      <span className="text-xs text-muted-foreground">
                        {isValidDate(anomaly.hour)
                          ? formatDistanceToNow(new Date(anomaly.hour), { addSuffix: true })
                          : "—"
                        }
                      </span>
                    </div>
                  </div>
                  <div className="text-right flex-shrink-0">
                    <p className={`text-sm font-bold transition-colors duration-300 ${
                      isNew ? "text-orange-500" : "text-destructive"
                    }`}>
                      {anomaly.deviation.toFixed(1)}x
                    </p>
                    <p className="text-xs text-muted-foreground">
                      vs baseline
                    </p>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
