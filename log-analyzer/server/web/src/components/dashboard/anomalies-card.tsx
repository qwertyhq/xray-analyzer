"use client";

import { Anomaly } from "@/lib/types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, TrendingUp, User } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import Link from "next/link";

// Check if date is valid (not zero time or year 1)
function isValidDate(dateStr: string): boolean {
  if (!dateStr) return false;
  const date = new Date(dateStr);
  return !isNaN(date.getTime()) && date.getFullYear() > 2000;
}

interface AnomaliesCardProps {
  anomalies: Anomaly[];
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

export function AnomaliesCard({ anomalies, loading }: AnomaliesCardProps) {
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
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base flex items-center gap-2">
          <AlertTriangle className="h-4 w-4" />
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
          <div className="space-y-3">
            {anomalies.map((anomaly, i) => {
              const Icon = anomalyIcons[anomaly.type] || AlertTriangle;
              const color = anomalyColors[anomaly.type] || "default";
              
              return (
                <div
                  key={i}
                  className="flex items-start gap-3 p-3 rounded-lg border bg-card"
                >
                  <div className="flex-shrink-0 mt-0.5">
                    <Badge variant={color} className="h-6 w-6 p-0 flex items-center justify-center">
                      <Icon className="h-3 w-3" />
                    </Badge>
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate">
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
                    <p className="text-sm font-bold text-destructive">
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
