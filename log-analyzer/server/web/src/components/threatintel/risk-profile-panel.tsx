"use client";

import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  TrendingUp, 
  TrendingDown, 
  Minus,
  Users,
  AlertTriangle,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  Globe,
  Activity
} from "lucide-react";
import { UserRiskSummary, UserRiskProfile, RiskLevel } from "@/lib/types";
import { formatDistanceToNow } from "date-fns";

interface RiskProfilePanelProps {
  data: UserRiskSummary | null;
  loading?: boolean;
  onRefresh?: () => void;
  onRecalculate?: () => void;
}

// Risk level configuration
const riskLevelConfig: Record<RiskLevel, { 
  color: string; 
  bgColor: string; 
  icon: React.ReactNode;
  label: string;
}> = {
  low: { 
    color: "text-green-600", 
    bgColor: "bg-green-100 dark:bg-green-900/30",
    icon: <ShieldCheck className="h-4 w-4" />,
    label: "Low Risk"
  },
  medium: { 
    color: "text-yellow-600", 
    bgColor: "bg-yellow-100 dark:bg-yellow-900/30",
    icon: <Shield className="h-4 w-4" />,
    label: "Medium Risk"
  },
  high: { 
    color: "text-orange-600", 
    bgColor: "bg-orange-100 dark:bg-orange-900/30",
    icon: <ShieldAlert className="h-4 w-4" />,
    label: "High Risk"
  },
  critical: { 
    color: "text-red-600", 
    bgColor: "bg-red-100 dark:bg-red-900/30",
    icon: <AlertTriangle className="h-4 w-4" />,
    label: "Critical Risk"
  },
};

// Trend icons
const trendIcons = {
  up: <TrendingUp className="h-4 w-4 text-red-500" />,
  down: <TrendingDown className="h-4 w-4 text-green-500" />,
  stable: <Minus className="h-4 w-4 text-gray-500" />,
};

function RiskScoreBar({ score }: { score: number }) {
  const getColor = () => {
    if (score >= 70) return "bg-red-500";
    if (score >= 50) return "bg-orange-500";
    if (score >= 25) return "bg-yellow-500";
    return "bg-green-500";
  };

  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
        <div 
          className={`h-full ${getColor()} transition-all`}
          style={{ width: `${score}%` }}
        />
      </div>
      <span className="text-sm font-medium w-8">{score}</span>
    </div>
  );
}

function UserRiskCard({ profile, expanded, onToggle }: { 
  profile: UserRiskProfile; 
  expanded: boolean;
  onToggle: () => void;
}) {
  const config = riskLevelConfig[profile.risk_level] || riskLevelConfig.low;
  const trend = trendIcons[profile.trend_direction] || trendIcons.stable;

  return (
    <Card className="mb-3">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg ${config.bgColor}`}>
              <span className={config.color}>{config.icon}</span>
            </div>
            <div>
              <CardTitle className="text-sm font-medium">{profile.user_email}</CardTitle>
              <div className="flex items-center gap-2 mt-1">
                <Badge variant="outline" className={config.color}>
                  {config.label}
                </Badge>
                <span className="flex items-center gap-1 text-xs text-muted-foreground">
                  {trend}
                  {profile.trend_direction === "up" ? "Increasing" : 
                   profile.trend_direction === "down" ? "Decreasing" : "Stable"}
                </span>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="text-right">
              <div className="text-2xl font-bold">{profile.risk_score}</div>
              <div className="text-xs text-muted-foreground">Risk Score</div>
            </div>
            <Button variant="ghost" size="sm" onClick={onToggle}>
              {expanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
            </Button>
          </div>
        </div>
      </CardHeader>
      
      {expanded && (
        <CardContent className="pt-2">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4 mb-4">
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-muted-foreground" />
              <div>
                <div className="text-sm font-medium">{profile.total_matches}</div>
                <div className="text-xs text-muted-foreground">Total Matches</div>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Globe className="h-4 w-4 text-muted-foreground" />
              <div>
                <div className="text-sm font-medium">{profile.unique_countries}</div>
                <div className="text-xs text-muted-foreground">Countries</div>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-muted-foreground" />
              <div>
                <div className="text-sm font-medium">{profile.anomaly_count}</div>
                <div className="text-xs text-muted-foreground">Anomalies</div>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Users className="h-4 w-4 text-muted-foreground" />
              <div>
                <div className="text-sm font-medium">{profile.days_active}</div>
                <div className="text-xs text-muted-foreground">Days Active</div>
              </div>
            </div>
          </div>

          {/* Threats by type */}
          {profile.threats_by_type && Object.keys(profile.threats_by_type).length > 0 && (
            <div className="mb-4">
              <div className="text-sm font-medium mb-2">Threats by Category</div>
              <div className="flex flex-wrap gap-2">
                {Object.entries(profile.threats_by_type).map(([type, count]) => (
                  <Badge key={type} variant="secondary">
                    {type}: {count}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {/* Risk factors */}
          {profile.risk_factors && profile.risk_factors.length > 0 && (
            <div>
              <div className="text-sm font-medium mb-2">Risk Factors</div>
              <div className="space-y-2">
                {profile.risk_factors.map((factor, idx) => (
                  <div key={idx} className="flex items-center justify-between text-sm p-2 bg-muted/50 rounded">
                    <span>{factor.description}</span>
                    <Badge variant="outline">+{factor.weight} pts</Badge>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Top domains */}
          {profile.top_domains && profile.top_domains.length > 0 && (
            <div className="mt-4">
              <div className="text-sm font-medium mb-2">Top Domains</div>
              <div className="flex flex-wrap gap-2">
                {profile.top_domains.map((domain, idx) => (
                  <Badge key={idx} variant="outline" className="font-mono text-xs">
                    {domain}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          <div className="mt-4 text-xs text-muted-foreground">
            Last activity: {profile.last_activity ? formatDistanceToNow(new Date(profile.last_activity), { addSuffix: true }) : "N/A"}
          </div>
        </CardContent>
      )}
    </Card>
  );
}

export function RiskProfilePanel({ data, loading = false, onRefresh, onRecalculate }: RiskProfilePanelProps) {
  const [expandedUser, setExpandedUser] = useState<string | null>(null);
  const [recalculating, setRecalculating] = useState(false);

  const handleRecalculate = async () => {
    setRecalculating(true);
    try {
      await fetch("/api/threatintel/risk-profiles", { method: "POST" });
      onRecalculate?.();
    } finally {
      setRecalculating(false);
    }
  };

  if (loading) {
    return (
      <Card>
        <CardHeader>
          <Skeleton className="h-6 w-48" />
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <Skeleton className="h-24 w-full" />
            <Skeleton className="h-24 w-full" />
          </div>
        </CardContent>
      </Card>
    );
  }

  if (!data) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldAlert className="h-5 w-5" />
            User Risk Profiles
          </CardTitle>
          <CardDescription>No risk profile data available</CardDescription>
        </CardHeader>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5" />
              User Risk Profiles
            </CardTitle>
            <CardDescription>
              {data.total_users} users analyzed • Average score: {data.average_risk_score?.toFixed(1) || 0}
            </CardDescription>
          </div>
          <div className="flex gap-2">
            {onRefresh && (
              <Button variant="outline" size="sm" onClick={onRefresh}>
                <RefreshCw className="h-4 w-4 mr-2" />
                Refresh
              </Button>
            )}
            <Button variant="default" size="sm" onClick={handleRecalculate} disabled={recalculating}>
              <RefreshCw className={`h-4 w-4 mr-2 ${recalculating ? "animate-spin" : ""}`} />
              Recalculate All
            </Button>
          </div>
        </div>
      </CardHeader>

      <CardContent>
        {/* Summary Stats */}
        <div className="grid gap-4 md:grid-cols-4 mb-6">
          <Card>
            <CardContent className="pt-4">
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-2xl font-bold text-red-600">
                    {(data.by_risk_level?.critical || 0) + (data.by_risk_level?.high || 0)}
                  </div>
                  <div className="text-xs text-muted-foreground">High Risk Users</div>
                </div>
                <ShieldAlert className="h-8 w-8 text-red-500 opacity-50" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-4">
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-2xl font-bold text-yellow-600">
                    {data.by_risk_level?.medium || 0}
                  </div>
                  <div className="text-xs text-muted-foreground">Medium Risk</div>
                </div>
                <Shield className="h-8 w-8 text-yellow-500 opacity-50" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-4">
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-2xl font-bold text-green-600">
                    {data.by_risk_level?.low || 0}
                  </div>
                  <div className="text-xs text-muted-foreground">Low Risk</div>
                </div>
                <ShieldCheck className="h-8 w-8 text-green-500 opacity-50" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-4">
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-2xl font-bold text-orange-600">
                    {data.recent_escalations || 0}
                  </div>
                  <div className="text-xs text-muted-foreground">Escalations (24h)</div>
                </div>
                <TrendingUp className="h-8 w-8 text-orange-500 opacity-50" />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* High Risk Users List */}
        {data.high_risk_users && data.high_risk_users.length > 0 ? (
          <div>
            <h3 className="text-lg font-semibold mb-4">High Risk Users</h3>
            {data.high_risk_users.map((profile) => (
              <UserRiskCard
                key={profile.user_email}
                profile={profile}
                expanded={expandedUser === profile.user_email}
                onToggle={() => setExpandedUser(
                  expandedUser === profile.user_email ? null : profile.user_email
                )}
              />
            ))}
          </div>
        ) : (
          <div className="text-center py-8 text-muted-foreground">
            <ShieldCheck className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>No high-risk users detected</p>
            <p className="text-sm">All users have risk scores below 50</p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
