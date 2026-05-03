"use client";

import { useMemo } from "react";
import { useWsUsers, useWsStats } from "@/contexts/websocket-context";
import { UsersTable } from "@/components/users/users-table";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { StatCard, StatCardGrid } from "@/components/threatintel/stat-card";
import { Wifi, WifiOff, Users, Activity, ShieldAlert, AlertTriangle, ShieldX } from "lucide-react";
import { useTranslations } from "next-intl";

// Calculate risk score (same logic as in users-table)
function calculateRiskScore(user: { total_requests: number; blacklist_hits: number; last_blacklist_hit?: string }) {
  if (user.total_requests === 0) return 0;
  const hitRatio = user.blacklist_hits / user.total_requests;
  let score = Math.min(hitRatio * 500, 50);
  if (user.blacklist_hits > 100) score += 30;
  else if (user.blacklist_hits > 50) score += 20;
  else if (user.blacklist_hits > 10) score += 10;
  else if (user.blacklist_hits > 0) score += 5;
  if (user.blacklist_hits > 0 && user.total_requests > 1000) score += 10;
  if (user.last_blacklist_hit) {
    const hoursSinceHit = (Date.now() - new Date(user.last_blacklist_hit).getTime()) / (1000 * 60 * 60);
    if (hoursSinceHit < 1) score += 10;
    else if (hoursSinceHit < 24) score += 5;
  }
  return Math.min(Math.round(score), 100);
}

export default function UsersPage() {
  const t = useTranslations("users");
  const tCommon = useTranslations("common");
  const { users, loading, connected } = useWsUsers();
  const { stats } = useWsStats();

  // Calculate risk groups
  const { highRisk, mediumRisk, blacklistUsers, totalRequests, totalBlacklistHits } = useMemo(() => {
    let high = 0, medium = 0;
    let requests = 0, hits = 0;
    const blacklist: typeof users = [];
    
    for (const u of users) {
      requests += u.total_requests;
      hits += u.blacklist_hits;
      if (u.blacklist_hits > 0) blacklist.push(u);
      
      const risk = calculateRiskScore(u);
      if (risk >= 70) high++;
      else if (risk >= 40) medium++;
    }
    
    return {
      highRisk: high,
      mediumRisk: medium,
      blacklistUsers: blacklist,
      totalRequests: requests,
      totalBlacklistHits: hits,
    };
  }, [users]);

  if (loading) {
    return (
      <div className="p-4 md:p-8 space-y-6">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-[600px]" />
      </div>
    );
  }

  return (
    <div className="p-4 md:p-8 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div>
          <h2 className="text-xl sm:text-2xl font-bold tracking-tight">{t("title")}</h2>
          <p className="text-sm text-muted-foreground">
            {t("description")}
          </p>
        </div>
        <Badge 
          variant={connected ? "default" : "destructive"} 
          className="flex items-center gap-1.5 self-start sm:self-auto"
        >
          {connected ? (
            <>
              <Wifi className="h-3 w-3" />
              {tCommon("live")}
            </>
          ) : (
            <>
              <WifiOff className="h-3 w-3" />
              {tCommon("disconnected")}
            </>
          )}
        </Badge>
      </div>

      <StatCardGrid columns={5}>
        <StatCard
          label={t("totalUsers")}
          value={(stats.total_unique_users || users.length).toLocaleString()}
          icon={<Users className="h-4 w-4" />}
        />
        <StatCard
          label={t("totalRequests")}
          value={totalRequests.toLocaleString()}
          icon={<Activity className="h-4 w-4" />}
        />
        <StatCard
          label={t("highRisk")}
          value={highRisk}
          subValue={t("highRiskSub")}
          icon={<ShieldAlert className="h-4 w-4" />}
          variant="danger"
        />
        <StatCard
          label={t("mediumRisk")}
          value={mediumRisk}
          subValue={t("mediumRiskSub")}
          icon={<AlertTriangle className="h-4 w-4" />}
          variant="warning"
        />
        <StatCard
          label={t("blacklistHits")}
          value={totalBlacklistHits.toLocaleString()}
          subValue={t("usersAffected", { count: blacklistUsers.length })}
          icon={<ShieldX className="h-4 w-4" />}
          variant="danger"
        />
      </StatCardGrid>

      <Card>
        <CardHeader>
          <CardTitle>{t("userActivity")}</CardTitle>
          <CardDescription>
            {t("filterDesc")}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="all">
            <TabsList>
              <TabsTrigger value="all">
                {t("allUsers")}
                <Badge variant="secondary" className="ml-2">{users.length}</Badge>
              </TabsTrigger>
              <TabsTrigger value="blacklist">
                {t("flagged")}
                <Badge variant="destructive" className="ml-2">{blacklistUsers.length}</Badge>
              </TabsTrigger>
            </TabsList>
            <TabsContent value="all" className="mt-4">
              <UsersTable users={users} showSearch pageSize={25} />
            </TabsContent>
            <TabsContent value="blacklist" className="mt-4">
              <UsersTable users={users} showBlacklistOnly showSearch pageSize={25} />
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
}
