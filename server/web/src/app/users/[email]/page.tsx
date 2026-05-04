"use client";

import { useParams } from "next/navigation";
import Link from "next/link";
import { useUserDetails } from "@/hooks/use-api";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ArrowLeft, User, Activity, ShieldAlert, Globe, Wifi, AlertTriangle, Gauge } from "lucide-react";
import { useTranslations } from "next-intl";
import { formatDistanceToNow } from "date-fns";
import { isValidDate } from "@/lib/utils/date";
import { UserDestinationsTable } from "@/components/users/user-destinations-table";
import { UserBlacklistMatches } from "@/components/users/user-blacklist-matches";
import { UserIPHistoryTable } from "@/components/users/user-ip-history";
import { UserThreatsTable } from "@/components/users/user-threats-table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

export default function UserDetailsPage() {
  const t = useTranslations("users");
  const params = useParams();
  const email = decodeURIComponent(params.email as string);
  const { details, loading, error } = useUserDetails(email);

  if (loading) {
    return (
      <div className="p-4 md:p-8 space-y-6">
        <Skeleton className="h-8 w-64" />
        <div className="grid gap-4 md:grid-cols-3">
          <Skeleton className="h-[100px]" />
          <Skeleton className="h-[100px]" />
          <Skeleton className="h-[100px]" />
        </div>
        <Skeleton className="h-[400px]" />
      </div>
    );
  }

  if (error || !details) {
    return (
      <div className="p-4 md:p-8">
        <Link href="/users">
          <Button variant="ghost" className="mb-4">
            <ArrowLeft className="h-4 w-4 mr-2" />
            {t("backToUsers")}
          </Button>
        </Link>
        <Card>
          <CardContent className="pt-6">
            <p className="text-center text-muted-foreground">
              {error || t("userNotFound")}
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="p-4 md:p-8 space-y-6">
      <div className="flex items-center gap-2 sm:gap-4">
        <Link href="/users">
          <Button variant="ghost" size="icon" className="shrink-0">
            <ArrowLeft className="h-4 w-4" />
          </Button>
        </Link>
        <div className="min-w-0">
          <h2 className="text-lg sm:text-2xl font-bold tracking-tight flex items-center gap-2 truncate">
            <User className="h-5 w-5 sm:h-6 sm:w-6 shrink-0" />
            <span className="truncate">{details.display_name || details.user_email}</span>
          </h2>
          <p className="text-sm text-muted-foreground">
            {details.display_name && details.display_name !== details.user_email && (
              <span className="mr-2 font-mono text-xs">{details.user_email}</span>
            )}
            {t("userActivity2", { count: details.nodes.length })}
          </p>
        </div>
      </div>

      <div className="grid gap-4 grid-cols-2 md:grid-cols-5">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-xs sm:text-sm font-medium">{t("requests")}</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground hidden sm:block" />
          </CardHeader>
          <CardContent>
            <div className="text-lg sm:text-2xl font-bold">
              {details.total_requests.toLocaleString()}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-xs sm:text-sm font-medium">{t("blacklist")}</CardTitle>
            <ShieldAlert className="h-4 w-4 text-muted-foreground hidden sm:block" />
          </CardHeader>
          <CardContent>
            <div className={`text-lg sm:text-2xl font-bold ${details.total_blacklist_hits > 0 ? "text-destructive" : ""}`}>
              {details.total_blacklist_hits}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-xs sm:text-sm font-medium">{t("threats")}</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground hidden sm:block" />
          </CardHeader>
          <CardContent>
            <div className={`text-lg sm:text-2xl font-bold ${(details.total_threats ?? 0) > 0 ? "text-orange-500" : ""}`}>
              {details.total_threats ?? 0}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-xs sm:text-sm font-medium">{t("risk")}</CardTitle>
            <Gauge className="h-4 w-4 text-muted-foreground hidden sm:block" />
          </CardHeader>
          <CardContent>
            {details.risk_level ? (
              <div className="flex items-baseline gap-2">
                <div className={`text-lg sm:text-2xl font-bold ${
                  details.risk_level === "critical" ? "text-destructive" :
                  details.risk_level === "high" ? "text-orange-500" :
                  details.risk_level === "medium" ? "text-yellow-500" :
                  "text-green-500"
                }`}>
                  {details.risk_score ?? 0}
                </div>
                <span className="text-xs text-muted-foreground uppercase">{details.risk_level}</span>
              </div>
            ) : (
              <div className="text-lg sm:text-2xl font-bold text-muted-foreground">—</div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-xs sm:text-sm font-medium">{t("nodes")}</CardTitle>
            <Globe className="h-4 w-4 text-muted-foreground hidden sm:block" />
          </CardHeader>
          <CardContent>
            <div className="text-lg sm:text-2xl font-bold">{details.nodes.length}</div>
          </CardContent>
        </Card>
      </div>

      {details.threats_by_type && Object.keys(details.threats_by_type).length > 0 && (() => {
        // Tab labels + counts come from threats_by_type (full aggregate).
        // The detail rows for the active tab are loaded paginated by
        // UserThreatsTable from /api/users/{email}/threats?type=...
        const sortedCats = Object.entries(details.threats_by_type)
          .sort(([, a], [, b]) => b - a)
          .map(([type]) => type);
        return (
          <Card>
            <CardHeader>
              <CardTitle className="text-base sm:text-lg flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-orange-500" />
                {t("threatIntelTitle")}
              </CardTitle>
              <CardDescription className="text-xs sm:text-sm">
                {t("threatIntelDesc")}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Tabs defaultValue={sortedCats[0]} className="w-full">
                <TabsList className="flex flex-wrap h-auto justify-start gap-1">
                  {sortedCats.map(cat => (
                    <TabsTrigger key={cat} value={cat} className="font-mono text-xs">
                      <span className="uppercase">{cat}</span>
                      <span className="ml-2 opacity-70">{details.threats_by_type?.[cat] ?? 0}</span>
                    </TabsTrigger>
                  ))}
                </TabsList>
                {sortedCats.map(cat => (
                  <TabsContent key={cat} value={cat} className="mt-4">
                    <UserThreatsTable email={email} threatType={cat} />
                  </TabsContent>
                ))}
              </Tabs>
            </CardContent>
          </Card>
        );
      })()}

      <Card>
        <CardHeader>
          <CardTitle className="text-base sm:text-lg">{t("activityByNode")}</CardTitle>
          <CardDescription className="text-xs sm:text-sm">{t("activityByNodeDesc")}</CardDescription>
        </CardHeader>
        <CardContent className="max-h-[300px] overflow-y-auto overflow-x-auto scrollbar-thin">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="whitespace-nowrap">{t("nodeColumn")}</TableHead>
                <TableHead className="text-right whitespace-nowrap">{t("requestsColumn")}</TableHead>
                <TableHead className="text-right whitespace-nowrap">{t("blacklistColumn")}</TableHead>
                <TableHead className="text-right whitespace-nowrap hidden sm:table-cell">{t("destinationsColumn")}</TableHead>
                <TableHead className="whitespace-nowrap hidden md:table-cell">{t("lastSeenColumn")}</TableHead>
                <TableHead className="whitespace-nowrap hidden lg:table-cell">{t("lastBlockedColumn")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {details.nodes.map((node) => (
                <TableRow key={node.node_id}>
                  <TableCell>
                    <Badge variant="outline" className="whitespace-nowrap">{node.node_id}</Badge>
                  </TableCell>
                  <TableCell className="text-right">
                    {node.total_requests.toLocaleString()}
                  </TableCell>
                  <TableCell className="text-right">
                    {node.blacklist_hits > 0 ? (
                      <Badge variant="destructive">{node.blacklist_hits}</Badge>
                    ) : (
                      <span className="text-muted-foreground">0</span>
                    )}
                  </TableCell>
                  <TableCell className="text-right hidden sm:table-cell">
                    {node.unique_destinations}
                  </TableCell>
                  <TableCell className="text-muted-foreground text-sm hidden md:table-cell whitespace-nowrap">
                    {isValidDate(node.last_seen)
                      ? formatDistanceToNow(new Date(node.last_seen), { addSuffix: true })
                      : "—"
                    }
                  </TableCell>
                  <TableCell className="text-muted-foreground text-sm max-w-[200px] truncate hidden lg:table-cell">
                    {node.last_blacklist_domain || "—"}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base sm:text-lg flex items-center gap-2">
            <Wifi className="h-4 w-4" />
            {t("ipHistory")}
          </CardTitle>
          <CardDescription className="text-xs sm:text-sm">{t("ipHistoryDesc")}</CardDescription>
        </CardHeader>
        <CardContent>
          <UserIPHistoryTable email={email} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t("visitedDestinations")}</CardTitle>
          <CardDescription>{t("visitedDesc")}</CardDescription>
        </CardHeader>
        <CardContent>
          <UserDestinationsTable email={email} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-destructive">{t("blacklistMatches")}</CardTitle>
          <CardDescription>{t("blacklistMatchesDesc")}</CardDescription>
        </CardHeader>
        <CardContent>
          <UserBlacklistMatches email={email} />
        </CardContent>
      </Card>
    </div>
  );
}
