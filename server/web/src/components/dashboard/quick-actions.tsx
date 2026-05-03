"use client";

import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  RefreshCw,
  Download,
  ShieldAlert,
  Users,
  Zap,
  FileText,
  AlertTriangle,
} from "lucide-react";
import { useTranslations } from "next-intl";
import { cn } from "@/lib/utils";

interface QuickActionsProps {
  onSyncRemnawave?: () => Promise<void>;
  onRefreshBlacklist?: () => Promise<void>;
  onExportReport?: () => Promise<void>;
  problemUsersCount?: number;
}

export function QuickActions({
  onSyncRemnawave,
  onRefreshBlacklist,
  onExportReport,
  problemUsersCount = 0,
}: QuickActionsProps) {
  const t = useTranslations("quickActions");
  const [syncing, setSyncing] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [exporting, setExporting] = useState(false);

  const handleSync = async () => {
    if (!onSyncRemnawave) return;
    setSyncing(true);
    try {
      await onSyncRemnawave();
    } finally {
      setSyncing(false);
    }
  };

  const handleRefresh = async () => {
    if (!onRefreshBlacklist) return;
    setRefreshing(true);
    try {
      await onRefreshBlacklist();
    } finally {
      setRefreshing(false);
    }
  };

  const handleExport = async () => {
    if (!onExportReport) return;
    setExporting(true);
    try {
      await onExportReport();
    } finally {
      setExporting(false);
    }
  };

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-medium flex items-center gap-2">
          <Zap className="h-4 w-4 text-yellow-500" />
          {t("title")}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        <div className="grid grid-cols-2 gap-2">
          <Button
            variant="outline"
            size="sm"
            className="h-auto py-2 px-3 flex flex-col items-center gap-1"
            onClick={handleSync}
            disabled={syncing || !onSyncRemnawave}
          >
            <RefreshCw className={cn("h-4 w-4", syncing && "animate-spin")} />
            <span className="text-xs">{t("syncRemnawave")}</span>
          </Button>

          <Button
            variant="outline"
            size="sm"
            className="h-auto py-2 px-3 flex flex-col items-center gap-1"
            onClick={handleRefresh}
            disabled={refreshing || !onRefreshBlacklist}
          >
            <ShieldAlert className={cn("h-4 w-4", refreshing && "animate-spin")} />
            <span className="text-xs">{t("refreshBlacklist")}</span>
          </Button>

          <Button
            variant="outline"
            size="sm"
            className="h-auto py-2 px-3 flex flex-col items-center gap-1"
            onClick={handleExport}
            disabled={exporting || !onExportReport}
          >
            <Download className={cn("h-4 w-4", exporting && "animate-bounce")} />
            <span className="text-xs">{t("exportReport")}</span>
          </Button>

          <Button
            variant="outline"
            size="sm"
            className="h-auto py-2 px-3 flex flex-col items-center gap-1 relative"
            asChild
          >
            <a href="/users?filter=high-risk">
              <Users className="h-4 w-4" />
              <span className="text-xs">{t("problemUsers")}</span>
              {problemUsersCount > 0 && (
                <Badge 
                  variant="destructive" 
                  className="absolute -top-1 -right-1 h-4 w-4 p-0 flex items-center justify-center text-[10px]"
                >
                  {problemUsersCount > 9 ? "9+" : problemUsersCount}
                </Badge>
              )}
            </a>
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
