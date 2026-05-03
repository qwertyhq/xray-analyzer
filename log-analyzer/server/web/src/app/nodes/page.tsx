"use client";

import { useState, useCallback } from "react";
import { authFetch } from "@/contexts/auth-context";
import { useWsNodes } from "@/contexts/websocket-context";
import { NodesTable } from "@/components/nodes/nodes-table";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { AnimatedNumber } from "@/components/ui/animated-number";
import { Wifi, WifiOff } from "lucide-react";
import { useTranslations } from "next-intl";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";

export default function NodesPage() {
  const t = useTranslations("nodesPage");
  const tCommon = useTranslations("common");
  const { nodes, loading, connected } = useWsNodes();
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);

  const deleteNode = useCallback(async (nodeId: string) => {
    try {
      const res = await authFetch("/api/nodes/delete", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ node_id: nodeId }),
      });
      return res.ok;
    } catch {
      return false;
    }
  }, []);

  const handleDelete = async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    await deleteNode(deleteTarget);
    setDeleting(false);
    setDeleteTarget(null);
  };

  const onlineNodes = nodes.filter(n => n.is_connected);
  const offlineNodes = nodes.filter(n => !n.is_connected);

  if (loading) {
    return (
      <div className="p-4 md:p-8 space-y-6">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-[400px]" />
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

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">{t("totalNodes")}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              <AnimatedNumber value={nodes.length} />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-green-600">{t("online")}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">
              <AnimatedNumber value={onlineNodes.length} />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">{t("offline")}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-muted-foreground">
              <AnimatedNumber value={offlineNodes.length} />
            </div>
          </CardContent>
        </Card>
      </div>

      {onlineNodes.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-green-600">{t("onlineNodes")}</CardTitle>
            <CardDescription>{t("onlineNodesDesc")}</CardDescription>
          </CardHeader>
          <CardContent>
            <NodesTable nodes={onlineNodes} />
          </CardContent>
        </Card>
      )}

      {offlineNodes.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-muted-foreground">{t("offlineNodes")}</CardTitle>
            <CardDescription>
              {t("offlineNodesDesc")}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <NodesTable 
              nodes={offlineNodes} 
              showActions 
              onDelete={setDeleteTarget}
            />
          </CardContent>
        </Card>
      )}

      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("deleteNodeTitle", { node: deleteTarget ?? "" })}</AlertDialogTitle>
            <AlertDialogDescription>
              {t("deleteNodeDesc")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleting}>{t("cancel")}</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDelete}
              disabled={deleting}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleting ? t("deleting") : t("delete")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
