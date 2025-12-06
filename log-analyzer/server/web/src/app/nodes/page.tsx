"use client";

import { useState } from "react";
import { useNodes } from "@/hooks/use-api";
import { NodesTable } from "@/components/nodes/nodes-table";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { RefreshCw } from "lucide-react";
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
  const { nodes, loading, refetch, deleteNode } = useNodes();
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);

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
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Nodes</h2>
          <p className="text-muted-foreground">
            Manage and monitor Xray proxy nodes
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={refetch}>
          <RefreshCw className="h-4 w-4 mr-2" />
          Refresh
        </Button>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Total Nodes</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{nodes.length}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-green-600">Online</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">{onlineNodes.length}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Offline</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-muted-foreground">{offlineNodes.length}</div>
          </CardContent>
        </Card>
      </div>

      {onlineNodes.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-green-600">Online Nodes</CardTitle>
            <CardDescription>Currently connected and receiving data</CardDescription>
          </CardHeader>
          <CardContent>
            <NodesTable nodes={onlineNodes} />
          </CardContent>
        </Card>
      )}

      {offlineNodes.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-muted-foreground">Offline Nodes</CardTitle>
            <CardDescription>
              Not currently connected. Delete old nodes to clean up.
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
            <AlertDialogTitle>Delete node "{deleteTarget}"?</AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete the node and all its statistics.
              This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleting}>Cancel</AlertDialogCancel>
            <AlertDialogAction 
              onClick={handleDelete} 
              disabled={deleting}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleting ? "Deleting..." : "Delete"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
