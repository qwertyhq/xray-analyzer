"use client";

import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { NodeStats } from "@/lib/types";
import { formatDistanceToNow } from "date-fns";
import { Trash2, RefreshCw } from "lucide-react";

// Check if date is valid (not zero time or year 1)
function isValidDate(dateStr: string): boolean {
  if (!dateStr) return false;
  const date = new Date(dateStr);
  return !isNaN(date.getTime()) && date.getFullYear() > 2000;
}

interface NodesTableProps {
  nodes: NodeStats[];
  onDelete?: (nodeId: string) => void;
  showActions?: boolean;
}

export function NodesTable({ nodes, onDelete, showActions = false }: NodesTableProps) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Node ID</TableHead>
          <TableHead>Status</TableHead>
          <TableHead className="text-right">Requests</TableHead>
          <TableHead className="text-right">Blacklist</TableHead>
          <TableHead className="text-right">Online</TableHead>
          <TableHead className="text-right">Total Users</TableHead>
          <TableHead>Last Seen</TableHead>
          {showActions && <TableHead className="w-[100px]">Actions</TableHead>}
        </TableRow>
      </TableHeader>
      <TableBody>
        {nodes.map((node) => (
          <TableRow key={node.node_id}>
            <TableCell className="font-medium">{node.node_id}</TableCell>
            <TableCell>
              <Badge variant={node.is_connected ? "default" : "secondary"}>
                {node.is_connected ? "Online" : "Offline"}
              </Badge>
            </TableCell>
            <TableCell className="text-right">
              {node.total_requests.toLocaleString()}
            </TableCell>
            <TableCell className="text-right">
              {node.blacklist_hits > 0 ? (
                <span className="text-destructive font-medium">
                  {node.blacklist_hits}
                </span>
              ) : (
                "0"
              )}
            </TableCell>
            <TableCell className="text-right">
              <span className="text-green-500 font-medium">{node.online_users || 0}</span>
            </TableCell>
            <TableCell className="text-right">{node.unique_users}</TableCell>
            <TableCell className="text-muted-foreground text-sm">
              {isValidDate(node.last_seen)
                ? formatDistanceToNow(new Date(node.last_seen), { addSuffix: true })
                : "—"
              }
            </TableCell>
            {showActions && (
              <TableCell>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8 text-destructive hover:text-destructive"
                  onClick={() => onDelete?.(node.node_id)}
                  title="Delete node"
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
              </TableCell>
            )}
          </TableRow>
        ))}
        {nodes.length === 0 && (
          <TableRow>
            <TableCell colSpan={showActions ? 8 : 7} className="text-center text-muted-foreground">
              No nodes found
            </TableCell>
          </TableRow>
        )}
      </TableBody>
    </Table>
  );
}
