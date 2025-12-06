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
import { NodeStats } from "@/lib/types";
import { formatDistanceToNow } from "date-fns";

interface NodesTableProps {
  nodes: NodeStats[];
}

export function NodesTable({ nodes }: NodesTableProps) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Node ID</TableHead>
          <TableHead>Status</TableHead>
          <TableHead className="text-right">Requests</TableHead>
          <TableHead className="text-right">Blacklist</TableHead>
          <TableHead className="text-right">Users</TableHead>
          <TableHead>Last Seen</TableHead>
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
            <TableCell className="text-right">{node.unique_users}</TableCell>
            <TableCell className="text-muted-foreground">
              {formatDistanceToNow(new Date(node.last_seen), {
                addSuffix: true,
              })}
            </TableCell>
          </TableRow>
        ))}
        {nodes.length === 0 && (
          <TableRow>
            <TableCell colSpan={6} className="text-center text-muted-foreground">
              No nodes connected
            </TableCell>
          </TableRow>
        )}
      </TableBody>
    </Table>
  );
}
