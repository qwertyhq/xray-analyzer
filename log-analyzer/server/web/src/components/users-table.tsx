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
import { UserStats } from "@/lib/types";
import { formatDistanceToNow } from "date-fns";

interface UsersTableProps {
  users: UserStats[];
  showBlacklistOnly?: boolean;
}

export function UsersTable({ users, showBlacklistOnly = false }: UsersTableProps) {
  const filteredUsers = showBlacklistOnly 
    ? users.filter(u => u.blacklist_hits > 0)
    : users;

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>User</TableHead>
          <TableHead>Node</TableHead>
          <TableHead className="text-right">Requests</TableHead>
          <TableHead className="text-right">Blacklist Hits</TableHead>
          <TableHead>Last Seen</TableHead>
          {showBlacklistOnly && <TableHead>Last Blocked</TableHead>}
        </TableRow>
      </TableHeader>
      <TableBody>
        {filteredUsers.map((user) => (
          <TableRow key={`${user.node_id}-${user.user_email}`}>
            <TableCell className="font-medium">{user.user_email}</TableCell>
            <TableCell>
              <Badge variant="outline">{user.node_id}</Badge>
            </TableCell>
            <TableCell className="text-right">
              {user.total_requests.toLocaleString()}
            </TableCell>
            <TableCell className="text-right">
              {user.blacklist_hits > 0 ? (
                <Badge variant="destructive">{user.blacklist_hits}</Badge>
              ) : (
                <span className="text-muted-foreground">0</span>
              )}
            </TableCell>
            <TableCell className="text-muted-foreground">
              {formatDistanceToNow(new Date(user.last_seen), {
                addSuffix: true,
              })}
            </TableCell>
            {showBlacklistOnly && (
              <TableCell className="text-muted-foreground">
                {user.last_blacklist_domain || "—"}
              </TableCell>
            )}
          </TableRow>
        ))}
        {filteredUsers.length === 0 && (
          <TableRow>
            <TableCell 
              colSpan={showBlacklistOnly ? 6 : 5} 
              className="text-center text-muted-foreground"
            >
              {showBlacklistOnly ? "No blacklist hits" : "No users found"}
            </TableCell>
          </TableRow>
        )}
      </TableBody>
    </Table>
  );
}
