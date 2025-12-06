"use client";

import { useState, useMemo } from "react";
import Link from "next/link";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { UserStats } from "@/lib/types";
import { formatDistanceToNow } from "date-fns";
import { Search, ExternalLink } from "lucide-react";

interface UsersTableProps {
  users: UserStats[];
  showBlacklistOnly?: boolean;
  showSearch?: boolean;
  pageSize?: number;
}

export function UsersTable({ 
  users, 
  showBlacklistOnly = false,
  showSearch = false,
  pageSize = 50,
}: UsersTableProps) {
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);

  const filteredUsers = useMemo(() => {
    let result = users;
    
    if (showBlacklistOnly) {
      result = result.filter(u => u.blacklist_hits > 0);
    }
    
    if (search) {
      const lower = search.toLowerCase();
      result = result.filter(u => 
        u.user_email.toLowerCase().includes(lower) ||
        u.node_id.toLowerCase().includes(lower) ||
        (u.last_ip && u.last_ip.includes(lower))
      );
    }
    
    return result;
  }, [users, showBlacklistOnly, search]);

  const paginatedUsers = useMemo(() => {
    const start = page * pageSize;
    return filteredUsers.slice(start, start + pageSize);
  }, [filteredUsers, page, pageSize]);

  const totalPages = Math.ceil(filteredUsers.length / pageSize);

  return (
    <div className="space-y-4">
      {showSearch && (
        <div className="relative">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search by user or node..."
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(0);
            }}
            className="pl-9"
          />
        </div>
      )}

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>User</TableHead>
            <TableHead>Node</TableHead>
            <TableHead>IP</TableHead>
            <TableHead className="text-right">Requests</TableHead>
            <TableHead className="text-right">Blacklist Hits</TableHead>
            <TableHead className="text-right">Destinations</TableHead>
            <TableHead>Last Seen</TableHead>
            {showBlacklistOnly && <TableHead>Last Blocked Domain</TableHead>}
          </TableRow>
        </TableHeader>
        <TableBody>
          {paginatedUsers.map((user) => (
            <TableRow key={`${user.node_id}-${user.user_email}`}>
              <TableCell className="font-medium max-w-[200px]">
                <Link 
                  href={`/users/${encodeURIComponent(user.user_email)}`}
                  className="hover:underline text-primary flex items-center gap-1 truncate"
                >
                  {user.user_email}
                  <ExternalLink className="h-3 w-3 flex-shrink-0" />
                </Link>
              </TableCell>
              <TableCell>
                <Badge variant="outline">{user.node_id}</Badge>
              </TableCell>
              <TableCell className="font-mono text-sm text-muted-foreground">
                {user.last_ip || "—"}
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
              <TableCell className="text-right">
                {user.unique_destinations}
              </TableCell>
              <TableCell className="text-muted-foreground text-sm">
                {formatDistanceToNow(new Date(user.last_seen), {
                  addSuffix: true,
                })}
              </TableCell>
              {showBlacklistOnly && (
                <TableCell className="text-muted-foreground text-sm max-w-[200px] truncate">
                  {user.last_blacklist_domain || "—"}
                </TableCell>
              )}
            </TableRow>
          ))}
          {paginatedUsers.length === 0 && (
            <TableRow>
              <TableCell 
                colSpan={showBlacklistOnly ? 8 : 7} 
                className="text-center text-muted-foreground"
              >
                {showBlacklistOnly ? "No blacklist hits" : "No users found"}
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>

      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <p className="text-sm text-muted-foreground">
            Showing {page * pageSize + 1}-{Math.min((page + 1) * pageSize, filteredUsers.length)} of {filteredUsers.length}
          </p>
          <div className="flex gap-2">
            <button
              onClick={() => setPage(p => Math.max(0, p - 1))}
              disabled={page === 0}
              className="px-3 py-1 text-sm border rounded disabled:opacity-50"
            >
              Previous
            </button>
            <button
              onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
              disabled={page >= totalPages - 1}
              className="px-3 py-1 text-sm border rounded disabled:opacity-50"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
