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
import { isValidDate } from "@/lib/utils/date";
import { IPInfoBadge } from "@/components/ui/ip-info-badge";

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

      <div className="overflow-x-auto -mx-4 sm:mx-0">
        <div className="inline-block min-w-full align-middle px-4 sm:px-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="whitespace-nowrap">User</TableHead>
                <TableHead className="whitespace-nowrap hidden sm:table-cell">Node</TableHead>
                <TableHead className="whitespace-nowrap hidden lg:table-cell">IP</TableHead>
                <TableHead className="text-right whitespace-nowrap hidden md:table-cell">Requests</TableHead>
                <TableHead className="text-right whitespace-nowrap">Blacklist</TableHead>
                <TableHead className="text-right whitespace-nowrap hidden lg:table-cell">Destinations</TableHead>
                <TableHead className="whitespace-nowrap hidden md:table-cell">Last Seen</TableHead>
                <TableHead className="whitespace-nowrap hidden xl:table-cell">Last Blocked</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {paginatedUsers.map((user) => (
                <TableRow key={`${user.node_id}-${user.user_email}`}>
                  <TableCell className="font-medium max-w-[150px] sm:max-w-[200px]">
                    <Link 
                      href={`/users/${encodeURIComponent(user.user_email)}`}
                      className="hover:underline text-primary flex items-center gap-1 truncate"
                    >
                      <span className="truncate">{user.user_email}</span>
                      <ExternalLink className="h-3 w-3 flex-shrink-0" />
                    </Link>
                  </TableCell>
                  <TableCell className="hidden sm:table-cell">
                    <Badge variant="outline" className="whitespace-nowrap">{user.node_id}</Badge>
                  </TableCell>
                  <TableCell className="hidden lg:table-cell">
                    {user.last_ip ? (
                      <IPInfoBadge ip={user.last_ip} />
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </TableCell>
                  <TableCell className="text-right hidden md:table-cell">
                    {user.total_requests.toLocaleString()}
                  </TableCell>
                  <TableCell className="text-right">
                    {user.blacklist_hits > 0 ? (
                      <Badge variant="destructive">{user.blacklist_hits}</Badge>
                    ) : (
                      <span className="text-muted-foreground">0</span>
                    )}
                  </TableCell>
                  <TableCell className="text-right hidden lg:table-cell">
                    {user.unique_destinations}
                  </TableCell>
                  <TableCell className="text-muted-foreground text-sm hidden md:table-cell whitespace-nowrap">
                    {isValidDate(user.last_seen) 
                      ? formatDistanceToNow(new Date(user.last_seen), { addSuffix: true })
                      : "—"
                    }
                  </TableCell>
                  <TableCell className="text-muted-foreground text-sm max-w-[200px] truncate hidden xl:table-cell">
                    {user.last_blacklist_domain || "—"}
                  </TableCell>
                </TableRow>
              ))}
              {paginatedUsers.length === 0 && (
                <TableRow>
                  <TableCell 
                    colSpan={8} 
                    className="text-center text-muted-foreground"
                  >
                    {showBlacklistOnly ? "No blacklist hits" : "No users found"}
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
      </div>

      {totalPages > 1 && (
        <div className="flex flex-col sm:flex-row items-center justify-between gap-2">
          <p className="text-sm text-muted-foreground">
            {page * pageSize + 1}-{Math.min((page + 1) * pageSize, filteredUsers.length)} из {filteredUsers.length}
          </p>
          <div className="flex gap-2">
            <button
              onClick={() => setPage(p => Math.max(0, p - 1))}
              disabled={page === 0}
              className="px-3 py-1 text-sm border rounded disabled:opacity-50"
            >
              Назад
            </button>
            <button
              onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
              disabled={page >= totalPages - 1}
              className="px-3 py-1 text-sm border rounded disabled:opacity-50"
            >
              Далее
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
