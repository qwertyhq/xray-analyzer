"use client";

import { useState, useEffect, useCallback } from "react";
import { authFetch } from "@/contexts/auth-context";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Download, ChevronLeft, ChevronRight, Loader2 } from "lucide-react";
import { ThreatMatch, FeedStatus, CategoryUserStats } from "@/lib/types";
import Link from "next/link";
import { MatchesTable } from "./matches-table";

interface TorrentTabProps {
  topUsers: CategoryUserStats[];
  feeds: FeedStatus[];
}

interface PaginatedUsersResponse {
  users: CategoryUserStats[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export function TorrentTab({ topUsers, feeds }: TorrentTabProps) {
  const [matches, setMatches] = useState<ThreatMatch[]>([]);
  
  // Paginated users state
  const [paginatedUsers, setPaginatedUsers] = useState<CategoryUserStats[]>([]);
  const [currentPage, setCurrentPage] = useState(1);
  const [totalUsers, setTotalUsers] = useState(0);
  const [totalPages, setTotalPages] = useState(0);
  const [usersLoading, setUsersLoading] = useState(true);
  const pageSize = 12;

  // Fetch paginated users
  const fetchUsers = useCallback(async (page: number) => {
    setUsersLoading(true);
    try {
      const token = localStorage.getItem("auth_token");
      const headers: HeadersInit = {};
      if (token) {
        headers["Authorization"] = `Bearer ${token}`;
      }
      const res = await authFetch(`/api/threatintel/top-users?category=torrent&page=${page}&page_size=${pageSize}`, { headers });
      if (res.ok) {
        const data: PaginatedUsersResponse = await res.json();
        setPaginatedUsers(data.users || []);
        setTotalUsers(data.total || 0);
        setTotalPages(data.total_pages || 0);
        setCurrentPage(data.page || 1);
      }
    } catch (err) {
      console.error("Failed to fetch users:", err);
    } finally {
      setUsersLoading(false);
    }
  }, []);

  // Fetch torrent matches on mount
  const fetchMatches = useCallback(async () => {
    try {
      const token = localStorage.getItem("auth_token");
      const headers: HeadersInit = {};
      if (token) {
        headers["Authorization"] = `Bearer ${token}`;
      }
      const res = await authFetch("/api/threatintel/matches?type=torrent&limit=20", { headers });
      if (res.ok) {
        const data = await res.json();
        setMatches(data || []);
      }
    } catch (err) {
      console.error("Failed to fetch torrent matches:", err);
    }
  }, []);

  useEffect(() => {
    fetchMatches();
    fetchUsers(1);
  }, [fetchMatches, fetchUsers]);

  // Sum indicators from all torrent-related feeds
  const totalIndicators = feeds.reduce((sum, f) => sum + (f.indicators || 0), 0);
  // Calculate total detections from paginated data or topUsers
  const displayUsers = paginatedUsers.length > 0 ? paginatedUsers : topUsers;
  const totalDetections = totalUsers > 0 
    ? displayUsers.reduce((sum, u) => sum + u.match_count, 0) 
    : topUsers?.reduce((sum, u) => sum + u.match_count, 0) || 0;
  const uniqueUsers = totalUsers > 0 ? totalUsers : (topUsers?.length || 0);
  
  return (
    <div className="space-y-6">
      {/* Torrent Stats */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Download className="h-4 w-4 text-cyan-600" />
              Torrent Detections
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-cyan-600">
              {totalDetections.toLocaleString()}
            </div>
            <p className="text-xs text-muted-foreground">On current page</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Unique Users</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {uniqueUsers}
            </div>
            <p className="text-xs text-muted-foreground">Using torrents (all time)</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Indicators Loaded</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {totalIndicators.toLocaleString()}
            </div>
            <p className="text-xs text-muted-foreground">
              From {feeds.length} source{feeds.length !== 1 ? 's' : ''}
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Top Torrent Users with Pagination */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Download className="h-5 w-5 text-cyan-600" />
                Torrent Users
              </CardTitle>
              <CardDescription>
                {totalUsers > 0 ? `${totalUsers} users with torrent activity` : 'Users with torrent activity'}
              </CardDescription>
            </div>
            {totalPages > 1 && (
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => fetchUsers(currentPage - 1)}
                  disabled={currentPage <= 1 || usersLoading}
                >
                  <ChevronLeft className="h-4 w-4" />
                </Button>
                <span className="text-sm text-muted-foreground">
                  {currentPage} / {totalPages}
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => fetchUsers(currentPage + 1)}
                  disabled={currentPage >= totalPages || usersLoading}
                >
                  <ChevronRight className="h-4 w-4" />
                </Button>
              </div>
            )}
          </div>
        </CardHeader>
        <CardContent>
          {usersLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : displayUsers.length > 0 ? (
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {displayUsers.map((user, idx) => (
                <div key={user.user_email} className="flex items-start gap-3 p-3 rounded-lg border">
                  <span className={`text-lg font-bold w-6 ${
                    currentPage === 1 && idx === 0 ? "text-yellow-500" :
                    currentPage === 1 && idx === 1 ? "text-gray-400" :
                    currentPage === 1 && idx === 2 ? "text-amber-600" :
                    "text-muted-foreground"
                  }`}>
                    {(currentPage - 1) * pageSize + idx + 1}
                  </span>
                  <div className="flex-1 min-w-0">
                    <Link
                      href={`/users/${encodeURIComponent(user.username || user.user_email || '')}`}
                      className="font-medium hover:underline block truncate"
                    >
                      {user.username || user.user_email}
                    </Link>
                    <div className="flex items-center gap-2 mt-1">
                      <Badge variant="secondary">{user.match_count} hits</Badge>
                    </div>
                    {user.domains && user.domains.length > 0 && (
                      <div className="mt-2 text-xs text-muted-foreground">
                        {user.domains.slice(0, 3).map((d, i) => (
                          <span key={d} className="font-mono">
                            {d}{i < Math.min(user.domains.length, 3) - 1 ? ", " : ""}
                          </span>
                        ))}
                        {user.domains.length > 3 && <span> +{user.domains.length - 3} more</span>}
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-muted-foreground">
              No torrent users detected yet
            </div>
          )}
        </CardContent>
      </Card>

      {/* Torrent Matches Table */}
      <MatchesTable 
        matches={matches} 
        title="Recent Torrent Activity"
        description={`Последние обнаружения торрент-активности`}
      />
    </div>
  );
}
