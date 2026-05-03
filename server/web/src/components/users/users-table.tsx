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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { UserStats } from "@/lib/types";
import { formatDistanceToNow } from "date-fns";
import { Search, ExternalLink, Download, ArrowUpDown, AlertTriangle, Shield, ShieldAlert } from "lucide-react";
import { isValidDate } from "@/lib/utils/date";
import { IPInfoBadge } from "@/components/ui/ip-info-badge";

// Calculate risk score based on user activity (0-100)
function calculateRiskScore(user: UserStats): number {
  if (user.total_requests === 0) return 0;
  
  // Base score from blacklist hit ratio
  const hitRatio = user.blacklist_hits / user.total_requests;
  let score = Math.min(hitRatio * 500, 50); // Max 50 from ratio
  
  // Add points for absolute number of hits
  if (user.blacklist_hits > 100) score += 30;
  else if (user.blacklist_hits > 50) score += 20;
  else if (user.blacklist_hits > 10) score += 10;
  else if (user.blacklist_hits > 0) score += 5;
  
  // Add points for high activity with hits
  if (user.blacklist_hits > 0 && user.total_requests > 1000) score += 10;
  
  // Recent activity boost
  if (user.last_blacklist_hit && isValidDate(user.last_blacklist_hit)) {
    const hoursSinceHit = (Date.now() - new Date(user.last_blacklist_hit).getTime()) / (1000 * 60 * 60);
    if (hoursSinceHit < 1) score += 10;
    else if (hoursSinceHit < 24) score += 5;
  }
  
  return Math.min(Math.round(score), 100);
}

// Risk level badge component
function RiskBadge({ score }: { score: number }) {
  if (score >= 70) {
    return (
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger>
            <Badge variant="destructive" className="gap-1">
              <ShieldAlert className="h-3 w-3" />
              {score}
            </Badge>
          </TooltipTrigger>
          <TooltipContent>High Risk - Immediate attention required</TooltipContent>
        </Tooltip>
      </TooltipProvider>
    );
  }
  if (score >= 40) {
    return (
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger>
            <Badge variant="outline" className="gap-1 border-yellow-500 text-yellow-600">
              <AlertTriangle className="h-3 w-3" />
              {score}
            </Badge>
          </TooltipTrigger>
          <TooltipContent>Medium Risk - Review recommended</TooltipContent>
        </Tooltip>
      </TooltipProvider>
    );
  }
  if (score > 0) {
    return (
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger>
            <Badge variant="secondary" className="gap-1">
              <Shield className="h-3 w-3" />
              {score}
            </Badge>
          </TooltipTrigger>
          <TooltipContent>Low Risk</TooltipContent>
        </Tooltip>
      </TooltipProvider>
    );
  }
  return <span className="text-muted-foreground text-sm">—</span>;
}

type SortField = "requests" | "blacklist" | "risk" | "last_seen" | "destinations";
type SortOrder = "asc" | "desc";
type RiskFilter = "all" | "high" | "medium" | "low" | "none";

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
  const [nodeFilter, setNodeFilter] = useState<string>("all");
  const [riskFilter, setRiskFilter] = useState<RiskFilter>("all");
  const [sortField, setSortField] = useState<SortField>("requests");
  const [sortOrder, setSortOrder] = useState<SortOrder>("desc");

  // Get unique individual nodes for filter (node_id can be comma-separated list)
  const uniqueNodes = useMemo(() => {
    const nodes = new Set<string>();
    for (const u of users) {
      // Split by comma and add each node
      const nodeList = u.node_id.split(",").map(n => n.trim()).filter(Boolean);
      for (const node of nodeList) {
        nodes.add(node);
      }
    }
    return Array.from(nodes).sort();
  }, [users]);

  // Calculate risk scores
  const usersWithRisk = useMemo(() => {
    return users.map(u => ({
      ...u,
      riskScore: calculateRiskScore(u),
    }));
  }, [users]);

  const filteredUsers = useMemo(() => {
    let result = usersWithRisk;
    
    if (showBlacklistOnly) {
      result = result.filter(u => u.blacklist_hits > 0);
    }
    
    // Node filter - check if selected node is in the comma-separated list
    if (nodeFilter !== "all") {
      result = result.filter(u => {
        const userNodes = u.node_id.split(",").map(n => n.trim());
        return userNodes.includes(nodeFilter);
      });
    }

    // Risk filter
    if (riskFilter !== "all") {
      result = result.filter(u => {
        switch (riskFilter) {
          case "high": return u.riskScore >= 70;
          case "medium": return u.riskScore >= 40 && u.riskScore < 70;
          case "low": return u.riskScore > 0 && u.riskScore < 40;
          case "none": return u.riskScore === 0;
          default: return true;
        }
      });
    }
    
    if (search) {
      const lower = search.toLowerCase();
      result = result.filter(u => 
        u.username.toLowerCase().includes(lower) ||
        u.node_id.toLowerCase().includes(lower) ||
        (u.last_ip && u.last_ip.includes(lower))
      );
    }

    // Sort
    result = [...result].sort((a, b) => {
      let cmp = 0;
      switch (sortField) {
        case "requests":
          cmp = a.total_requests - b.total_requests;
          break;
        case "blacklist":
          cmp = a.blacklist_hits - b.blacklist_hits;
          break;
        case "risk":
          cmp = a.riskScore - b.riskScore;
          break;
        case "destinations":
          cmp = a.unique_destinations - b.unique_destinations;
          break;
        case "last_seen":
          cmp = new Date(a.last_seen || 0).getTime() - new Date(b.last_seen || 0).getTime();
          break;
      }
      return sortOrder === "desc" ? -cmp : cmp;
    });
    
    return result;
  }, [usersWithRisk, showBlacklistOnly, nodeFilter, riskFilter, search, sortField, sortOrder]);

  const paginatedUsers = useMemo(() => {
    const start = page * pageSize;
    return filteredUsers.slice(start, start + pageSize);
  }, [filteredUsers, page, pageSize]);

  const totalPages = Math.ceil(filteredUsers.length / pageSize);

  // Export to CSV
  const handleExportCSV = () => {
    const headers = ["Username", "Node", "Requests", "Blacklist Hits", "Risk Score", "Destinations", "Last IP", "Last Seen", "Last Blocked Domain"];
    const rows = filteredUsers.map(u => [
      u.username,
      u.node_id,
      u.total_requests,
      u.blacklist_hits,
      u.riskScore,
      u.unique_destinations,
      u.last_ip || "",
      u.last_seen || "",
      u.last_blacklist_domain || "",
    ]);
    
    const csv = [headers.join(","), ...rows.map(r => r.map(c => `"${c}"`).join(","))].join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `users-export-${new Date().toISOString().split("T")[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const toggleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder(o => o === "desc" ? "asc" : "desc");
    } else {
      setSortField(field);
      setSortOrder("desc");
    }
    setPage(0);
  };

  return (
    <div className="space-y-4">
      {showSearch && (
        <div className="flex flex-col sm:flex-row gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search by user, node or IP..."
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(0);
              }}
              className="pl-9"
            />
          </div>
          <Select value={nodeFilter} onValueChange={(v) => { setNodeFilter(v); setPage(0); }}>
            <SelectTrigger className="w-full sm:w-[180px]">
              <SelectValue placeholder="All nodes" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All nodes</SelectItem>
              {uniqueNodes.map(node => (
                <SelectItem key={node} value={node}>{node}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={riskFilter} onValueChange={(v) => { setRiskFilter(v as RiskFilter); setPage(0); }}>
            <SelectTrigger className="w-full sm:w-[150px]">
              <SelectValue placeholder="Risk Level" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All risks</SelectItem>
              <SelectItem value="high">
                <span className="flex items-center gap-2">
                  <span className="h-2 w-2 rounded-full bg-red-500" />
                  High (≥70)
                </span>
              </SelectItem>
              <SelectItem value="medium">
                <span className="flex items-center gap-2">
                  <span className="h-2 w-2 rounded-full bg-yellow-500" />
                  Medium (40-69)
                </span>
              </SelectItem>
              <SelectItem value="low">
                <span className="flex items-center gap-2">
                  <span className="h-2 w-2 rounded-full bg-gray-400" />
                  Low (1-39)
                </span>
              </SelectItem>
              <SelectItem value="none">
                <span className="flex items-center gap-2">
                  <span className="h-2 w-2 rounded-full bg-green-500" />
                  None (0)
                </span>
              </SelectItem>
            </SelectContent>
          </Select>
          <Button variant="outline" size="icon" onClick={handleExportCSV} title="Export CSV">
            <Download className="h-4 w-4" />
          </Button>
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
                <TableHead 
                  className="text-right whitespace-nowrap hidden md:table-cell cursor-pointer hover:text-foreground"
                  onClick={() => toggleSort("requests")}
                >
                  <span className="inline-flex items-center gap-1">
                    Requests
                    <ArrowUpDown className={`h-3 w-3 ${sortField === "requests" ? "text-primary" : ""}`} />
                  </span>
                </TableHead>
                <TableHead 
                  className="text-right whitespace-nowrap cursor-pointer hover:text-foreground"
                  onClick={() => toggleSort("blacklist")}
                >
                  <span className="inline-flex items-center gap-1">
                    Blacklist
                    <ArrowUpDown className={`h-3 w-3 ${sortField === "blacklist" ? "text-primary" : ""}`} />
                  </span>
                </TableHead>
                <TableHead 
                  className="text-center whitespace-nowrap hidden md:table-cell cursor-pointer hover:text-foreground"
                  onClick={() => toggleSort("risk")}
                >
                  <span className="inline-flex items-center gap-1">
                    Risk
                    <ArrowUpDown className={`h-3 w-3 ${sortField === "risk" ? "text-primary" : ""}`} />
                  </span>
                </TableHead>
                <TableHead 
                  className="text-right whitespace-nowrap hidden lg:table-cell cursor-pointer hover:text-foreground"
                  onClick={() => toggleSort("destinations")}
                >
                  <span className="inline-flex items-center gap-1">
                    Destinations
                    <ArrowUpDown className={`h-3 w-3 ${sortField === "destinations" ? "text-primary" : ""}`} />
                  </span>
                </TableHead>
                <TableHead 
                  className="whitespace-nowrap hidden md:table-cell cursor-pointer hover:text-foreground"
                  onClick={() => toggleSort("last_seen")}
                >
                  <span className="inline-flex items-center gap-1">
                    Last Seen
                    <ArrowUpDown className={`h-3 w-3 ${sortField === "last_seen" ? "text-primary" : ""}`} />
                  </span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {paginatedUsers.map((user) => (
                <TableRow key={`${user.node_id}-${user.username}`}>
                  <TableCell className="font-medium max-w-[150px] sm:max-w-[200px]">
                    <Link 
                      href={`/users/${encodeURIComponent(user.username)}`}
                      className="hover:underline text-primary flex items-center gap-1 truncate"
                    >
                      <span className="truncate">{user.username}</span>
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
                  <TableCell className="text-center hidden md:table-cell">
                    <RiskBadge score={user.riskScore} />
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
            {page * pageSize + 1}-{Math.min((page + 1) * pageSize, filteredUsers.length)} of {filteredUsers.length}
          </p>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage(p => Math.max(0, p - 1))}
              disabled={page === 0}
            >
              Previous
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
              disabled={page >= totalPages - 1}
            >
              Next
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
