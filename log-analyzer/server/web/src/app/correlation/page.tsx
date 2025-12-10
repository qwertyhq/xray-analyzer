"use client";

import { useState, useEffect, useCallback, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { PaginationControls, usePagination } from "@/components/ui/data-table";
import { SubscriptionAbuseAnalytics } from "@/components/remnawave/subscription-abuse-analytics";
import { 
  Users, 
  Network, 
  AlertTriangle, 
  RefreshCw,
  Shield,
  Fingerprint,
  Smartphone,
  Globe,
  Search,
  TrendingUp,
  Link2
} from "lucide-react";
import { SubscriptionAbuse, RemnawaveAbuseUser } from "@/lib/types";

interface CorrelationStats {
  shared_ips: number;
  shared_hwids: number;
  total_fingerprints: number;
  users_with_shared_ip: number;
  users_with_shared_hwid: number;
  total_clusters: number;
  users_in_clusters: number;
}

interface UserAIProfile {
  user_email: string;
  remna_username?: string;
  unique_ips: number;
  unique_hwids: number;
  unique_fingerprints: number;
  unique_countries: number;
  unique_nodes: number;
  total_requests: number;
  total_sessions: number;
  total_threat_matches: number;
  threat_categories: Record<string, number>;
  shared_ip_users: number;
  shared_hwid_users: number;
  cluster_ids: string[];
  risk_score: number;
  risk_factors: string[];
  remna_uuid?: string;
  remna_status?: string;
  remna_traffic_used: number;
  remna_traffic_limit: number;
  remna_hwid_devices: number;
  remna_hwid_limit: number;
  first_seen: string;
  last_seen: string;
  active_days: number;
  updated_at: string;
}

interface SharedIPInfo {
  ip_address: string;
  user_count: number;
  last_seen: string;
  total_requests: number;
  users: string[];
}

interface SharedHWIDInfo {
  hwid: string;
  platform: string;
  user_count: number;
  last_seen: string;
  total_requests: number;
  users: string[];
}

export default function CorrelationPage() {
  const [stats, setStats] = useState<CorrelationStats | null>(null);
  const [profiles, setProfiles] = useState<UserAIProfile[]>([]);
  const [sharedIPs, setSharedIPs] = useState<SharedIPInfo[]>([]);
  const [sharedHWIDs, setSharedHWIDs] = useState<SharedHWIDInfo[]>([]);
  const [ipAbuseUsers, setIpAbuseUsers] = useState<SubscriptionAbuse[]>([]);
  const [hwidAbuseUsers, setHwidAbuseUsers] = useState<RemnawaveAbuseUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  const [minRiskScore, setMinRiskScore] = useState(0);

  const fetchData = useCallback(async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    else setLoading(true);
    
    try {
      const token = localStorage.getItem("auth_token");
      const headers: HeadersInit = {};
      if (token) {
        headers["Authorization"] = `Bearer ${token}`;
      }

      const [statsRes, profilesRes, sharedIPsRes, sharedHWIDsRes, ipAbuseRes, hwidAbuseRes] = await Promise.all([
        fetch("/api/correlation/stats", { headers }),
        fetch(`/api/correlation/profiles?limit=100&min_risk=${minRiskScore}`, { headers }),
        fetch("/api/correlation/shared-ips?limit=50", { headers }),
        fetch("/api/correlation/shared-hwids?limit=50", { headers }),
        fetch("/api/blacklist/abuse", { headers }),
        fetch("/api/remnawave/abuse", { headers })
      ]);

      const [statsData, profilesData, sharedIPsData, sharedHWIDsData, ipAbuseData, hwidAbuseData] = await Promise.all([
        statsRes.ok ? statsRes.json() : null,
        profilesRes.ok ? profilesRes.json() : { profiles: [] },
        sharedIPsRes.ok ? sharedIPsRes.json() : { shared_ips: [] },
        sharedHWIDsRes.ok ? sharedHWIDsRes.json() : { shared_hwids: [] },
        ipAbuseRes.ok ? ipAbuseRes.json() : [],
        hwidAbuseRes.ok ? hwidAbuseRes.json() : { enabled: false, users: [] }
      ]);

      setStats(statsData);
      setProfiles(profilesData.profiles || []);
      setSharedIPs(sharedIPsData.shared_ips || []);
      setSharedHWIDs(sharedHWIDsData.shared_hwids || []);
      setIpAbuseUsers(ipAbuseData || []);
      setHwidAbuseUsers(hwidAbuseData.users || []);
    } catch (err) {
      console.error("Failed to fetch correlation data:", err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [minRiskScore]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const getRiskBadge = (score: number) => {
    if (score >= 70) return <Badge variant="destructive">Critical ({score})</Badge>;
    if (score >= 50) return <Badge className="bg-orange-500">High ({score})</Badge>;
    if (score >= 30) return <Badge className="bg-yellow-500">Medium ({score})</Badge>;
    if (score >= 10) return <Badge variant="secondary">Low ({score})</Badge>;
    return <Badge variant="outline">Minimal ({score})</Badge>;
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  const filteredProfiles = useMemo(() => 
    profiles.filter(p => p.user_email.toLowerCase().includes(searchTerm.toLowerCase())),
    [profiles, searchTerm]
  );

  // Pagination hooks for each table
  const profilesPagination = usePagination(filteredProfiles, 20);
  const sharedIPsPagination = usePagination(sharedIPs, 20);
  const sharedHWIDsPagination = usePagination(sharedHWIDs, 20);

  if (loading) {
    return (
      <div className="container mx-auto p-6 space-y-6">
        <Skeleton className="h-12 w-64" />
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => (
            <Skeleton key={i} className="h-32" />
          ))}
        </div>
        <Skeleton className="h-96" />
      </div>
    );
  }

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">User Correlation Analysis</h1>
          <p className="text-muted-foreground">
            AI-powered user behavior analysis and fraud detection
          </p>
        </div>
        <Button onClick={() => fetchData(true)} disabled={refreshing}>
          <RefreshCw className={`mr-2 h-4 w-4 ${refreshing ? "animate-spin" : ""}`} />
          Refresh
        </Button>
      </div>

      {/* Stats Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Shared IPs</CardTitle>
            <Network className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.shared_ips || 0}</div>
            <p className="text-xs text-muted-foreground">
              {stats?.users_with_shared_ip || 0} users affected
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Shared HWIDs</CardTitle>
            <Smartphone className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-orange-500">{stats?.shared_hwids || 0}</div>
            <p className="text-xs text-muted-foreground">
              {stats?.users_with_shared_hwid || 0} users affected
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Fingerprints</CardTitle>
            <Fingerprint className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.total_fingerprints || 0}</div>
            <p className="text-xs text-muted-foreground">
              Unique IP+HWID combinations
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">User Clusters</CardTitle>
            <Link2 className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.total_clusters || 0}</div>
            <p className="text-xs text-muted-foreground">
              {stats?.users_in_clusters || 0} users linked
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Main Content Tabs */}
      <Tabs defaultValue="abuse" className="space-y-4">
        <TabsList>
          <TabsTrigger value="abuse" className="flex items-center gap-2">
            <Shield className="h-4 w-4" />
            Abuse Detection
            {(ipAbuseUsers.length > 0 || hwidAbuseUsers.length > 0) && (
              <Badge variant="destructive" className="ml-1">
                {ipAbuseUsers.length + hwidAbuseUsers.length}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="profiles">
            <Users className="mr-2 h-4 w-4" />
            AI Profiles
          </TabsTrigger>
          <TabsTrigger value="shared-ips">
            <Network className="mr-2 h-4 w-4" />
            Shared IPs
          </TabsTrigger>
          <TabsTrigger value="shared-hwids">
            <Smartphone className="mr-2 h-4 w-4" />
            Shared HWIDs
          </TabsTrigger>
        </TabsList>

        <TabsContent value="abuse" className="space-y-4">
          <SubscriptionAbuseAnalytics
            ipAbuseData={ipAbuseUsers}
            hwidAbuseData={hwidAbuseUsers}
            onHwidCleared={() => fetchData(true)}
          />
        </TabsContent>

        <TabsContent value="profiles" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>User AI Profiles</CardTitle>
              <CardDescription>
                Comprehensive analysis profiles for fraud detection and AI processing
              </CardDescription>
              <div className="flex gap-4 mt-4">
                <div className="relative flex-1">
                  <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                  <Input
                    placeholder="Search by email..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="pl-8"
                  />
                </div>
                <select
                  className="border rounded-md px-3"
                  value={minRiskScore}
                  onChange={(e) => setMinRiskScore(Number(e.target.value))}
                >
                  <option value={0}>All Risk Levels</option>
                  <option value={10}>Risk ≥ 10</option>
                  <option value={30}>Risk ≥ 30</option>
                  <option value={50}>Risk ≥ 50</option>
                  <option value={70}>Risk ≥ 70</option>
                </select>
              </div>
            </CardHeader>
            <CardContent>
              <div className="overflow-auto max-h-[600px] border rounded-md">
              <Table>
                <TableHeader className="sticky top-0 bg-background z-10">
                  <TableRow>
                    <TableHead>User</TableHead>
                    <TableHead>Risk</TableHead>
                    <TableHead>IPs</TableHead>
                    <TableHead>HWIDs</TableHead>
                    <TableHead>Shared With</TableHead>
                    <TableHead>Threats</TableHead>
                    <TableHead>Countries</TableHead>
                    <TableHead>Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {profilesPagination.paginatedData.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={8} className="text-center text-muted-foreground">
                        No profiles found. Data will appear after log processing.
                      </TableCell>
                    </TableRow>
                  ) : (
                    profilesPagination.paginatedData.map((profile) => (
                      <TableRow key={profile.user_email}>
                        <TableCell className="font-medium">
                          <div className="flex flex-col">
                            <span>{profile.remna_username || profile.user_email}</span>
                            {profile.remna_username && profile.remna_username !== profile.user_email && (
                              <span className="text-xs text-muted-foreground">ID: {profile.user_email}</span>
                            )}
                          </div>
                          {profile.risk_factors && profile.risk_factors.length > 0 && (
                            <div className="flex flex-wrap gap-1 mt-1">
                              {profile.risk_factors.slice(0, 3).map((factor, i) => (
                                <Badge key={i} variant="outline" className="text-xs">
                                  {factor.replace(/_/g, " ")}
                                </Badge>
                              ))}
                            </div>
                          )}
                        </TableCell>
                        <TableCell>{getRiskBadge(profile.risk_score)}</TableCell>
                        <TableCell>
                          <Badge variant="outline">{profile.unique_ips}</Badge>
                        </TableCell>
                        <TableCell>
                          <Badge variant={profile.unique_hwids > 3 ? "destructive" : "outline"}>
                            {profile.unique_hwids}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <div className="flex gap-2">
                            {profile.shared_ip_users > 0 && (
                              <Badge variant="secondary">
                                {profile.shared_ip_users} IP
                              </Badge>
                            )}
                            {profile.shared_hwid_users > 0 && (
                              <Badge variant="destructive">
                                {profile.shared_hwid_users} HWID
                              </Badge>
                            )}
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge variant={profile.total_threat_matches > 10 ? "destructive" : "outline"}>
                            {profile.total_threat_matches}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline">
                            <Globe className="h-3 w-3 mr-1" />
                            {profile.unique_countries}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          {profile.remna_status && (
                            <Badge variant={profile.remna_status === "ACTIVE" ? "default" : "secondary"}>
                              {profile.remna_status}
                            </Badge>
                          )}
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
              </div>
              <PaginationControls {...profilesPagination} />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="shared-ips" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Shared IP Addresses</CardTitle>
              <CardDescription>
                IPs used by multiple user accounts - potential VPN exit nodes or shared networks
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="overflow-auto max-h-[600px] border rounded-md">
              <Table>
                <TableHeader className="sticky top-0 bg-background z-10">
                  <TableRow>
                    <TableHead>IP Address</TableHead>
                    <TableHead>Users</TableHead>
                    <TableHead>Total Requests</TableHead>
                    <TableHead>Last Seen</TableHead>
                    <TableHead>User List</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {sharedIPsPagination.paginatedData.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5} className="text-center text-muted-foreground">
                        No shared IPs found
                      </TableCell>
                    </TableRow>
                  ) : (
                    sharedIPsPagination.paginatedData.map((ip) => (
                      <TableRow key={ip.ip_address}>
                        <TableCell className="font-mono">{ip.ip_address}</TableCell>
                        <TableCell>
                          <Badge variant={ip.user_count > 5 ? "destructive" : "secondary"}>
                            {ip.user_count} users
                          </Badge>
                        </TableCell>
                        <TableCell>{ip.total_requests.toLocaleString()}</TableCell>
                        <TableCell>{ip.last_seen}</TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-1 max-w-md">
                            {ip.users?.slice(0, 5).map((user, i) => (
                              <Badge key={i} variant="outline" className="text-xs">
                                {user}
                              </Badge>
                            ))}
                            {ip.users?.length > 5 && (
                              <Badge variant="outline" className="text-xs">
                                +{ip.users.length - 5} more
                              </Badge>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
              </div>
              <PaginationControls {...sharedIPsPagination} />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="shared-hwids" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <AlertTriangle className="h-5 w-5 mr-2 text-orange-500" />
                Shared Hardware IDs
              </CardTitle>
              <CardDescription>
                Same device used by multiple accounts - potential account sharing or fraud
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="overflow-auto max-h-[600px] border rounded-md">
              <Table>
                <TableHeader className="sticky top-0 bg-background z-10">
                  <TableRow>
                    <TableHead>HWID</TableHead>
                    <TableHead>Platform</TableHead>
                    <TableHead>Users</TableHead>
                    <TableHead>Total Requests</TableHead>
                    <TableHead>Last Seen</TableHead>
                    <TableHead>User List</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {sharedHWIDsPagination.paginatedData.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center text-muted-foreground">
                        No shared HWIDs found - this is good!
                      </TableCell>
                    </TableRow>
                  ) : (
                    sharedHWIDsPagination.paginatedData.map((hwid) => (
                      <TableRow key={hwid.hwid} className="bg-orange-50 dark:bg-orange-950/20">
                        <TableCell className="font-mono text-xs">
                          {hwid.hwid.substring(0, 16)}...
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline">{hwid.platform || "Unknown"}</Badge>
                        </TableCell>
                        <TableCell>
                          <Badge variant="destructive">
                            {hwid.user_count} users
                          </Badge>
                        </TableCell>
                        <TableCell>{hwid.total_requests.toLocaleString()}</TableCell>
                        <TableCell>{hwid.last_seen}</TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-1 max-w-md">
                            {hwid.users?.map((user, i) => (
                              <Badge key={i} variant="destructive" className="text-xs">
                                {user}
                              </Badge>
                            ))}
                          </div>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
              </div>
              <PaginationControls {...sharedHWIDsPagination} />
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
