"use client";

import { useParams } from "next/navigation";
import Link from "next/link";
import { useUserDetails } from "@/hooks/use-api";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ArrowLeft, User, Activity, ShieldAlert, Globe } from "lucide-react";
import { formatDistanceToNow, format } from "date-fns";
import { isValidDate } from "@/lib/utils/date";
import { UserDestinationsTable } from "@/components/users/user-destinations-table";
import { UserAlertsTable } from "@/components/users/user-alerts-table";

export default function UserDetailsPage() {
  const params = useParams();
  const email = decodeURIComponent(params.email as string);
  const { details, loading, error } = useUserDetails(email);

  if (loading) {
    return (
      <div className="p-4 md:p-8 space-y-6">
        <Skeleton className="h-8 w-64" />
        <div className="grid gap-4 md:grid-cols-3">
          <Skeleton className="h-[100px]" />
          <Skeleton className="h-[100px]" />
          <Skeleton className="h-[100px]" />
        </div>
        <Skeleton className="h-[400px]" />
      </div>
    );
  }

  if (error || !details) {
    return (
      <div className="p-4 md:p-8">
        <Link href="/users">
          <Button variant="ghost" className="mb-4">
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Users
          </Button>
        </Link>
        <Card>
          <CardContent className="pt-6">
            <p className="text-center text-muted-foreground">
              {error || "User not found"}
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="p-4 md:p-8 space-y-6">
      <div className="flex items-center gap-4">
        <Link href="/users">
          <Button variant="ghost" size="icon">
            <ArrowLeft className="h-4 w-4" />
          </Button>
        </Link>
        <div>
          <h2 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <User className="h-6 w-6" />
            {details.user_email}
          </h2>
          <p className="text-muted-foreground">
            User activity across {details.nodes.length} node(s)
          </p>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Requests</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {details.total_requests.toLocaleString()}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Blacklist Hits</CardTitle>
            <ShieldAlert className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className={`text-2xl font-bold ${details.total_blacklist_hits > 0 ? "text-destructive" : ""}`}>
              {details.total_blacklist_hits}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Nodes</CardTitle>
            <Globe className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{details.nodes.length}</div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Activity by Node</CardTitle>
          <CardDescription>User statistics per connected node</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Node</TableHead>
                <TableHead className="text-right">Requests</TableHead>
                <TableHead className="text-right">Blacklist</TableHead>
                <TableHead className="text-right">Destinations</TableHead>
                <TableHead>Last Seen</TableHead>
                <TableHead>Last Blocked Domain</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {details.nodes.map((node) => (
                <TableRow key={node.node_id}>
                  <TableCell>
                    <Badge variant="outline">{node.node_id}</Badge>
                  </TableCell>
                  <TableCell className="text-right">
                    {node.total_requests.toLocaleString()}
                  </TableCell>
                  <TableCell className="text-right">
                    {node.blacklist_hits > 0 ? (
                      <Badge variant="destructive">{node.blacklist_hits}</Badge>
                    ) : (
                      <span className="text-muted-foreground">0</span>
                    )}
                  </TableCell>
                  <TableCell className="text-right">
                    {node.unique_destinations}
                  </TableCell>
                  <TableCell className="text-muted-foreground text-sm">
                    {isValidDate(node.last_seen)
                      ? formatDistanceToNow(new Date(node.last_seen), { addSuffix: true })
                      : "—"
                    }
                  </TableCell>
                  <TableCell className="text-muted-foreground text-sm max-w-[200px] truncate">
                    {node.last_blacklist_domain || "—"}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Visited Destinations</CardTitle>
          <CardDescription>Resources visited by this user (sorted by request count)</CardDescription>
        </CardHeader>
        <CardContent>
          <UserDestinationsTable email={email} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-destructive">Alerts History</CardTitle>
          <CardDescription>All alerts generated for this user</CardDescription>
        </CardHeader>
        <CardContent>
          <UserAlertsTable email={email} />
        </CardContent>
      </Card>

      {details.recent_matches && details.recent_matches.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-destructive">Recent Blacklist Matches</CardTitle>
            <CardDescription>Last 50 blocked requests</CardDescription>
          </CardHeader>
          <CardContent className="max-h-[400px] overflow-y-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Time</TableHead>
                  <TableHead>Node</TableHead>
                  <TableHead>Source IP</TableHead>
                  <TableHead>Destination</TableHead>
                  <TableHead>Matched Rule</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {details.recent_matches.map((match, idx) => (
                  <TableRow key={idx}>
                    <TableCell className="text-muted-foreground text-sm">
                      {isValidDate(match.timestamp)
                        ? format(new Date(match.timestamp), "MMM d, HH:mm:ss")
                        : "—"
                      }
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{match.node_id}</Badge>
                    </TableCell>
                    <TableCell className="font-mono text-sm">
                      {match.source_ip}
                    </TableCell>
                    <TableCell className="max-w-[200px] truncate font-mono text-sm">
                      {match.destination}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {match.matched_rule}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
