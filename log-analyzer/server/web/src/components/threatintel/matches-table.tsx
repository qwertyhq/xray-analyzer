"use client";

import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ThreatMatch } from "@/lib/types";
import { format } from "date-fns";
import Link from "next/link";
import { threatTypeConfig, sourceLabels } from "./config";

interface MatchesTableProps {
  matches: ThreatMatch[];
  title: string;
  description: string;
}

export function MatchesTable({ matches, title, description }: MatchesTableProps) {
  const [page, setPage] = useState(1);
  const pageSize = 20;
  const totalPages = Math.ceil(matches.length / pageSize);
  const paginatedMatches = matches.slice((page - 1) * pageSize, page * pageSize);

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>{title}</CardTitle>
            <CardDescription>{description}</CardDescription>
          </div>
          {totalPages > 1 && (
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="px-3 py-1 text-sm border rounded hover:bg-muted disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Prev
              </button>
              <span className="text-sm text-muted-foreground">
                Page {page} of {totalPages}
              </span>
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                className="px-3 py-1 text-sm border rounded hover:bg-muted disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Next
              </button>
            </div>
          )}
        </div>
      </CardHeader>
      <CardContent className="max-h-[500px] overflow-y-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Time</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>User</TableHead>
              <TableHead>Destination</TableHead>
              <TableHead>Source</TableHead>
              <TableHead className="text-right">Confidence</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {paginatedMatches.map((match) => {
              const config = threatTypeConfig[match.threat_type] || threatTypeConfig.malware;
              return (
                <TableRow key={match.id}>
                  <TableCell className="text-muted-foreground whitespace-nowrap">
                    {format(new Date(match.matched_at), "MMM d, HH:mm")}
                  </TableCell>
                  <TableCell>
                    <Badge className={`${config.color} text-white`}>
                      {config.label}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Link
                      href={`/users/${encodeURIComponent(match.user_email)}`}
                      className="hover:underline text-primary"
                    >
                      {match.user_email}
                    </Link>
                  </TableCell>
                  <TableCell className="font-mono text-sm max-w-[250px] truncate">
                    {match.destination}
                  </TableCell>
                  <TableCell className="text-muted-foreground text-sm">
                    {sourceLabels[match.source] || match.source}
                  </TableCell>
                  <TableCell className="text-right">
                    <Badge
                      variant={match.confidence >= 80 ? "destructive" : "secondary"}
                    >
                      {match.confidence}%
                    </Badge>
                  </TableCell>
                </TableRow>
              );
            })}
            {matches.length === 0 && (
              <TableRow>
                <TableCell colSpan={6} className="text-center text-muted-foreground py-8">
                  No matches detected
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}
