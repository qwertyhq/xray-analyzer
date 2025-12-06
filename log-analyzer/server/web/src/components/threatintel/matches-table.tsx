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
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <CardTitle className="text-base sm:text-lg">{title}</CardTitle>
            <CardDescription className="text-xs sm:text-sm">{description}</CardDescription>
          </div>
          {totalPages > 1 && (
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="px-2 sm:px-3 py-1 text-xs sm:text-sm border rounded hover:bg-muted disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Назад
              </button>
              <span className="text-xs sm:text-sm text-muted-foreground whitespace-nowrap">
                {page} / {totalPages}
              </span>
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                className="px-2 sm:px-3 py-1 text-xs sm:text-sm border rounded hover:bg-muted disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Далее
              </button>
            </div>
          )}
        </div>
      </CardHeader>
      <CardContent className="max-h-[500px] overflow-y-auto overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="whitespace-nowrap hidden sm:table-cell">Time</TableHead>
              <TableHead className="whitespace-nowrap">Type</TableHead>
              <TableHead className="whitespace-nowrap">User</TableHead>
              <TableHead className="whitespace-nowrap hidden md:table-cell">Destination</TableHead>
              <TableHead className="whitespace-nowrap hidden lg:table-cell">Source</TableHead>
              <TableHead className="text-right whitespace-nowrap hidden sm:table-cell">Conf</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {paginatedMatches.map((match) => {
              const config = threatTypeConfig[match.threat_type] || threatTypeConfig.malware;
              return (
                <TableRow key={match.id}>
                  <TableCell className="text-muted-foreground whitespace-nowrap hidden sm:table-cell">
                    {format(new Date(match.matched_at), "HH:mm")}
                  </TableCell>
                  <TableCell>
                    <Badge className={`${config.color} text-white text-xs`}>
                      {config.label}
                    </Badge>
                  </TableCell>
                  <TableCell className="max-w-[100px] sm:max-w-none">
                    <Link
                      href={`/users/${encodeURIComponent(match.user_email)}`}
                      className="hover:underline text-primary truncate block"
                    >
                      {match.user_email}
                    </Link>
                  </TableCell>
                  <TableCell className="font-mono text-xs sm:text-sm max-w-[200px] truncate hidden md:table-cell">
                    {match.destination}
                  </TableCell>
                  <TableCell className="text-muted-foreground text-sm hidden lg:table-cell">
                    {sourceLabels[match.source] || match.source}
                  </TableCell>
                  <TableCell className="text-right hidden sm:table-cell">
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
