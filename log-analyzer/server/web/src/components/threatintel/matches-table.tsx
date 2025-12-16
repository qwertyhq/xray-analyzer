"use client";

import { useState, useMemo, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ThreatMatch, ThreatType } from "@/lib/types";
import { format } from "date-fns";
import Link from "next/link";
import { threatTypeConfig, sourceLabels } from "./config";
import { Search, ChevronLeft, ChevronRight } from "lucide-react";

interface MatchesTableProps {
  matches: ThreatMatch[] | null;
  title: string;
  description: string;
}

export function MatchesTable({ matches: matchesProp, title, description }: MatchesTableProps) {
  const matches = matchesProp || [];
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [confidenceFilter, setConfidenceFilter] = useState<string>("all");
  const pageSize = 20;

  // Get unique threat types from matches - must be before any conditional returns
  const threatTypes = useMemo(() => {
    const types = new Set<ThreatType>();
    matches.forEach(m => types.add(m.threat_type));
    return Array.from(types).sort();
  }, [matches]);

  // Filter matches - must be before any conditional returns
  const filteredMatches = useMemo(() => {
    let result = [...matches];
    
    // Search filter
    if (search.trim()) {
      const searchLower = search.toLowerCase();
      result = result.filter(m => 
        (m.username && m.username.toLowerCase().includes(searchLower)) ||
        (m.user_email && m.user_email.toLowerCase().includes(searchLower)) ||
        m.destination.toLowerCase().includes(searchLower)
      );
    }
    
    // Type filter
    if (typeFilter !== "all") {
      result = result.filter(m => m.threat_type === typeFilter);
    }
    
    // Confidence filter
    if (confidenceFilter !== "all") {
      const minConf = parseInt(confidenceFilter);
      result = result.filter(m => m.confidence >= minConf);
    }
    
    return result;
  }, [matches, search, typeFilter, confidenceFilter]);

  const totalPages = Math.ceil(filteredMatches.length / pageSize);
  const paginatedMatches = filteredMatches.slice((page - 1) * pageSize, page * pageSize);

  // Reset page when filters change - must be before any conditional returns
  useEffect(() => {
    setPage(1);
  }, [search, typeFilter, confidenceFilter]);

  // If no matches at all, show empty state - AFTER all hooks
  if (matches.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-base sm:text-lg">{title}</CardTitle>
          <CardDescription className="text-xs sm:text-sm">{description}</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="text-center py-12 text-muted-foreground">
            <div className="text-4xl mb-4">🔍</div>
            <p className="text-sm">Нет недавней активности для этой категории</p>
            <p className="text-xs mt-2 max-w-md mx-auto">
              Статистика выше показывает общее число детекций за всё время. 
              Детальные записи хранятся 30 дней — возможно, активность этого типа была давно.
            </p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-col gap-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <CardTitle className="text-base sm:text-lg">{title}</CardTitle>
              <CardDescription className="text-xs sm:text-sm">{description}</CardDescription>
            </div>
            <div className="text-sm text-muted-foreground">
              {filteredMatches.length} из {matches.length}
            </div>
          </div>
          
          {/* Filters */}
          <div className="flex flex-wrap gap-2">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Поиск по email или destination..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-8 h-9"
              />
            </div>
            <Select value={typeFilter} onValueChange={setTypeFilter}>
              <SelectTrigger className="w-[130px] h-9">
                <SelectValue placeholder="Тип" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Все типы</SelectItem>
                {threatTypes.map(type => {
                  const config = threatTypeConfig[type];
                  return (
                    <SelectItem key={type} value={type}>
                      {config?.label || type}
                    </SelectItem>
                  );
                })}
              </SelectContent>
            </Select>
            <Select value={confidenceFilter} onValueChange={setConfidenceFilter}>
              <SelectTrigger className="w-[130px] h-9">
                <SelectValue placeholder="Confidence" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Все</SelectItem>
                <SelectItem value="90">≥ 90%</SelectItem>
                <SelectItem value="80">≥ 80%</SelectItem>
                <SelectItem value="50">≥ 50%</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      </CardHeader>
      <CardContent className="max-h-[500px] overflow-y-auto overflow-x-auto scrollbar-thin">
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
                      href={`/users/${encodeURIComponent(match.username || match.user_email || '')}`}
                      className="hover:underline text-primary truncate block"
                    >
                      {match.username || match.user_email || 'Unknown'}
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
            {filteredMatches.length === 0 && (
              <TableRow>
                <TableCell colSpan={6} className="text-center text-muted-foreground py-8">
                  Совпадений не найдено
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </CardContent>
      
      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between p-4 pt-2 border-t">
          <p className="text-sm text-muted-foreground">
            Страница {page} из {totalPages}
          </p>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
            >
              <ChevronLeft className="h-4 w-4" />
              Назад
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
            >
              Далее
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}
    </Card>
  );
}