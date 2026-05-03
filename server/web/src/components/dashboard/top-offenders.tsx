"use client";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { 
  AlertTriangle, 
  User, 
  ExternalLink,
  ShieldAlert,
  TrendingUp
} from "lucide-react";
import Link from "next/link";

interface TopOffender {
  user_email: string;
  blacklist_hits: number;
  threat_matches?: number;
  risk_score?: number;
  last_seen?: string;
}

interface TopOffendersProps {
  users: TopOffender[];
  title?: string;
  maxItems?: number;
}

function getRiskBadge(score: number) {
  if (score >= 70) return <Badge variant="destructive" className="text-xs">Critical</Badge>;
  if (score >= 50) return <Badge className="bg-orange-500 text-white text-xs">High</Badge>;
  if (score >= 30) return <Badge className="bg-yellow-500 text-white text-xs">Medium</Badge>;
  return <Badge variant="secondary" className="text-xs">Low</Badge>;
}

export function TopOffenders({ users, title = "Top Offenders", maxItems = 5 }: TopOffendersProps) {
  const topUsers = users.slice(0, maxItems);

  if (users.length === 0) {
    return (
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-orange-500" />
            {title}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-center py-6 text-muted-foreground">
            <ShieldAlert className="h-8 w-8 mx-auto mb-2 opacity-30" />
            <p className="text-sm">No problem users detected</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  const maxHits = Math.max(...topUsers.map(u => u.blacklist_hits), 1);

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-medium flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 text-orange-500" />
          {title}
        </CardTitle>
        <CardDescription className="text-xs">
          Users with most blacklist hits
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {topUsers.map((user, index) => {
          const percentage = (user.blacklist_hits / maxHits) * 100;
          return (
            <div key={user.user_email} className="space-y-1.5">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 min-w-0">
                  <span className={`text-sm font-bold w-5 ${
                    index === 0 ? "text-red-500" :
                    index === 1 ? "text-orange-500" :
                    index === 2 ? "text-yellow-500" :
                    "text-muted-foreground"
                  }`}>
                    #{index + 1}
                  </span>
                  <Link 
                    href={`/users/${encodeURIComponent(user.user_email)}`}
                    className="text-sm font-medium truncate hover:underline text-primary flex items-center gap-1"
                  >
                    {user.user_email}
                    <ExternalLink className="h-3 w-3 opacity-50" />
                  </Link>
                </div>
                <div className="flex items-center gap-2">
                  {user.risk_score !== undefined && getRiskBadge(user.risk_score)}
                  <Badge variant="destructive" className="font-mono text-xs">
                    {user.blacklist_hits.toLocaleString()}
                  </Badge>
                </div>
              </div>
              <div className="h-1 bg-muted rounded-full overflow-hidden ml-7">
                <div 
                  className={`h-full rounded-full transition-all ${
                    index === 0 ? "bg-red-500" :
                    index === 1 ? "bg-orange-500" :
                    index === 2 ? "bg-yellow-500" :
                    "bg-muted-foreground"
                  }`}
                  style={{ width: `${percentage}%` }}
                />
              </div>
            </div>
          );
        })}
        
        <Link 
          href="/users?sort=blacklist_hits&order=desc"
          className="block text-center text-xs text-primary hover:underline pt-2"
        >
          View all users →
        </Link>
      </CardContent>
    </Card>
  );
}
