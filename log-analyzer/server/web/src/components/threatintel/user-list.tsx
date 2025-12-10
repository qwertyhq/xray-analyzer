"use client";

import { Badge } from "@/components/ui/badge";
import { CategoryUserStats } from "@/lib/types";
import Link from "next/link";

interface UserListProps {
  users: CategoryUserStats[];
  maxHeight?: string;
}

export function UserList({ users, maxHeight = "300px" }: UserListProps) {
  if (users.length === 0) {
    return (
      <div className="py-6 text-center text-sm text-muted-foreground">
        Нет данных
      </div>
    );
  }

  return (
    <div className="space-y-2 overflow-y-auto scrollbar-thin" style={{ maxHeight }}>
      {users.map((user, idx) => (
        <div key={`${user.user_email}-${idx}`} className="flex items-start gap-2 overflow-hidden py-1">
          <span className="text-xs font-medium w-5 text-muted-foreground shrink-0">
            {idx + 1}.
          </span>
          
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between gap-2">
              <Link
                href={`/users/${encodeURIComponent(user.user_email)}`}
                className="text-sm hover:underline truncate"
                title={user.username || user.user_email}
              >
                {user.username || user.user_email}
              </Link>
              <Badge variant="secondary" className="text-xs font-mono shrink-0">
                {user.match_count}
              </Badge>
            </div>
            
            {user.domains && user.domains.length > 0 && (
              <div className="mt-0.5 text-xs text-muted-foreground truncate" title={user.domains.join(", ")}>
                {user.domains.slice(0, 2).join(", ")}
                {user.domains.length > 2 && ` +${user.domains.length - 2}`}
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
