"use client";

import { Badge } from "@/components/ui/badge";
import { CategoryUserStats } from "@/lib/types";
import Link from "next/link";

interface UserListProps {
  users: CategoryUserStats[];
}

export function UserList({ users }: UserListProps) {
  if (users.length === 0) {
    return (
      <div className="py-6 text-center text-sm text-muted-foreground">
        Нет данных
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {users.map((user, idx) => (
        <div key={user.user_email} className="flex items-start gap-2.5">
          <span className={`text-sm font-medium w-4 ${
            idx === 0 ? "text-yellow-500" :
            idx === 1 ? "text-gray-400" :
            idx === 2 ? "text-amber-600" :
            "text-muted-foreground"
          }`}>
            {idx + 1}.
          </span>
          
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between gap-2">
              <Link
                href={`/users/${encodeURIComponent(user.user_email)}`}
                className="text-sm hover:underline truncate"
                title={user.user_email}
              >
                {user.user_email}
              </Link>
              <Badge variant="secondary" className="text-xs font-mono">
                {user.match_count}
              </Badge>
            </div>
            
            {user.domains && user.domains.length > 0 && (
              <div className="mt-1 text-xs text-muted-foreground truncate" title={user.domains.join(", ")}>
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
