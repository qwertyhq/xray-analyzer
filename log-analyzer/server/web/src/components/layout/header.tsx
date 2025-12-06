"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import { Activity, ShieldAlert, LogOut } from "lucide-react";
import { useAuth } from "@/contexts/auth-context";
import { Button } from "@/components/ui/button";

const navItems = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/nodes", label: "Nodes" },
  { href: "/users", label: "Users" },
  { href: "/blacklist", label: "Blacklist" },
  { href: "/threatintel", label: "Threat Intel", icon: ShieldAlert },
];

export function Header() {
  const pathname = usePathname();
  const { isAuthenticated, logout } = useAuth();

  // Don't show header on login page
  if (pathname === "/login") {
    return null;
  }

  return (
    <header className="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="flex h-14 items-center px-4 md:px-8">
        <Link href="/dashboard" className="flex items-center gap-2 font-bold">
          <Activity className="h-5 w-5 text-primary" />
          <span>Xray Analyzer</span>
        </Link>

        <nav className="ml-8 flex items-center gap-6">
          {navItems.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "text-sm font-medium transition-colors hover:text-primary flex items-center gap-1",
                pathname === item.href
                  ? "text-foreground"
                  : "text-muted-foreground"
              )}
            >
              {item.icon && <item.icon className="h-3.5 w-3.5" />}
              {item.label}
            </Link>
          ))}
        </nav>

        <div className="ml-auto flex items-center gap-4">
          <span className="text-xs text-muted-foreground">
            analyzer.z-hq.com
          </span>
          {isAuthenticated && (
            <Button
              variant="ghost"
              size="sm"
              onClick={logout}
              className="text-muted-foreground hover:text-foreground"
            >
              <LogOut className="h-4 w-4 mr-1" />
              Выход
            </Button>
          )}
        </div>
      </div>
    </header>
  );
}
