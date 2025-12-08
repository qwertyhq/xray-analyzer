"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import { Activity, ShieldAlert, LogOut, Menu, X, Smartphone } from "lucide-react";
import { useAuth } from "@/contexts/auth-context";
import { Button } from "@/components/ui/button";
import { ThemeToggle } from "@/components/ui/theme-toggle";

const navItems = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/nodes", label: "Nodes" },
  { href: "/users", label: "Users" },
  { href: "/blacklist", label: "Blacklist" },
  { href: "/threatintel", label: "Threat Intel", icon: ShieldAlert },
  { href: "/remnawave", label: "Remnawave", icon: Smartphone },
];

export function Header() {
  const pathname = usePathname();
  const { isAuthenticated, logout } = useAuth();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // Don't show header on login page
  if (pathname === "/login") {
    return null;
  }

  return (
    <header className="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="flex h-14 items-center px-4 md:px-8">
        <Link href="/dashboard" className="flex items-center gap-2 font-bold">
          <Activity className="h-5 w-5 text-primary" />
          <span className="hidden sm:inline">Xray Analyzer</span>
          <span className="sm:hidden">Xray</span>
        </Link>

        {/* Desktop navigation */}
        <nav className="ml-8 hidden md:flex items-center gap-6">
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

        <div className="ml-auto flex items-center gap-2">
          <span className="text-xs text-muted-foreground hidden lg:block">
            analyzer.z-hq.com
          </span>
          <ThemeToggle />
          {isAuthenticated && (
            <Button
              variant="ghost"
              size="sm"
              onClick={logout}
              className="text-muted-foreground hover:text-foreground hidden md:flex"
            >
              <LogOut className="h-4 w-4 mr-1" />
              Выход
            </Button>
          )}
          
          {/* Mobile menu button */}
          <Button
            variant="ghost"
            size="sm"
            className="md:hidden"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          >
            {mobileMenuOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </Button>
        </div>
      </div>

      {/* Mobile navigation */}
      {mobileMenuOpen && (
        <div className="md:hidden border-t bg-background">
          <nav className="flex flex-col p-4 space-y-3">
            {navItems.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                onClick={() => setMobileMenuOpen(false)}
                className={cn(
                  "text-sm font-medium transition-colors hover:text-primary flex items-center gap-2 py-2",
                  pathname === item.href
                    ? "text-foreground"
                    : "text-muted-foreground"
                )}
              >
                {item.icon && <item.icon className="h-4 w-4" />}
                {item.label}
              </Link>
            ))}
            <div className="pt-2 border-t">
              {isAuthenticated && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    logout();
                    setMobileMenuOpen(false);
                  }}
                  className="text-muted-foreground hover:text-foreground w-full justify-start"
                >
                  <LogOut className="h-4 w-4 mr-2" />
                  Выход
                </Button>
              )}
            </div>
          </nav>
        </div>
      )}
    </header>
  );
}
