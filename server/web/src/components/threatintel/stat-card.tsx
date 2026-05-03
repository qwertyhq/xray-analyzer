"use client";

import React from "react";
import { cn } from "@/lib/utils";
import { AnimatedNumber } from "@/components/ui/animated-number";

export type StatCardVariant = "default" | "danger" | "warning" | "success" | "info" | "muted";

interface StatCardProps {
  icon: React.ReactNode;
  label: string;
  value: string | number;
  subValue?: string;
  variant?: StatCardVariant;
  highlight?: boolean;
  className?: string;
}

const variantStyles: Record<StatCardVariant, string> = {
  default: "bg-card border border-border",
  danger: "bg-red-500/10 border border-red-500/20",
  warning: "bg-amber-500/10 border border-amber-500/20",
  success: "bg-emerald-500/10 border border-emerald-500/20",
  info: "bg-blue-500/10 border border-blue-500/20",
  muted: "bg-muted/50 border border-border",
};

const variantTextStyles: Record<StatCardVariant, string> = {
  default: "text-foreground",
  danger: "text-red-600 dark:text-red-400",
  warning: "text-amber-600 dark:text-amber-400",
  success: "text-emerald-600 dark:text-emerald-400",
  info: "text-blue-600 dark:text-blue-400",
  muted: "text-muted-foreground",
};

const variantIconStyles: Record<StatCardVariant, string> = {
  default: "text-muted-foreground",
  danger: "text-red-500",
  warning: "text-amber-500",
  success: "text-emerald-500",
  info: "text-blue-500",
  muted: "text-muted-foreground",
};

/**
 * Unified stat card component for displaying metrics.
 * Uses muted color palette for consistency across the application.
 */
export function StatCard({ 
  icon, 
  label, 
  value, 
  subValue, 
  variant = "default",
  highlight = false,
  className 
}: StatCardProps) {
  return (
    <div 
      className={cn(
        "relative overflow-hidden rounded-xl p-4 transition-all duration-200",
        variantStyles[variant],
        highlight && "ring-2 ring-offset-2 ring-offset-background ring-primary/50",
        "hover:shadow-md",
        className
      )}
    >
      <div className="relative z-10">
        <div className="flex items-center gap-2 mb-2">
          <span className={variantIconStyles[variant]}>{icon}</span>
          <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            {label}
          </span>
        </div>
        <div className={cn("text-2xl font-bold", variantTextStyles[variant])}>
          {typeof value === "number" ? <AnimatedNumber value={value} /> : value}
        </div>
        {subValue && (
          <div className="text-xs text-muted-foreground mt-1">{subValue}</div>
        )}
      </div>
    </div>
  );
}

/**
 * Grid container for stat cards with responsive layout.
 */
export function StatCardGrid({ 
  children, 
  columns = 4,
  className 
}: { 
  children: React.ReactNode; 
  columns?: 2 | 3 | 4 | 5;
  className?: string;
}) {
  const colsClass = {
    2: "md:grid-cols-2",
    3: "md:grid-cols-3",
    4: "md:grid-cols-4",
    5: "grid-cols-2 lg:grid-cols-5",
  };

  return (
    <div className={cn("grid gap-4", colsClass[columns], className)}>
      {children}
    </div>
  );
}
