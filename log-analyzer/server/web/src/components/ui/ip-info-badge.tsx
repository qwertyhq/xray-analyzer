"use client";

import { useState, useEffect } from "react";
import { authFetch } from "@/contexts/auth-context";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { MapPin, Wifi, Server, Shield, Smartphone } from "lucide-react";
import { IPInfo } from "@/lib/types";

interface IPInfoBadgeProps {
  ip: string;
  showFull?: boolean;
  className?: string;
}

// Cache for IP info to avoid repeated API calls
const ipInfoCache = new Map<string, IPInfo>();

export function IPInfoBadge({ ip, showFull = false, className }: IPInfoBadgeProps) {
  const [info, setInfo] = useState<IPInfo | null>(ipInfoCache.get(ip) || null);
  const [loading, setLoading] = useState(!ipInfoCache.has(ip));

  useEffect(() => {
    if (ipInfoCache.has(ip)) {
      setInfo(ipInfoCache.get(ip)!);
      setLoading(false);
      return;
    }

    const fetchInfo = async () => {
      try {
        const res = await authFetch(`/api/ipinfo?ip=${encodeURIComponent(ip)}`);
        if (res.ok) {
          const data: IPInfo = await res.json();
          ipInfoCache.set(ip, data);
          setInfo(data);
        }
      } catch {
        // Ignore errors
      } finally {
        setLoading(false);
      }
    };

    fetchInfo();
  }, [ip]);

  if (loading) {
    return <Skeleton className="h-5 w-20" />;
  }

  if (!info || info.country === "Private") {
    return (
      <span className={`font-mono text-xs text-muted-foreground ${className}`}>
        {ip}
      </span>
    );
  }

  // Country flag emoji from country code
  const flagEmoji = info.country_code
    ? String.fromCodePoint(...[...info.country_code.toUpperCase()].map(c => 0x1F1E6 - 65 + c.charCodeAt(0)))
    : "";

  if (showFull) {
    return (
      <div className={`flex items-center gap-2 ${className}`}>
        <span className="text-lg">{flagEmoji}</span>
        <div className="flex flex-col">
          <span className="text-sm font-medium">
            {info.city}, {info.country}
          </span>
          <span className="text-xs text-muted-foreground">
            {info.isp}
          </span>
        </div>
        <div className="flex gap-1 ml-2">
          {info.mobile && (
            <Badge variant="outline" className="text-xs">
              <Smartphone className="h-3 w-3 mr-1" />
              Mobile
            </Badge>
          )}
          {info.proxy && (
            <Badge variant="destructive" className="text-xs">
              <Shield className="h-3 w-3 mr-1" />
              VPN/Proxy
            </Badge>
          )}
          {info.hosting && (
            <Badge variant="secondary" className="text-xs">
              <Server className="h-3 w-3 mr-1" />
              Hosting
            </Badge>
          )}
        </div>
      </div>
    );
  }

  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <span className={`inline-flex items-center gap-1 cursor-help ${className}`}>
            <span>{flagEmoji}</span>
            <span className="text-xs">
              {info.city || info.country}
            </span>
            {info.proxy && <Shield className="h-3 w-3 text-destructive" />}
            {info.mobile && <Smartphone className="h-3 w-3 text-muted-foreground" />}
          </span>
        </TooltipTrigger>
        <TooltipContent className="max-w-xs">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <MapPin className="h-3 w-3" />
              <span>{info.city}, {info.region}, {info.country}</span>
            </div>
            <div className="flex items-center gap-2">
              <Wifi className="h-3 w-3" />
              <span className="text-xs">{info.isp}</span>
            </div>
            {info.org && info.org !== info.isp && (
              <div className="flex items-center gap-2">
                <Server className="h-3 w-3" />
                <span className="text-xs">{info.org}</span>
              </div>
            )}
            <div className="flex gap-1 mt-1">
              {info.mobile && <Badge variant="outline" className="text-xs">Mobile</Badge>}
              {info.proxy && <Badge variant="destructive" className="text-xs">VPN/Proxy</Badge>}
              {info.hosting && <Badge variant="secondary" className="text-xs">Datacenter</Badge>}
            </div>
            <div className="text-xs text-muted-foreground mt-1 font-mono">
              {ip}
            </div>
          </div>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}
