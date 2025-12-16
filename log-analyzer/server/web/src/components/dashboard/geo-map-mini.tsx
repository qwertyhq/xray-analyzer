"use client";

import { useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Globe, MapPin } from "lucide-react";

interface GeoData {
  country: string;
  country_code: string;
  count: number;
  users: number;
}

interface GeoMapMiniProps {
  data: GeoData[];
  title?: string;
  maxItems?: number;
}

// Country flag emoji from country code
function getFlag(countryCode: string): string {
  if (!countryCode || countryCode.length !== 2) return "🌍";
  const codePoints = countryCode
    .toUpperCase()
    .split("")
    .map(char => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}

// Color based on count
function getCountryColor(count: number, max: number): string {
  const intensity = count / max;
  if (intensity < 0.2) return "bg-blue-500/20 text-blue-600";
  if (intensity < 0.4) return "bg-blue-500/40 text-blue-600";
  if (intensity < 0.6) return "bg-blue-500/60 text-blue-100";
  if (intensity < 0.8) return "bg-blue-500/80 text-white";
  return "bg-blue-600 text-white";
}

export function GeoMapMini({ data, title = "Geographic Distribution", maxItems = 8 }: GeoMapMiniProps) {
  const sortedData = useMemo(() => {
    if (!data || data.length === 0) return [];
    return [...data]
      .sort((a, b) => b.count - a.count)
      .slice(0, maxItems);
  }, [data, maxItems]);

  const totalCount = useMemo(() => (data || []).reduce((sum, d) => sum + d.count, 0), [data]);
  const maxCount = sortedData[0]?.count || 1;

  if (!data || data.length === 0) {
    return (
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Globe className="h-4 w-4 text-blue-500" />
            {title}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-center py-6 text-muted-foreground">
            <Globe className="h-8 w-8 mx-auto mb-2 opacity-30" />
            <p className="text-sm">No geographic data available</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-medium flex items-center gap-2">
          <Globe className="h-4 w-4 text-blue-500" />
          {title}
        </CardTitle>
        <CardDescription className="text-xs">
          {data.length} countries • {totalCount.toLocaleString()} total connections
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-2">
          {sortedData.map((item, index) => {
            const percentage = ((item.count / totalCount) * 100).toFixed(1);
            return (
              <div 
                key={item.country_code} 
                className="flex items-center gap-2"
              >
                <span className="text-lg w-6">{getFlag(item.country_code)}</span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm font-medium truncate">{item.country}</span>
                    <div className="flex items-center gap-2">
                      <Badge variant="secondary" className="text-xs">
                        {item.users} users
                      </Badge>
                      <span className="text-xs text-muted-foreground w-12 text-right">
                        {percentage}%
                      </span>
                    </div>
                  </div>
                  <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                    <div 
                      className="h-full bg-blue-500 rounded-full transition-all"
                      style={{ width: `${percentage}%` }}
                    />
                  </div>
                </div>
              </div>
            );
          })}
        </div>
        
        {data.length > maxItems && (
          <p className="text-xs text-muted-foreground text-center mt-3">
            +{data.length - maxItems} more countries
          </p>
        )}
      </CardContent>
    </Card>
  );
}
