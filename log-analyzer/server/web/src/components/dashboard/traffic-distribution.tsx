"use client";

import { useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { NodeStats } from "@/lib/types";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from "recharts";

interface TrafficDistributionProps {
  nodes: NodeStats[];
  title?: string;
}

const COLORS = [
  "hsl(262, 83%, 58%)", // purple
  "hsl(142, 71%, 45%)", // green
  "hsl(38, 92%, 50%)",  // orange
  "hsl(199, 89%, 48%)", // blue
  "hsl(340, 82%, 52%)", // pink
  "hsl(172, 66%, 50%)", // teal
  "hsl(291, 64%, 42%)", // violet
  "hsl(25, 95%, 53%)",  // red-orange
  "hsl(221, 83%, 53%)", // indigo
  "hsl(47, 96%, 53%)",  // yellow
];

export function TrafficDistribution({ nodes, title = "Traffic by Node" }: TrafficDistributionProps) {
  const chartData = useMemo(() => {
    if (!nodes || nodes.length === 0) return [];
    return nodes
      .filter(n => n.total_requests > 0)
      .map(node => ({
        name: node.node_id,
        value: node.total_requests,
        blacklist: node.blacklist_hits,
        users: node.unique_users,
        online: node.is_connected,
      }))
      .sort((a, b) => b.value - a.value);
  }, [nodes]);

  const totalRequests = chartData.reduce((sum, d) => sum + d.value, 0);

  if (chartData.length === 0) {
    return (
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium">{title}</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-center py-8 text-muted-foreground">
            <p className="text-sm">No traffic data available</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload;
      const percentage = ((data.value / totalRequests) * 100).toFixed(1);
      return (
        <div className="bg-popover border rounded-lg shadow-lg p-3 text-sm">
          <p className="font-medium flex items-center gap-2">
            <span 
              className="w-2.5 h-2.5 rounded-full" 
              style={{ backgroundColor: payload[0].payload.fill }}
            />
            {data.name}
          </p>
          <div className="mt-1 space-y-0.5 text-xs text-muted-foreground">
            <p>Requests: <span className="text-foreground font-medium">{data.value.toLocaleString()}</span> ({percentage}%)</p>
            <p>Blacklist: <span className="text-foreground font-medium">{data.blacklist.toLocaleString()}</span></p>
            <p>Users: <span className="text-foreground font-medium">{data.users.toLocaleString()}</span></p>
            <p>Status: <span className={data.online ? "text-green-500" : "text-red-500"}>{data.online ? "Online" : "Offline"}</span></p>
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        <CardDescription className="text-xs">
          {totalRequests.toLocaleString()} total requests
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="h-[200px]">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={chartData}
                cx="50%"
                cy="50%"
                innerRadius={45}
                outerRadius={70}
                paddingAngle={2}
                dataKey="value"
              >
                {chartData.map((entry, index) => (
                  <Cell 
                    key={`cell-${index}`} 
                    fill={COLORS[index % COLORS.length]}
                    opacity={entry.online ? 1 : 0.5}
                    stroke="none"
                  />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
            </PieChart>
          </ResponsiveContainer>
        </div>
        
        {/* Legend */}
        <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1">
          {chartData.slice(0, 6).map((entry, index) => {
            const percentage = ((entry.value / totalRequests) * 100).toFixed(1);
            return (
              <div key={entry.name} className="flex items-center gap-1.5 text-xs">
                <span 
                  className={`w-2 h-2 rounded-full ${!entry.online && "opacity-50"}`}
                  style={{ backgroundColor: COLORS[index % COLORS.length] }}
                />
                <span className="truncate text-muted-foreground">{entry.name}</span>
                <span className="ml-auto font-medium">{percentage}%</span>
              </div>
            );
          })}
        </div>
        {chartData.length > 6 && (
          <p className="text-[10px] text-muted-foreground text-center mt-1">
            +{chartData.length - 6} more nodes
          </p>
        )}
      </CardContent>
    </Card>
  );
}
