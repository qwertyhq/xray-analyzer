"use client";

import { useEffect, useRef, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { 
  Activity, 
  ShieldAlert, 
  UserPlus, 
  Server,
  AlertTriangle,
  Globe,
  Ban,
  CheckCircle,
  Filter
} from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuCheckboxItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

export type EventType = 
  | "blacklist_hit" 
  | "threat_match" 
  | "user_online" 
  | "node_status" 
  | "anomaly"
  | "sync";

export interface FeedEvent {
  id: string;
  type: EventType;
  message: string;
  details?: string;
  timestamp: string;
  severity?: "info" | "warning" | "error";
  link?: string;
}

interface RealTimeFeedProps {
  events: FeedEvent[];
  maxEvents?: number;
  title?: string;
}

const eventIcons: Record<EventType, React.ReactNode> = {
  blacklist_hit: <Ban className="h-3.5 w-3.5" />,
  threat_match: <ShieldAlert className="h-3.5 w-3.5" />,
  user_online: <UserPlus className="h-3.5 w-3.5" />,
  node_status: <Server className="h-3.5 w-3.5" />,
  anomaly: <AlertTriangle className="h-3.5 w-3.5" />,
  sync: <CheckCircle className="h-3.5 w-3.5" />,
};

const eventColors: Record<EventType, string> = {
  blacklist_hit: "bg-red-500/10 text-red-500 border-red-500/20",
  threat_match: "bg-orange-500/10 text-orange-500 border-orange-500/20",
  user_online: "bg-green-500/10 text-green-500 border-green-500/20",
  node_status: "bg-blue-500/10 text-blue-500 border-blue-500/20",
  anomaly: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
  sync: "bg-purple-500/10 text-purple-500 border-purple-500/20",
};

const eventLabels: Record<EventType, string> = {
  blacklist_hit: "Blacklist",
  threat_match: "Threat",
  user_online: "User",
  node_status: "Node",
  anomaly: "Anomaly",
  sync: "Sync",
};

export function RealTimeFeed({ events, maxEvents = 50, title = "Real-time Feed" }: RealTimeFeedProps) {
  const [filter, setFilter] = useState<Set<EventType>>(new Set(Object.keys(eventIcons) as EventType[]));
  const [newEventIds, setNewEventIds] = useState<Set<string>>(new Set());
  const prevEventsRef = useRef<Set<string>>(new Set());
  const scrollRef = useRef<HTMLDivElement>(null);

  // Track new events for animation
  useEffect(() => {
    const currentIds = new Set(events.map(e => e.id));
    const newIds = new Set<string>();
    
    currentIds.forEach(id => {
      if (!prevEventsRef.current.has(id)) {
        newIds.add(id);
      }
    });
    
    if (newIds.size > 0) {
      setNewEventIds(newIds);
      
      // Remove highlight after animation
      const timer = setTimeout(() => {
        setNewEventIds(new Set());
      }, 2000);
      
      return () => clearTimeout(timer);
    }
    
    prevEventsRef.current = currentIds;
  }, [events]);

  useEffect(() => {
    prevEventsRef.current = new Set(events.map(e => e.id));
  }, [events]);

  const filteredEvents = events
    .filter(e => filter.has(e.type))
    .slice(0, maxEvents);

  const toggleFilter = (type: EventType) => {
    setFilter(prev => {
      const next = new Set(prev);
      if (next.has(type)) {
        next.delete(type);
      } else {
        next.add(type);
      }
      return next;
    });
  };

  return (
    <Card className="flex flex-col h-full max-h-[500px]">
      <CardHeader className="pb-3 flex-none">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Activity className="h-4 w-4 text-green-500" />
            {title}
            <Badge variant="secondary" className="text-xs animate-pulse">
              Live
            </Badge>
          </CardTitle>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="sm" className="h-7 px-2">
                <Filter className="h-3.5 w-3.5" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              {(Object.keys(eventIcons) as EventType[]).map(type => (
                <DropdownMenuCheckboxItem
                  key={type}
                  checked={filter.has(type)}
                  onCheckedChange={() => toggleFilter(type)}
                >
                  <span className="flex items-center gap-2">
                    {eventIcons[type]}
                    {eventLabels[type]}
                  </span>
                </DropdownMenuCheckboxItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </CardHeader>
      <CardContent className="flex-1 overflow-hidden p-0 min-h-0">
        <div
          ref={scrollRef}
          className="h-full overflow-y-auto scrollbar-thin px-4 pb-4"
        >
          {filteredEvents.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Activity className="h-8 w-8 mx-auto mb-2 opacity-30" />
              <p className="text-sm">No events to display</p>
            </div>
          ) : (
            <div className="space-y-2">
              {filteredEvents.map((event) => {
                const isNew = newEventIds.has(event.id);
                return (
                  <div
                    key={event.id}
                    className={`flex items-start gap-2 p-2 rounded-lg border transition-all duration-300 ${
                      eventColors[event.type]
                    } ${isNew ? "animate-fade-in-row ring-1 ring-primary/50" : ""}`}
                  >
                    <div className="mt-0.5">{eventIcons[event.type]}</div>
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-medium truncate">{event.message}</p>
                      {event.details && (
                        <p className="text-[10px] text-muted-foreground truncate">
                          {event.details}
                        </p>
                      )}
                    </div>
                    <span className="text-[10px] text-muted-foreground whitespace-nowrap">
                      {formatDistanceToNow(new Date(event.timestamp), { addSuffix: true })}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
