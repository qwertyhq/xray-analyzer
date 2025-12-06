"use client";

import React, { createContext, useContext, useState, useEffect, useRef, useCallback, ReactNode } from "react";
import { Stats, NodeStats, UserStats, HourlyStats, Anomaly, BlacklistAnalytics, ThreatStats, ThreatMatch, CategoryTopUsers } from "@/lib/types";

interface ThreatIntelData {
  stats: ThreatStats | null;
  matches: ThreatMatch[];
  topUsers: CategoryTopUsers | null;
}

interface WebSocketState {
  stats: Stats;
  nodes: NodeStats[];
  users: UserStats[];
  hourly: HourlyStats[];
  anomalies: Anomaly[];
  blacklist: BlacklistAnalytics | null;
  threatIntel: ThreatIntelData;
  connected: boolean;
  loading: boolean;
}

interface WebSocketContextValue extends WebSocketState {
  refetch: () => void;
}

const defaultStats: Stats = {
  total_requests: 0,
  total_blacklist: 0,
  nodes_total: 0,
  nodes_connected: 0,
  total_unique_users: 0,
  online_users: 0,
};

const defaultState: WebSocketState = {
  stats: defaultStats,
  nodes: [],
  users: [],
  hourly: [],
  anomalies: [],
  blacklist: null,
  threatIntel: { stats: null, matches: [], topUsers: null },
  connected: false,
  loading: true,
};

const WebSocketContext = createContext<WebSocketContextValue | null>(null);

interface DashboardUpdate {
  type: string;
  data: unknown;
}

// Get WebSocket URL based on environment
function getWebSocketUrl(): string {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const hostname = window.location.hostname;
  const port = window.location.port;
  
  // Development: Next.js on port 3925, Go backend on 8237 (same host)
  if (port === "3925") {
    return `ws://${hostname}:8237/ws/dashboard`;
  }
  
  // Production with Caddy/nginx: WebSocket proxied through same host
  // Caddy handles /ws/* routing to backend
  return `${protocol}//${window.location.host}/ws/dashboard`;
}

export function WebSocketProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<WebSocketState>(defaultState);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const reconnectAttempts = useRef(0);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      return;
    }

    const wsUrl = getWebSocketUrl();
    console.log("[WS] Connecting to:", wsUrl);
    
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      console.log("[WS] Connected");
      setState(prev => ({ ...prev, connected: true, loading: false }));
      reconnectAttempts.current = 0;
    };

    ws.onmessage = (event) => {
      try {
        const update: DashboardUpdate = JSON.parse(event.data);
        
        setState(prev => {
          switch (update.type) {
            case "stats":
              return { ...prev, stats: update.data as Stats };
            case "nodes":
              return { ...prev, nodes: update.data as NodeStats[] };
            case "users":
              return { ...prev, users: update.data as UserStats[] };
            case "hourly":
              return { ...prev, hourly: update.data as HourlyStats[] };
            case "anomalies":
              return { ...prev, anomalies: update.data as Anomaly[] };
            case "blacklist":
              return { ...prev, blacklist: update.data as BlacklistAnalytics };
            case "threatintel":
              return { ...prev, threatIntel: update.data as ThreatIntelData };
            default:
              return prev;
          }
        });
      } catch (err) {
        console.error("[WS] Parse error:", err);
      }
    };

    ws.onclose = (event) => {
      console.log("[WS] Disconnected:", event.code, event.reason);
      setState(prev => ({ ...prev, connected: false }));
      wsRef.current = null;

      // Reconnect with exponential backoff
      const delay = Math.min(1000 * Math.pow(2, reconnectAttempts.current), 30000);
      reconnectAttempts.current++;
      
      console.log(`[WS] Reconnecting in ${delay}ms...`);
      reconnectTimeoutRef.current = setTimeout(connect, delay);
    };

    ws.onerror = (error) => {
      console.error("[WS] Error:", error);
    };
  }, []);

  const refetch = useCallback(() => {
    // Force reconnect to get fresh data
    if (wsRef.current) {
      wsRef.current.close();
    }
  }, []);

  useEffect(() => {
    connect();

    return () => {
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [connect]);

  return (
    <WebSocketContext.Provider value={{ ...state, refetch }}>
      {children}
    </WebSocketContext.Provider>
  );
}

export function useWebSocket(): WebSocketContextValue {
  const context = useContext(WebSocketContext);
  if (!context) {
    throw new Error("useWebSocket must be used within a WebSocketProvider");
  }
  return context;
}

// Convenient individual hooks that use the global WebSocket
export function useWsStats() {
  const { stats, loading, connected } = useWebSocket();
  return { stats, loading, connected };
}

export function useWsNodes() {
  const { nodes, loading, connected, refetch } = useWebSocket();
  return { nodes, loading, connected, refetch };
}

export function useWsUsers() {
  const { users, loading, connected } = useWebSocket();
  return { users, loading, connected };
}

export function useWsBlacklist() {
  const { blacklist, loading, connected } = useWebSocket();
  return { blacklist, loading, connected };
}

export function useWsThreatIntel() {
  const { threatIntel, loading, connected } = useWebSocket();
  return { threatIntel, loading, connected };
}
