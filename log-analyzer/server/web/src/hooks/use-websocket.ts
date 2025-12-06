"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { Stats, NodeStats, HourlyStats, Anomaly, BlacklistAnalytics } from "@/lib/types";

interface DashboardState {
  stats: Stats;
  nodes: NodeStats[];
  hourly: HourlyStats[];
  anomalies: Anomaly[];
  blacklist: BlacklistAnalytics | null;
  connected: boolean;
  loading: boolean;
}

const defaultStats: Stats = {
  total_requests: 0,
  total_blacklist: 0,
  nodes_total: 0,
  nodes_connected: 0,
  total_unique_users: 0,
  online_users: 0,
};

interface DashboardUpdate {
  type: string;
  data: unknown;
}

export function useDashboardWebSocket() {
  const [state, setState] = useState<DashboardState>({
    stats: defaultStats,
    nodes: [],
    hourly: [],
    anomalies: [],
    blacklist: null,
    connected: false,
    loading: true,
  });

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const reconnectAttempts = useRef(0);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      return;
    }

    // Determine WebSocket URL
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const host = window.location.host;
    
    // Use same host - Next.js rewrites will proxy to Go backend
    const wsUrl = `${protocol}//${host}/ws/dashboard`;

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
            case "hourly":
              return { ...prev, hourly: update.data as HourlyStats[] };
            case "anomalies":
              return { ...prev, anomalies: update.data as Anomaly[] };
            case "blacklist":
              return { ...prev, blacklist: update.data as BlacklistAnalytics };
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

  return state;
}
