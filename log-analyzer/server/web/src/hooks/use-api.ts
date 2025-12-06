"use client";

import { useState, useEffect, useCallback } from "react";
import { Stats, NodeStats, UserStats, HourlyStats, UserDetails, Anomaly, Alert, TimeRange } from "@/lib/types";

interface ApiState {
  stats: Stats;
  nodes: NodeStats[];
  users: UserStats[];
  loading: boolean;
  error: string | null;
}

const defaultStats: Stats = {
  total_requests: 0,
  total_blacklist: 0,
  nodes_total: 0,
  nodes_connected: 0,
  total_unique_users: 0,
  online_users: 0,
};

export function useApi(refreshInterval = 5000) {
  const [state, setState] = useState<ApiState>({
    stats: defaultStats,
    nodes: [],
    users: [],
    loading: true,
    error: null,
  });

  const fetchData = useCallback(async () => {
    try {
      const [statsRes, nodesRes, usersRes] = await Promise.all([
        fetch("/api/stats"),
        fetch("/api/nodes"),
        fetch("/api/users/all"),
      ]);

      const [stats, nodes, users] = await Promise.all([
        statsRes.ok ? statsRes.json() : defaultStats,
        nodesRes.ok ? nodesRes.json() : [],
        usersRes.ok ? usersRes.json() : [],
      ]);

      setState({
        stats,
        nodes,
        users,
        loading: false,
        error: null,
      });
    } catch (error) {
      setState((prev) => ({
        ...prev,
        loading: false,
        error: error instanceof Error ? error.message : "Failed to fetch data",
      }));
    }
  }, []);

  const deleteNode = useCallback(async (nodeId: string) => {
    try {
      const res = await fetch("/api/nodes/delete", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ node_id: nodeId }),
      });
      if (res.ok) {
        await fetchData();
        return true;
      }
      return false;
    } catch {
      return false;
    }
  }, [fetchData]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, refreshInterval);
    return () => clearInterval(interval);
  }, [fetchData, refreshInterval]);

  return { ...state, refetch: fetchData, deleteNode };
}

// Individual hooks for specific pages
export function useStats(refreshInterval = 5000) {
  const [stats, setStats] = useState<Stats>(defaultStats);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const res = await fetch("/api/stats");
        if (res.ok) setStats(await res.json());
      } catch {
        // ignore
      } finally {
        setLoading(false);
      }
    };

    fetchStats();
    const interval = setInterval(fetchStats, refreshInterval);
    return () => clearInterval(interval);
  }, [refreshInterval]);

  return { stats, loading };
}

export function useNodes(refreshInterval = 5000) {
  const [nodes, setNodes] = useState<NodeStats[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchNodes = useCallback(async () => {
    try {
      const res = await fetch("/api/nodes");
      if (res.ok) setNodes(await res.json());
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  }, []);

  const deleteNode = useCallback(async (nodeId: string) => {
    try {
      const res = await fetch("/api/nodes/delete", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ node_id: nodeId }),
      });
      if (res.ok) {
        await fetchNodes();
        return true;
      }
      return false;
    } catch {
      return false;
    }
  }, [fetchNodes]);

  useEffect(() => {
    fetchNodes();
    const interval = setInterval(fetchNodes, refreshInterval);
    return () => clearInterval(interval);
  }, [fetchNodes, refreshInterval]);

  return { nodes, loading, refetch: fetchNodes, deleteNode };
}

export function useUsers(refreshInterval = 5000) {
  const [users, setUsers] = useState<UserStats[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchUsers = async () => {
      try {
        const res = await fetch("/api/users/all");
        if (res.ok) setUsers(await res.json());
      } catch {
        // ignore
      } finally {
        setLoading(false);
      }
    };

    fetchUsers();
    const interval = setInterval(fetchUsers, refreshInterval);
    return () => clearInterval(interval);
  }, [refreshInterval]);

  return { users, loading };
}

export function useHourlyStats(hours = 24) {
  const [stats, setStats] = useState<HourlyStats[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const res = await fetch(`/api/hourly?hours=${hours}`);
        if (res.ok) setStats(await res.json());
      } catch {
        // ignore
      } finally {
        setLoading(false);
      }
    };

    fetchStats();
    // Refresh hourly stats every minute
    const interval = setInterval(fetchStats, 60000);
    return () => clearInterval(interval);
  }, [hours]);

  return { stats, loading };
}

export function useUserDetails(userEmail: string) {
  const [details, setDetails] = useState<UserDetails | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchDetails = async () => {
      if (!userEmail) {
        setLoading(false);
        return;
      }

      try {
        const res = await fetch(`/api/users/${encodeURIComponent(userEmail)}`);
        if (res.ok) {
          setDetails(await res.json());
          setError(null);
        } else {
          setError("User not found");
        }
      } catch {
        setError("Failed to fetch user details");
      } finally {
        setLoading(false);
      }
    };

    fetchDetails();
    const interval = setInterval(fetchDetails, 10000);
    return () => clearInterval(interval);
  }, [userEmail]);

  return { details, loading, error };
}

// Helper to convert TimeRange to hours or date range
function getTimeRangeParams(range: TimeRange): { hours?: number; from?: string; to?: string } {
  switch (range) {
    case "1h":
      return { hours: 1 };
    case "6h":
      return { hours: 6 };
    case "24h":
      return { hours: 24 };
    case "7d":
      return { hours: 168 };
    case "30d":
      const from = new Date();
      from.setDate(from.getDate() - 30);
      return { from: from.toISOString(), to: new Date().toISOString() };
    default:
      return { hours: 24 };
  }
}

export function useHourlyStatsWithRange(range: TimeRange = "24h") {
  const [stats, setStats] = useState<HourlyStats[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const params = getTimeRangeParams(range);
        const searchParams = new URLSearchParams();
        if (params.hours) searchParams.set("hours", params.hours.toString());
        if (params.from) searchParams.set("from", params.from);
        if (params.to) searchParams.set("to", params.to);
        
        const res = await fetch(`/api/hourly?${searchParams.toString()}`);
        if (res.ok) setStats(await res.json());
      } catch {
        // ignore
      } finally {
        setLoading(false);
      }
    };

    fetchStats();
    const interval = setInterval(fetchStats, 60000);
    return () => clearInterval(interval);
  }, [range]);

  return { stats, loading };
}

export function useAnomalies(refreshInterval = 30000) {
  const [anomalies, setAnomalies] = useState<Anomaly[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchAnomalies = async () => {
      try {
        const res = await fetch("/api/anomalies");
        if (res.ok) {
          const data = await res.json();
          setAnomalies(data || []);
        }
      } catch {
        // ignore
      } finally {
        setLoading(false);
      }
    };

    fetchAnomalies();
    const interval = setInterval(fetchAnomalies, refreshInterval);
    return () => clearInterval(interval);
  }, [refreshInterval]);

  return { anomalies, loading };
}

export function useAlerts(limit = 50) {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchAlerts = async () => {
      try {
        const res = await fetch(`/api/alerts?limit=${limit}`);
        if (res.ok) {
          const data = await res.json();
          setAlerts(data || []);
        }
      } catch {
        // ignore
      } finally {
        setLoading(false);
      }
    };

    fetchAlerts();
    const interval = setInterval(fetchAlerts, 30000);
    return () => clearInterval(interval);
  }, [limit]);

  return { alerts, loading };
}
