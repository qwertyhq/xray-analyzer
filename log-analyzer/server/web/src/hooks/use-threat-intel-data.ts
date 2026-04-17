"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import { authFetch } from "@/contexts/auth-context";
import {
  FeedStatus,
  TimeStats,
  GeoSummary,
  AnomalySummary,
  UserRiskSummary,
  ReportSummary,
  ReportConfig,
} from "@/lib/types";

interface ThreatIntelData {
  feeds: FeedStatus[];
  timeStats: TimeStats | null;
  geoStats: GeoSummary | null;
  anomalies: AnomalySummary | null;
  riskProfiles: UserRiskSummary | null;
  reports: ReportSummary | null;
}

interface UseThreatIntelDataReturn extends ThreatIntelData {
  loading: boolean;
  error: string | null;
  refresh: () => Promise<void>;
  refreshFeeds: () => Promise<void>;
  refreshAnomalies: () => Promise<void>;
  refreshRiskProfiles: () => Promise<void>;
  refreshReports: () => Promise<void>;
  runAnomalyDetection: () => Promise<void>;
  recalculateRiskProfiles: () => Promise<void>;
  generateReport: (config: ReportConfig) => Promise<void>;
  deleteReport: (id: string) => Promise<void>;
}

const DEFAULT_REFRESH_INTERVALS = {
  feeds: 60000,       // 1 min
  timeStats: 30000,   // 30 sec
  geoStats: 60000,    // 1 min
  anomalies: 60000,   // 1 min
  riskProfiles: 120000, // 2 min
  reports: 60000,       // 1 min
};

/**
 * Hook for managing Threat Intelligence data fetching and state.
 * Consolidates multiple API calls and provides automatic refresh.
 */
export function useThreatIntelData(): UseThreatIntelDataReturn {
  const [data, setData] = useState<ThreatIntelData>({
    feeds: [],
    timeStats: null,
    geoStats: null,
    anomalies: null,
    riskProfiles: null,
    reports: null,
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const intervalsRef = useRef<ReturnType<typeof setInterval>[]>([]);

  const fetchWithError = useCallback(async <T,>(
    url: string,
    errorMessage: string
  ): Promise<T | null> => {
    try {
      const res = await authFetch(url);
      if (!res.ok) {
        console.error(`${errorMessage}: ${res.status}`);
        return null;
      }
      return await res.json();
    } catch (err) {
      console.error(`${errorMessage}:`, err);
      return null;
    }
  }, []);

  const fetchFeeds = useCallback(async () => {
    const feeds = await fetchWithError<FeedStatus[]>(
      "/api/threatintel/feeds",
      "Failed to fetch feeds"
    );
    if (feeds) {
      setData(prev => ({ ...prev, feeds }));
    }
  }, [fetchWithError]);

  const fetchTimeStats = useCallback(async () => {
    const timeStats = await fetchWithError<TimeStats>(
      "/api/threatintel/time-stats",
      "Failed to fetch time stats"
    );
    if (timeStats) {
      setData(prev => ({ ...prev, timeStats }));
    }
  }, [fetchWithError]);

  const fetchGeoStats = useCallback(async () => {
    const geoStats = await fetchWithError<GeoSummary>(
      "/api/threatintel/geo-stats?summary=true",
      "Failed to fetch geo stats"
    );
    if (geoStats) {
      setData(prev => ({ ...prev, geoStats }));
    }
  }, [fetchWithError]);

  const fetchAnomalies = useCallback(async () => {
    const anomalies = await fetchWithError<AnomalySummary>(
      "/api/threatintel/anomalies?summary=true",
      "Failed to fetch anomalies"
    );
    if (anomalies) {
      setData(prev => ({ ...prev, anomalies }));
    }
  }, [fetchWithError]);

  const fetchRiskProfiles = useCallback(async () => {
    const riskProfiles = await fetchWithError<UserRiskSummary>(
      "/api/threatintel/risk-profiles",
      "Failed to fetch risk profiles"
    );
    if (riskProfiles) {
      setData(prev => ({ ...prev, riskProfiles }));
    }
  }, [fetchWithError]);

  const fetchReports = useCallback(async () => {
    const reports = await fetchWithError<ReportSummary>(
      "/api/threatintel/reports",
      "Failed to fetch reports"
    );
    if (reports) {
      setData(prev => ({ ...prev, reports }));
    }
  }, [fetchWithError]);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      await Promise.all([
        fetchFeeds(),
        fetchTimeStats(),
        fetchGeoStats(),
        fetchAnomalies(),
        fetchRiskProfiles(),
        fetchReports(),
      ]);
      setError(null);
    } catch (err) {
      setError("Failed to refresh data");
      console.error("Failed to refresh threat intelligence data:", err);
    } finally {
      setLoading(false);
    }
  }, [fetchFeeds, fetchTimeStats, fetchGeoStats, fetchAnomalies, fetchRiskProfiles, fetchReports]);

  const runAnomalyDetection = useCallback(async () => {
    try {
      const res = await authFetch("/api/threatintel/anomalies", { method: "POST" });
      if (res.ok) {
        await fetchAnomalies();
      } else {
        console.error("Failed to run anomaly detection");
      }
    } catch (err) {
      console.error("Failed to run anomaly detection:", err);
    }
  }, [fetchAnomalies]);

  const recalculateRiskProfiles = useCallback(async () => {
    try {
      const res = await authFetch("/api/threatintel/risk-profiles", { method: "POST" });
      if (res.ok) {
        await fetchRiskProfiles();
      } else {
        console.error("Failed to recalculate risk profiles");
      }
    } catch (err) {
      console.error("Failed to recalculate risk profiles:", err);
    }
  }, [fetchRiskProfiles]);

  const generateReport = useCallback(async (config: ReportConfig) => {
    try {
      const res = await authFetch("/api/threatintel/reports", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(config),
      });
      if (res.ok) {
        await fetchReports();
      } else {
        console.error("Failed to generate report");
      }
    } catch (err) {
      console.error("Failed to generate report:", err);
    }
  }, [fetchReports]);

  const deleteReport = useCallback(async (id: string) => {
    try {
      const res = await authFetch(`/api/threatintel/reports?id=${id}`, { method: "DELETE" });
      if (res.ok) {
        await fetchReports();
      } else {
        console.error("Failed to delete report");
      }
    } catch (err) {
      console.error("Failed to delete report:", err);
    }
  }, [fetchReports]);

  // Initial fetch
  useEffect(() => {
    refresh();
  }, [refresh]);

  // Setup intervals for auto-refresh
  useEffect(() => {
    intervalsRef.current = [
      setInterval(fetchFeeds, DEFAULT_REFRESH_INTERVALS.feeds),
      setInterval(fetchTimeStats, DEFAULT_REFRESH_INTERVALS.timeStats),
      setInterval(fetchGeoStats, DEFAULT_REFRESH_INTERVALS.geoStats),
      setInterval(fetchAnomalies, DEFAULT_REFRESH_INTERVALS.anomalies),
      setInterval(fetchRiskProfiles, DEFAULT_REFRESH_INTERVALS.riskProfiles),
      setInterval(fetchReports, DEFAULT_REFRESH_INTERVALS.reports),
    ];

    return () => {
      intervalsRef.current.forEach(clearInterval);
    };
  }, [fetchFeeds, fetchTimeStats, fetchGeoStats, fetchAnomalies, fetchRiskProfiles, fetchReports]);

  return {
    ...data,
    loading,
    error,
    refresh,
    refreshFeeds: fetchFeeds,
    refreshAnomalies: fetchAnomalies,
    refreshRiskProfiles: fetchRiskProfiles,
    refreshReports: fetchReports,
    runAnomalyDetection,
    recalculateRiskProfiles,
    generateReport,
    deleteReport,
  };
}
