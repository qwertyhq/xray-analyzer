"use client";

import React, { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  FileText,
  Download,
  RefreshCw,
  Plus,
  Calendar,
  Clock,
  CheckCircle,
  AlertCircle,
  Loader2,
  FileJson,
  FileSpreadsheet,
  Globe,
  Trash2,
  Eye,
} from "lucide-react";
import type { Report, ReportSummary, ReportConfig, ReportType, ReportFormat, ReportStatus } from "@/lib/types";

interface ReportsPanelProps {
  reports: ReportSummary | null;
  onGenerate: (config: ReportConfig) => Promise<void>;
  onRefresh: () => void;
  onDelete?: (id: string) => Promise<void>;
  onExport?: (id: string, format: ReportFormat) => void;
}

const reportTypeConfig: Record<ReportType, { label: string; description: string; icon: React.ReactNode }> = {
  summary: { label: "Summary", description: "Overview of all threat data", icon: <FileText className="h-4 w-4" /> },
  threat_summary: { label: "Threat Summary", description: "Detailed threat analysis", icon: <AlertCircle className="h-4 w-4" /> },
  user_risk: { label: "User Risk", description: "User risk profile analysis", icon: <FileText className="h-4 w-4" /> },
  geo_analysis: { label: "Geographic", description: "Geographic threat distribution", icon: <Globe className="h-4 w-4" /> },
  dns_analysis: { label: "DNS Analysis", description: "DNS query analysis", icon: <FileText className="h-4 w-4" /> },
  detailed: { label: "Detailed", description: "Full detailed report", icon: <FileText className="h-4 w-4" /> },
  user: { label: "User Report", description: "Single user analysis", icon: <FileText className="h-4 w-4" /> },
  incident: { label: "Incident", description: "Security incident report", icon: <AlertCircle className="h-4 w-4" /> },
  compliance: { label: "Compliance", description: "Compliance audit report", icon: <CheckCircle className="h-4 w-4" /> },
};

const formatConfig: Record<ReportFormat, { label: string; icon: React.ReactNode }> = {
  json: { label: "JSON", icon: <FileJson className="h-4 w-4" /> },
  csv: { label: "CSV", icon: <FileSpreadsheet className="h-4 w-4" /> },
  html: { label: "HTML", icon: <Globe className="h-4 w-4" /> },
  pdf: { label: "PDF", icon: <FileText className="h-4 w-4" /> },
};

const statusConfig: Record<ReportStatus, { label: string; color: string; icon: React.ReactNode }> = {
  pending: { label: "Pending", color: "bg-yellow-500", icon: <Clock className="h-3 w-3" /> },
  generating: { label: "Generating", color: "bg-blue-500", icon: <Loader2 className="h-3 w-3 animate-spin" /> },
  completed: { label: "Completed", color: "bg-green-500", icon: <CheckCircle className="h-3 w-3" /> },
  failed: { label: "Failed", color: "bg-red-500", icon: <AlertCircle className="h-3 w-3" /> },
};

export function ReportsPanel({ reports, onGenerate, onRefresh, onDelete, onExport }: ReportsPanelProps) {
  const [activeTab, setActiveTab] = useState("reports");
  const [isGenerating, setIsGenerating] = useState(false);
  const [selectedReport, setSelectedReport] = useState<Report | null>(null);

  // Form state for new report
  const [newReportType, setNewReportType] = useState<ReportType>("summary");
  const [newReportFormat, setNewReportFormat] = useState<ReportFormat>("html");
  const [newReportTitle, setNewReportTitle] = useState("");
  const [startDate, setStartDate] = useState(() => {
    const d = new Date();
    d.setDate(d.getDate() - 30);
    return d.toISOString().split("T")[0];
  });
  const [endDate, setEndDate] = useState(() => new Date().toISOString().split("T")[0]);

  const handleGenerate = async () => {
    setIsGenerating(true);
    try {
      const config: ReportConfig = {
        type: newReportType,
        format: newReportFormat,
        title: newReportTitle || `${reportTypeConfig[newReportType].label} Report - ${new Date().toLocaleDateString()}`,
        start_date: new Date(startDate).toISOString(),
        end_date: new Date(endDate).toISOString(),
      };
      await onGenerate(config);
      setNewReportTitle("");
      setActiveTab("reports");
    } finally {
      setIsGenerating(false);
    }
  };

  const handleExport = (report: Report, format: ReportFormat) => {
    if (onExport) {
      onExport(report.id, format);
    } else {
      // Default: open in new window
      window.open(`/api/threatintel/reports?id=${report.id}&format=${format}`, "_blank");
    }
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <div>
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5 text-muted-foreground" />
            Reports & Exports
          </CardTitle>
          <CardDescription>Generate and export threat intelligence reports</CardDescription>
        </div>
        <Button variant="outline" size="sm" onClick={onRefresh}>
          <RefreshCw className="h-4 w-4 mr-1" />
          Refresh
        </Button>
      </CardHeader>
      <CardContent>
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="reports">Reports ({reports?.total_reports || 0})</TabsTrigger>
            <TabsTrigger value="generate">
              <Plus className="h-4 w-4 mr-1" />
              Generate New
            </TabsTrigger>
            <TabsTrigger value="quick">Quick Export</TabsTrigger>
          </TabsList>

          {/* Reports List Tab */}
          <TabsContent value="reports" className="space-y-4">
            {/* Stats cards */}
            <div className="grid grid-cols-3 gap-4">
              <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-lg p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">Completed</p>
                    <p className="text-2xl font-bold text-emerald-600 dark:text-emerald-400">{reports?.completed_reports || 0}</p>
                  </div>
                  <CheckCircle className="h-8 w-8 text-emerald-500 opacity-50" />
                </div>
              </div>
              <div className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">Pending</p>
                    <p className="text-2xl font-bold text-amber-600 dark:text-amber-400">{reports?.pending_reports || 0}</p>
                  </div>
                  <Clock className="h-8 w-8 text-amber-500 opacity-50" />
                </div>
              </div>
              <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">Total</p>
                    <p className="text-2xl font-bold text-blue-600 dark:text-blue-400">{reports?.total_reports || 0}</p>
                  </div>
                  <FileText className="h-8 w-8 text-blue-500 opacity-50" />
                </div>
              </div>
            </div>

            {/* Reports list */}
            {reports?.reports && reports.reports.length > 0 ? (
              <div className="space-y-3">
                {reports.reports.map((report) => (
                  <div
                    key={report.id}
                    className="border rounded-lg p-4 hover:bg-accent/50 transition-colors"
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex items-start gap-3">
                        <div className="p-2 rounded-lg bg-muted">
                          {reportTypeConfig[report.type]?.icon || <FileText className="h-4 w-4" />}
                        </div>
                        <div>
                          <h4 className="font-medium">{report.title}</h4>
                          <p className="text-sm text-muted-foreground">
                            {reportTypeConfig[report.type]?.label || report.type}
                          </p>
                          <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
                            <Calendar className="h-3 w-3" />
                            {formatDate(report.generated_at)}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge
                          variant="secondary"
                          className={`${statusConfig[report.status].color} text-white flex items-center gap-1`}
                        >
                          {statusConfig[report.status].icon}
                          {statusConfig[report.status].label}
                        </Badge>
                        {report.status === "completed" && (
                          <div className="flex items-center gap-1">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => setSelectedReport(report)}
                              title="View Report"
                            >
                              <Eye className="h-4 w-4" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => handleExport(report, "html")}
                              title="Export HTML"
                            >
                              <Globe className="h-4 w-4" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => handleExport(report, "csv")}
                              title="Export CSV"
                            >
                              <FileSpreadsheet className="h-4 w-4" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => handleExport(report, "json")}
                              title="Export JSON"
                            >
                              <FileJson className="h-4 w-4" />
                            </Button>
                          </div>
                        )}
                        {onDelete && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => onDelete(report.id)}
                            className="text-destructive hover:text-destructive"
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        )}
                      </div>
                    </div>
                    
                    {/* Report summary stats if available */}
                    {report.summary && report.status === "completed" && (
                      <div className="grid grid-cols-4 gap-2 mt-3 pt-3 border-t text-center">
                        <div>
                          <p className="text-lg font-semibold">{report.summary.total_threats}</p>
                          <p className="text-xs text-muted-foreground">Threats</p>
                        </div>
                        <div>
                          <p className="text-lg font-semibold">{report.summary.blocked_threats}</p>
                          <p className="text-xs text-muted-foreground">Blocked</p>
                        </div>
                        <div>
                          <p className="text-lg font-semibold">{report.summary.unique_users}</p>
                          <p className="text-xs text-muted-foreground">Users</p>
                        </div>
                        <div>
                          <p className="text-lg font-semibold">{report.summary.high_risk_users}</p>
                          <p className="text-xs text-muted-foreground">High Risk</p>
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8 text-muted-foreground">
                <FileText className="h-12 w-12 mx-auto mb-2 opacity-30" />
                <p>No reports generated yet</p>
                <Button variant="outline" className="mt-4" onClick={() => setActiveTab("generate")}>
                  <Plus className="h-4 w-4 mr-1" />
                  Generate First Report
                </Button>
              </div>
            )}
          </TabsContent>

          {/* Generate New Report Tab */}
          <TabsContent value="generate" className="space-y-4">
            <div className="grid gap-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Report Type</Label>
                  <Select value={newReportType} onValueChange={(v) => setNewReportType(v as ReportType)}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {Object.entries(reportTypeConfig).map(([key, config]) => (
                        <SelectItem key={key} value={key}>
                          <div className="flex items-center gap-2">
                            {config.icon}
                            <span>{config.label}</span>
                          </div>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <p className="text-xs text-muted-foreground">
                    {reportTypeConfig[newReportType].description}
                  </p>
                </div>

                <div className="space-y-2">
                  <Label>Output Format</Label>
                  <Select value={newReportFormat} onValueChange={(v) => setNewReportFormat(v as ReportFormat)}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {Object.entries(formatConfig).map(([key, config]) => (
                        <SelectItem key={key} value={key}>
                          <div className="flex items-center gap-2">
                            {config.icon}
                            <span>{config.label}</span>
                          </div>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="space-y-2">
                <Label>Report Title (optional)</Label>
                <Input
                  placeholder="Auto-generated if empty"
                  value={newReportTitle}
                  onChange={(e) => setNewReportTitle(e.target.value)}
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Start Date</Label>
                  <Input
                    type="date"
                    value={startDate}
                    onChange={(e) => setStartDate(e.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <Label>End Date</Label>
                  <Input
                    type="date"
                    value={endDate}
                    onChange={(e) => setEndDate(e.target.value)}
                  />
                </div>
              </div>

              <Button onClick={handleGenerate} disabled={isGenerating} className="w-full">
                {isGenerating ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    Generating...
                  </>
                ) : (
                  <>
                    <Plus className="h-4 w-4 mr-2" />
                    Generate Report
                  </>
                )}
              </Button>
            </div>
          </TabsContent>

          {/* Quick Export Tab */}
          <TabsContent value="quick" className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <Card className="cursor-pointer hover:bg-accent/50 transition-colors" onClick={() => handleQuickExport("threat_summary", "csv")}>
                <CardContent className="p-4 flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-blue-100 dark:bg-blue-900/30">
                    <FileSpreadsheet className="h-5 w-5 text-blue-600" />
                  </div>
                  <div>
                    <p className="font-medium">Export Threats CSV</p>
                    <p className="text-sm text-muted-foreground">All threat matches</p>
                  </div>
                </CardContent>
              </Card>

              <Card className="cursor-pointer hover:bg-accent/50 transition-colors" onClick={() => handleQuickExport("user_risk", "csv")}>
                <CardContent className="p-4 flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-orange-100 dark:bg-orange-900/30">
                    <FileSpreadsheet className="h-5 w-5 text-orange-600" />
                  </div>
                  <div>
                    <p className="font-medium">Export User Risks CSV</p>
                    <p className="text-sm text-muted-foreground">User risk profiles</p>
                  </div>
                </CardContent>
              </Card>

              <Card className="cursor-pointer hover:bg-accent/50 transition-colors" onClick={() => handleQuickExport("geo_analysis", "json")}>
                <CardContent className="p-4 flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-green-100 dark:bg-green-900/30">
                    <FileJson className="h-5 w-5 text-green-600" />
                  </div>
                  <div>
                    <p className="font-medium">Export Geo Data JSON</p>
                    <p className="text-sm text-muted-foreground">Geographic analysis</p>
                  </div>
                </CardContent>
              </Card>

              <Card className="cursor-pointer hover:bg-accent/50 transition-colors" onClick={() => handleQuickExport("summary", "html")}>
                <CardContent className="p-4 flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-purple-100 dark:bg-purple-900/30">
                    <Globe className="h-5 w-5 text-purple-600" />
                  </div>
                  <div>
                    <p className="font-medium">Full Report HTML</p>
                    <p className="text-sm text-muted-foreground">Comprehensive report</p>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        </Tabs>

        {/* Report Detail Modal */}
        {selectedReport && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4" onClick={() => setSelectedReport(null)}>
            <div className="bg-background rounded-lg max-w-3xl w-full max-h-[80vh] overflow-auto" onClick={(e) => e.stopPropagation()}>
              <div className="p-6">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-xl font-bold">{selectedReport.title}</h2>
                  <Button variant="ghost" size="sm" onClick={() => setSelectedReport(null)}>×</Button>
                </div>
                
                {/* Summary */}
                <div className="grid grid-cols-4 gap-4 mb-6">
                  <div className="text-center p-3 bg-accent rounded-lg">
                    <p className="text-2xl font-bold">{selectedReport.summary.total_threats}</p>
                    <p className="text-xs text-muted-foreground">Total Threats</p>
                  </div>
                  <div className="text-center p-3 bg-accent rounded-lg">
                    <p className="text-2xl font-bold">{selectedReport.summary.blocked_threats}</p>
                    <p className="text-xs text-muted-foreground">Blocked</p>
                  </div>
                  <div className="text-center p-3 bg-accent rounded-lg">
                    <p className="text-2xl font-bold">{selectedReport.summary.unique_users}</p>
                    <p className="text-xs text-muted-foreground">Users</p>
                  </div>
                  <div className="text-center p-3 bg-accent rounded-lg">
                    <p className="text-2xl font-bold">{selectedReport.summary.unique_countries}</p>
                    <p className="text-xs text-muted-foreground">Countries</p>
                  </div>
                </div>

                {/* Sections */}
                {selectedReport.sections && selectedReport.sections.length > 0 && (
                  <div className="space-y-4">
                    {selectedReport.sections.map((section, i) => (
                      <div key={i} className="border-l-4 border-purple-500 pl-4">
                        <h3 className="font-semibold">{section.title}</h3>
                        <p className="text-sm text-muted-foreground whitespace-pre-wrap">{section.content}</p>
                      </div>
                    ))}
                  </div>
                )}

                {/* Export buttons */}
                <div className="flex gap-2 mt-6 pt-4 border-t">
                  <Button variant="outline" onClick={() => handleExport(selectedReport, "html")}>
                    <Globe className="h-4 w-4 mr-2" />
                    Export HTML
                  </Button>
                  <Button variant="outline" onClick={() => handleExport(selectedReport, "csv")}>
                    <FileSpreadsheet className="h-4 w-4 mr-2" />
                    Export CSV
                  </Button>
                  <Button variant="outline" onClick={() => handleExport(selectedReport, "json")}>
                    <FileJson className="h-4 w-4 mr-2" />
                    Export JSON
                  </Button>
                </div>
              </div>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );

  function handleQuickExport(type: ReportType, format: ReportFormat) {
    const config: ReportConfig = {
      type,
      format,
      title: `Quick ${reportTypeConfig[type].label} Export`,
      start_date: new Date(startDate).toISOString(),
      end_date: new Date(endDate).toISOString(),
    };
    onGenerate(config);
  }
}
