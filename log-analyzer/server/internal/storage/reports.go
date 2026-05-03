package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/xray-log-analyzer/server/internal/threatintel"
)

// ==================== Reports Functions ====================

// CreateReport creates a new report in the database
func (s *Storage) CreateReport(ctx context.Context, report *threatintel.Report) error {
	sectionsJSON, _ := json.Marshal(report.Sections)
	topThreatsJSON, _ := json.Marshal(report.TopThreats)
	topUsersJSON, _ := json.Marshal(report.TopUsers)
	topCountriesJSON, _ := json.Marshal(report.TopCountries)
	summaryJSON, _ := json.Marshal(report.Summary)

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO reports (id, type, format, title, description, start_date, end_date,
			generated_at, status, sections, top_threats, top_users, top_countries, summary)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`, report.ID, report.Type, report.Format, report.Title, report.Description,
		report.StartDate, report.EndDate, report.GeneratedAt, report.Status,
		string(sectionsJSON), string(topThreatsJSON), string(topUsersJSON),
		string(topCountriesJSON), string(summaryJSON))

	return err
}

// GetReport retrieves a report by ID
func (s *Storage) GetReport(ctx context.Context, id string) (*threatintel.Report, error) {
	report := &threatintel.Report{}
	var sectionsJSON, topThreatsJSON, topUsersJSON, topCountriesJSON, summaryJSON sql.NullString

	err := s.db.QueryRowContext(ctx, `
		SELECT id, type, format, title, description, start_date, end_date,
			generated_at, status, sections, top_threats, top_users, top_countries, summary
		FROM reports WHERE id = $1
	`, id).Scan(&report.ID, &report.Type, &report.Format, &report.Title, &report.Description,
		&report.StartDate, &report.EndDate, &report.GeneratedAt, &report.Status,
		&sectionsJSON, &topThreatsJSON, &topUsersJSON, &topCountriesJSON, &summaryJSON)

	if err != nil {
		return nil, err
	}

	if sectionsJSON.Valid {
		json.Unmarshal([]byte(sectionsJSON.String), &report.Sections)
	}
	if topThreatsJSON.Valid {
		json.Unmarshal([]byte(topThreatsJSON.String), &report.TopThreats)
	}
	if topUsersJSON.Valid {
		json.Unmarshal([]byte(topUsersJSON.String), &report.TopUsers)
	}
	if topCountriesJSON.Valid {
		json.Unmarshal([]byte(topCountriesJSON.String), &report.TopCountries)
	}
	if summaryJSON.Valid {
		json.Unmarshal([]byte(summaryJSON.String), &report.Summary)
	}

	return report, nil
}

// GetReportSummary returns a summary of all reports
func (s *Storage) GetReportSummary(ctx context.Context) (*threatintel.ReportSummary, error) {
	summary := &threatintel.ReportSummary{
		Reports: []*threatintel.Report{},
	}

	// Get report counts by status
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM reports`).Scan(&summary.TotalReports)
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM reports WHERE status = 'completed'`).Scan(&summary.CompletedReports)
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM reports WHERE status = 'pending' OR status = 'generating'`).Scan(&summary.PendingReports)

	// Get recent reports
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, type, format, title, description, start_date, end_date, generated_at, status
		FROM reports
		ORDER BY generated_at DESC
		LIMIT 20
	`)
	if err != nil {
		return summary, nil
	}
	defer rows.Close()

	for rows.Next() {
		r := &threatintel.Report{}
		rows.Scan(&r.ID, &r.Type, &r.Format, &r.Title, &r.Description,
			&r.StartDate, &r.EndDate, &r.GeneratedAt, &r.Status)
		summary.Reports = append(summary.Reports, r)
	}

	// Get last generated time
	if len(summary.Reports) > 0 {
		summary.LastGenerated = summary.Reports[0].GeneratedAt
	}

	return summary, nil
}

// DeleteReport deletes a report by ID
func (s *Storage) DeleteReport(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM reports WHERE id = $1`, id)
	return err
}

// GenerateReport generates a comprehensive report based on config
func (s *Storage) GenerateReport(ctx context.Context, config threatintel.ReportConfig) (*threatintel.Report, error) {
	report := &threatintel.Report{
		ID:          fmt.Sprintf("rpt_%d", time.Now().UnixNano()),
		Type:        config.Type,
		Format:      config.Format,
		Title:       config.Title,
		Description: config.Description,
		StartDate:   config.StartDate,
		EndDate:     config.EndDate,
		GeneratedAt: time.Now(),
		Status:      threatintel.StatusGenerating,
		Sections:    []*threatintel.ReportSection{},
	}

	// Set defaults if not provided
	if report.StartDate.IsZero() {
		report.StartDate = time.Now().AddDate(0, 0, -30)
	}
	if report.EndDate.IsZero() {
		report.EndDate = time.Now()
	}
	if report.Title == "" {
		report.Title = fmt.Sprintf("Threat Intelligence Report - %s", time.Now().Format("2006-01-02"))
	}
	if report.Format == "" {
		report.Format = threatintel.FormatJSON
	}

	// Generate report based on type
	switch config.Type {
	case threatintel.ReportTypeThreatSummary:
		s.generateThreatSummaryReport(ctx, report)
	case threatintel.ReportTypeUserRisk:
		s.generateUserRiskReport(ctx, report)
	case threatintel.ReportTypeGeoAnalysis:
		s.generateGeoAnalysisReport(ctx, report)
	case threatintel.ReportTypeDNSAnalysis:
		s.generateDNSAnalysisReport(ctx, report)
	default:
		// Generate comprehensive report
		s.generateComprehensiveReport(ctx, report)
	}

	report.Status = threatintel.StatusCompleted

	// Save report to database
	if err := s.CreateReport(ctx, report); err != nil {
		return nil, err
	}

	return report, nil
}

// generateThreatSummaryReport generates threat summary report
func (s *Storage) generateThreatSummaryReport(ctx context.Context, report *threatintel.Report) {
	// Get threat stats from direct queries
	var totalThreats, blockedThreats int64
	var uniqueUsers int

	s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(match_count), 0) FROM threat_type_stats`).Scan(&totalThreats)
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM threat_matches WHERE blocked = 1`).Scan(&blockedThreats)
	s.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT user_email) FROM threat_matches`).Scan(&uniqueUsers)

	report.Summary.TotalThreats = int(totalThreats)
	report.Summary.BlockedThreats = int(blockedThreats)
	report.Summary.UniqueUsers = uniqueUsers

	// Add threat summary section
	report.Sections = append(report.Sections, &threatintel.ReportSection{
		Title:   "Threat Overview",
		Content: fmt.Sprintf("During the reporting period, %d threats were detected, with %d blocked. %d unique users were affected.", report.Summary.TotalThreats, report.Summary.BlockedThreats, report.Summary.UniqueUsers),
		Order:   1,
	})

	// Get top threats
	var topThreats []*threatintel.ReportThreat
	rows, err := s.db.QueryContext(ctx, `
		SELECT threat_type, source_feed, COUNT(*) as cnt,
			SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked_cnt
		FROM threat_matches
		WHERE matched_at >= $1 AND matched_at <= $2
		GROUP BY threat_type, source_feed
		ORDER BY cnt DESC
		LIMIT 10
	`, report.StartDate, report.EndDate)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			t := &threatintel.ReportThreat{}
			var blockedCnt int
			rows.Scan(&t.Type, &t.Source, &t.Count, &blockedCnt)
			t.Blocked = blockedCnt > 0
			topThreats = append(topThreats, t)
		}
	}
	report.TopThreats = topThreats

	// Get top affected users
	s.populateTopUsers(ctx, report)
}

// generateUserRiskReport generates user risk report
func (s *Storage) generateUserRiskReport(ctx context.Context, report *threatintel.Report) {
	// Get risk summary
	riskSummary, _ := s.GetUserRiskSummary(ctx)
	if riskSummary != nil {
		report.Summary.UniqueUsers = riskSummary.TotalUsers
		report.Summary.HighRiskUsers = riskSummary.ByRiskLevel["high"] + riskSummary.ByRiskLevel["critical"]
	}

	report.Sections = append(report.Sections, &threatintel.ReportSection{
		Title:   "User Risk Analysis",
		Content: fmt.Sprintf("Analysis of %d users. %d users are classified as high/critical risk.", report.Summary.UniqueUsers, report.Summary.HighRiskUsers),
		Order:   1,
	})

	// Get high risk users
	s.populateTopUsers(ctx, report)
}

// generateGeoAnalysisReport generates geographic analysis report
func (s *Storage) generateGeoAnalysisReport(ctx context.Context, report *threatintel.Report) {
	// Get geo summary
	geoSummary, _ := s.GetGeoSummary(ctx)
	if geoSummary != nil {
		report.Summary.UniqueCountries = geoSummary.TotalCountries

		// Add top countries
		for _, c := range geoSummary.TopCountries {
			report.TopCountries = append(report.TopCountries, &threatintel.ReportCountry{
				Country: c.CountryName,
				Code:    c.CountryCode,
				Count:   int(c.TotalMatches),
			})
		}
	}

	report.Sections = append(report.Sections, &threatintel.ReportSection{
		Title:   "Geographic Analysis",
		Content: fmt.Sprintf("Threats detected from %d countries.", report.Summary.UniqueCountries),
		Order:   1,
	})
}

// generateDNSAnalysisReport generates DNS analysis report
func (s *Storage) generateDNSAnalysisReport(ctx context.Context, report *threatintel.Report) {
	// Get DNS summary
	dnsSummary, _ := s.GetDNSAnalysisSummary(ctx)
	if dnsSummary != nil && dnsSummary.QueryStats != nil {
		report.Summary.DNSQueries = int(dnsSummary.QueryStats.TotalQueries)
		report.Summary.SuspiciousDomains = len(dnsSummary.TopBadDomains)
	}

	report.Sections = append(report.Sections, &threatintel.ReportSection{
		Title:   "DNS Analysis",
		Content: fmt.Sprintf("Analyzed %d DNS queries. %d suspicious domains identified.", report.Summary.DNSQueries, report.Summary.SuspiciousDomains),
		Order:   1,
	})
}

// generateComprehensiveReport generates all sections
func (s *Storage) generateComprehensiveReport(ctx context.Context, report *threatintel.Report) {
	// Threat summary from direct queries
	var totalThreats, blockedThreats int64
	var uniqueUsers int

	s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(match_count), 0) FROM threat_type_stats`).Scan(&totalThreats)
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM threat_matches WHERE blocked = 1`).Scan(&blockedThreats)
	s.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT user_email) FROM threat_matches`).Scan(&uniqueUsers)

	report.Summary.TotalThreats = int(totalThreats)
	report.Summary.BlockedThreats = int(blockedThreats)
	report.Summary.UniqueUsers = uniqueUsers

	report.Sections = append(report.Sections, &threatintel.ReportSection{
		Title:   "Executive Summary",
		Content: fmt.Sprintf("This report covers threat intelligence data from %s to %s. A total of %d threats were detected, with %d blocked. %d unique users were affected by these threats.", report.StartDate.Format("Jan 2, 2006"), report.EndDate.Format("Jan 2, 2006"), report.Summary.TotalThreats, report.Summary.BlockedThreats, report.Summary.UniqueUsers),
		Order:   1,
	})

	// Risk summary
	riskSummary, _ := s.GetUserRiskSummary(ctx)
	if riskSummary != nil {
		report.Summary.HighRiskUsers = riskSummary.ByRiskLevel["high"] + riskSummary.ByRiskLevel["critical"]

		report.Sections = append(report.Sections, &threatintel.ReportSection{
			Title:   "User Risk Analysis",
			Content: fmt.Sprintf("Out of %d monitored users, %d are in critical risk category, %d are high risk, and %d are medium risk. Average risk score is %.1f.", riskSummary.TotalUsers, riskSummary.ByRiskLevel["critical"], riskSummary.ByRiskLevel["high"], riskSummary.ByRiskLevel["medium"], riskSummary.AverageRiskScore),
			Order:   2,
		})
	}

	// Geo summary
	geoSummary, _ := s.GetGeoSummary(ctx)
	if geoSummary != nil {
		report.Summary.UniqueCountries = geoSummary.TotalCountries

		countriesList := ""
		for i, c := range geoSummary.TopCountries {
			if i >= 5 {
				break
			}
			if i > 0 {
				countriesList += ", "
			}
			countriesList += fmt.Sprintf("%s (%d)", c.CountryName, c.TotalMatches)
		}

		report.Sections = append(report.Sections, &threatintel.ReportSection{
			Title:   "Geographic Distribution",
			Content: fmt.Sprintf("Threats originated from %d countries. Top sources: %s.", report.Summary.UniqueCountries, countriesList),
			Order:   3,
		})

		// Add top countries
		for _, c := range geoSummary.TopCountries {
			report.TopCountries = append(report.TopCountries, &threatintel.ReportCountry{
				Country: c.CountryName,
				Code:    c.CountryCode,
				Count:   int(c.TotalMatches),
			})
		}
	}

	// DNS summary
	dnsSummary, _ := s.GetDNSAnalysisSummary(ctx)
	if dnsSummary != nil && dnsSummary.QueryStats != nil {
		report.Summary.DNSQueries = int(dnsSummary.QueryStats.TotalQueries)
		report.Summary.SuspiciousDomains = len(dnsSummary.TopBadDomains)

		report.Sections = append(report.Sections, &threatintel.ReportSection{
			Title:   "DNS Security Analysis",
			Content: fmt.Sprintf("Total DNS queries: %d. Blocked queries: %d (%.1f%% block rate). %d suspicious domains were detected.", dnsSummary.QueryStats.TotalQueries, dnsSummary.QueryStats.BlockedQueries, dnsSummary.QueryStats.BlockRate, len(dnsSummary.TopBadDomains)),
			Order:   4,
		})
	}

	// Get top threats
	var topThreats []*threatintel.ReportThreat
	rows, err := s.db.QueryContext(ctx, `
		SELECT threat_type, source_feed, COUNT(*) as cnt
		FROM threat_matches
		GROUP BY threat_type, source_feed
		ORDER BY cnt DESC
		LIMIT 10
	`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			t := &threatintel.ReportThreat{}
			rows.Scan(&t.Type, &t.Source, &t.Count)
			topThreats = append(topThreats, t)
		}
	}
	report.TopThreats = topThreats

	// Recommendations section
	recommendations := []string{}
	if report.Summary.HighRiskUsers > 0 {
		recommendations = append(recommendations, fmt.Sprintf("Review and address %d high-risk user accounts", report.Summary.HighRiskUsers))
	}
	if report.Summary.SuspiciousDomains > 0 {
		recommendations = append(recommendations, fmt.Sprintf("Block or investigate %d suspicious domains", report.Summary.SuspiciousDomains))
	}
	if report.Summary.TotalThreats > report.Summary.BlockedThreats {
		recommendations = append(recommendations, "Increase blocking rate for detected threats")
	}
	recommendations = append(recommendations, "Continue monitoring and update threat intelligence feeds regularly")

	recContent := "Based on the analysis, we recommend:\n"
	for i, r := range recommendations {
		recContent += fmt.Sprintf("%d. %s\n", i+1, r)
	}

	report.Sections = append(report.Sections, &threatintel.ReportSection{
		Title:   "Recommendations",
		Content: recContent,
		Order:   5,
	})

	// Get top users
	s.populateTopUsers(ctx, report)
}

// populateTopUsers adds top affected users to report
func (s *Storage) populateTopUsers(ctx context.Context, report *threatintel.Report) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT user_email, total_matches, risk_score
		FROM user_risk_profiles
		ORDER BY risk_score DESC
		LIMIT 10
	`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			u := &threatintel.ReportUser{}
			rows.Scan(&u.Email, &u.ThreatCount, &u.RiskScore)
			report.TopUsers = append(report.TopUsers, u)
		}
	}
}
