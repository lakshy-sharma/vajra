/*
Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package internal

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type APIServer struct {
	echo   *echo.Echo
	db     *sql.DB
	ctx    context.Context
	cancel context.CancelFunc
}

// Response structures
type FileScanRecord struct {
	ID           int64           `json:"id"`
	LastScanTime int64           `json:"lastscan_time"`
	FilePath     string          `json:"filepath"`
	YaraResults  json.RawMessage `json:"yara_results"`
}

type ProcessScanRecord struct {
	ID           int64           `json:"id"`
	LastScanTime int64           `json:"lastscan_time"`
	PID          int32           `json:"pid"`
	ProcessName  string          `json:"process_name"`
	Cmdline      string          `json:"cmdline"`
	YaraResults  json.RawMessage `json:"yara_results"`
}

type DashboardStats struct {
	TotalFileScans       int64 `json:"total_file_scans"`
	TotalProcessScans    int64 `json:"total_process_scans"`
	FilesWithMatches     int64 `json:"files_with_matches"`
	ProcessesWithMatches int64 `json:"processes_with_matches"`
	LastFileScan         int64 `json:"last_file_scan"`
	LastProcessScan      int64 `json:"last_process_scan"`
}

type PaginatedResponse struct {
	Data       interface{} `json:"data"`
	Page       int         `json:"page"`
	PageSize   int         `json:"page_size"`
	TotalCount int64       `json:"total_count"`
	TotalPages int         `json:"total_pages"`
}

// NewAPIServer creates a new API server instance
func NewAPIServer(ctx context.Context, cancel context.CancelFunc, db *sql.DB) *APIServer {
	e := echo.New()
	e.HideBanner = true

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	server := &APIServer{
		echo:   e,
		db:     db,
		ctx:    ctx,
		cancel: cancel,
	}

	server.setupRoutes()
	return server
}

// setupRoutes configures all API routes
func (s *APIServer) setupRoutes() {
	// Health check
	s.echo.GET("/api/health", s.healthCheck)

	// Dashboard stats
	s.echo.GET("/api/stats", s.getDashboardStats)

	// File scan results
	s.echo.GET("/api/files", s.getFileScans)
	s.echo.GET("/api/files/:id", s.getFileScanByID)
	s.echo.GET("/api/files/matches", s.getFilesWithMatches)

	// Process scan results
	s.echo.GET("/api/processes", s.getProcessScans)
	s.echo.GET("/api/processes/:id", s.getProcessScanByID)
	s.echo.GET("/api/processes/matches", s.getProcessesWithMatches)

	// Recent activity
	s.echo.GET("/api/recent/files", s.getRecentFileScans)
	s.echo.GET("/api/recent/processes", s.getRecentProcessScans)

	// Serve static files for React dashboard
	s.echo.Static("/", "web/dist")
}

// Start begins the API server
func (s *APIServer) Start(address string) error {
	logger.Info().Str("address", address).Msg("starting API server")
	return s.echo.Start(address)
}

// Stop gracefully shuts down the API server
func (s *APIServer) Stop() error {
	logger.Info().Msg("stopping API server")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return s.echo.Shutdown(ctx)
}

// Health check endpoint
func (s *APIServer) healthCheck(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{
		"status": "healthy",
		"time":   time.Now().Format(time.RFC3339),
	})
}

// Get dashboard statistics
func (s *APIServer) getDashboardStats(c echo.Context) error {
	stats := DashboardStats{}

	// Total file scans
	err := s.db.QueryRow("SELECT COUNT(*) FROM file_scan_results").Scan(&stats.TotalFileScans)
	if err != nil && err != sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to get file scan count")
	}

	// Total process scans
	err = s.db.QueryRow("SELECT COUNT(*) FROM process_scan_results").Scan(&stats.TotalProcessScans)
	if err != nil && err != sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to get process scan count")
	}

	// Files with matches
	err = s.db.QueryRow("SELECT COUNT(*) FROM file_scan_results WHERE yara_results != '[]' AND yara_results != 'null'").Scan(&stats.FilesWithMatches)
	if err != nil && err != sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to get files with matches")
	}

	// Processes with matches
	err = s.db.QueryRow("SELECT COUNT(*) FROM process_scan_results WHERE yara_results != '[]' AND yara_results != 'null'").Scan(&stats.ProcessesWithMatches)
	if err != nil && err != sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to get processes with matches")
	}

	// Last file scan
	err = s.db.QueryRow("SELECT MAX(lastscan_time) FROM file_scan_results").Scan(&stats.LastFileScan)
	if err != nil && err != sql.ErrNoRows {
		stats.LastFileScan = 0
	}

	// Last process scan
	err = s.db.QueryRow("SELECT MAX(lastscan_time) FROM process_scan_results").Scan(&stats.LastProcessScan)
	if err != nil && err != sql.ErrNoRows {
		stats.LastProcessScan = 0
	}

	return c.JSON(http.StatusOK, stats)
}

// Get file scans with pagination
func (s *APIServer) getFileScans(c echo.Context) error {
	page, _ := strconv.Atoi(c.QueryParam("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(c.QueryParam("page_size"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	offset := (page - 1) * pageSize

	// Get total count
	var totalCount int64
	err := s.db.QueryRow("SELECT COUNT(*) FROM file_scan_results").Scan(&totalCount)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to get count")
	}

	// Get records
	rows, err := s.db.Query(`
		SELECT id, lastscan_time, filepath, yara_results 
		FROM file_scan_results 
		ORDER BY lastscan_time DESC 
		LIMIT ? OFFSET ?
	`, pageSize, offset)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to query file scans")
	}
	defer rows.Close()

	records := []FileScanRecord{}
	for rows.Next() {
		var r FileScanRecord
		if err := rows.Scan(&r.ID, &r.LastScanTime, &r.FilePath, &r.YaraResults); err != nil {
			continue
		}
		records = append(records, r)
	}

	totalPages := int((totalCount + int64(pageSize) - 1) / int64(pageSize))

	return c.JSON(http.StatusOK, PaginatedResponse{
		Data:       records,
		Page:       page,
		PageSize:   pageSize,
		TotalCount: totalCount,
		TotalPages: totalPages,
	})
}

// Get specific file scan by ID
func (s *APIServer) getFileScanByID(c echo.Context) error {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid ID")
	}

	var record FileScanRecord
	err = s.db.QueryRow(`
		SELECT id, lastscan_time, filepath, yara_results 
		FROM file_scan_results 
		WHERE id = ?
	`, id).Scan(&record.ID, &record.LastScanTime, &record.FilePath, &record.YaraResults)

	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "record not found")
	}
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to query record")
	}

	return c.JSON(http.StatusOK, record)
}

// Get files with YARA matches
func (s *APIServer) getFilesWithMatches(c echo.Context) error {
	page, _ := strconv.Atoi(c.QueryParam("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(c.QueryParam("page_size"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	offset := (page - 1) * pageSize

	// Get total count
	var totalCount int64
	err := s.db.QueryRow("SELECT COUNT(*) FROM file_scan_results WHERE yara_results != '[]' AND yara_results != 'null'").Scan(&totalCount)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to get count")
	}

	// Get records
	rows, err := s.db.Query(`
		SELECT id, lastscan_time, filepath, yara_results 
		FROM file_scan_results 
		WHERE yara_results != '[]' AND yara_results != 'null'
		ORDER BY lastscan_time DESC 
		LIMIT ? OFFSET ?
	`, pageSize, offset)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to query file scans")
	}
	defer rows.Close()

	records := []FileScanRecord{}
	for rows.Next() {
		var r FileScanRecord
		if err := rows.Scan(&r.ID, &r.LastScanTime, &r.FilePath, &r.YaraResults); err != nil {
			continue
		}
		records = append(records, r)
	}

	totalPages := int((totalCount + int64(pageSize) - 1) / int64(pageSize))

	return c.JSON(http.StatusOK, PaginatedResponse{
		Data:       records,
		Page:       page,
		PageSize:   pageSize,
		TotalCount: totalCount,
		TotalPages: totalPages,
	})
}

// Get process scans with pagination
func (s *APIServer) getProcessScans(c echo.Context) error {
	page, _ := strconv.Atoi(c.QueryParam("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(c.QueryParam("page_size"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	offset := (page - 1) * pageSize

	// Get total count
	var totalCount int64
	err := s.db.QueryRow("SELECT COUNT(*) FROM process_scan_results").Scan(&totalCount)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to get count")
	}

	// Get records
	rows, err := s.db.Query(`
		SELECT id, lastscan_time, pid, process_name, cmdline, yara_results 
		FROM process_scan_results 
		ORDER BY lastscan_time DESC 
		LIMIT ? OFFSET ?
	`, pageSize, offset)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to query process scans")
	}
	defer rows.Close()

	records := []ProcessScanRecord{}
	for rows.Next() {
		var r ProcessScanRecord
		if err := rows.Scan(&r.ID, &r.LastScanTime, &r.PID, &r.ProcessName, &r.Cmdline, &r.YaraResults); err != nil {
			continue
		}
		records = append(records, r)
	}

	totalPages := int((totalCount + int64(pageSize) - 1) / int64(pageSize))

	return c.JSON(http.StatusOK, PaginatedResponse{
		Data:       records,
		Page:       page,
		PageSize:   pageSize,
		TotalCount: totalCount,
		TotalPages: totalPages,
	})
}

// Get specific process scan by ID
func (s *APIServer) getProcessScanByID(c echo.Context) error {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid ID")
	}

	var record ProcessScanRecord
	err = s.db.QueryRow(`
		SELECT id, lastscan_time, pid, process_name, cmdline, yara_results 
		FROM process_scan_results 
		WHERE id = ?
	`, id).Scan(&record.ID, &record.LastScanTime, &record.PID, &record.ProcessName, &record.Cmdline, &record.YaraResults)

	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "record not found")
	}
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to query record")
	}

	return c.JSON(http.StatusOK, record)
}

// Get processes with YARA matches
func (s *APIServer) getProcessesWithMatches(c echo.Context) error {
	page, _ := strconv.Atoi(c.QueryParam("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(c.QueryParam("page_size"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	offset := (page - 1) * pageSize

	// Get total count
	var totalCount int64
	err := s.db.QueryRow("SELECT COUNT(*) FROM process_scan_results WHERE yara_results != '[]' AND yara_results != 'null'").Scan(&totalCount)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to get count")
	}

	// Get records
	rows, err := s.db.Query(`
		SELECT id, lastscan_time, pid, process_name, cmdline, yara_results 
		FROM process_scan_results 
		WHERE yara_results != '[]' AND yara_results != 'null'
		ORDER BY lastscan_time DESC 
		LIMIT ? OFFSET ?
	`, pageSize, offset)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to query process scans")
	}
	defer rows.Close()

	records := []ProcessScanRecord{}
	for rows.Next() {
		var r ProcessScanRecord
		if err := rows.Scan(&r.ID, &r.LastScanTime, &r.PID, &r.ProcessName, &r.Cmdline, &r.YaraResults); err != nil {
			continue
		}
		records = append(records, r)
	}

	totalPages := int((totalCount + int64(pageSize) - 1) / int64(pageSize))

	return c.JSON(http.StatusOK, PaginatedResponse{
		Data:       records,
		Page:       page,
		PageSize:   pageSize,
		TotalCount: totalCount,
		TotalPages: totalPages,
	})
}

// Get recent file scans
func (s *APIServer) getRecentFileScans(c echo.Context) error {
	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	if limit < 1 || limit > 100 {
		limit = 10
	}

	rows, err := s.db.Query(`
		SELECT id, lastscan_time, filepath, yara_results 
		FROM file_scan_results 
		ORDER BY lastscan_time DESC 
		LIMIT ?
	`, limit)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to query recent file scans")
	}
	defer rows.Close()

	records := []FileScanRecord{}
	for rows.Next() {
		var r FileScanRecord
		if err := rows.Scan(&r.ID, &r.LastScanTime, &r.FilePath, &r.YaraResults); err != nil {
			continue
		}
		records = append(records, r)
	}

	return c.JSON(http.StatusOK, records)
}

// Get recent process scans
func (s *APIServer) getRecentProcessScans(c echo.Context) error {
	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	if limit < 1 || limit > 100 {
		limit = 10
	}

	rows, err := s.db.Query(`
		SELECT id, lastscan_time, pid, process_name, cmdline, yara_results 
		FROM process_scan_results 
		ORDER BY lastscan_time DESC 
		LIMIT ?
	`, limit)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to query recent process scans")
	}
	defer rows.Close()

	records := []ProcessScanRecord{}
	for rows.Next() {
		var r ProcessScanRecord
		if err := rows.Scan(&r.ID, &r.LastScanTime, &r.PID, &r.ProcessName, &r.Cmdline, &r.YaraResults); err != nil {
			continue
		}
		records = append(records, r)
	}

	return c.JSON(http.StatusOK, records)
}
