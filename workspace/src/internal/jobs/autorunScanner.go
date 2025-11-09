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
package jobs

import (
	"context"
	"fmt"
	"sync"
	"time"

	"vajra/internal/database"
	"vajra/internal/utilities"

	"github.com/botherder/go-autoruns"
	"github.com/rs/zerolog"
)

type AutorunScanner struct {
	ctx          context.Context
	wg           *sync.WaitGroup
	logger       *zerolog.Logger
	dbHandler    *database.DBHandler
	appConfig    *utilities.Config
	currentState map[string]*AutorunResult // Key: MD5 or unique identifier
	mu           sync.RWMutex
}

type AutorunResult struct {
	Type      string    `json:"type"`
	Location  string    `json:"location"`
	ImagePath string    `json:"image_path"`
	ImageName string    `json:"image_name"`
	Arguments string    `json:"arguments"`
	MD5       string    `json:"md5"`
	SHA1      string    `json:"sha1"`
	SHA256    string    `json:"sha256"`
	FirstSeen int64     `json:"first_seen"`
	LastSeen  int64     `json:"last_seen"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	IsActive  bool      `json:"is_active"`
}

// Generator for autorun scanner
func NewAutorunScanner(ctx context.Context, wg *sync.WaitGroup, logger *zerolog.Logger, dbHandler *database.DBHandler, config *utilities.Config) *AutorunScanner {
	return &AutorunScanner{
		appConfig:    config,
		ctx:          ctx,
		wg:           wg,
		logger:       logger,
		dbHandler:    dbHandler,
		currentState: make(map[string]*AutorunResult),
	}
}

func (as *AutorunScanner) Stop() {
	as.logger.Info().Msg("stopping autorun scanner")
}

// LoadState loads existing autoruns from database.
func (as *AutorunScanner) LoadState() error {
	as.mu.Lock()
	defer as.mu.Unlock()

	as.logger.Info().Msg("loading autorun state from database")

	// Query active autoruns from database
	query := "SELECT type, location, image_path, image_name, arguments, md5, sha1, sha256, first_seen, last_seen, created_at, updated_at FROM autoruns WHERE is_active = 1"

	rows, err := as.dbHandler.DB.Query(query)
	if err != nil {
		as.logger.Error().Err(err).Msg("failed to query autoruns from database")
		return err
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var result AutorunResult
		err := rows.Scan(
			&result.Type,
			&result.Location,
			&result.ImagePath,
			&result.ImageName,
			&result.Arguments,
			&result.MD5,
			&result.SHA1,
			&result.SHA256,
			&result.FirstSeen,
			&result.LastSeen,
			&result.CreatedAt,
			&result.UpdatedAt,
		)
		if err != nil {
			as.logger.Error().Err(err).Msg("failed to scan autorun row")
			continue
		}

		result.IsActive = true
		key := as.generateKey(&result)
		as.currentState[key] = &result
		count++
	}

	if err = rows.Err(); err != nil {
		as.logger.Error().Err(err).Msg("error iterating autorun rows")
		return err
	}

	as.logger.Info().Int("count", count).Msg("loaded autoruns from database")
	return nil
}

// Scan performs a scan and returns scan results.
func (as *AutorunScanner) Scan() ([]*AutorunResult, error) {
	as.logger.Info().Msg("starting autorun scan")

	autoruns := autoruns.Autoruns()
	results := make([]*AutorunResult, 0, len(autoruns))

	for _, autorun := range autoruns {
		result := &AutorunResult{
			Type:      autorun.Type,
			Location:  autorun.Location,
			ImagePath: autorun.ImagePath,
			ImageName: autorun.ImageName,
			Arguments: autorun.Arguments,
			MD5:       autorun.MD5,
			SHA1:      autorun.SHA1,
			SHA256:    autorun.SHA256,
			IsActive:  true,
		}

		results = append(results, result)
	}

	as.logger.Info().Int("count", len(results)).Msg("autorun scan completed")
	return results, nil
}

// CheckResults performs a cross check of existing vs new entries
func (as *AutorunScanner) CheckResults(newResults []*AutorunResult) error {
	as.mu.Lock()
	defer as.mu.Unlock()

	as.logger.Info().Msg("checking autorun results")

	// Create a map of new results for quick lookup
	newResultsMap := make(map[string]*AutorunResult)
	for _, result := range newResults {
		key := as.generateKey(result)
		newResultsMap[key] = result
	}

	now := time.Now().Unix()

	// Mark old entries as inactive if they no longer exist
	for key, oldResult := range as.currentState {
		if _, exists := newResultsMap[key]; !exists {
			// Mark as inactive in database
			if err := as.markInactive(oldResult, now); err != nil {
				as.logger.Error().
					Err(err).
					Str("key", key).
					Msg("failed to mark autorun as inactive")
			} else {
				as.logger.Info().
					Str("type", oldResult.Type).
					Str("location", oldResult.Location).
					Msg("autorun removed")
				delete(as.currentState, key)
			}
		} else {
			// Update last_seen timestamp for existing autoruns
			if err := as.updateLastSeen(oldResult, now); err != nil {
				as.logger.Error().
					Err(err).
					Str("key", key).
					Msg("failed to update last_seen")
			}
		}
	}

	// Add new entries
	for key, newResult := range newResultsMap {
		if _, exists := as.currentState[key]; !exists {
			// New autorun detected
			nowTime := time.Unix(now, 0)
			newResult.FirstSeen = now
			newResult.LastSeen = now
			newResult.CreatedAt = nowTime
			newResult.UpdatedAt = nowTime

			if err := as.saveToDatabase(newResult); err != nil {
				as.logger.Error().
					Err(err).
					Str("key", key).
					Msg("failed to save new autorun")
			} else {
				as.logger.Warn().
					Str("type", newResult.Type).
					Str("location", newResult.Location).
					Str("image_path", newResult.ImagePath).
					Str("md5", newResult.MD5).
					Str("sha256", newResult.SHA256).
					Msg("NEW AUTORUN DETECTED")
				as.currentState[key] = newResult
			}
		}
	}

	as.logger.Info().
		Int("active", len(as.currentState)).
		Int("new", len(newResultsMap)).
		Msg("autorun check completed")

	return nil
}

// generateKey creates a unique key for an autorun entry
func (as *AutorunScanner) generateKey(result *AutorunResult) string {
	// Use a combination of type, location, and image_path as key
	// If MD5 exists, prefer that for uniqueness
	if result.MD5 != "" {
		return result.MD5
	}
	return fmt.Sprintf("%s|%s|%s", result.Type, result.Location, result.ImagePath)
}

// saveToDatabase inserts a new autorun entry into the database
func (as *AutorunScanner) saveToDatabase(result *AutorunResult) error {
	query := `
		INSERT INTO autoruns (type, location, image_path, image_name, arguments, md5, sha1, sha256, is_active, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := as.dbHandler.DB.Exec(
		query,
		result.Type,
		result.Location,
		result.ImagePath,
		result.ImageName,
		result.Arguments,
		result.MD5,
		result.SHA1,
		result.SHA256,
		result.IsActive,
		result.FirstSeen,
		result.LastSeen,
	)

	return err
}

// markInactive marks an autorun entry as inactive in the database
func (as *AutorunScanner) markInactive(result *AutorunResult, timestamp int64) error {
	query := `
		UPDATE autoruns 
		SET is_active = 0, last_seen = ?, updated_at = CURRENT_TIMESTAMP
		WHERE (md5 != '' AND md5 = ?) OR (type = ? AND location = ? AND image_path = ?)
	`

	_, err := as.dbHandler.DB.Exec(
		query,
		timestamp,
		result.MD5,
		result.Type,
		result.Location,
		result.ImagePath,
	)

	return err
}

// updateLastSeen updates the last_seen timestamp for an existing autorun
func (as *AutorunScanner) updateLastSeen(result *AutorunResult, timestamp int64) error {
	query := `
		UPDATE autoruns 
		SET last_seen = ?, updated_at = CURRENT_TIMESTAMP
		WHERE (md5 != '' AND md5 = ?) OR (type = ? AND location = ? AND image_path = ?)
	`

	_, err := as.dbHandler.DB.Exec(
		query,
		timestamp,
		result.MD5,
		result.Type,
		result.Location,
		result.ImagePath,
	)

	return err
}

// RunAutorunScan is a function that runs like a goroutine and periodically finds autoruns.
// If a new autorun is detected it gets saved into our database.
func RunAutorunScan(ctx context.Context, wg *sync.WaitGroup, logger *zerolog.Logger, dbHandler *database.DBHandler, config *utilities.Config) {
	defer wg.Done()

	autorunScanner := NewAutorunScanner(ctx, wg, logger, dbHandler, config)

	// Load existing state from database
	if err := autorunScanner.LoadState(); err != nil {
		logger.Error().Err(err).Msg("failed to load initial autorun state")
	}

	// Perform initial scan
	if results, err := autorunScanner.Scan(); err != nil {
		logger.Error().Err(err).Msg("failed to perform initial autorun scan")
	} else {
		if err := autorunScanner.CheckResults(results); err != nil {
			logger.Error().Err(err).Msg("failed to check initial autorun results")
		}
	}

	ticker := time.NewTicker(time.Duration(config.TimingSettings.AutorunScanTimeMin) * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			autorunScanner.Stop()
			return

		case <-ticker.C:
			logger.Info().Msg("performing periodic autorun scan")

			results, err := autorunScanner.Scan()
			if err != nil {
				logger.Error().Err(err).Msg("autorun scan failed")
				continue
			}

			if err := autorunScanner.CheckResults(results); err != nil {
				logger.Error().Err(err).Msg("failed to check autorun results")
			}
		}
	}
}
