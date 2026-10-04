// internal/jobs/autoruns/sources_windows.go
//
//go:build windows

// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package autoruns

import "vajra/shared/models"

// GetSources returns Windows persistence sources.
// All sources are stubs — full implementation in a future sprint.
func GetSources() []AutorunSource {
	return []AutorunSource{
		&WinRegistryRunSource{},
		&WinScheduledTaskSource{},
		&WinStartupFolderSource{},
		&WinServiceSource{},
		&WinWMISource{},
	}
}

type WinRegistryRunSource struct{}

func (s *WinRegistryRunSource) Name() string { return "win_registry_run" }
func (s *WinRegistryRunSource) Collect() ([]*models.AutorunEntry, error) {
	return nil, nil // TODO: implement
}

type WinScheduledTaskSource struct{}

func (s *WinScheduledTaskSource) Name() string { return "win_scheduled_task" }
func (s *WinScheduledTaskSource) Collect() ([]*models.AutorunEntry, error) {
	return nil, nil // TODO: implement
}

type WinStartupFolderSource struct{}

func (s *WinStartupFolderSource) Name() string { return "win_startup_folder" }
func (s *WinStartupFolderSource) Collect() ([]*models.AutorunEntry, error) {
	return nil, nil // TODO: implement
}

type WinServiceSource struct{}

func (s *WinServiceSource) Name() string { return "win_service" }
func (s *WinServiceSource) Collect() ([]*models.AutorunEntry, error) {
	return nil, nil // TODO: implement
}

type WinWMISource struct{}

func (s *WinWMISource) Name() string { return "win_wmi" }
func (s *WinWMISource) Collect() ([]*models.AutorunEntry, error) {
	return nil, nil // TODO: implement
}
