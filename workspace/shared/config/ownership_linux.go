// shared/config/ownership_linux.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package config

import (
	"fmt"
	"syscall"
)

// checkOwnership returns an error if the file at path is not owned by uid 0.
// A config file writable by a non-root user could be used to alter EDR
// behaviour or redirect log output to an attacker-controlled location.
func checkOwnership(path string) error {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		// File not found — let ReadFile return a clear error to the caller.
		return nil
	}
	if st.Uid != 0 {
		return fmt.Errorf("%s is owned by uid %d; must be owned by root (uid 0)", path, st.Uid)
	}
	return nil
}
