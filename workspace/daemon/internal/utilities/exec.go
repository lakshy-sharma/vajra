// internal/utilities/exec.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package utilities

import (
	"io"
	"os"
)

// HasExecutableMagic reads the first 4 bytes from an already-open file
// and returns true if they match a known executable format.
//
// Taking *os.File rather than a path prevents the TOCTOU race between
// os.Stat and a subsequent open — the caller opens the file once and
// passes the same fd here and to the scanner.
//
// ReadAt is used so the file position is not disturbed; the caller can
// continue reading from the fd without seeking.
func HasExecutableMagic(f *os.File) bool {
	var magic [4]byte
	n, err := f.ReadAt(magic[:], 0)
	if (err != nil && err != io.EOF) || n < 2 {
		return false
	}
	// ELF
	if n >= 4 && magic[0] == 0x7f && magic[1] == 0x45 && magic[2] == 0x4c && magic[3] == 0x46 {
		return true
	}
	// Shebang
	if magic[0] == '#' && magic[1] == '!' {
		return true
	}
	// MZ / PE
	if magic[0] == 0x4d && magic[1] == 0x5a {
		return true
	}
	// Mach-O (fat binary or 32-bit)
	if n >= 4 && magic[0] == 0xca && magic[1] == 0xfe && magic[2] == 0xba && magic[3] == 0xbe {
		return true
	}
	return false
}
