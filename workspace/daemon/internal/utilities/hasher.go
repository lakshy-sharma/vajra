// internal/utilities/hasher.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package utilities

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

const quickHashBytes = 8192

// QuickHash hashes the first and last 8 KiB of a file.
// Fast enough for scan dedup; not a forensic hash.
//
// mtime is intentionally excluded: an attacker replacing a binary can
// restore mtime with touch -t, making mtime inclusion a false sense of
// security. Content (head + tail) is sufficient to catch prepend/append
// injection and in-place binary replacement.
func QuickHash(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("quickhash: open: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("quickhash: stat: %w", err)
	}

	h := sha256.New()

	head := make([]byte, quickHashBytes)
	n, err := f.Read(head)
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("quickhash: read head: %w", err)
	}
	h.Write(head[:n])

	if info.Size() > int64(quickHashBytes*2) {
		if _, err := f.Seek(info.Size()-int64(quickHashBytes), io.SeekStart); err != nil {
			return "", fmt.Errorf("quickhash: seek: %w", err)
		}
		tail := make([]byte, quickHashBytes)
		n, err = f.Read(tail)
		if err != nil && err != io.EOF {
			return "", fmt.Errorf("quickhash: read tail: %w", err)
		}
		h.Write(tail[:n])
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// FullSHA256 returns the SHA256 digest of the entire file.
func FullSHA256(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("sha256: open: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("sha256: hash: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// FileInfo bundles stat values used by scanners to decide whether to rehash.
type FileInfo struct {
	Size  int64
	MTime int64
}

func StatFile(filePath string) (FileInfo, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return FileInfo{}, fmt.Errorf("statfile: %w", err)
	}
	return FileInfo{Size: info.Size(), MTime: info.ModTime().Unix()}, nil
}
