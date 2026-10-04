// internal/scanner/hasher.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package scanner

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

const quickHashBytes = 8192 // 8 KB sample for deduplication

// QuickHash returns a SHA256 of the first 8 KB of a file.
// Used for fast deduplication — not suitable as a forensic hash.
func QuickHash(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("hasher.QuickHash: open: %w", err)
	}
	defer f.Close()

	buf := make([]byte, quickHashBytes)
	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("hasher.QuickHash: read: %w", err)
	}

	h := sha256.Sum256(buf[:n])
	return hex.EncodeToString(h[:]), nil
}

// FullSHA256 returns the SHA256 of the entire file.
func FullSHA256(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("hasher.FullSHA256: open: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hasher.FullSHA256: hash: %w", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// FullSHA1 returns the SHA1 of the entire file.
func FullSHA1(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("hasher.FullSHA1: open: %w", err)
	}
	defer f.Close()

	h := sha1.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hasher.FullSHA1: hash: %w", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// FullMD5 returns the MD5 of the entire file.
// MD5 is included for compatibility with threat intel feeds
// that still index on MD5; do not use it for security decisions.
func FullMD5(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("hasher.FullMD5: open: %w", err)
	}
	defer f.Close()

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hasher.FullMD5: hash: %w", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// HashFile computes SHA256, SHA1, and MD5 in a single pass.
// More efficient than calling each function separately when
// all three are needed (e.g. autorun entry creation).
func HashFile(filePath string) (sha256Hash, sha1Hash, md5Hash string, err error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", "", "", fmt.Errorf("hasher.HashFile: open: %w", err)
	}
	defer f.Close()

	h256 := sha256.New()
	h1 := sha1.New()
	hmd5 := md5.New()

	// Write to all three hashers in a single read pass.
	w := io.MultiWriter(h256, h1, hmd5)
	if _, err := io.Copy(w, f); err != nil {
		return "", "", "", fmt.Errorf("hasher.HashFile: hash: %w", err)
	}

	return hex.EncodeToString(h256.Sum(nil)),
		hex.EncodeToString(h1.Sum(nil)),
		hex.EncodeToString(hmd5.Sum(nil)),
		nil
}

// FileInfo bundles the stat values needed by the scanner
// and autorun code to decide whether to rehash.
type FileInfo struct {
	Size  int64
	MTime int64 // Unix timestamp
}

// StatFile returns size and mtime for the given path.
func StatFile(filePath string) (FileInfo, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return FileInfo{}, fmt.Errorf("hasher.StatFile: %w", err)
	}
	return FileInfo{
		Size:  info.Size(),
		MTime: info.ModTime().Unix(),
	}, nil
}
