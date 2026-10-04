// internal/scanner/hasher.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package scanner

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

const quickHashBytes = 8192 // 8 KB sample from start and end

// QuickHash returns a SHA256 of:
//   - first 8 KB of the file
//   - last 8 KB of the file (or overlap with first if file < 16 KB)
//   - file mtime as a little-endian uint64
//
// This catches both prepend and append injection, and ensures a
// binary replaced in-place (same content, new mtime) is treated
// as a new file rather than being deduplicated away.
// Not suitable as a forensic hash — use FullSHA256 for that.
func QuickHash(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("hasher.QuickHash: open: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("hasher.QuickHash: stat: %w", err)
	}

	size := info.Size()
	mtime := info.ModTime().Unix()

	h := sha256.New()

	// ── First 8 KB ────────────────────────────────────────────
	head := make([]byte, quickHashBytes)
	n, err := f.Read(head)
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("hasher.QuickHash: read head: %w", err)
	}
	h.Write(head[:n])

	// ── Last 8 KB ─────────────────────────────────────────────
	// Only seek to the tail if the file is large enough that
	// the tail doesn't overlap with the head we already read.
	// For files ≤ 16 KB the head read already covered everything.
	if size > int64(quickHashBytes*2) {
		tailOffset := size - int64(quickHashBytes)
		if _, err := f.Seek(tailOffset, io.SeekStart); err != nil {
			return "", fmt.Errorf("hasher.QuickHash: seek tail: %w", err)
		}
		tail := make([]byte, quickHashBytes)
		n, err = f.Read(tail)
		if err != nil && err != io.EOF {
			return "", fmt.Errorf("hasher.QuickHash: read tail: %w", err)
		}
		h.Write(tail[:n])
	}

	// ── mtime ─────────────────────────────────────────────────
	// Encode mtime as 8 bytes so a binary replaced in-place
	// (identical bytes, new timestamp) produces a different hash
	// and bypasses the dedup cache correctly.
	var mtimeBuf [8]byte
	binary.LittleEndian.PutUint64(mtimeBuf[:], uint64(mtime))
	h.Write(mtimeBuf[:])

	return hex.EncodeToString(h.Sum(nil)), nil
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
