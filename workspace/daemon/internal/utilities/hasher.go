// internal/utilities/hasher.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package utilities

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

const quickHashBytes = 8192

// QuickHash hashes the first 8KB, last 8KB, and mtime of a file.
// Fast enough for dedup — not suitable as a forensic hash.
// Catches both prepend/append injection and in-place replacement.
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

	var mtimeBuf [8]byte
	binary.LittleEndian.PutUint64(mtimeBuf[:], uint64(info.ModTime().Unix()))
	h.Write(mtimeBuf[:])

	return hex.EncodeToString(h.Sum(nil)), nil
}

// FullSHA256 returns the SHA256 of the entire file.
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

// HashFile computes SHA256, SHA1, and MD5 in a single pass.
func HashFile(filePath string) (sha256Hash, sha1Hash, md5Hash string, err error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", "", "", fmt.Errorf("hashfile: open: %w", err)
	}
	defer f.Close()

	h256 := sha256.New()
	h1 := sha1.New()
	hmd5 := md5.New()

	if _, err := io.Copy(io.MultiWriter(h256, h1, hmd5), f); err != nil {
		return "", "", "", fmt.Errorf("hashfile: hash: %w", err)
	}
	return hex.EncodeToString(h256.Sum(nil)),
		hex.EncodeToString(h1.Sum(nil)),
		hex.EncodeToString(hmd5.Sum(nil)),
		nil
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
