// internal/utilities/split.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package utilities

import "bytes"

// NullScanner is a bufio.SplitFunc for null-byte-delimited byte streams.
// /proc/PID/environ separates key=value pairs with null bytes rather than
// newlines — the standard bufio.ScanLines would read the entire file as
// one token.
func NullScanner(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexByte(data, 0); i >= 0 {
		return i + 1, data[:i], nil
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}
