// internal/utilities/detectionlists.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

// Package utilities — detection reference lists.
//
// This file contains ONLY curated constant lists used by detection logic.
// No code lives here. Every list cites its authoritative source.
// To add or remove entries, edit this file directly and note the reason.
//
// REVISIT: These lists require periodic review against current interpreter
// landscape. Track new scripting runtimes and versioned interpreter binaries
// as distributions update. Last reviewed: October 2026.

package utilities

// KnownInterpreters is the set of scripting language interpreter binary
// basenames. Used exclusively by the file scanner eligibility check.
//
// When a FileEvent's TriggerComm matches an entry here, the magic byte
// check is bypassed and the opened file is submitted to YARA regardless
// of its content signature. This closes the gap where malicious scripts
// without a shebang line (e.g. `python3 malware.py`) would escape scanning
// since the script file itself carries no ELF or shebang magic bytes.
//
// This list is NOT used for reverse shell detection. Reverse shell detection
// is driven purely by dup2/dup3 events onto stdio fds — no process name
// filtering applies there.
//
// Sources:
//   - Wikipedia "Scripting language" — https://en.wikipedia.org/wiki/Scripting_language
//   - Wikipedia "List of programming languages by type" (Interpreted section)
//     https://en.wikipedia.org/wiki/List_of_programming_languages_by_type
//   - Wikipedia "List of command-line interpreters"
//     https://en.wikipedia.org/wiki/List_of_command-line_interpreters
var KnownInterpreters = map[string]bool{
	// Python — https://www.python.org/
	"python":     true,
	"python2":    true,
	"python3":    true,
	"python3.6":  true,
	"python3.7":  true,
	"python3.8":  true,
	"python3.9":  true,
	"python3.10": true,
	"python3.11": true,
	"python3.12": true,
	"python3.13": true,

	// Perl — https://www.perl.org/
	"perl":  true,
	"perl5": true,

	// Ruby — https://www.ruby-lang.org/
	"ruby":  true,
	"ruby3": true,

	// PHP — https://www.php.net/
	"php":  true,
	"php5": true,
	"php7": true,
	"php8": true,

	// Node.js / JavaScript — https://nodejs.org/
	"node":   true,
	"nodejs": true,

	// Lua — https://www.lua.org/
	"lua":    true,
	"lua5.1": true,
	"lua5.2": true,
	"lua5.3": true,
	"lua5.4": true,

	// Tcl — https://www.tcl.tk/
	"tclsh": true,
	"wish":  true,

	// R — statistical computing, https://www.r-project.org/
	"Rscript": true,
	"R":       true,

	// Groovy — https://groovy-lang.org/
	"groovy": true,

	// Julia — https://julialang.org/
	"julia": true,

	// AWK variants — text processing interpreters, execute arbitrary code from files
	"awk":  true,
	"gawk": true,
	"mawk": true,
	"nawk": true,

	// Expect — scripted terminal interaction, https://core.tcl-lang.org/expect/
	"expect": true,
}
