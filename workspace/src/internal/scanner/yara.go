// internal/scanner/yara.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package scanner

import (
	"archive/zip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/hillu/go-yara/v4"
	"github.com/rs/zerolog"
)

// RulesCompiler handles rule extraction from a zip bundle
// and compilation into a *yara.Rules object.
type RulesCompiler struct {
	logger *zerolog.Logger
}

func NewRulesCompiler(logger *zerolog.Logger) *RulesCompiler {
	return &RulesCompiler{logger: logger}
}

// ExtractRules unzips a rules bundle into extractionPath,
// guarding against path traversal.
func (rc *RulesCompiler) ExtractRules(zipPath, extractionPath string) error {
	rc.logger.Info().
		Str("zip", zipPath).
		Str("dest", extractionPath).
		Msg("extracting YARA rules")

	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("yara.ExtractRules: open zip: %w", err)
	}
	defer r.Close()

	if err := os.MkdirAll(extractionPath, 0o755); err != nil {
		return fmt.Errorf("yara.ExtractRules: mkdir dest: %w", err)
	}

	var extracted int
	for _, f := range r.File {
		fpath := filepath.Join(extractionPath, f.Name)

		// Path traversal guard.
		rel, err := filepath.Rel(extractionPath, fpath)
		if err != nil || strings.HasPrefix(rel, "..") {
			rc.logger.Warn().Str("file", f.Name).Msg("skipping: path traversal risk")
			continue
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(fpath, f.Mode()); err != nil {
				return fmt.Errorf("yara.ExtractRules: mkdir %s: %w", fpath, err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fpath), 0o755); err != nil {
			return fmt.Errorf("yara.ExtractRules: mkdir parent: %w", err)
		}

		if err := writeFile(f, fpath); err != nil {
			return err
		}

		extracted++
	}

	rc.logger.Info().Int("files", extracted).Msg("rule extraction complete")
	return nil
}

func writeFile(f *zip.File, dest string) error {
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
	if err != nil {
		return fmt.Errorf("yara.writeFile: create %s: %w", dest, err)
	}
	defer out.Close()

	in, err := f.Open()
	if err != nil {
		return fmt.Errorf("yara.writeFile: open zip entry: %w", err)
	}
	defer in.Close()

	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("yara.writeFile: copy %s: %w", dest, err)
	}

	return nil
}

// CompileRules walks rulesDir recursively, compiles all
// .yar/.yara files into a single *yara.Rules object.
// Files with syntax errors are skipped and logged.
func (rc *RulesCompiler) CompileRules(rulesDir string) (*yara.Rules, error) {
	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("yara.CompileRules: new compiler: %w", err)
	}
	defer compiler.Destroy()

	var added, skipped int

	err = filepath.WalkDir(rulesDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		name := d.Name()
		if !strings.HasSuffix(name, ".yar") && !strings.HasSuffix(name, ".yara") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			rc.logger.Error().Err(err).Str("file", path).Msg("cannot read rule file")
			skipped++
			return nil
		}

		// Validate syntax in a throwaway compiler before
		// touching the main one — a bad rule must never
		// corrupt the main compiler state.
		if !rc.validateRule(string(content), path) {
			skipped++
			return nil
		}

		if err := compiler.AddString(string(content), path); err != nil {
			rc.logger.Error().Err(err).Str("file", path).Msg("unexpected compile error after validation")
			skipped++
			return nil
		}

		added++
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("yara.CompileRules: walk: %w", err)
	}

	rules, err := compiler.GetRules()
	if err != nil {
		return nil, fmt.Errorf("yara.CompileRules: get rules: %w", err)
	}

	rc.logger.Info().
		Int("added", added).
		Int("skipped", skipped).
		Msg("YARA rule compilation complete")

	return rules, nil
}

// validateRule returns true if the rule string compiles
// without errors in an isolated throwaway compiler.
func (rc *RulesCompiler) validateRule(content, path string) bool {
	check, err := yara.NewCompiler()
	if err != nil {
		return false
	}
	defer check.Destroy()

	if err := check.AddString(content, path); err != nil {
		rc.logger.Error().Err(err).Str("file", path).Msg("YARA syntax error, skipping rule")
		return false
	}

	return true
}
