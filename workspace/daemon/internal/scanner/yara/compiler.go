// internal/scanner/yara/compiler.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package yara

import (
	"archive/zip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	goyara "github.com/hillu/go-yara/v4"
	"github.com/rs/zerolog"
)

// Compiler handles extraction and compilation of YARA rule bundles.
type Compiler struct {
	logger *zerolog.Logger
}

func NewCompiler(logger *zerolog.Logger) *Compiler {
	return &Compiler{logger: logger}
}

// ExtractRules unzips a rules bundle into extractionPath,
// guarding against path traversal.
func (c *Compiler) ExtractRules(zipPath, extractionPath string) error {
	c.logger.Info().Str("zip", zipPath).Str("dest", extractionPath).Msg("extracting YARA rules")

	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("yara: extract: open zip: %w", err)
	}
	defer r.Close()

	if err := os.MkdirAll(extractionPath, 0o755); err != nil {
		return fmt.Errorf("yara: extract: mkdir: %w", err)
	}

	var extracted int
	for _, f := range r.File {
		fpath := filepath.Join(extractionPath, f.Name)
		rel, err := filepath.Rel(extractionPath, fpath)
		if err != nil || strings.HasPrefix(rel, "..") {
			c.logger.Warn().Str("file", f.Name).Msg("skipping: path traversal risk")
			continue
		}
		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, f.Mode())
			continue
		}
		if err := os.MkdirAll(filepath.Dir(fpath), 0o755); err != nil {
			return fmt.Errorf("yara: extract: mkdir parent: %w", err)
		}
		if err := writeZipEntry(f, fpath); err != nil {
			return err
		}
		extracted++
	}

	c.logger.Info().Int("files", extracted).Msg("rule extraction complete")
	return nil
}

// CompileRules walks rulesDir and compiles all .yar/.yara files
// into a single *goyara.Rules object. Bad rules are skipped, not fatal.
func (c *Compiler) CompileRules(rulesDir string) (*goyara.Rules, error) {
	compiler, err := goyara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("yara: compile: new compiler: %w", err)
	}
	defer compiler.Destroy()

	var added, skipped int
	err = filepath.WalkDir(rulesDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".yar") && !strings.HasSuffix(name, ".yara") {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			c.logger.Error().Err(err).Str("file", path).Msg("cannot read rule file")
			skipped++
			return nil
		}
		if !c.validateRule(string(content), path) {
			skipped++
			return nil
		}
		if err := compiler.AddString(string(content), path); err != nil {
			c.logger.Error().Err(err).Str("file", path).Msg("unexpected compile error after validation")
			skipped++
			return nil
		}
		added++
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("yara: compile: walk: %w", err)
	}

	rules, err := compiler.GetRules()
	if err != nil {
		return nil, fmt.Errorf("yara: compile: get rules: %w", err)
	}

	c.logger.Info().Int("added", added).Int("skipped", skipped).Msg("YARA rule compilation complete")
	return rules, nil
}

// validateRule compiles a rule in an isolated throwaway compiler.
// A syntax error must never corrupt the main compiler state.
func (c *Compiler) validateRule(content, path string) bool {
	check, err := goyara.NewCompiler()
	if err != nil {
		return false
	}
	defer check.Destroy()
	if err := check.AddString(content, path); err != nil {
		c.logger.Error().Err(err).Str("file", path).Msg("YARA syntax error, skipping rule")
		return false
	}
	return true
}

func writeZipEntry(f *zip.File, dest string) error {
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
	if err != nil {
		return fmt.Errorf("yara: write entry: create: %w", err)
	}
	defer out.Close()
	in, err := f.Open()
	if err != nil {
		return fmt.Errorf("yara: write entry: open: %w", err)
	}
	defer in.Close()
	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("yara: write entry: copy: %w", err)
	}
	return nil
}
