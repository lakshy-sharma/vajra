/*
Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
package utilities

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

type YaraHandler struct {
	logger *zerolog.Logger
}

func NewYaraCompiler(logger *zerolog.Logger) *YaraHandler {
	return &YaraHandler{
		logger: logger,
	}
}

// Extracts all rules into designated directory.
func (yh *YaraHandler) ExtractRules(zipPath string, extractionPath string) error {
	yh.logger.Info().Str("zip", zipPath).Str("dest", extractionPath).Msg("starting rule extraction")

	var openedFiles int

	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open zip file %s: %w", zipPath, err)
	}
	defer r.Close()

	// Ensure the destination directory exists
	if err := os.MkdirAll(extractionPath, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	for _, f := range r.File {
		// Construct the full path for the extracted file
		fpath := filepath.Join(extractionPath, f.Name)

		// Security check: Prevent Path Traversal (crucial for untrusted zip files)
		relPath, err := filepath.Rel(extractionPath, fpath)
		if err != nil || strings.HasPrefix(relPath, "..") {
			yh.logger.Warn().Str("filename", f.Name).Msg("skipping file due to path traversal risk")
			continue
		}

		// Handle directories
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(fpath, f.Mode()); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", fpath, err)
			}
			continue
		}

		// Handle files
		if err := os.MkdirAll(filepath.Dir(fpath), 0755); err != nil {
			return fmt.Errorf("failed to create file path dir: %w", err)
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return fmt.Errorf("failed to create output file %s: %w", fpath, err)
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return fmt.Errorf("failed to open file in zip: %w", err)
		}

		_, err = io.Copy(outFile, rc)
		// Close handles immediately after use
		rc.Close()
		outFile.Close()
		openedFiles++
		if err != nil {
			return fmt.Errorf("failed to copy content for %s: %w", fpath, err)
		}
	}
	yh.logger.Info().Int("rule_files", openedFiles).Msg("rule extraction complete.")
	return nil
}

// Compiles all yara rules specified inside a target directory.
func (yh *YaraHandler) CompileRules(rulesDir string) (*yara.Rules, error) {
	var rulesAdded int
	var rulesSkipped int

	// Start a new compiler.
	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("could not create YARA compiler: %w", err)
	}
	defer compiler.Destroy()

	// Parse all files and
	if err = filepath.WalkDir(rulesDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		// Only process files ending in .yar or .yara
		if strings.HasSuffix(d.Name(), ".yar") || strings.HasSuffix(d.Name(), ".yara") {
			yh.logger.Debug().Str("rule_file", path).Msg("adding rule to compiler")

			// Read the rule content.
			content, readErr := os.ReadFile(path)
			if readErr != nil {
				yh.logger.Error().Err(readErr).Str("rule_file", path).Msg("could not read rule file content")
				rulesSkipped++
				return nil
			}

			// Create a temp compiler for syntax checking
			checkCompiler, checkErr := yara.NewCompiler()
			if checkErr != nil {
				return fmt.Errorf("could not create temporary YARA compiler for checking: %w", checkErr)
			}
			defer checkCompiler.Destroy()
			ruleContent := string(content)

			// Attempt to compile the rule into temp compiler
			if addErr := checkCompiler.AddString(ruleContent, path); addErr != nil {
				yh.logger.Error().Err(addErr).Str("rule_file", path).Msg("syntax error in rule file. skipping")
				rulesSkipped++
				// Do NOT touch the main compiler. Continue walking.
				return nil
			}

			// If temp compiler passed then add rule to main compiler.
			if finalAddErr := compiler.AddString(ruleContent, path); finalAddErr != nil {
				return fmt.Errorf("unexpected error adding pre-checked rule to main compiler %s: %w", path, finalAddErr)
			}

			rulesAdded++
			yh.logger.Debug().Str("rule_file", path).Msg("rule added to compiler")
		}
		return nil
	}); err != nil {
		return nil, err
	}

	// Get compiled rules from compiler.
	rules, err := compiler.GetRules()
	if err != nil {
		return nil, fmt.Errorf("could not get compiled rules after adding files: %w", err)
	}

	yh.logger.Info().Int("rule_added", rulesAdded).Int("rules_skipped", rulesSkipped).Msg("compiled rules")
	return rules, nil
}
