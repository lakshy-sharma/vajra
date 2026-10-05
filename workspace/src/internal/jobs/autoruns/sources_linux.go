// internal/jobs/autoruns/sources_linux.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package autoruns

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"vajra/internal/scanner"
	"vajra/shared/models"
)

func GetSources() []AutorunSource {
	return []AutorunSource{
		&SystemdSystemSource{root: "/"},
		&SystemdUserSource{root: "/"},
		&CronSystemSource{root: "/"},
		&CronUserSource{spoolDir: "/var/spool/cron/crontabs"},
		&ShellProfileSource{root: "/"},
		&SysVInitSource{root: "/"},
		&XDGAutostartSource{root: "/"},
		&DBusSource{root: "/"},
		&AtJobSource{spoolDir: "/var/spool/at"},
		&AnacronSource{root: "/"},
		&LDPreloadSource{root: "/"},
		&PAMSource{root: "/"},
	}
}

func hashEntry(e *models.AutorunEntry) {
	if e.ImagePath == "" {
		return
	}
	sha256h, sha1h, md5h, err := scanner.HashFile(e.ImagePath)
	if err != nil {
		return
	}
	e.SHA256 = sha256h
	e.SHA1 = sha1h
	e.MD5 = md5h
}

func parseShellWords(line string) (exe, args string) {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return "", ""
	}
	return parts[0], strings.Join(parts[1:], " ")
}

func allUsers() []string {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil
	}
	defer f.Close()

	var homes []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) >= 6 && parts[5] != "" && parts[5] != "/" {
			homes = append(homes, parts[5])
		}
	}
	return homes
}

// ── Systemd ──────────────────────────────────────────────────

type SystemdSystemSource struct{ root string }

func (s *SystemdSystemSource) Name() string { return "systemd_system" }
func (s *SystemdSystemSource) Collect() ([]*models.AutorunEntry, error) {
	dirs := []string{
		filepath.Join(s.root, "etc/systemd/system"),
		filepath.Join(s.root, "usr/lib/systemd/system"),
		filepath.Join(s.root, "run/systemd/system"),
	}
	var entries []*models.AutorunEntry
	for _, dir := range dirs {
		found, _ := collectSystemdDir(dir, models.CategorySystemdSystem)
		entries = append(entries, found...)
	}
	return entries, nil
}

type SystemdUserSource struct{ root string }

func (s *SystemdUserSource) Name() string { return "systemd_user" }
func (s *SystemdUserSource) Collect() ([]*models.AutorunEntry, error) {
	dirs := []string{
		filepath.Join(s.root, "etc/systemd/user"),
		filepath.Join(s.root, "usr/lib/systemd/user"),
	}
	var entries []*models.AutorunEntry
	for _, dir := range dirs {
		found, _ := collectSystemdDir(dir, models.CategorySystemdUser)
		entries = append(entries, found...)
	}
	for _, home := range allUsers() {
		found, _ := collectSystemdDir(filepath.Join(home, ".config/systemd/user"), models.CategorySystemdUser)
		entries = append(entries, found...)
	}
	return entries, nil
}

var reSection = regexp.MustCompile(`^\[.*\]$`)

func collectSystemdDir(dir string, category models.AutorunCategory) ([]*models.AutorunEntry, error) {
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil
	}
	var results []*models.AutorunEntry
	for _, de := range dirEntries {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		isService := strings.HasSuffix(name, ".service")
		isTimer := strings.HasSuffix(name, ".timer")
		if !isService && !isTimer {
			continue
		}
		cat := category
		if isTimer {
			cat = models.CategorySystemdTimer
		}
		e, err := parseSystemdUnit(filepath.Join(dir, name), cat)
		if err != nil || e == nil {
			continue
		}
		hashEntry(e)
		results = append(results, e)
	}
	return results, nil
}

func parseSystemdUnit(path string, category models.AutorunCategory) (*models.AutorunEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	e := &models.AutorunEntry{Category: category, Location: path}
	section := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if reSection.MatchString(line) {
			section = line
			continue
		}
		switch section {
		case "[Service]":
			if strings.HasPrefix(line, "ExecStart=") {
				exe, args := parseShellWords(strings.TrimPrefix(line, "ExecStart="))
				e.ImagePath = exe
				e.ImageName = filepath.Base(exe)
				e.Arguments = args
			}
		case "[D-BUS Service]":
			if strings.HasPrefix(line, "Exec=") {
				exe, args := parseShellWords(strings.TrimPrefix(line, "Exec="))
				e.ImagePath = exe
				e.ImageName = filepath.Base(exe)
				e.Arguments = args
			}
		}
	}
	if e.ImagePath == "" {
		return nil, nil
	}
	return e, nil
}

// ── Cron ─────────────────────────────────────────────────────

type CronSystemSource struct{ root string }

func (s *CronSystemSource) Name() string { return "cron_system" }
func (s *CronSystemSource) Collect() ([]*models.AutorunEntry, error) {
	var entries []*models.AutorunEntry
	entries = append(entries, parseCrontab(filepath.Join(s.root, "etc/crontab"), models.CategoryCronSystem)...)

	files, err := os.ReadDir(filepath.Join(s.root, "etc/cron.d"))
	if err == nil {
		for _, f := range files {
			if !f.IsDir() {
				entries = append(entries, parseCrontab(filepath.Join(s.root, "etc/cron.d", f.Name()), models.CategoryCronSystem)...)
			}
		}
	}

	for _, d := range []string{"etc/cron.hourly", "etc/cron.daily", "etc/cron.weekly", "etc/cron.monthly"} {
		scripts, err := os.ReadDir(filepath.Join(s.root, d))
		if err != nil {
			continue
		}
		for _, sc := range scripts {
			if sc.IsDir() {
				continue
			}
			imgPath := filepath.Join(s.root, d, sc.Name())
			e := &models.AutorunEntry{
				Category:  models.CategoryCronSystem,
				Location:  filepath.Join(s.root, d),
				ImagePath: imgPath,
				ImageName: sc.Name(),
			}
			hashEntry(e)
			entries = append(entries, e)
		}
	}
	return entries, nil
}

type CronUserSource struct{ spoolDir string }

func (s *CronUserSource) Name() string { return "cron_user" }
func (s *CronUserSource) Collect() ([]*models.AutorunEntry, error) {
	files, err := os.ReadDir(s.spoolDir)
	if err != nil {
		return nil, nil
	}
	var entries []*models.AutorunEntry
	for _, f := range files {
		if !f.IsDir() {
			entries = append(entries, parseCrontab(filepath.Join(s.spoolDir, f.Name()), models.CategoryCronUser)...)
		}
	}
	return entries, nil
}

func parseCrontab(path string, category models.AutorunCategory) []*models.AutorunEntry {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var entries []*models.AutorunEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "=") && !strings.Contains(line, " ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		cmdIdx := 5
		if len(fields) > 6 && !strings.HasPrefix(fields[5], "/") {
			cmdIdx = 6
		}
		if cmdIdx >= len(fields) {
			continue
		}
		exe, args := parseShellWords(strings.Join(fields[cmdIdx:], " "))
		e := &models.AutorunEntry{
			Category:  category,
			Location:  path,
			ImagePath: exe,
			ImageName: filepath.Base(exe),
			Arguments: args,
		}
		hashEntry(e)
		entries = append(entries, e)
	}
	return entries
}

// ── Shell profiles ────────────────────────────────────────────

type ShellProfileSource struct{ root string }

func (s *ShellProfileSource) Name() string { return "shell_profile" }
func (s *ShellProfileSource) Collect() ([]*models.AutorunEntry, error) {
	var entries []*models.AutorunEntry

	for _, rel := range []string{"etc/profile", "etc/bash.bashrc", "etc/zsh/zshrc", "etc/zsh/zprofile"} {
		if e := profileEntry(filepath.Join(s.root, rel), models.CategoryShellProfile); e != nil {
			entries = append(entries, e)
		}
	}

	scripts, err := os.ReadDir(filepath.Join(s.root, "etc/profile.d"))
	if err == nil {
		for _, sc := range scripts {
			if !sc.IsDir() {
				if e := profileEntry(filepath.Join(s.root, "etc/profile.d", sc.Name()), models.CategoryShellProfile); e != nil {
					entries = append(entries, e)
				}
			}
		}
	}

	for _, home := range allUsers() {
		for _, rel := range []string{".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zprofile", ".zlogin"} {
			if e := profileEntry(filepath.Join(home, rel), models.CategoryShellProfile); e != nil {
				entries = append(entries, e)
			}
		}
	}
	return entries, nil
}

func profileEntry(path string, category models.AutorunCategory) *models.AutorunEntry {
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	e := &models.AutorunEntry{
		Category:  category,
		Location:  path,
		ImagePath: path,
		ImageName: filepath.Base(path),
	}
	hashEntry(e)
	return e
}

// ── SysV Init ─────────────────────────────────────────────────

type SysVInitSource struct{ root string }

func (s *SysVInitSource) Name() string { return "sysv_init" }
func (s *SysVInitSource) Collect() ([]*models.AutorunEntry, error) {
	initDir := filepath.Join(s.root, "etc/init.d")
	files, err := os.ReadDir(initDir)
	if err != nil {
		return nil, nil
	}
	var entries []*models.AutorunEntry
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		path := filepath.Join(initDir, f.Name())
		e := &models.AutorunEntry{
			Category:  models.CategorySysVInit,
			Location:  initDir,
			ImagePath: path,
			ImageName: f.Name(),
		}
		hashEntry(e)
		entries = append(entries, e)
	}
	return entries, nil
}

// ── XDG Autostart ─────────────────────────────────────────────

type XDGAutostartSource struct{ root string }

func (s *XDGAutostartSource) Name() string { return "xdg_autostart" }
func (s *XDGAutostartSource) Collect() ([]*models.AutorunEntry, error) {
	dirs := []string{filepath.Join(s.root, "etc/xdg/autostart")}
	for _, home := range allUsers() {
		dirs = append(dirs, filepath.Join(home, ".config/autostart"))
	}
	var entries []*models.AutorunEntry
	for _, dir := range dirs {
		found, _ := collectDesktopFiles(dir)
		entries = append(entries, found...)
	}
	return entries, nil
}

func collectDesktopFiles(dir string) ([]*models.AutorunEntry, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil
	}
	var entries []*models.AutorunEntry
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".desktop") {
			continue
		}
		e, err := parseDesktopFile(filepath.Join(dir, f.Name()))
		if err != nil || e == nil {
			continue
		}
		hashEntry(e)
		entries = append(entries, e)
	}
	return entries, nil
}

func parseDesktopFile(path string) (*models.AutorunEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	e := &models.AutorunEntry{Category: models.CategoryXDGAutostart, Location: path}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "Exec=") {
			val := regexp.MustCompile(`%[a-zA-Z]`).ReplaceAllString(strings.TrimPrefix(line, "Exec="), "")
			exe, args := parseShellWords(strings.TrimSpace(val))
			e.ImagePath = exe
			e.ImageName = filepath.Base(exe)
			e.Arguments = args
		}
	}
	if e.ImagePath == "" {
		return nil, nil
	}
	return e, nil
}

// ── D-Bus ─────────────────────────────────────────────────────

type DBusSource struct{ root string }

func (s *DBusSource) Name() string { return "dbus" }
func (s *DBusSource) Collect() ([]*models.AutorunEntry, error) {
	dirs := []string{
		filepath.Join(s.root, "usr/share/dbus-1/system-services"),
		filepath.Join(s.root, "usr/share/dbus-1/services"),
	}
	var entries []*models.AutorunEntry
	for _, dir := range dirs {
		files, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".service") {
				continue
			}
			e, err := parseDBusService(filepath.Join(dir, f.Name()))
			if err != nil || e == nil {
				continue
			}
			hashEntry(e)
			entries = append(entries, e)
		}
	}
	return entries, nil
}

func parseDBusService(path string) (*models.AutorunEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	e := &models.AutorunEntry{Category: models.CategoryDBus, Location: path}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "Exec=") {
			exe, args := parseShellWords(strings.TrimPrefix(line, "Exec="))
			e.ImagePath = exe
			e.ImageName = filepath.Base(exe)
			e.Arguments = args
		}
	}
	if e.ImagePath == "" {
		return nil, nil
	}
	return e, nil
}

// ── At jobs ───────────────────────────────────────────────────

type AtJobSource struct{ spoolDir string }

func (s *AtJobSource) Name() string { return "at_job" }
func (s *AtJobSource) Collect() ([]*models.AutorunEntry, error) {
	files, err := os.ReadDir(s.spoolDir)
	if err != nil {
		return nil, nil
	}
	var entries []*models.AutorunEntry
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		path := filepath.Join(s.spoolDir, f.Name())
		e := &models.AutorunEntry{
			Category:  models.CategoryAtJob,
			Location:  s.spoolDir,
			ImagePath: path,
			ImageName: f.Name(),
		}
		hashEntry(e)
		entries = append(entries, e)
	}
	return entries, nil
}

// ── Anacron ───────────────────────────────────────────────────

type AnacronSource struct{ root string }

func (s *AnacronSource) Name() string { return "anacron" }
func (s *AnacronSource) Collect() ([]*models.AutorunEntry, error) {
	return parseCrontab(filepath.Join(s.root, "etc/anacrontab"), models.CategoryAnacron), nil
}

// ── LD Preload ────────────────────────────────────────────────

type LDPreloadSource struct{ root string }

func (s *LDPreloadSource) Name() string { return "ld_preload" }
func (s *LDPreloadSource) Collect() ([]*models.AutorunEntry, error) {
	var entries []*models.AutorunEntry

	preload := filepath.Join(s.root, "etc/ld.so.preload")
	if f, err := os.Open(preload); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			e := &models.AutorunEntry{
				Category:  models.CategoryLDPreload,
				Location:  preload,
				ImagePath: line,
				ImageName: filepath.Base(line),
			}
			hashEntry(e)
			entries = append(entries, e)
		}
	}

	files, err := os.ReadDir(filepath.Join(s.root, "etc/ld.so.conf.d"))
	if err == nil {
		for _, f := range files {
			if f.IsDir() {
				continue
			}
			path := filepath.Join(s.root, "etc/ld.so.conf.d", f.Name())
			e := &models.AutorunEntry{
				Category:  models.CategoryLDPreload,
				Location:  path,
				ImagePath: path,
				ImageName: f.Name(),
			}
			hashEntry(e)
			entries = append(entries, e)
		}
	}
	return entries, nil
}

// ── PAM ───────────────────────────────────────────────────────

type PAMSource struct{ root string }

func (s *PAMSource) Name() string { return "pam" }
func (s *PAMSource) Collect() ([]*models.AutorunEntry, error) {
	pamDir := filepath.Join(s.root, "etc/pam.d")
	files, err := os.ReadDir(pamDir)
	if err != nil {
		return nil, nil
	}
	var entries []*models.AutorunEntry
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		found, err := parsePAMFile(filepath.Join(pamDir, f.Name()))
		if err != nil {
			continue
		}
		entries = append(entries, found...)
	}
	return entries, nil
}

func parsePAMFile(path string) ([]*models.AutorunEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []*models.AutorunEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		module := fields[2]
		if !strings.HasPrefix(module, "/") {
			continue
		}
		e := &models.AutorunEntry{
			Category:  models.CategoryPAM,
			Location:  path,
			ImagePath: module,
			ImageName: filepath.Base(module),
		}
		hashEntry(e)
		entries = append(entries, e)
	}
	return entries, nil
}
