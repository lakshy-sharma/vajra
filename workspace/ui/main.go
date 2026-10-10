// ui/main.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package main

import (
	"embed"
	"flag"
	"log"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/logger"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/linux"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	// Config path resolution order:
	//   1. --config flag
	//   2. VAJRA_CONFIG environment variable
	//   3. /etc/vajra/config.yaml default
	defaultCfg := os.Getenv("VAJRA_CONFIG")
	if defaultCfg == "" {
		defaultCfg = "/etc/vajra/config.yaml"
	}
	cfgPath := flag.String("config", defaultCfg, "path to config.yaml")
	flag.Parse()

	app := NewApp(*cfgPath)

	// UI5: derive window background from the configured theme so the native
	// window colour matches what the HTML will render — prevents a flash of
	// mismatched colour between the OS window draw and the first HTML paint.
	// The blocking <script> in index.html also sets data-theme before the
	// bundle loads; this just makes the window chrome consistent.
	bgColour := &options.RGBA{R: 10, G: 10, B: 10, A: 255} // dark default

	// UI6: read window dimensions from config.
	width, height := 1280, 800
	minWidth, minHeight := 900, 600

	if app.cfg != nil {
		ui := app.cfg.UISettings
		switch ui.DefaultTheme {
		case "light":
			bgColour = &options.RGBA{R: 255, G: 255, B: 255, A: 255}
			// "dark" and "system" both use the dark background above — for "system"
			// the blocking script in index.html corrects it before first paint.
		}
		if ui.WindowWidth > 0 {
			width = ui.WindowWidth
		}
		if ui.WindowHeight > 0 {
			height = ui.WindowHeight
		}
		if ui.MinWindowWidth > 0 {
			minWidth = ui.MinWindowWidth
		}
		if ui.MinWindowHeight > 0 {
			minHeight = ui.MinWindowHeight
		}
	}

	err := wails.Run(&options.App{
		Title:            "Vajra EDR",
		Width:            width,
		Height:           height,
		MinWidth:         minWidth,  // UI6
		MinHeight:        minHeight, // UI6
		BackgroundColour: bgColour,  // UI5
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		OnStartup:  app.startup,
		OnShutdown: app.shutdown,
		Bind:       []interface{}{app},
		LogLevel:   logger.WARNING,
		Linux: &linux.Options{
			ProgramName:         "vajra-ui",
			Icon:                nil,
			WindowIsTranslucent: false,
		},
	})
	if err != nil {
		log.Fatalf("vajra-ui: run: %v", err)
	}
}
