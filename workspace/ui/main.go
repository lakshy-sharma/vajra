// ui/main.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package main

import (
	"embed"
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
	cfgPath := os.Getenv("VAJRA_CONFIG")
	if cfgPath == "" {
		cfgPath = "/etc/vajra/config.yaml"
	}

	app := NewApp(cfgPath)

	err := wails.Run(&options.App{
		Title:  "Vajra EDR",
		Width:  1280,
		Height: 800,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 18, G: 18, B: 18, A: 1},
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
		Bind:             []interface{}{app},
		LogLevel:         logger.WARNING,
		Linux: &linux.Options{
			// Use the system WebKit; ships with most distros via libwebkit2gtk.
			// WindowIsTranslucent is false — solid background avoids compositor
			// artefacts on compositors that don't support alpha on app windows.
			ProgramName:         "vajra-ui",
			Icon:                nil,
			WindowIsTranslucent: false,
		},
	})
	if err != nil {
		log.Fatalf("vajra-ui: run: %v", err)
	}
}
