// main.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package main

import (
	"vajra/cmd"

	"github.com/common-nighthawk/go-figure"
)

func main() {
	myFigure := figure.NewColorFigure("Vajra", "", "green", true)
	myFigure.Print()
	cmd.Execute()
}
