package main

import (
	"fmt"
	"os"
	"runtime/debug"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/matinsenpai/senpaiscanner/internal/debuglog"
	"github.com/matinsenpai/senpaiscanner/internal/ui"
	"github.com/matinsenpai/senpaiscanner/pkg/version"
)

func main() {
	// --version flag without launching TUI
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-v" || os.Args[1] == "version") {
		fmt.Println("SenPai Scanner", version.String())
		return
	}

	settings := debuglog.LoadSettings()
	for {
		if err := debuglog.StartSession(settings.DebugMode, version.Version, os.Args); err != nil {
			fmt.Fprintln(os.Stderr, "debug log error:", err)
		}
		model := ui.NewApp(version.Version, settings.DebugMode)

		p := tea.NewProgram(
			model,
			tea.WithAltScreen(),
			tea.WithMouseCellMotion(),
		)

		// Give the UI package a reference so background goroutines can send messages.
		ui.SetProgram(p)

		finalModel, err := runProgram(p)
		if err != nil {
			debuglog.Printf("program_error error=%q", err.Error())
			debuglog.Close("error")
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}

		app, _ := finalModel.(ui.AppModel)
		if app.RestartRequested() {
			debuglog.Close("restart")
			settings = debuglog.LoadSettings()
			continue
		}
		debuglog.Close("normal")
		return
	}
}

func runProgram(p *tea.Program) (model tea.Model, err error) {
	defer func() {
		if v := recover(); v != nil {
			debuglog.Printf("panic scope=main value=%v stack=%q", v, string(debug.Stack()))
			debuglog.Close("panic")
			panic(v)
		}
	}()
	return p.Run()
}
