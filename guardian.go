package main

// Guardian (defensa que se vigila a sí misma): detecta si una pieza de defensa
// cae (falco/suricata/responder/guardian) y alerta. Equivalente en Go de
// fase-w/guardian.py (versión de detección, sin auto-restart del contenedor).

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var watchDefense = []string{"falco", "suricata", "tetragon", "responder.py", "guardian.py"}

var defState = map[string]bool{}

func startGuardian() {
	go func() {
		for range time.Tick(5 * time.Second) {
			checkDefense()
		}
	}()
}

func checkDefense() {
	procs := readProcNames()
	for _, name := range watchDefense {
		present := procs[name]
		if defState[name] && !present {
			emit("DEFENSA_APAGADA", "guardian", fmt.Sprintf("pieza de defensa %q no encontrada", name))
		}
		defState[name] = present
	}
}

// readProcNames mapea los nombres vistos en /proc (comm + tokens del cmdline).
func readProcNames() map[string]bool {
	out := map[string]bool{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		if comm, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm")); err == nil {
			out[strings.TrimSpace(string(comm))] = true
		}
		if cmd, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline")); err == nil {
			for _, part := range strings.Split(strings.ReplaceAll(string(cmd), "\x00", " "), " ") {
				if part != "" {
					out[part] = true
				}
			}
		}
	}
	return out
}
