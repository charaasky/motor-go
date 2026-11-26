package main

// Resolución de "padres legítimos" (supervisores de la propia defensa) que
// pueden lanzar `docker` sin disparar DOCKER_CLI ni APP_PROCESO_INESPERADO.
//
// Dos fuentes, combinables:
//   - `-allow-docker-pid`  : PIDs explícitos (para una ejecución puntual).
//   - `-config`            : archivo con patrones de cmdline (uno por línea,
//                            `#` comentarios). Se re-resuelve cada 10 s, de
//                            modo que no importa si el supervisor se reinicia
//                            con otro PID.
//
// El kernel solo da `comm` (16 bytes) del padre, insuficiente para distinguir
// `guardian.py` de cualquier otro `python3`; por eso el mapeo patrón→PID se
// hace en userspace leyendo /proc/<pid>/cmdline.

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	allowMu    sync.RWMutex
	flagPids   = map[uint32]bool{} // de -allow-docker-pid
	configPids = map[uint32]bool{} // resueltos desde -config
	configPath string
)

func init() {
	flag.StringVar(&configPath, "config", "", "archivo de config: patrones de cmdline de padres legítimos (uno por línea, # comentarios)")
	flag.Func("allow-docker-pid", "PIDs de padres que pueden lanzar docker sin alerta (coma-separados)", func(s string) error {
		for _, p := range strings.Split(s, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			var n uint64
			if _, err := fmt.Sscanf(p, "%d", &n); err != nil {
				return fmt.Errorf("PID inválido: %q", p)
			}
			allowMu.Lock()
			flagPids[uint32(n)] = true
			allowMu.Unlock()
		}
		return nil
	})
}

// isAllowedDocker informa si el padre (ppid) está whitelisteado.
func isAllowedDocker(ppid uint32) bool {
	allowMu.RLock()
	defer allowMu.RUnlock()
	return flagPids[ppid] || configPids[ppid]
}

// resolveTrustedPids escanea /proc/*/cmdline y mapea los PIDs cuyo cmdline
// contiene alguno de los patrones del config. Devuelve cuántos encontró.
func resolveTrustedPids() int {
	patterns := readPatterns()
	if len(patterns) == 0 {
		return 0
	}
	found := map[uint32]bool{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err != nil {
			continue
		}
		line := strings.ReplaceAll(string(raw), "\x00", " ")
		for _, pat := range patterns {
			if strings.Contains(line, pat) {
				found[uint32(pid)] = true
				break
			}
		}
	}
	allowMu.Lock()
	configPids = found
	allowMu.Unlock()
	return len(found)
}

func readPatterns() []string {
	if configPath == "" {
		return nil
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, l)
	}
	return out
}

// startTrustedRefresher re-resuelve los PIDs cada 10 s (por si un supervisor
// se reinicia y cambia de PID). No bloquea y no loguea (silencioso).
func startTrustedRefresher() {
	if configPath == "" {
		return
	}
	go func() {
		for {
			time.Sleep(10 * time.Second)
			resolveTrustedPids()
		}
	}()
}
