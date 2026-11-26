package main

// Respuesta activa: auditoría + matar ofensor + conexión con responder.py.
//
// - `-output <file>` : anexa cada alerta (JSONL) a un archivo de auditoría.
// - `-respond`       : escribe eventos compatibles con `fase-c/bloqueo/responder.py`
//                      (mismo formato Falco: rule + output_fields.proc.pid/pname)
//                      para que el responder existente mate/bore la amenaza.
// - `-kill`          : respuesta activa DIRECTA en Go: SIGKILL al ofensor y su
//                      árbol (sin depender de responder.py).

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	outputFile     string
	respondMode    bool
	killMode       bool
	respondPathStr string
)

func init() {
	flag.StringVar(&outputFile, "output", "", "archivo JSONL donde anexar alertas (auditoría); vacío = solo stdout")
	flag.BoolVar(&respondMode, "respond", false, "escribir eventos compatibles con responder.py en el events.jsonl")
	flag.StringVar(&respondPathStr, "respond-path", "", "ruta del events.jsonl del responder (con -respond); por defecto ../fase-c/bloqueo/events.jsonl relativo al CWD")
	flag.BoolVar(&killMode, "kill", false, "respuesta activa directa: SIGKILL al proceso ofensor y su árbol")
}

// respondFile: archivo que vigila el responder de Falco.
func respondFile() string {
	if respondPathStr != "" {
		return respondPathStr
	}
	wd, _ := os.Getwd()
	return filepath.Join(wd, "..", "fase-c", "bloqueo", "events.jsonl")
}

// respondRule mapea una regla de motor-go a la regla Falco que el responder
// sabe matar. Si no hay equivalente, devuelve el nombre original (se registra
// en events.jsonl pero el responder no actúa sobre ella).
func respondRule(rule string) string {
	m := map[string]string{
		"SHELL (RCE)":            "Shell lanzado",
		"DOCKER_CLI":             "App web lanza proceso inesperado (RCE sin shell)",
		"APP_PROCESO_INESPERADO": "App web lanza proceso inesperado (RCE sin shell)",
		"MMAP_RWX":               "mmap RWX",
	}
	if r, ok := m[rule]; ok {
		return r
	}
	return rule
}

// emit imprime (stdout) y, con -output, anexa al archivo de auditoría.
func emit(rule, proc, extra string) {
	if !lim.allowed(rule, proc) {
		return
	}
	if !policyRuleAllowed(rule) {
		return
	}
	j, _ := json.Marshal(map[string]any{
		"rule": rule, "proc": proc, "detail": extra, "ts": time.Now().Format(time.RFC3339),
	})
	fmt.Println(string(j))
	appendLine(outputFile, j)
}

// emitProc es emit para reglas con PID: además escribe el evento compatible
// con responder.py y, con -kill, mata al ofensor.
func emitProc(rule, proc string, pid uint32, extra string) {
	emit(rule, proc, extra)
	if respondMode && pid != 0 {
		ev, _ := json.Marshal(map[string]any{
			"rule": respondRule(rule),
			"output_fields": map[string]any{
				"proc.pid":   pid,
				"proc.pname": proc,
			},
		})
		appendLine(respondFile(), ev)
	}
	maybeKill(pid)
	// Quorum sensing: ≥N eventos del mismo origen → kill-chain.
	if rule != "KILL_CHAIN (quorum)" && co.observe(proc) {
		emitProc("KILL_CHAIN (quorum)", proc, pid, "≥4 eventos del mismo origen en 10s")
	}
}

func appendLine(path string, b []byte) {
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("respond: no se pudo abrir %s: %v", path, err)
		return
	}
	f.Write(append(b, '\n'))
	f.Close()
}

func maybeKill(pid uint32) {
	if !killMode || pid == 0 {
		return
	}
	// Cinturón y tirantes: nunca matarse a sí mismo, sea cual sea la regla que
	// lo haya disparado (defensa en profundidad además de defenseTools).
	if pid == uint32(os.Getpid()) {
		return
	}
	if ks := killTree(pid); len(ks) > 0 {
		log.Printf("respuesta activa: SIGKILL árbol %v", ks)
	}
}

// killTree mata el proceso y sus hijos (recursivo vía /proc/<pid>/task/<pid>/children).
func killTree(pid uint32) []int {
	killed := []int{}
	for _, c := range childrenOf(pid) {
		killed = append(killed, killTree(uint32(c))...)
	}
	if err := syscall.Kill(int(pid), syscall.SIGKILL); err == nil {
		killed = append(killed, int(pid))
	}
	return killed
}

func childrenOf(pid uint32) []int {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", pid, pid))
	if err != nil {
		return nil
	}
	var out []int
	for _, s := range strings.Fields(string(data)) {
		if n, err := strconv.Atoi(s); err == nil {
			out = append(out, n)
		}
	}
	return out
}
