package main

// Invariantes de escape (P1).
//
// El sujeto firmado en la política (cgroup + UID + exe/allow) es la "forma"
// esperada del proceso que corre DENTRO de la microVM. Cualquier desviación es
// señal de escape y se emite como regla ESCAPE_*:
//
//   ESCAPE_UID               proceso del cgroup con UID real/efectivo distinto
//                            al firmado (escalada de privilegios dentro del VM).
//   ESCAPE_EXEC              proceso del cgroup cuyo binario no está en
//                            {exe} ∪ {allow} (el guest rompió el VMM y ejecutó
//                            un binario de host, o apareció un proceso nuevo).
//   ESCAPE_CGROUP_MIGRATION  proceso del sujeto que salió del cgroup estando
//                            vivo (evasión del filtro por cgroup).
//
// Un único watcher (goroutine) escanea el cgroup cada 2s. La latencia máxima de
// detección es de 2s. El escaneo se ejecuta como root (igual que el resto de
// px-motor), por lo que puede leer /proc/<pid>/{status,comm,exe} de cualquier
// UID.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const escapeInterval = 2 * time.Second
const escapeReemit = 30 * time.Second // dedup: no repetir la misma señal antes de 30s

var (
	subjectAllowed map[string]bool     // {exe} ∪ allow (basename/ruta)
	subjectSeen    = map[uint32]bool{} // PIDs vistos en el último escaneo
	escapeEmitted  = map[string]time.Time{}
)

// startEscapeInvariants lanza el watcher si hay un sujeto (cgroup) y al menos
// una invariante firmada (UID o binario). Se llama tras loadPolicy().
func startEscapeInvariants() {
	if subjectCgroup == "" {
		return
	}
	if policyState.uid < 0 && policyState.exe == "" && len(policyState.allow) == 0 {
		return // sin invariantes firmadas que verificar
	}
	buildSubjectAllowed()
	go func() {
		for {
			time.Sleep(escapeInterval)
			checkEscapeInvariants()
		}
	}()
	log.Printf("escape-invariants: watcher activo (cgroup=%s, uid=%d, exe=%q, allow=%d)",
		subjectCgroup, policyState.uid, policyState.exe, len(policyState.allow))
}

func buildSubjectAllowed() {
	subjectAllowed = map[string]bool{}
	if policyState.exe != "" {
		subjectAllowed[policyState.exe] = true
	}
	for _, a := range policyState.allow {
		if a != "" {
			subjectAllowed[a] = true
		}
	}
}

func checkEscapeInvariants() {
	procs := readCgroupProcs(subjectCgroup)
	seen := map[uint32]bool{}
	for _, p := range procs {
		seen[p] = true
		checkSubjectPID(p)
	}
	// Migración de cgroup: estaba en el último escaneo, ya no está, y sigue vivo.
	for p := range subjectSeen {
		if seen[p] {
			continue
		}
		if processAlive(p) {
			comm, _ := procComm(p)
			emitEscape("ESCAPE_CGROUP_MIGRATION", comm, p, fmt.Sprintf("salió del cgroup %s", subjectCgroup))
		}
		delete(subjectSeen, p)
	}
	for p := range seen {
		subjectSeen[p] = true
	}
}

func checkSubjectPID(pid uint32) {
	comm, ok := procComm(pid)
	if !ok {
		return
	}
	if policyState.uid >= 0 {
		real, eff, ok := procUIDs(pid)
		if ok && (real != policyState.uid || eff != policyState.uid) {
			emitEscape("ESCAPE_UID", comm, pid,
				fmt.Sprintf("UID real=%d efectivo=%d (esperado %d)", real, eff, policyState.uid))
		}
	}
	if !matchSubjectProcess(pid, comm) {
		emitEscape("ESCAPE_EXEC", comm, pid,
			fmt.Sprintf("binario no permitido %q en el cgroup del sujeto", comm))
	}
}

// matchSubjectProcess decide si el binario del proceso está permitido en el
// cgroup del sujeto. Compara por comm, por ruta del exe (absoluta o basename)
// y, si hay exe_sha256 firmado, por hash del binario en disco.
func matchSubjectProcess(pid uint32, comm string) bool {
	if len(subjectAllowed) == 0 {
		return true // sin restricción de binario firmada
	}
	if subjectAllowed[comm] {
		return true
	}
	exe, ok := procExe(pid)
	if !ok {
		return false
	}
	if subjectAllowed[exe] || subjectAllowed[filepath.Base(exe)] {
		return true
	}
	if policyState.exeSHA256 != "" {
		if h, ok := sha256File(exe); ok && h == policyState.exeSHA256 {
			return true
		}
	}
	return false
}

func emitEscape(rule, comm string, pid uint32, detail string) {
	key := fmt.Sprintf("%s:%d:%s", rule, pid, detail)
	if last, seen := escapeEmitted[key]; seen && time.Since(last) < escapeReemit {
		return
	}
	escapeEmitted[key] = time.Now()
	emitProc(rule, comm, pid, detail)
}

func readCgroupProcs(rel string) []uint32 {
	b, err := os.ReadFile("/sys/fs/cgroup/" + rel + "/cgroup.procs")
	if err != nil {
		return nil
	}
	var out []uint32
	for _, f := range strings.Fields(string(b)) {
		if n, err := strconv.ParseUint(f, 10, 32); err == nil {
			out = append(out, uint32(n))
		}
	}
	return out
}

func procComm(pid uint32) (string, bool) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

// procUIDs devuelve el UID real y efectivo desde /proc/<pid>/status.
func procUIDs(pid uint32) (real, eff int, ok bool) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		f := strings.Fields(line) // ["Uid:", real, effective, saved, fs]
		if len(f) < 3 {
			return 0, 0, false
		}
		r, e1 := strconv.Atoi(f[1])
		e, e2 := strconv.Atoi(f[2])
		if e1 != nil || e2 != nil {
			return 0, 0, false
		}
		return r, e, true
	}
	return 0, 0, false
}

func procExe(pid uint32) (string, bool) {
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", false
	}
	return exe, true
}

func sha256File(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", false
	}
	return hex.EncodeToString(h.Sum(nil)), true
}

func processAlive(pid uint32) bool {
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}
