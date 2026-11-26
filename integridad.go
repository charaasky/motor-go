package main

// Integridad (endosimbiosis + dormancia): vigila un árbol de archivos por SHA-256
// y alerta ante archivos NUEVOS, MODIFICADOS o BORRADOS. Equivalente en Go de
// fase-w/integridad.py.

import (
	"bytes"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var integrityDirs string

func init() {
	flag.StringVar(&integrityDirs, "integrity", "", "directorios a vigilar por integridad (separados por coma)")
}

var (
	intStore = map[string][32]byte{}
	intMu    sync.Mutex
)

func hashFile(p string) ([32]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return [32]byte{}, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return [32]byte{}, err
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

func trainIntegrity() {
	if integrityDirs == "" {
		return
	}
	intMu.Lock()
	defer intMu.Unlock()
	for _, d := range strings.Split(integrityDirs, ",") {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		filepath.Walk(d, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if h, err := hashFile(p); err == nil {
				intStore[p] = h
			}
			return nil
		})
	}
	log.Printf("integridad: %d archivos vigilados", len(intStore))
}

func startIntegrityWatch() {
	if integrityDirs == "" {
		return
	}
	trainIntegrity()
	go func() {
		for range time.Tick(10 * time.Second) {
			checkIntegrity()
		}
	}()
}

func checkIntegrity() {
	intMu.Lock()
	defer intMu.Unlock()
	seen := map[string]bool{}
	for _, d := range strings.Split(integrityDirs, ",") {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		filepath.Walk(d, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			seen[p] = true
			h, err := hashFile(p)
			if err != nil {
				return nil
			}
			old, ok := intStore[p]
			switch {
			case !ok:
				emit("ENDOSIMBIOSIS_NUEVO", "integridad", fmt.Sprintf("path=%s", p))
				intStore[p] = h
			case old != h:
				emit("ENDOSIMBIOSIS_MODIFICADO", "integridad", fmt.Sprintf("path=%s", p))
				intStore[p] = h
			}
			return nil
		})
	}
	for p := range intStore {
		if !seen[p] {
			emit("ENDOSIMBIOSIS_BORRADO", "integridad", fmt.Sprintf("path=%s", p))
			delete(intStore, p)
		}
	}
}

// --- Integridad de binarios por checksum (T1036.005, defensa en profundidad) ---
// Aprende el SHA-256 de los binarios de sistema durante el entrenamiento y lo
// verifica en CADA exec: si un binario fue reemplazado (suplantación de nombre),
// el hash no coincide con el baseline y se alerta — aunque el reemplazo no se
// haya visto (write antes del arranque del detector, o vía un bypass del bloqueo
// de escritura). Resuelve el binario REAL con readlink /proc/<pid>/exe y lo abre
// vía /proc/<pid>/root<exe>: para un proceso host root == /, para un contenedor
// root es su rootfs → cubre binarios de contenedores y del host por igual.
var (
	binHashes   = map[string][32]byte{}
	binHashesMu sync.Mutex
)

// execBinResolved devuelve la ruta real del binario (tal como el proceso la ve)
// y su ruta accesible desde el namespace del motor (/proc/<pid>/root<exe>).
func execBinResolved(pid uint32) (string, string, bool) {
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil || target == "" {
		return "", "", false
	}
	target = strings.TrimSuffix(target, " (deleted)")
	hostPath := fmt.Sprintf("/proc/%d/root%s", pid, target)
	return target, hostPath, true
}

// verifyExecBinary aprende (entrenamiento) o verifica (post-entrenamiento) el
// checksum del binario ejecutado por pid. Solo binarios de sistema (/usr/,
// /bin/, /sbin/): no hashea binarios de app arbitrarios en cada exec.
func verifyExecBinary(pid uint32, comm string) {
	target, hostPath, ok := execBinResolved(pid)
	if !ok {
		return
	}
	if !(strings.HasPrefix(target, "/usr/") || strings.HasPrefix(target, "/bin/") ||
		strings.HasPrefix(target, "/sbin/")) {
		return
	}
	h, err := hashFile(hostPath)
	if err != nil {
		return // no verificable → fail-safe: no alertar sin evidencia
	}
	tampered := false
	binHashesMu.Lock()
	if bl.isTraining() {
		binHashes[target] = h
	} else if good, seen := binHashes[target]; seen && good != h {
		tampered = true
	}
	binHashesMu.Unlock()
	if tampered {
		emitProc("BINARY_TAMPERED (T1036.005)", comm, pid,
			fmt.Sprintf("bin=%s sha256 no coincide con el baseline (binario suplantado)", target))
	}
}

// checkPackedBinary detecta la ejecución de un binario EMPAQUETADO (T1027.002,
// software packing): los packers (UPX y familia) comprimen el payload y lo
// descomprimen en memoria al arrancar — evita firmas estáticas, sandbox de
// contenido y heurísticas de tamaño. El packer deja su firma ("UPX!" para UPX,
// el estándar de facto) en las primeras páginas del ELF: se lee el inicio del
// binario vía /proc/<pid>/root<exe> en el propio evento exec. Lectura barata
// (4 KiB) y sin estado. Un binario legítimo de contenedor NO viene empaquetado
// del upstream de Alpine/Debian: cero falsos positivos esperables.
func checkPackedBinary(pid uint32, comm string) {
	_, hostPath, ok := execBinResolved(pid)
	if !ok {
		return
	}
	f, err := os.Open(hostPath)
	if err != nil {
		return // no legible → fail-safe: no alertar sin evidencia
	}
	defer f.Close()
	buf := make([]byte, 4096)
	n, _ := f.Read(buf)
	if n == 0 {
		return
	}
	if bytes.Contains(buf[:n], []byte("UPX!")) {
		emitProc("OFUSCACION_PACKED (T1027.002)", comm, pid,
			fmt.Sprintf("binario empaquetado con UPX ejecutado (evasión de firmas estáticas)"))
	}
}
