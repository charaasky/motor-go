package main

// Capa 4 (parte 1): negative selection — baseline por app.
// Durante `-train` se aprende qué hijos y destinos son normales para cada app;
// después, cualquier hijo/destino NO visto (y no whitelisteado) es desviación.
// Es el equivalente en Go de fase-w/baseline.py.

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

var (
	trainSecs      int
	egressAllow    string
	egressAllowAll bool
	bl             = newBaseline()
)

func init() {
	flag.IntVar(&trainSecs, "train", 0, "segundos de entrenamiento del baseline (negative selection); 0 = sin baseline")
	flag.StringVar(&egressAllow, "egress-allow", "", "IPs IPv4 extra allowlisteadas para el egress default-deny (separadas por coma)")
	flag.BoolVar(&egressAllowAll, "egress-allow-all", false, "permitir egress a CUALQUIER destino (desactiva default-deny y detección EXFIL_CONNECT*/UDP)")
}

type baseline struct {
	mu       sync.Mutex
	training bool
	trainEnd time.Time
	children map[string]map[string]bool // app -> hijo (comm)
	dests    map[string]map[string]bool // app -> "ip:puerto"
}

func newBaseline() *baseline {
	return &baseline{
		children: map[string]map[string]bool{},
		dests:    map[string]map[string]bool{},
	}
}

func (b *baseline) begin(d time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.training = true
	b.trainEnd = time.Now().Add(d)
}

func (b *baseline) isTraining() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.training && time.Now().After(b.trainEnd) {
		b.training = false
	}
	return b.training
}

func (b *baseline) execLearn(app, child string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.training || app == "" || child == "" {
		return
	}
	if time.Now().After(b.trainEnd) {
		b.training = false
		return
	}
	if b.children[app] == nil {
		b.children[app] = map[string]bool{}
	}
	b.children[app][child] = true
}

func (b *baseline) connLearn(app, dest string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.training || app == "" || dest == "" {
		return
	}
	if time.Now().After(b.trainEnd) {
		b.training = false
		return
	}
	if b.dests[app] == nil {
		b.dests[app] = map[string]bool{}
	}
	b.dests[app][dest] = true
}

// execDeviation informa si `child` es anómalo para `app` (tras el entrenamiento).
// Si la app no fue vista en entrenamiento, no se juzga (devuelve false).
func (b *baseline) execDeviation(app, child string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.training {
		return false
	}
	set := b.children[app]
	if set == nil {
		return false
	}
	return !set[child]
}

// connDeviation informa si `dest` es anómalo para `app`.
func (b *baseline) connDeviation(app, dest string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.training {
		return false
	}
	set := b.dests[app]
	if set == nil {
		return false
	}
	return !set[dest]
}

// summary para log de arranque.
func (b *baseline) summary() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, c := range b.children {
		n += len(c)
	}
	return fmt.Sprintf("baseline: %d apps, %d relaciones hijas aprendidas", len(b.children), n)
}

// hasLearned informa si terminó el entrenamiento y hay datos aprendidos.
func (b *baseline) hasLearned() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.training && len(b.children) > 0
}

// learnedIPs devuelve las IPs IPv4 de destino aprendidas durante el
// entrenamiento, para el allowlist del egress default-deny en kernel.
func (b *baseline) learnedIPs() map[uint32]bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	ips := map[uint32]bool{}
	for _, dests := range b.dests {
		for dest := range dests {
			host := dest
			if i := strings.LastIndexByte(host, ':'); i >= 0 {
				host = host[:i]
			}
			if ip := net.ParseIP(host); ip != nil {
				if v4 := ip.To4(); v4 != nil {
					ips[binary.BigEndian.Uint32(v4)] = true
				}
			}
		}
	}
	return ips
}

// egressAllowIPs parsea la lista -egress-allow en claves uint32 (big-endian)
// para el allowlist del egress default-deny en kernel.
func egressAllowIPs() []uint32 {
	var out []uint32
	for _, s := range strings.Split(egressAllow, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if ip := net.ParseIP(s); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				out = append(out, binary.BigEndian.Uint32(v4))
			}
		}
	}
	return out
}

// egressAllowedGo: set de IPs (string) allowlisteadas para el egress, compartido
// entre el default-deny en kernel y la detección userspace (EXFIL_CONNECT_GENERAL).
var (
	egressMu      sync.Mutex
	egressAllowed = map[string]bool{}
)

func ipStrFromU32(ip uint32) string {
	v4 := make(net.IP, 4)
	binary.BigEndian.PutUint32(v4, ip)
	return v4.String()
}

// u32ToKey devuelve los 4 bytes en network order (big-endian) de una IP
// codificada con binary.BigEndian.Uint32, para usarla como clave del mapa
// eBPF lsm_egress_allow (el kernel compara los bytes del daddr tal cual).
func u32ToKey(ip uint32) [4]byte {
	return [4]byte{byte(ip >> 24), byte(ip >> 16), byte(ip >> 8), byte(ip)}
}

func refreshEgressAllowed() {
	egressMu.Lock()
	defer egressMu.Unlock()
	egressAllowed = map[string]bool{}
	for ip := range bl.learnedIPs() {
		egressAllowed[ipStrFromU32(ip)] = true
	}
	for _, ip := range egressAllowIPs() {
		egressAllowed[ipStrFromU32(ip)] = true
	}
}

func isEgressAllowed(s string) bool {
	if egressAllowAll {
		return true
	}
	egressMu.Lock()
	defer egressMu.Unlock()
	return egressAllowed[s]
}
