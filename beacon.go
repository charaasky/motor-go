package main

// Beacon (canal de tiempo + ósmosis por volumen): detecta conexiones periódicas
// (beaconing, coef. de variación bajo) y ráfagas de volumen (bytes/s).
// Equivalente en Go de fase-w/beacon.py. DNS tunneling queda fuera del alcance
// de esta sonda (no captura payload DNS en XDP).

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/cilium/ebpf"
)

var be = &beacon{flows: map[string][]time.Time{}}

const (
	beaconMin    = 5    // al menos 5 latidos
	beaconCV     = 0.25 // coef. de variación máximo (regularidad)
	beaconWindow = 30 * time.Second
	osmosisBPS   = 1 << 20 // 1 MB/s = exfil por volumen
)

type beacon struct {
	mu    sync.Mutex
	flows map[string][]time.Time // "app\x00dest" -> timestamps de conexión
}

// observeConnect registra una conexión y devuelve true si es beaconing regular.
func (b *beacon) observeConnect(app, dest string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	key := app + "\x00" + dest
	now := time.Now()
	ts := append(b.flows[key], now)
	kept := ts[:0]
	for _, t := range ts {
		if now.Sub(t) <= beaconWindow {
			kept = append(kept, t)
		}
	}
	b.flows[key] = kept
	if len(kept) < beaconMin {
		return false
	}
	intervals := make([]float64, 0, len(kept)-1)
	for i := 1; i < len(kept); i++ {
		intervals = append(intervals, kept[i].Sub(kept[i-1]).Seconds())
	}
	if len(intervals) == 0 {
		return false
	}
	var sum float64
	for _, iv := range intervals {
		sum += iv
	}
	mean := sum / float64(len(intervals))
	if mean <= 0 {
		return false
	}
	var vsum float64
	for _, iv := range intervals {
		d := iv - mean
		vsum += d * d
	}
	cv := math.Sqrt(vsum/float64(len(intervals))) / mean
	return cv <= beaconCV
}

// startVolumeWatch lee el contador de bytes XDP cada segundo y alerta si el
// volumen supera el umbral de ósmosis.
func startVolumeWatch(coll *ebpf.Collection) {
	m := coll.Maps["counters"]
	if m == nil {
		return
	}
	prev := readCounters(m)[cntBytes]
	go func() {
		for range time.Tick(time.Second) {
			cur := readCounters(m)[cntBytes]
			delta := cur - prev
			prev = cur
			if delta >= osmosisBPS {
				emit("OSMOSIS_VOLUMEN", "xdp", fmt.Sprintf("bytes=%d en 1s (umbral %d)", delta, osmosisBPS))
			}
		}
	}()
}
