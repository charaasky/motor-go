package main

// Correlador (quorum sensing + kill-chain): si un mismo PID acumula N eventos
// en una ventana corta, se dispara KILL_CHAIN. Equivalente en Go de
// fase-w/correlador.py.

import (
	"sync"
	"time"
)

var co = &correlador{events: map[string][]time.Time{}}

const (
	quorumWindow = 10 * time.Second
	quorumMin    = 4 // ≥4 eventos del mismo origen en la ventana
)

type correlador struct {
	mu     sync.Mutex
	events map[string][]time.Time // origen (app) -> timestamps
}

// observe registra un evento del origen y devuelve true si se alcanzó el quórum.
func (c *correlador) observe(key string) bool {
	if key == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	ts := append(c.events[key], now)
	kept := ts[:0]
	for _, t := range ts {
		if now.Sub(t) <= quorumWindow {
			kept = append(kept, t)
		}
	}
	c.events[key] = kept
	return len(kept) >= quorumMin
}
