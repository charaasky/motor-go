package main

// Limitador (canalopatía): dedup de alertas — si la misma regla+proceso se
// repite dentro de una ventana, se suprime (protección anti-flood).
// Equivalente en Go de fase-w/limitador.py.

import (
	"sync"
	"time"
)

var lim = &limitador{m: map[string]time.Time{}}

const dedupWindow = 2 * time.Second

type limitador struct {
	mu         sync.Mutex
	m          map[string]time.Time
	suppressed int
}

// allowed informa si la alerta debe emitirse (no es duplicado reciente).
func (l *limitador) allowed(rule, proc string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := rule + "\x00" + proc
	now := time.Now()
	if last, ok := l.m[key]; ok && now.Sub(last) < dedupWindow {
		l.suppressed++
		return false
	}
	l.m[key] = now
	if len(l.m) > 20000 {
		for k, v := range l.m {
			if now.Sub(v) > dedupWindow {
				delete(l.m, k)
			}
		}
	}
	return true
}
