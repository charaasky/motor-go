package main

// Capa 4 (parte 2): selección clonal (CLONALG-lite).
// Un antígeno (desviación repetida) incrementa su conteo de clones; al llegar
// al umbral "madura" y se generaliza a TODAS las apps (red idiotípica parcial),
// de modo que un ataque aprendido en `node` se reconoce en `python`, etc.
// Equivalente en Go de fase-w/clonal.py.

import "sync"

var cl = &clonal{counts: map[string]int{}, mature: map[string]bool{}}

const cloneThreshold = 3

type clonal struct {
	mu     sync.Mutex
	counts map[string]int  // "app\x00antigen" -> clones
	mature map[string]bool // antígenos maduros (generalizados)
}

// observe registra un antígeno y devuelve (clones, maduróAhora).
func (c *clonal) observe(app, antigen string) (int, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := app + "\x00" + antigen
	c.counts[key]++
	n := c.counts[key]
	if n >= cloneThreshold && !c.mature[antigen] {
		c.mature[antigen] = true
		return n, true
	}
	return n, false
}

// isMature informa si el antígeno ya está generalizado.
func (c *clonal) isMature(antigen string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mature[antigen]
}
