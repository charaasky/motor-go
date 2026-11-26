package main

// RASP — detección de lógica de aplicación (port del guard/DB-controller de la
// suite): honeytokens IDOR, JWT alg:none, mass assignment, error SQL verbose
// (misconfig), enumeración de cuentas (T1087) e intento de race (TOCTOU).

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

var honeytokens = []string{"/999", "/998", "/997", "/888", "/887", "/886", "id=999", "id=998", "id=888"}
var jwtNone = []string{`alg":"none"`, "alg':'none'", "alg=none", "eyjhbgcioijub25lin0"} // base64url de {"alg":"none"} en minúsculas
var massAssign = []string{"is_admin=true", `is_admin":true`, "is_admin':true", "role=admin", `role":"admin"`}
var sqlerr = []string{"sql syntax", "psycopg2", "pg_exception", "does not exist", "unhandled exception", "traceback", "syntax error at", "duplicate key", "db-error", "unterminated", "at or near", "line 1"}

type raspState struct {
	mu    sync.Mutex
	enum  map[string][]time.Time // src -> timestamps de recursos enumerables
	races map[string]time.Time   // src+cuerpo -> último POST
}

var rs = &raspState{enum: map[string][]time.Time{}, races: map[string]time.Time{}}

// request inspecciona una petición HTTP (línea + headers + body, ya URL-decoded).
func (r *raspState) request(payload string, src net.IP) {
	lower := strings.ToLower(payload)
	s := src.String()

	for _, ht := range honeytokens {
		if strings.Contains(lower, ht) {
			emit("IDOR_HONEYTOKEN", s, "recurso señuelo "+ht)
			blockIP(netColl, src)
			return
		}
	}
	for _, j := range jwtNone {
		if strings.Contains(lower, j) {
			emit("JWT_ALG_NONE", s, "JWT con alg=none")
			blockIP(netColl, src)
			return
		}
	}
	for _, m := range massAssign {
		if strings.Contains(lower, m) {
			emit("MASS_ASSIGNMENT", s, "campo privilegiado: "+m)
			blockIP(netColl, src)
			return
		}
	}

	// Enumeración de cuentas (T1087): ráfaga de requests a recursos enumerables.
	if strings.Contains(lower, "/users") || strings.Contains(lower, "?id=") || strings.Contains(lower, "/notes") {
		now := time.Now()
		r.mu.Lock()
		r.enum[s] = append(r.enum[s], now)
		kept := r.enum[s][:0]
		for _, t := range r.enum[s] {
			if now.Sub(t) <= 5*time.Second {
				kept = append(kept, t)
			}
		}
		r.enum[s] = kept
		n := len(kept)
		r.mu.Unlock()
		if n >= 8 {
			emit("ACCOUNT_DISCOVERY", s, fmt.Sprintf("%d requests en 5s", n))
			blockIP(netColl, src)
		}
	}

	// Race (TOCTOU): el mismo POST repetido en <200 ms.
	if strings.HasPrefix(lower, "post ") {
		body := payload
		if i := strings.Index(payload, "\r\n\r\n"); i >= 0 {
			body = payload[i+4:]
		}
		now := time.Now()
		key := s + "\x00" + body
		r.mu.Lock()
		last, ok := r.races[key]
		r.races[key] = now
		r.mu.Unlock()
		if ok && now.Sub(last) < 200*time.Millisecond {
			emit("RACE_ATTEMPT", s, "mismo POST repetido en <200ms")
		}
	}
}

// response inspecciona una respuesta HTTP (SQL verbose = misconfig A05).
func (r *raspState) response(payload string, src net.IP) {
	// Las respuestas en loopback (healthcheck/cron interno del lab) generan
	// ruido periódico con errores SQL: no son una fuga hacia un cliente
	// externo. Se omiten para no inundar; la regla sigue para fugas reales.
	if src.IsLoopback() {
		return
	}
	lower := strings.ToLower(payload)
	for _, e := range sqlerr {
		if strings.Contains(lower, e) {
			emit("MISCONFIG_SQL_LEAK", src.String(), "error SQL verbose: "+e)
			return
		}
	}
}
