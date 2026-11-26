package policy

// Package policy define el formato firmado de política runtime de px-motor.
//
// La política fija el SUJETO a vigilar (cgroup + UID + ejecutable), el modo de
// respuesta (alert|kill), las reglas activas y los sinks de alertas. Se firma
// Ed25519 con separación de dominio para que una firma de política no pueda
// reutilizarse en otro contexto (p.ej. la licencia del vendedor).
//
// La clave privada de política NUNCA vive en el host que corre px-motor; solo
// la pública va embebida como ancla de confianza en el binario. La generación
// y la firma son OFFLINE (policygen/).
//
// Se firma la ruta RELATIVA del cgroup (estable), NO el ID/inode (cambia en
// cada restart) ni PIDs. Cambiar el esquema exige bump de versión (v1 -> v2).

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
)

// Domain es el prefijo de separación de dominio. El mensaje firmado es
// Domain || Payload. Garantiza que una firma emitida para política no valga
// para otro contexto (licencia, fingerprint, etc.).
const Domain = "px-motor/policy/v1\x00"

// Subject identifica al proceso que px-motor debe vigilar (lo que corre DENTRO
// de la microVM/contenedor), para detectar escapes. Todos los campos se firman.
type Subject struct {
	// Cgroup es la ruta relativa a /sys/fs/cgroup, p.ej.
	// "system.slice/hcma-firecracker.service". Vacío = no fijado.
	Cgroup string `json:"cgroup"`
	// UID del usuario que corre el sujeto. -1 = no fijado.
	UID int `json:"uid"`
	// Exe es el comm/ejecutable esperado. Vacío = no fijado.
	Exe string `json:"exe"`
	// ExeSHA256 es el hash del binario del sujeto (opcional, recomendado).
	ExeSHA256 string `json:"exe_sha256,omitempty"`
	// Allow lista los binarios AUXILIARES que pueden convivir en el cgroup del
	// sujeto sin disparar ESCAPE_EXEC (p.ej. el lanzador "python3" que corre
	// lanzar.py y luego ejecuta firecracker). Vacío = solo Exe está permitido.
	Allow []string `json:"allow,omitempty"`
}

// Rules fija el comportamiento de respuesta.
type Rules struct {
	// Mode: "alert" (solo registrar) o "kill" (respuesta activa SIGKILL).
	Mode string `json:"mode"`
	// Active es la lista de nombres de regla habilitados. Vacío = todas.
	Active []string `json:"active"`
}

// Sinks define a dónde van las alertas.
type Sinks struct {
	// Output es la ruta del JSONL de auditoría (equivalente a -output).
	Output string `json:"output"`
}

// Policy es el contenido firmado (sin la firma).
type Policy struct {
	Serial      int     `json:"serial"`      // monótono (placeholder anti-rollback)
	NotAfter    string  `json:"not_after"`   // RFC3339; vacío = sin vencimiento
	Fingerprint string  `json:"fingerprint"` // máquina; vacío = cualquier máquina
	Subject     Subject `json:"subject"`
	Rules       Rules   `json:"rules"`
	Sinks       Sinks   `json:"sinks"`
}

// Signed es el archivo de política en disco: Policy + firma hex.
type Signed struct {
	Policy
	Sig string `json:"sig"`
}

// Payload devuelve la serialización canónica de los campos firmados (todo
// menos Sig). Go ordena las claves JSON de struct de forma determinista (orden
// de declaración), así que este byte-slice es idéntico al firmar (offline) y
// al verificar (en el binario).
func (s *Signed) Payload() []byte {
	p := Policy{
		Serial:      s.Serial,
		NotAfter:    s.NotAfter,
		Fingerprint: s.Fingerprint,
		Subject:     s.Subject,
		Rules:       s.Rules,
		Sinks:       s.Sinks,
	}
	b, _ := json.Marshal(p)
	return b
}

// Message es lo que se firma/verifica: Domain || Payload.
func (s *Signed) Message() []byte {
	return append([]byte(Domain), s.Payload()...)
}

// Sign firma con la clave privada de política y rellena s.Sig (hex).
func (s *Signed) Sign(priv ed25519.PrivateKey) {
	s.Sig = hex.EncodeToString(ed25519.Sign(priv, s.Message()))
}

// Verify comprueba la firma con la clave pública de política.
func (s *Signed) Verify(pub ed25519.PublicKey) bool {
	sig, err := hex.DecodeString(s.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, s.Message(), sig)
}
