package main

// Política runtime firmada (P0.2): fija sujeto/reglas/sinks con Ed25519 y
// separación de dominio, con comportamiento fail-closed.
//
//   -policy <file>   carga una política firmada (JSON) que REEMPLAZA las flags
//                    sueltas -subject-cgroup / -kill / -output. Si el archivo
//                    no se puede leer, la firma no valida, está vencida, el
//                    fingerprint no coincide o no fija ningún selector, px-motor
//                    NO arranca (fail-closed): nunca se degrada a "vigilar todo"
//                    por una política rota.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"log"
	"os"
	"strings"
	"time"

	"motor-go/policy"
)

// policyPubKey es la clave PÚBLICA de política embebida como ancla de confianza.
// Es DISTINTA de vendorPubKey (licencia ≠ política). La privada correspondiente
// (/home/charasky/.keys/px-motor/policy.key en lab, offline en producción)
// NUNCA vive en este host. Solo policygen/ firma con ella.
const policyPubKey = "fedfb8b7ae88f1cc4a89bee6b256c50e5bc55279075987c86b4218b26bd75ac4"

var policyPath string
var policyCheck bool

func init() {
	flag.StringVar(&policyPath, "policy", "", "política firmada (JSON Ed25519) que fija sujeto/reglas/sinks; vacío = usar flags sueltas")
	flag.BoolVar(&policyCheck, "policy-check", false, "cargar y validar la política (firma/serial/selectores) y salir sin arrancar eBPF (dry-run)")
}

// policyState guarda el sujeto corroborante firmado (UID/exe) para las
// invariantes de escape (P1). En P0.2 el selector efectivo es el cgroup.
var policyState = struct {
	uid       int
	exe       string
	exeSHA256 string
	allow     []string
}{uid: -1}

// policyActiveRules, si es no-nil, es el allowlist de nombres de regla activos.
var policyActiveRules map[string]bool

func loadPolicy() {
	if policyPath == "" {
		return
	}
	data, err := os.ReadFile(policyPath)
	if err != nil {
		log.Fatalf("policy: no se pudo leer %s: %v", policyPath, err)
	}
	var s policy.Signed
	if err := json.Unmarshal(data, &s); err != nil {
		log.Fatalf("policy: JSON inválido: %v", err)
	}
	pub, err := hex.DecodeString(policyPubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		log.Fatalf("policy: ancla de confianza embebida inválida")
	}
	if !s.Verify(ed25519.PublicKey(pub)) {
		log.Fatalf("policy: firma inválida (manipulada o no autorizada) — fail-closed")
	}
	if s.Serial < 1 {
		log.Fatalf("policy: serial inválido (%d) — fail-closed", s.Serial)
	}
	// Anti-rollback: rechazar una política con serial menor al último aceptado.
	if cur := currentPolicySerial(); s.Serial < cur {
		log.Fatalf("policy: serial %d anterior al último aceptado %d (rollback) — fail-closed", s.Serial, cur)
	}
	if s.NotAfter != "" {
		exp, err := time.Parse(time.RFC3339, s.NotAfter)
		if err != nil {
			log.Fatalf("policy: not_after inválido — fail-closed")
		}
		if time.Now().After(exp) {
			log.Fatalf("policy: vencida (%s) — fail-closed", s.NotAfter)
		}
	}
	if s.Fingerprint != "" && s.Fingerprint != machineFingerprint() {
		log.Fatalf("policy: fingerprint no corresponde a esta máquina — fail-closed")
	}
	// Fail-closed: al menos un selector de sujeto debe estar fijado.
	if s.Subject.Cgroup == "" && s.Subject.UID < 0 && s.Subject.Exe == "" && s.Subject.ExeSHA256 == "" {
		log.Fatalf("policy: sin selector de sujeto (cgroup/uid/exe) — fail-closed")
	}
	// Selector de sujeto: cgroup. UID/exe quedan firmados como invariantes
	// corroborantes, enforcement por el watcher de escape (invariants.go).
	if s.Subject.Cgroup == "" {
		log.Fatalf("policy: cgroup vacío — fail-closed (el selector de sujeto es el cgroup)")
	}
	switch s.Rules.Mode {
	case "alert":
		killMode = false
	case "kill":
		killMode = true
	default:
		log.Fatalf("policy: modo %q inválido (se espera alert|kill) — fail-closed", s.Rules.Mode)
	}
	if s.Sinks.Output != "" {
		outputFile = s.Sinks.Output
	}
	if len(s.Rules.Active) > 0 {
		m := make(map[string]bool, len(s.Rules.Active))
		for _, r := range s.Rules.Active {
			if r != "" {
				m[r] = true
			}
		}
		policyActiveRules = m
	}

	subjectCgroup = s.Subject.Cgroup
	policyState.uid = s.Subject.UID
	policyState.exe = s.Subject.Exe
	policyState.exeSHA256 = s.Subject.ExeSHA256
	policyState.allow = s.Subject.Allow

	log.Printf("policy: válida (serial=%d, cgroup=%s, modo=%s, output=%s)",
		s.Serial, s.Subject.Cgroup, s.Rules.Mode, outputFile)
	if s.Subject.UID >= 0 {
		log.Printf("policy: invariante UID=%d firmada (watcher ESCAPE_UID activo)", s.Subject.UID)
	}
	if s.Subject.Exe != "" {
		log.Printf("policy: invariante exe=%s firmada (watcher ESCAPE_EXEC activo)", s.Subject.Exe)
	}
	if len(s.Rules.Active) > 0 {
		log.Printf("policy: allowlist de reglas activas: %d reglas", len(s.Rules.Active))
	}
	// Persistir el serial aceptado (solo si es mayor que el estado previo).
	// En dry-run (-policy-check) NO mutamos el estado: es solo validación.
	if !policyCheck {
		persistPolicySerial(s.Serial)
	}
}

// policyRuleAllowed devuelve false si la política fija un allowlist de reglas
// activas y `rule` no está en él.
func policyRuleAllowed(rule string) bool {
	if policyActiveRules == nil {
		return true
	}
	// Las invariantes de escape son un mecanismo de contención crítico: se
	// emiten SIEMPRE, con independencia del allowlist de reglas generales.
	if strings.HasPrefix(rule, "ESCAPE_") {
		return true
	}
	return policyActiveRules[rule]
}
