package main

// Anti-rollback de política (P1): persiste el mayor serial de política aceptado
// en una ruta root-only. Una política con serial menor al persistido se rechaza
// (fail-closed), impidiendo reintroducir una política vieja re-firmada.
//
// El estado es un archivo de texto con el serial, en una ruta que el sujeto
// (microVM) no puede escribir. La escritura es atómica (temp + rename). Si el
// archivo se borra, el sistema vuelve a "primera ejecución" (acepta cualquier
// serial); la mitigación de esa vía es fs-verity/IMA (pendiente P1).

import (
	"flag"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var policyStatePath string

func init() {
	flag.StringVar(&policyStatePath, "policy-state", "/var/lib/px-motor/policy.serial",
		"archivo persistente del mayor serial de política aceptado (anti-rollback)")
}

// currentPolicySerial devuelve el serial persistido, o 0 si no hay estado.
func currentPolicySerial() int {
	b, err := os.ReadFile(policyStatePath)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || n < 1 {
		return 0
	}
	return n
}

// persistPolicySerial guarda el serial si es mayor que el persistido (o si no
// había estado). Escritura atómica; un fallo no es fatal (se registra), pero la
// próxima verificación vuelve a comparar contra el estado anterior.
func persistPolicySerial(serial int) {
	cur := currentPolicySerial()
	if serial <= cur {
		return
	}
	dir := filepath.Dir(policyStatePath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Printf("policy: no se pudo crear %s: %v", dir, err)
		return
	}
	tmp := policyStatePath + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.Itoa(serial)+"\n"), 0o600); err != nil {
		log.Printf("policy: no se pudo escribir estado anti-rollback: %v", err)
		return
	}
	if err := os.Rename(tmp, policyStatePath); err != nil {
		log.Printf("policy: no se pudo persistir estado anti-rollback: %v", err)
		return
	}
	log.Printf("policy: anti-rollback actualizado → serial %d (%s)", serial, policyStatePath)
}
