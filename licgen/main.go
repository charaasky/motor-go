package main

// licgen — genera licencias firmadas para px-motor (solo el vendedor).
//
// Uso:
//   go run . -autofp -days 30 -key ../vendor.key -o license.json
//   go run . -fp <fingerprint> -days 365 -key ../vendor.key -o license.json
//
// La clave privada (vendor.key) NUNCA se distribuye; la pública va embebida
// en px-motor. La licencia resultante es un JSON apto para mostrarse como QR.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	fp := flag.String("fp", "", "fingerprint de la máquina (o -autofp para calcularlo aquí)")
	autofp := flag.Bool("autofp", false, "calcular el fingerprint de ESTA máquina")
	days := flag.Int("days", 30, "días de validez")
	key := flag.String("key", "../vendor.key", "archivo con la clave privada Ed25519 (hex)")
	out := flag.String("o", "license.json", "archivo de salida")
	flag.Parse()

	fingerprint := *fp
	if *autofp {
		fingerprint = fingerprintOf()
	}
	if fingerprint == "" {
		fmt.Fprintln(os.Stderr, "uso: licgen -fp <fp> -days 30 -key vendor.key -o license.json")
		os.Exit(2)
	}

	privHex, err := os.ReadFile(*key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "no se pudo leer la clave privada:", err)
		os.Exit(1)
	}
	priv, err := hex.DecodeString(strings.TrimSpace(string(privHex)))
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		fmt.Fprintln(os.Stderr, "clave privada inválida")
		os.Exit(1)
	}

	expires := time.Now().AddDate(0, 0, *days).Format(time.RFC3339)
	msg := []byte(fingerprint + "|" + expires)
	sig := ed25519.Sign(ed25519.PrivateKey(priv), msg)

	lic := map[string]string{
		"fingerprint": fingerprint,
		"expires":     expires,
		"sig":         hex.EncodeToString(sig),
	}
	data, _ := json.MarshalIndent(lic, "", "  ")
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("licencia generada: %s (máquina %.12s…, válida %d días)\n", *out, fingerprint, *days)
}

// fingerprintOf replica el cálculo de machineFingerprint() de px-motor.
func fingerprintOf() string {
	h := sha256.New()
	if b, err := os.ReadFile("/etc/machine-id"); err == nil {
		h.Write(b)
	}
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 || i.HardwareAddr == nil {
			continue
		}
		if s := i.HardwareAddr.String(); s != "" && s != "00:00:00:00:00:00" {
			h.Write([]byte(s))
			break
		}
	}
	if hn, err := os.Hostname(); err == nil {
		h.Write([]byte(hn))
	}
	return hex.EncodeToString(h.Sum(nil))
}
