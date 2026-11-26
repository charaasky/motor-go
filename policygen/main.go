package main

// policygen — genera y firma políticas runtime de px-motor (OFFLINE).
//
// La clave privada de política se genera y usa FUERA del host que corre
// px-motor. El binario solo embebe la pública (policyPubKey). Dos modos:
//
//   policygen -keygen -priv policy.key          # genera par; pública a stdout
//   policygen -sign   -priv policy.key \
//             -in  policy.unsigned.json \
//             -out policy.json                  # firma una política sin firmar

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"motor-go/policy"
)

func main() {
	keygen := flag.Bool("keygen", false, "generar par de claves de política (privada a -priv, pública a stdout)")
	sign := flag.Bool("sign", false, "firmar una política sin firmar (-in) y escribirla (-out)")
	privPath := flag.String("priv", "policy.key", "archivo de clave privada Ed25519 (hex)")
	inPath := flag.String("in", "", "política sin firmar (JSON) de entrada")
	outPath := flag.String("out", "policy.json", "política firmada de salida")
	flag.Parse()

	switch {
	case *keygen:
		pub, prv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fatal(err)
		}
		if err := os.WriteFile(*privPath, []byte(hex.EncodeToString(prv)+"\n"), 0o600); err != nil {
			fatal(err)
		}
		fmt.Printf("privada: %s  (NUNCA en el host de producción)\n", *privPath)
		fmt.Printf("pública (embebida como policyPubKey): %s\n", hex.EncodeToString(pub))
	case *sign:
		if *inPath == "" {
			usage()
		}
		prvHex, err := os.ReadFile(*privPath)
		if err != nil {
			fatal(err)
		}
		prv, err := hex.DecodeString(strings.TrimSpace(string(prvHex)))
		if err != nil || len(prv) != ed25519.PrivateKeySize {
			fatal(fmt.Errorf("clave privada inválida (esperado %d bytes hex)", ed25519.PrivateKeySize))
		}
		raw, err := os.ReadFile(*inPath)
		if err != nil {
			fatal(err)
		}
		var s policy.Signed
		if err := json.Unmarshal(raw, &s); err != nil {
			fatal(fmt.Errorf("JSON de entrada inválido: %w", err))
		}
		s.Sig = ""
		s.Sign(ed25519.PrivateKey(prv))
		out, err := json.MarshalIndent(s, "", "  ")
		if err != nil {
			fatal(err)
		}
		if err := os.WriteFile(*outPath, append(out, '\n'), 0o644); err != nil {
			fatal(err)
		}
		fmt.Printf("política firmada: %s\n", *outPath)
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "uso: policygen -keygen -priv policy.key")
	fmt.Fprintln(os.Stderr, "   o  policygen -sign -priv policy.key -in policy.unsigned.json -out policy.json")
	os.Exit(2)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "policygen:", err)
	os.Exit(1)
}
