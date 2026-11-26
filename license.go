package main

// Licenciamiento (capa 1 + 2): ligado a máquina + firma Ed25519 + expiración.
//
// El binario VERIFICA licencias con la clave PÚBLICA embebida; solo el vendedor
// (que tiene vendor.key, la privada) puede firmarlas con licgen/. La licencia
// vale para UNA máquina (fingerprint) y expira en una fecha. Con período de
// gracia: si la licencia vence, px-motor avisa y sigue (defensa > licencia),
// salvo que se configure -license-strict.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	licensePath   string
	printFP       bool
	licenseStrict bool
	activateURL   string
)

func init() {
	flag.StringVar(&licensePath, "license", "", "archivo de licencia firmada (JSON). Vacío = sin licencia")
	flag.BoolVar(&printFP, "fingerprint", false, "imprimir el fingerprint de la máquina y salir")
	flag.BoolVar(&licenseStrict, "license-strict", false, "si la licencia vence, detener (por defecto: avisar y seguir)")
	flag.StringVar(&activateURL, "activate", "", "URL del servidor de licencias (POST /request + poll /license/<id>)")
}

// Clave pública del vendedor (Ed25519). No es secreta: solo permite VERIFICAR.
// La privada (vendor.key) firma y NO se distribuye.
const vendorPubKey = "f91a3fb6c2cc2426d518540d14ef79f644dae3f2705e0cfb50e3ede061e390ba"

type licenseFile struct {
	Fingerprint string `json:"fingerprint"`
	Expires     string `json:"expires"` // RFC3339
	Sig         string `json:"sig"`     // hex Ed25519 sobre fingerprint+"|"+expires
}

// doActivate activa esta máquina contra el servidor central (capa 3): envía el
// fingerprint, queda pendiente de aprobación manual, y poll hasta recibir la
// licencia firmada (la guarda en license.json y sale).
func doActivate() {
	if activateURL == "" {
		return
	}
	fp := machineFingerprint()
	host, _ := os.Hostname()
	base := strings.TrimRight(activateURL, "/")
	body, _ := json.Marshal(map[string]string{"fingerprint": fp, "customer": host})
	resp, err := http.Post(base+"/request", "application/json", bytes.NewReader(body))
	if err != nil {
		log.Fatalf("activación: no se pudo contactar %s: %v", base, err)
	}
	var r struct {
		ID string `json:"id"`
	}
	json.NewDecoder(resp.Body).Decode(&r)
	resp.Body.Close()
	if r.ID == "" {
		log.Fatalf("activación: respuesta inválida del servidor")
	}
	log.Printf("solicitud enviada (id=%s) a %s — esperando aprobación manual…", r.ID, base)
	deadline := time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) {
		time.Sleep(3 * time.Second)
		lr, err := http.Get(base + "/license/" + r.ID)
		if err != nil {
			continue
		}
		switch lr.StatusCode {
		case 200:
			data, _ := io.ReadAll(lr.Body)
			lr.Body.Close()
			if err := os.WriteFile("license.json", data, 0o600); err != nil {
				log.Fatalf("activación: no se pudo guardar la licencia: %v", err)
			}
			log.Printf("licencia recibida y guardada en license.json. Arrancá con: px-motor -license license.json")
			os.Exit(0)
		case 403:
			lr.Body.Close()
			log.Fatalf("activación: rechazada por el vendedor")
		default:
			lr.Body.Close()
		}
	}
	log.Fatalf("activación: tiempo de espera agotado (la solicitud sigue pendiente en el servidor)")
}

func checkLicense() {
	if printFP {
		fmt.Println(machineFingerprint())
		os.Exit(0)
	}
	if licensePath == "" {
		return
	}
	data, err := os.ReadFile(licensePath)
	if err != nil {
		log.Fatalf("licencia: no se pudo leer %s: %v", licensePath, err)
	}
	var l licenseFile
	if err := json.Unmarshal(data, &l); err != nil {
		log.Fatalf("licencia: archivo inválido: %v", err)
	}
	pub, _ := hex.DecodeString(vendorPubKey)
	sig, err := hex.DecodeString(l.Sig)
	if err != nil || !ed25519.Verify(pub, licenseMsg(l.Fingerprint, l.Expires), sig) {
		log.Fatalf("licencia: firma inválida (manipulada o no autorizada)")
	}
	if l.Fingerprint != machineFingerprint() {
		log.Fatalf("licencia: no corresponde a esta máquina")
	}
	exp, err := time.Parse(time.RFC3339, l.Expires)
	if err != nil {
		log.Fatalf("licencia: fecha inválida")
	}
	if time.Now().After(exp) {
		if licenseStrict {
			log.Fatalf("licencia: vencida (expiró %s)", l.Expires)
		}
		log.Printf("licencia: VENCIDA (expiró %s) — modo gracia: la defensa sigue activa", l.Expires)
		return
	}
	log.Printf("licencia válida: máquina %.12s… hasta %s", l.Fingerprint, l.Expires)
}

func licenseMsg(fp, exp string) []byte {
	return []byte(fp + "|" + exp)
}

// machineFingerprint: SHA-256 de machine-id + MAC de la primera interfaz física
// + hostname. Estable entre reinicios y distinto por máquina.
func machineFingerprint() string {
	h := sha256.New()
	if b, err := os.ReadFile("/etc/machine-id"); err == nil {
		h.Write(b)
	}
	if mac := firstMAC(); mac != "" {
		h.Write([]byte(mac))
	}
	if hn, err := os.Hostname(); err == nil {
		h.Write([]byte(hn))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func firstMAC() string {
	ifs, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 || i.HardwareAddr == nil {
			continue
		}
		if s := i.HardwareAddr.String(); s != "" && s != "00:00:00:00:00:00" {
			return s
		}
	}
	return ""
}
