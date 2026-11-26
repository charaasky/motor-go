package main

// Firmas HTTP (L7) en Go — reemplaza las 554 reglas HTTP de Suricata con reglas
// propias (tu IP). Captura paquetes IPv4/TCP vía AF_PACKET, extrae el payload
// HTTP y matchea subcadenas. Al detectar, bloquea la IP origen en XDP.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
)

type httpSig struct {
	name     string
	patterns []string         // subcadena, payload completo
	uri      []string         // subcadena, solo línea de request (http_uri)
	regex    []*regexp.Regexp // regex compilada, payload completo
}

var (
	sniffIface   string
	sigsFile     string
	fpIgnoreFile string
	mgmtPort     int
	netColl      *ebpf.Collection // sonda XDP (para bloquear IPs)
	blockedTTL   = 60 * time.Second
	// liveSigs guarda el set efectivo de firmas L7. Por defecto usa las
	// embebidas; con -sigs carga un JSON con hot-reload cada 2s.
	liveSigs atomic.Pointer[[]httpSig]
)

func init() {
	flag.StringVar(&sniffIface, "sniff", "", "interfaz para firmas HTTP L7 (AF_PACKET); vacío = desactivar")
	flag.StringVar(&sigsFile, "sigs", "", "archivo cifrado (AES-GCM)+HMAC de firmas L7 con hot-reload; vacío = set básico compilado")
	flag.StringVar(&fpIgnoreFile, "fp-ignore", "", "JSON firmado (HMAC) con nombres de firmas en cuarentena por falso positivo; vacío = sin cuarentena")
	flag.IntVar(&mgmtPort, "mgmt-port", 0, "puerto del dashboard de gestión (eco de detecciones): excluido del matcheo L7; 0 = desactivado")
	liveSigs.Store(&builtinSigs)
}

// Firmas HTTP: nombre -> patrones (subcadena, minúsculas, sobre URI+body).
var builtinSigs = []httpSig{
	{name: "SQLi", patterns: []string{"union select", "or 1=1", "and 1=1", "pg_sleep", "substring("}},
	{name: "XSS", patterns: []string{"<script", "javascript:"}},
	{name: "SSTI", patterns: []string{"{{", "<%", "${{"}},
	{name: "XXE", patterns: []string{"<!entity"}},
	{name: "PathTraversal", patterns: []string{"../", "%2e%2e", "..%2f", "%2e%2e%2f"}},
	{name: "CmdInjection", patterns: []string{";id", "|id", "$(", ";uname", ";cat", ";ls"}},
	{name: "WebShell", patterns: []string{"<?php", "eval(", "system("}},
	{name: "Log4Shell", patterns: []string{"jndi:ldap", "${${"}},
	{name: "Shellshock", patterns: []string{"() {"}},
	{name: "OpenRedirect", patterns: []string{"url=http"}},
	{name: "SSRF", patterns: []string{"169.254.169.254"}},
	// Cola de firmas CVE-específicas (equivale a las reglas Suricata restantes):
	{name: "CVE-2017-7529", patterns: []string{"bytes=-", "range: bytes=-17208"}},
	{name: "Spring4Shell", patterns: []string{"class.module.classloader"}},
	{name: "SpringCloudSpEL", patterns: []string{"spring.cloud.function.routing-expression", "routing-expression"}},
	{name: "SpringGateway", patterns: []string{"/actuator/gateway", "#{t("}},
	{name: "YAMLDeser", patterns: []string{"!!python/object"}},
	{name: "PrototypePollution", patterns: []string{"__proto__", "constructor.prototype", "constructor[prototype]"}},
	{name: "ActuatorExpuesto", patterns: []string{"/actuator", "/jolokia", "/h2-console"}},
	{name: "PHPNuke", patterns: []string{"modules.php", "name=search", "instory="}},
	// Técnicas nuevas 2025-2026:
	{name: "CSSExfil", patterns: []string{"background:url(https://", "background:url(http://", "input[value"}},
	{name: "WebhookExfil", patterns: []string{"/api/webhooks/", "content-type: application/octet-stream"}},
	{name: "DesyncProbe", patterns: []string{"x-forwarded: a", "x-inject:"}},
	// Vectores web que faltaban:
	{name: "NoSQLi", patterns: []string{"\"$ne\":", "\"$gt\":", "\"$regex\":", "\"$where\":"}},
	{name: "PHPSerialize", patterns: []string{"o:8:\"", "o:10:\"", "o:16:\""}},
	{name: "SSI", patterns: []string{"<!--#exec", "<!--#include", "<!--#echo"}},
	{name: "LDAPi", patterns: []string{"*)(|(uid=", "*)(uid=", "(&(uid="}},
	{name: "CRLFInj", patterns: []string{"%0d%0aset-cookie:", "%0d%0ax-forwarded-for:"}},
	{name: "JWTnone", patterns: []string{"\"alg\":\"none\"", "\"alg\": \"none\""}},
}

// sigsKey: clave HMAC-SHA256 para validar px-motor.sigs.enc. Debe coincidir con la
// que usa fase-n/updater.py al firmar. Sin esta validación, un atacante con
// escritura sobre el archivo podría cegar o envenenar las firmas L7.
const sigsKey = "px-motor-lab-sigs-hmac-2026"

// verifySigs valida el HMAC-SHA256 de `data` contra el sidecar `hmacPath`.
func verifySigs(data []byte, hmacPath string) bool {
	raw, err := os.ReadFile(hmacPath)
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(sigsKey))
	mac.Write(data)
	return hmac.Equal(mac.Sum(nil), want)
}

// sigsAESKey: clave AES-256 (derivada por SHA-256) para CIFRAR px-motor.sigs.enc.
// El cifrado (AES-256-GCM) oculta los patrones de detección: un atacante con
// solo LECTURA ya no puede leer las firmas para evadirlas. La integridad la dan
// el HMAC (sidecar .hmac) y el tag GCM.
var sigsAESKey = sha256.Sum256([]byte("px-motor-lab-sigs-aes-2026"))

// decryptSigs descifra un blob AES-256-GCM (formato: nonce(12) + ciphertext+tag).
func decryptSigs(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(sigsAESKey[:])
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < g.NonceSize() {
		return nil, fmt.Errorf("blob cifrado demasiado corto")
	}
	return g.Open(nil, data[:g.NonceSize()], data[g.NonceSize():], nil)
}

// loadFPIgnore lee la lista de firmas en cuarentena por falso positivo (JSON de
// nombres, firmado con HMAC igual que px-motor.sigs.enc). Si el HMAC no valida
// devuelve error → fail-closed: no se ignora NINGUNA firma, porque una lista
// alterada podría cegar detección real.
func loadFPIgnore(path string) (map[string]struct{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !verifySigs(data, path+".hmac") {
		return nil, fmt.Errorf("firma HMAC inválida o ausente en %s.hmac", path)
	}
	var names []string
	if err := json.Unmarshal(data, &names); err != nil {
		return nil, err
	}
	set := make(map[string]struct{}, len(names))
	for _, n := range names {
		set[n] = struct{}{}
	}
	return set, nil
}

// loadSigsFile lee firmas L7 desde un JSON [{name, patterns}] y las normaliza
// a minúsculas (el matcher compara sobre el payload en minúsculas).
// parseSigs parsea un JSON de firmas [{name, patterns, uri, regex}] a []httpSig.
// Las firmas cuyo nombre está en `ignore` (cuarentena FP) se omiten.
func parseSigs(data []byte, ignore map[string]struct{}) ([]httpSig, error) {
	var in []struct {
		Name     string   `json:"name"`
		Patterns []string `json:"patterns"`
		URI      []string `json:"uri"`
		Regex    []string `json:"regex"`
	}
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, err
	}
	out := make([]httpSig, 0, len(in))
	quarantined := 0
	for _, s := range in {
		if _, fp := ignore[s.Name]; fp {
			quarantined++
			continue
		}
		sig := httpSig{name: s.Name}
		for _, p := range s.Patterns {
			if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
				sig.patterns = append(sig.patterns, p)
			}
		}
		for _, p := range s.URI {
			if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
				sig.uri = append(sig.uri, p)
			}
		}
		for _, r := range s.Regex {
			re, err := regexp.Compile(r)
			if err != nil {
				log.Printf("sigs: regex inválida en %q: %v (ignorada)", s.Name, err)
				continue
			}
			sig.regex = append(sig.regex, re)
		}
		if sig.name != "" && (len(sig.patterns)+len(sig.uri)+len(sig.regex) > 0) {
			out = append(out, sig)
		}
	}
	if quarantined > 0 {
		log.Printf("sigs: %d firmas en cuarentena FP (ignoradas)", quarantined)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("sin firmas válidas")
	}
	return out, nil
}

func loadSigsFile(path string, ignore map[string]struct{}) ([]httpSig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !verifySigs(data, path+".hmac") {
		return nil, fmt.Errorf("firma HMAC inválida o ausente en %s.hmac", path)
	}
	plain, err := decryptSigs(data)
	if err != nil {
		return nil, fmt.Errorf("no se pudo descifrar %s: %v", path, err)
	}
	return parseSigs(plain, ignore)
}

// startSigReload carga el JSON de firmas y vigila AMBOS archivos (firmas y
// cuarentena FP) por mtime cada 2s (hot-reload sin reinicio). Si una recarga
// falla, se mantiene el set anterior.
func startSigReload() {
	if sigsFile == "" {
		// Sin archivo externo: se usa el set básico compilado (builtinSigs).
		log.Printf("sigs: sin -sigs, uso el set básico compilado (%d firmas)", len(builtinSigs))
		return
	}
	var last, lastFP time.Time
	reload := func() {
		ignore := map[string]struct{}{}
		if fpIgnoreFile != "" {
			if set, err := loadFPIgnore(fpIgnoreFile); err != nil {
				if os.IsNotExist(err) {
					log.Printf("fp-ignore: %s ausente (sin cuarentena FP)", fpIgnoreFile)
				} else {
					// Fail-closed: con una lista no verificada no se ignora nada.
					log.Printf("fp-ignore: ERROR: %v (no se ignora ninguna firma)", err)
				}
			} else if len(set) > 0 {
				ignore = set
				log.Printf("fp-ignore: %d firmas en cuarentena FP", len(set))
			}
		}
		if sigs, err := loadSigsFile(sigsFile, ignore); err != nil {
			log.Printf("sigs: %v (se mantiene el set actual)", err)
		} else {
			liveSigs.Store(&sigs)
			log.Printf("sigs: %d firmas L7 cargadas desde %s", len(sigs), sigsFile)
		}
		if st, e := os.Stat(sigsFile); e == nil {
			last = st.ModTime()
		}
		if fpIgnoreFile != "" {
			if st, e := os.Stat(fpIgnoreFile); e == nil {
				lastFP = st.ModTime()
			}
		}
	}
	reload()
	go func() {
		for {
			time.Sleep(2 * time.Second)
			changed := false
			if st, err := os.Stat(sigsFile); err == nil && !st.ModTime().Equal(last) {
				changed = true
			}
			if fpIgnoreFile != "" {
				if st, err := os.Stat(fpIgnoreFile); err == nil && !st.ModTime().Equal(lastFP) {
					changed = true
				}
			}
			if changed {
				reload()
			}
		}
	}()
}

type httpFlow struct {
	data []byte
	seen time.Time
}

var httpFlows = struct {
	sync.Mutex
	items map[string]httpFlow
}{items: make(map[string]httpFlow)}

const (
	maxHTTPFlowBytes = 16 * 1024
	maxHTTPFlows     = 4096
	httpFlowTTL      = 10 * time.Second
)

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// startSniff captura paquetes en la interfaz indicada y en cada veth del host,
// y matchea firmas HTTP. Se captura también el veth porque el request
// host→contenedor NO pasa por el RX del bridge (docker0): sin el veth, la capa
// L7 solo vería las respuestas y quedaría ciega al ataque entrante.
func startSniff(coll *ebpf.Collection) {
	if sniffIface == "" {
		return
	}
	startSigReload()
	// expiración de IPs bloqueadas (una sola vez)
	go func() {
		for {
			time.Sleep(10 * time.Second)
			sweepBlocked(coll)
			sweepHTTPFlows()
		}
	}()

	seen := map[string]bool{sniffIface: true}
	sniffOne(coll, sniffIface)
	scan := func() {
		if ifs, err := net.Interfaces(); err == nil {
			for _, i := range ifs {
				name := i.Name
				// loopback (ataques vía 127.0.0.1), bridges del lab y veth de los
				// contenedores. Se excluye el uplink físico (wlp*/enp*/eth*) para no
				// capturar el tráfico personal del host.
				if isUplink(name) {
					continue
				}
				if name == "lo" || strings.HasPrefix(name, "br-") || strings.HasPrefix(name, "veth") {
					if !seen[name] {
						seen[name] = true
						sniffOne(coll, name)
					}
				}
			}
		}
	}
	scan()
	go func() {
		for {
			time.Sleep(10 * time.Second)
			scan()
		}
	}()
}

// sniffOne abre sockets AF_PACKET sobre una interfaz para capturar AMBAS
// direcciones: PACKET_HOST (entrante, pkttype=0) y PACKET_OUTGOING (saliente,
// pkttype=4). En un bridge/veth, el request host→contenedor es saliente del veth
// (o del bridge), así que sin el socket saliente la capa L7 no vería el ataque
// entrante.
func sniffOne(coll *ebpf.Collection, name string) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		log.Printf("sniff(%s): %v", name, err)
		return
	}
	openSniff(coll, name, ifi.Index, 0) // PACKET_HOST: entrante
	openSniff(coll, name, ifi.Index, 4) // PACKET_OUTGOING: saliente
}

// openSniff abre, vincula y pone en modo promiscuo un socket AF_PACKET con el
// pkttype indicado, y arranca el loop de captura en background.
func openSniff(coll *ebpf.Collection, name string, ifindex int, pkttype uint8) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, int(htons(syscall.ETH_P_IP)))
	if err != nil {
		log.Printf("sniff(%s,pkttype=%d): socket: %v", name, pkttype, err)
		return
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_IP), Ifindex: ifindex, Pkttype: pkttype}); err != nil {
		log.Printf("sniff(%s,pkttype=%d): bind: %v", name, pkttype, err)
		return
	}
	// Modo promiscuo: amplía la captura (PACKET_OTHERHOST) más allá del tráfico
	// dirigido a la propia interfaz.
	type packetMreq struct {
		Ifindex int32
		Type    uint16
		Alen    uint16
		Address [8]byte
	}
	const (
		solPacket           = 263 // SOL_PACKET
		packetAddMembership = 1
		packetMrPromisc     = 1
	)
	mreq := packetMreq{Ifindex: int32(ifindex), Type: packetMrPromisc}
	if _, _, e0 := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd), uintptr(solPacket),
		uintptr(packetAddMembership), uintptr(unsafe.Pointer(&mreq)), unsafe.Sizeof(mreq), 0); e0 != 0 {
		log.Printf("sniff(%s,pkttype=%d): promisc: %v", name, pkttype, e0)
	}
	log.Printf("sniff HTTP activo en %s (pkttype=%d)", name, pkttype)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := syscall.Recvfrom(fd, buf, 0)
			if err != nil {
				continue
			}
			handlePacket(coll, buf[:n])
		}
	}()
}

// handlePacket parsea eth+ip+tcp y matchea firmas sobre el payload HTTP.
func handlePacket(coll *ebpf.Collection, b []byte) {
	if len(b) < 54 { // eth(14) + ip(20) + tcp(20)
		return
	}
	ipStart := 14
	ihl := int(b[ipStart]&0x0f) * 4
	if len(b) < ipStart+ihl+20 {
		return
	}
	if b[ipStart+9] != 6 { // TCP
		return
	}
	srcIP := net.IP(b[ipStart+12 : ipStart+16])
	dstIP := net.IP(b[ipStart+16 : ipStart+20])
	tcpStart := ipStart + ihl
	dstPort := binary.BigEndian.Uint16(b[tcpStart+2 : tcpStart+4])
	doff := int(b[tcpStart+12]>>4) * 4
	payloadStart := tcpStart + doff
	if payloadStart >= len(b) {
		return
	}
	payload := b[payloadStart:]
	// El tráfico cifrado (TLS) no debe pasar por las firmas HTTP: los bytes
	// cifrados pueden coincidir por azar con patrones cortos (ej. "$(") y
	// generar falsos positivos tipo SIG_HTTP (CmdInjection).
	if isTLSRecord(payload) {
		return
	}
	flowKey := fmt.Sprintf("%s:%d-%s:%d", srcIP, binary.BigEndian.Uint16(b[tcpStart:tcpStart+2]), dstIP, binary.BigEndian.Uint16(b[tcpStart+2:tcpStart+4]))
	newRequest := isRequest(payload)
	if newRequest || hasHTTPFlow(flowKey) || isHTTPPort(dstPort) {
		payload = appendHTTPFlow(flowKey, payload, newRequest)
		request := isRequest(payload)
		// Normalizar como Suricata (http.uri decodifica %XX y '+' → espacio):
		// así "1%20OR%201=1" se ve como "1 OR 1=1".
		dec := urlDecode(string(payload))
		hay := strings.ToLower(dec)
		// Línea de request (método + URI) para firmas con alcance http_uri.
		uriHay := strings.TrimRight(hay, "\r")
		if i := strings.IndexByte(hay, '\n'); i >= 0 {
			uriHay = strings.TrimRight(hay[:i], "\r")
		}
		if !request {
			// Semántica Suricata (flow:to_server): las firmas HTTP solo se
			// evalúan sobre requests. El eco de payloads de ataque en RESPUESTAS
			// (ej. el JSON de /api/events listando eventos del dashboard) no debe
			// disparar SIG_HTTP; las respuestas van solo al RASP.
			rs.response(dec, srcIP)
			return
		}
		if mgmtPort > 0 && int(dstPort) == mgmtPort {
			// Tráfico hacia el dashboard de gestión (127.0.0.1:<mgmt-port>): la
			// propia UI re-envía nombres de firma y payloads de detecciones para
			// mostrarlos o analizarlos (LLM). Matchear firmas aquí genera FPs en
			// bucle (el dashboard dispara el motor y éste bloquea al dashboard).
			// Se excluye del matcheo L7; el RASP sigue activo.
			rs.request(dec, srcIP)
			return
		}
		for _, sig := range *liveSigs.Load() {
			for _, p := range sig.patterns {
				if strings.Contains(hay, p) {
					emit("SIG_HTTP ("+sig.name+")", "http", fmt.Sprintf("src=%s payload=%.120q", srcIP, payload))
					blockIP(coll, srcIP)
					return
				}
			}
			for _, p := range sig.uri {
				if strings.Contains(uriHay, p) {
					emit("SIG_HTTP ("+sig.name+")", "http", fmt.Sprintf("src=%s payload=%.120q", srcIP, payload))
					blockIP(coll, srcIP)
					return
				}
			}
			// Regex: semántica Suricata (AND). En Suricata las condiciones de una
			// misma regla son conjuntivas; el OR independiente hacía que un regex
			// genérico (p.ej. "(exe|bat|com|dll|ini)") disparara solo la firma. Por
			// eso basta "bat" en "bateria.html" (Referer del dashboard) para disparar
			// ACTIVEX sin el SnapshotPath. Requiere que TODOS los regex matcheen.
			reAll := len(sig.regex) > 0
			for _, re := range sig.regex {
				if !re.MatchString(hay) {
					reAll = false
					break
				}
			}
			if reAll {
				emit("SIG_HTTP ("+sig.name+")", "http", fmt.Sprintf("src=%s payload=%.120q", srcIP, payload))
				blockIP(coll, srcIP)
				return
			}
		}
		// RASP: lógica de aplicación (IDOR/JWT/mass-assignment/enumeración/race).
		rs.request(dec, srcIP)
		return
	}
	// Respuesta o cuerpo de respuesta: buscar fuga SQL (misconfig A05).
	rs.response(string(payload), srcIP)
}

// isTLSRecord detecta el inicio de un registro TLS (handshake/appdata/CCS/alert).
// Se usa para no escanear tráfico cifrado con las firmas HTTP.
func isTLSRecord(b []byte) bool {
	if len(b) < 3 {
		return false
	}
	switch b[0] {
	case 0x14, 0x15, 0x16, 0x17: // change_cipher_spec, alert, handshake, application_data
	default:
		return false
	}
	// Versión: SSL3.0 (0x0300) .. TLS1.3 (0x0304)
	return b[1] == 0x03 && b[2] <= 0x04
}

func isHTTPPort(port uint16) bool {
	switch port {
	case 80, 443, 3000, 8000, 8080, 8081, 8105, 8106:
		return true
	default:
		return false
	}
}

// urlDecode decodifica %XX y '+' (espacio en query strings).
func urlDecode(s string) string {
	s = strings.ReplaceAll(s, "+", " ")
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if b, ok := hexByte(s[i+1 : i+3]); ok {
				out = append(out, b)
				i += 2
				continue
			}
		}
		out = append(out, s[i])
	}
	return string(out)
}

func hasHTTPFlow(key string) bool {
	httpFlows.Lock()
	defer httpFlows.Unlock()
	flow, ok := httpFlows.items[key]
	if !ok || time.Since(flow.seen) > httpFlowTTL {
		delete(httpFlows.items, key)
		return false
	}
	return true
}

func appendHTTPFlow(key string, payload []byte, request bool) []byte {
	httpFlows.Lock()
	defer httpFlows.Unlock()
	now := time.Now()
	flow := httpFlows.items[key]
	if request || now.Sub(flow.seen) > httpFlowTTL {
		flow.data = nil
	}
	if len(httpFlows.items) >= maxHTTPFlows {
		for staleKey := range httpFlows.items {
			delete(httpFlows.items, staleKey)
			break
		}
	}
	combined := make([]byte, 0, maxHTTPFlowBytes)
	combined = append(combined, flow.data...)
	combined = append(combined, payload...)
	if len(combined) > maxHTTPFlowBytes {
		combined = combined[len(combined)-maxHTTPFlowBytes:]
	}
	flow.data = combined
	flow.seen = now
	httpFlows.items[key] = flow
	return append([]byte(nil), flow.data...)
}

func sweepHTTPFlows() {
	httpFlows.Lock()
	defer httpFlows.Unlock()
	cutoff := time.Now().Add(-httpFlowTTL)
	for key, flow := range httpFlows.items {
		if flow.seen.Before(cutoff) {
			delete(httpFlows.items, key)
		}
	}
}

func hexByte(s string) (byte, bool) {
	var v byte
	for _, c := range []byte(s) {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= c - '0'
		case c >= 'a' && c <= 'f':
			v |= c - 'a' + 10
		case c >= 'A' && c <= 'F':
			v |= c - 'A' + 10
		default:
			return 0, false
		}
	}
	return v, true
}

func isRequest(p []byte) bool {
	s := string(p)
	return strings.HasPrefix(s, "GET ") || strings.HasPrefix(s, "POST ") ||
		strings.HasPrefix(s, "PUT ") || strings.HasPrefix(s, "DELETE ") ||
		strings.HasPrefix(s, "HEAD ") || strings.HasPrefix(s, "OPTIONS ")
}

// blockIP añade la IP origen al mapa XDP `blocked` (drop en L2). Solo en modo
// respuesta activa (-kill): en modo batería la firma se EMITE pero la IP no se
// bloquea — el modo batería es detección pura (mismo criterio que el resto de
// la respuesta: egress allow-all, sin SIGKILL).
func blockIP(coll *ebpf.Collection, ip net.IP) {
	if coll == nil || !killMode {
		return
	}
	m := coll.Maps["blocked"]
	if m == nil {
		return
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return
	}
	if !isSafeToBlock(ip4) {
		log.Printf("respuesta activa: no se bloquea %s (IP local/link-local/multicast)", ip4)
		return
	}
	key := binary.LittleEndian.Uint32(ip4) // mismo orden en memoria que iphdr->saddr (LE)
	if err := m.Put(key, uint64(time.Now().UnixNano())); err == nil {
		log.Printf("respuesta activa: IP %s bloqueada en XDP", ip4)
	}
}

// isSafeToBlock evita que la respuesta activa tumbe la propia máquina: nunca se
// bloquea loopback, link-local, multicast ni una IP local del host.
func isSafeToBlock(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			var host net.IP
			switch v := a.(type) {
			case *net.IPNet:
				host = v.IP
			case *net.IPAddr:
				host = v.IP
			}
			if host != nil && ip.Equal(host) {
				return false
			}
		}
	}
	return true
}

// sweepBlocked borra las entradas bloqueadas cuya TTL expiró.
func sweepBlocked(coll *ebpf.Collection) {
	if coll == nil {
		return
	}
	m := coll.Maps["blocked"]
	if m == nil {
		return
	}
	now := uint64(time.Now().UnixNano())
	var key uint32
	var val uint64
	var del []uint32
	it := m.Iterate()
	for it.Next(&key, &val) {
		if now-val > uint64(blockedTTL) {
			del = append(del, key)
		}
	}
	for _, k := range del {
		m.Delete(k)
	}
}
