// motor-go — detector comportamental original (eBPF + Go).
// Captura execve/connect/mmap en kernel y aplica la LÓGICA DE DETECCIÓN en Go.
// Escrito desde cero; no deriva de Falco/Suricata.
package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:embed probe.bpf.o
var probeO []byte

//go:embed lsm.bpf.o
var lsmO []byte

// Runtimes de apps web que NO deberían lanzar shells ni conectarse afuera.
var apps = map[string]bool{
	"python": true, "python3": true, "node": true, "java": true,
	"go-vuln": true, "dotnet": true, "dotnet-vuln": true, "php": true,
	"ruby": true, "rust-vuln": true,
}

var shells = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "csh": true,
}

// Hijos "legítimos" que una app puede lanzar sin alarma (reduce falsos positivos).
var allowedChildren = map[string]bool{
	"id": true, "hostname": true, "uname": true, "ls": true,
	"pgrep": true, "ss": true, "curl": true, "ps": true,
}

// Atribución de origen de app a través de la cadena de procesos. Una app web
// (php/node/python...) que lanza un shell y ese shell lanza herramientas
// (tar/base64/ssh...) debe seguir atribuyéndose a la app: el pcomm inmediato
// del tool es el shell, no la app. pidApp mapea pid → comm de la app origen.
var pidAppMu sync.Mutex
var pidApp = map[uint32]string{}

const maxPidApp = 8192

// appAncestor devuelve el comm de la app origen del proceso ("" si no es de app).
func appAncestor(pid uint32) string {
	pidAppMu.Lock()
	defer pidAppMu.Unlock()
	return pidApp[pid]
}

// trackAppAncestry propaga la atribución de app en cada exec: si el padre
// desciende de una app, el hijo la hereda; si el proceso ES una app (o su
// padre inmediato lo es — cubre apps ya corriendo antes del detector), se
// marca el origen.
func trackAppAncestry(pid, ppid uint32, comm, pcomm string) {
	pidAppMu.Lock()
	defer pidAppMu.Unlock()
	if len(pidApp) >= maxPidApp {
		pidApp = map[uint32]string{} // poda drástica: evita fuga de pids muertos
	}
	if a, ok := pidApp[ppid]; ok {
		pidApp[pid] = a
	} else if apps[comm] {
		pidApp[pid] = comm
	} else if apps[pcomm] {
		pidApp[pid] = pcomm
	}
}

// Herramientas de defensa/observabilidad que leen archivos sensibles de forma
// legítima (Falco mapea UIDs con /etc/passwd, etc.). No deben auto-detectarse.
var defenseTools = map[string]bool{
	"falco": true, "suricata": true, "tetragon": true, "px-motor": true,
	"bpftool": true, "tracee": true, "sysdig": true, "node_exporter": true,
	"cadvisor": true,
}

// Procesos de SISTEMA que rutinariamente conectan afuera (DNS/NTP/updates).
// Se excluyen del detector general para no inundar de ruido; el resto de
// binarios (incluido un binario propio del atacante) SÍ dispara EXFIL_CONNECT_GENERAL.
var systemNet = map[string]bool{
	"systemd-resolve": true, "systemd-resolved": true, "systemd-timesyn": true,
	"systemd-timesync": true, "chronyd": true, "ntpd": true, "dnsmasq": true,
	"avahi-daemon": true, "snapd": true, "NetworkManager": true, "unattended-upgr": true,
	"apt.systemd.daily": true, "packagekitd": true, "fwupd": true, "dockerd": true,
}

// Motores de base de datos: escriben MUCHOS archivos de forma legítima (WAL,
// data files, temp files) durante carga/checkpoint/truncate. La heurística de
// masa (RANSOMWARE T1486, ≥20 archivos/5s) no debe disparar sobre su I/O normal.
var dbDaemons = map[string]bool{
	"postgres": true, "postmaster": true, "mysqld": true, "mariadbd": true,
	"mongod": true, "redis-server": true, "etcd": true, "sqlservr": true,
	"cassandra": true, "cockroach": true, "influxd": true, "clickhouse": true,
}

// -only-docker restringe TODA la lógica (detección y -kill) a procesos que viven
// en un cgroup de Docker. Con --pid=host sobre la máquina real, sin este filtro
// la respuesta activa mata procesos legítimos del host (Chrome, VS Code, JVM,
// cron...). En un VM dedicado del lab se puede omitir.
var onlyDocker bool
var subjectCgroup string
var excludeContainers string
var heartbeatPath string

var memfdMu sync.Mutex
var memfdPids = map[uint32]memfdObservation{}

const memfdExecWindow = 10 * time.Second
const maxMemfdObservations = 4096

type memfdObservation struct {
	seen      time.Time
	startTime uint64
}

func init() {
	flag.BoolVar(&onlyDocker, "only-docker", false, "solo procesar eventos de procesos en cgroups de Docker")
	flag.StringVar(&excludeContainers, "exclude-container", "", "contenedores excluidos del monitoreo (nombres separados por coma)")
	flag.StringVar(&heartbeatPath, "heartbeat", "", "archivo de latido periódico para watchdog externo (vacío = desactivado)")
	flag.StringVar(&subjectCgroup, "subject-cgroup", "", "cgroup systemd del sujeto a vigilar (p.ej. system.slice/hcma-firecracker.service); vacío = sin filtro por sujeto")
}

// inDockerCgroup indica si el PID pertenece a un contenedor vigilado (Docker
// o LXC/LXD). Docker con systemd usa docker-<hex>.scope; LXC usa
// lxc.payload.<nombre> / lxc.monitor.<nombre> (cgroup v2) o /lxc/<nombre>
// (cgroupfs/v1). Excluye la infraestructura del host (docker.service,
// lxc-monitord...), que NO debe ser detectada ni matada. Si no se puede
// verificar, devuelve false (fail-safe).
func inDockerCgroup(pid uint32) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return false
	}
	s := string(b)
	if strings.Contains(s, "docker-") && strings.Contains(s, ".scope") {
		return true
	}
	if strings.Contains(s, "lxc.payload.") || strings.Contains(s, "lxc.monitor.") {
		return true
	}
	return strings.Contains(s, "/lxc/") || strings.HasPrefix(s, "lxc-")
}

// excludedScopeNames consulta la API de Docker (socket unix /var/run/docker.sock)
// para mapear los NOMBRES de contenedor excluidos a sus cgroup scope names
// (docker-<id>.scope). Infraestructura del lab como la VM Windows (dockur) no es
// superficie de ataque: el detector la mataba (fila 82: QEMU/aria2c conectando a
// CDN de Microsoft no son exfil).
func excludedScopeNames() map[string]bool {
	res := map[string]bool{}
	if excludeContainers == "" {
		return res
	}
	want := map[string]bool{}
	for _, n := range strings.Split(excludeContainers, ",") {
		if n = strings.TrimSpace(n); n != "" {
			want[n] = true
		}
	}
	if len(want) == 0 {
		return res
	}
	// Resolver NOMBRE → cgroup scope (docker-<id>.scope) leyendo la metadata
	// en /var/lib/docker/containers/<id>/config.v2.json. NO se usa el socket
	// docker.sock: el propio detector flaggea la conexión AF_UNIX a docker.sock
	// como DOCKER_SOCK (T1611) y se auto-mataba (KILL_CHAIN quorum).
	entries, err := os.ReadDir("/var/lib/docker/containers")
	if err != nil {
		return res
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id := e.Name()
		data, err := os.ReadFile(filepath.Join("/var/lib/docker/containers", id, "config.v2.json"))
		if err != nil {
			continue
		}
		var cfg struct {
			Name string `json:"Name"`
		}
		if json.Unmarshal(data, &cfg) != nil {
			continue
		}
		if want[strings.TrimPrefix(cfg.Name, "/")] {
			res["docker-"+id+".scope"] = true
		}
	}
	return res
}

// Cache de scopes excluidos para el filtro Go-side de hooks LSM que no filtran
// en kernel (socket_connect): evita releer /var/lib/docker en cada evento.
var exclMu sync.Mutex
var exclScopesCache map[string]bool
var exclScopesAt time.Time

func excludedScopesCached() map[string]bool {
	exclMu.Lock()
	defer exclMu.Unlock()
	if exclScopesCache == nil || time.Since(exclScopesAt) > 5*time.Second {
		exclScopesCache = excludedScopeNames()
		exclScopesAt = time.Now()
	}
	return exclScopesCache
}

// inExcludedCgroup indica si el PID vive en un contenedor excluido (infra).
func inExcludedCgroup(pid uint32) bool {
	scopes := excludedScopesCached()
	if len(scopes) == 0 {
		return false
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return false
	}
	s := string(b)
	for scope := range scopes {
		if strings.Contains(s, scope) {
			return true
		}
	}
	return false
}

// scanDockerCgroups recorre /host/cgroup y vuelca los cgroup de contenedores
// Docker actuales al mapa `allowed`. Se llama al arrancar y periódicamente,
// porque un contenedor creado DESPUÉS del arranque tiene un cgroup nuevo que
// el kernel filtraría (should_report devuelve 0) si nunca se vuelve a escanear.
func scanDockerCgroups(allowed *ebpf.Map) int {
	n := 0
	excluded := excludedScopesCached()
	_ = filepath.Walk("/host/cgroup", func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.IsDir() {
			return nil
		}
		name := info.Name()
		isDocker := strings.HasPrefix(name, "docker-") && strings.HasSuffix(name, ".scope")
		// LXC/LXD: el contenedor es un SUBÁRBOL de cgroups (systemd anida
		// lxc.payload.<nombre>/system.slice/sshd.service...). Se coincide por
		// RUTA completa (no solo basename) para cubrir todos los cgroups hoja.
		isLxc := strings.Contains(path, "/lxc.payload.") ||
			strings.Contains(path, "/lxc.monitor.") ||
			strings.Contains(path, "/lxc/") ||
			strings.HasPrefix(name, "lxc.payload.") ||
			strings.HasPrefix(name, "lxc.monitor.")
		if isDocker || isLxc {
			if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Ino != 0 {
				if excluded[name] {
					allowed.Delete(st.Ino) // quitar si se añadió en un escaneo previo
					return nil
				}
				var one uint8 = 1
				if allowed.Put(st.Ino, one) == nil {
					n++
				}
			}
		}
		return nil
	})
	return n
}

// resolveCgroupInode devuelve el inode (== cgroup id que ve bpf_get_current_cgroup_id)
// del cgroup dado por su path relativo a /sys/fs/cgroup.
func resolveCgroupInode(rel string) (uint64, bool) {
	st, err := os.Stat("/sys/fs/cgroup/" + rel)
	if err != nil {
		return 0, false
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys.Ino != 0 {
		return sys.Ino, true
	}
	return 0, false
}

// inSubjectCgroup indica si el PID vive en el cgroup del sujeto (flag -subject-cgroup).
func inSubjectCgroup(pid uint32) bool {
	if subjectCgroup == "" {
		return false
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return false
	}
	return strings.Contains(string(b), subjectCgroup)
}

// enableCgroupFilter llena el mapa BPF allowed_cgroups con los IDs de cgroup de
// los contenedores del lab y activa el filtro en kernel (filter_cfg[0]=1). El
// kernel descarta en origen los eventos de procesos del host, así no satura el
// ringbuf ni la respuesta activa mata apps legítimas. El escaneo se repite cada
// 5s (goroutine) para cubrir contenedores creados después del arranque.
func enableCgroupFilter(coll *ebpf.Collection) {
	allowed := coll.Maps["allowed_cgroups"]
	cfg := coll.Maps["filter_cfg"]
	if allowed == nil || cfg == nil {
		log.Fatalf("filtro cgroup: mapas no encontrados (¿probe.bpf.o viejo?)")
	}
	if subjectCgroup != "" {
		ino, ok := resolveCgroupInode(subjectCgroup)
		if !ok {
			log.Fatalf("subject-cgroup: no se pudo resolver /sys/fs/cgroup/%s", subjectCgroup)
		}
		var one uint8 = 1
		_ = allowed.Put(ino, one)
		var k uint32 = 0
		var f uint32 = 1
		_ = cfg.Put(k, f)
		log.Printf("subject-cgroup: filtro cgroup activo (inode %d)", ino)
		go func() {
			for {
				time.Sleep(5 * time.Second)
				if ni, ok := resolveCgroupInode(subjectCgroup); ok && ni != ino {
					_ = allowed.Delete(ino)
					_ = allowed.Put(ni, one)
					ino = ni
				}
			}
		}()
		return
	}
	if !onlyDocker {
		return
	}
	n := scanDockerCgroups(allowed)
	if n == 0 {
		log.Fatalf("only-docker: no se encontraron contenedores Docker en /host/cgroup (falta el mount -v /sys/fs/cgroup:/host/cgroup:ro)")
	}
	var k uint32 = 0
	var one uint32 = 1
	_ = cfg.Put(k, one)
	log.Printf("only-docker: filtro cgroup activo (%d contenedores permitidos)", n)
	go func() {
		for {
			time.Sleep(5 * time.Second)
			scanDockerCgroups(allowed)
		}
	}()
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// isSystemPath verifica que el binario real del proceso (readlink /proc/pid/exe)
// esté en una ruta de sistema. Cierra la suplantación de nombre: un
// "NetworkManager" falso en /tmp o /home devuelve false y dispara.
func isSystemPath(pid uint32) bool {
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return false // no verificable → no excluir (fail-safe)
	}
	return strings.HasPrefix(target, "/usr/") ||
		strings.HasPrefix(target, "/sbin/") ||
		strings.HasPrefix(target, "/bin/") ||
		strings.HasPrefix(target, "/lib/") ||
		strings.HasPrefix(target, "/snap/")
}

// seccompDisabled detecta el prerequisito real de la evasión por io_uring: sin
// seccomp (o con un filtro no-estricto) los tracepoints sys_enter_* quedan
// ciegos ante I/O hecho vía io_uring_enter (medido en fase-e/matriz-medicion.md,
// experimento 5). "Seccomp: 0" en /proc/<pid>/status = sin filtro activo.
var seccompMu sync.Mutex
var seccompWarned = map[uint32]bool{}

func seccompDisabled(pid uint32) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Seccomp:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Seccomp:")) == "0"
		}
	}
	return false
}

func handle(raw []byte) {
	if len(raw) < 16 {
		return
	}
	le := binary.LittleEndian
	typ := le.Uint32(raw[0:4])
	pid := le.Uint32(raw[4:8])
	ppid := le.Uint32(raw[8:12])
	comm := cstr(raw[12:28])
	pcomm := cstr(raw[28:44])

	switch typ {
	case 1: // exec
		// Atribución de app a través de la cadena de procesos (app→shell→tool).
		trackAppAncestry(pid, ppid, comm, pcomm)
		// T1036.005 (defensa en profundidad): verificar el checksum del binario
		// ejecutado contra el baseline aprendido en entrenamiento — caza la
		// suplantación de nombre aunque el reemplazo no se viera en vivo.
		verifyExecBinary(pid, comm)
		// T1027.002 (software packing): binario empaquetado (UPX) ejecutado —
		// evasión de firmas estáticas y de heurísticas de tamaño/contenido.
		checkPackedBinary(pid, comm)
		// D3-SCA (System Call Analysis): secuencia "escribir + ejecutar el
		// mismo archivo" (dropper/downloader, T1105) — el atacante escribe un
		// binario y lo ejecuta en <10s; ninguna regla por-path lo ve (está en
		// /tmp). Correlación write→exec entre eventos.
		checkDropper(pid, comm)
		// T1574.006: entorno del exec copiado por el tracepoint en el TAIL del
		// evento (offset 256, right-aligned: termina en env_end). e->prot marca
		// los bytes válidos → se parsean los ÚLTIMOS prot bytes del slot.
		envLen := int(le.Uint64(raw[64:72]))
		if envLen > 0 && envLen <= 4096 && len(raw) >= 256+envLen {
			env := raw[len(raw)-envLen:]
			for _, kv := range bytes.Split(env, []byte{0}) {
				if bytes.HasPrefix(kv, []byte("LD_PRELOAD=")) || bytes.HasPrefix(kv, []byte("LD_AUDIT=")) {
					val := string(kv[len("LD_PRELOAD="):])
					if bytes.HasPrefix(kv, []byte("LD_AUDIT=")) {
						val = string(kv[len("LD_AUDIT="):])
					}
					if val != "" {
						// Auditoría sin kill (emit, no emitProc): un LD_PRELOAD a
						// ruta de sistema es legítimo (opcache, jemalloc,
						// profilers). El bloqueo es solo de la escalación.
						emit("LD_PRELOAD_SET (T1574.006)", comm, fmt.Sprintf("%s (exec de %s) pid=%d", val, comm, pid))
						if isWritablePathLD(val) {
							emitProc("LD_PRELOAD_HIJACK (T1574.006)", comm, pid, fmt.Sprintf("ruta escribible: %s", val))
						}
					}
					break
				}
			}
			// T1574.006 (extensiones): variables de EJECUCIÓN DE CÓDIGO de los
			// intérpretes — misma semántica que LD_PRELOAD con otro nombre.
			// BASH_ENV (bash no-interactivo), ENV (sh POSIX), PERL5OPT=-e/exec
			// (perl sin tocar argv), RUBYOPT=-r (require al arrancar),
			// PYTHONSTARTUP (script pre-shell). Set → auditoría; valor que
			// apunta a ruta escribible (payload del atacante) → kill, mismo
			// criterio de escalación de la fila 14. PYTHONPATH/NODE_OPTIONS
			// NO van aquí: son flags benignos de configuración salvo --require
			// (NODE_OPTIONS) cuyo valor lleva ruta — cubierto por el check de
			// ruta escribible cuando aplica.
			for _, kv := range bytes.Split(env, []byte{0}) {
				var name, val string
				switch {
				case bytes.HasPrefix(kv, []byte("BASH_ENV=")):
					name, val = "BASH_ENV", string(kv[9:])
				case bytes.HasPrefix(kv, []byte("ENV=")):
					name, val = "ENV", string(kv[4:])
				case bytes.HasPrefix(kv, []byte("PERL5OPT=")):
					name, val = "PERL5OPT", string(kv[9:])
				case bytes.HasPrefix(kv, []byte("RUBYOPT=")):
					name, val = "RUBYOPT", string(kv[8:])
				case bytes.HasPrefix(kv, []byte("PYTHONSTARTUP=")):
					name, val = "PYTHONSTARTUP", string(kv[14:])
				case bytes.HasPrefix(kv, []byte("NODE_OPTIONS=")):
					name, val = "NODE_OPTIONS", string(kv[13:])
				default:
					continue
				}
				if val == "" {
					continue
				}
				emit("ENV_HIJACK_SET (T1574.006)", comm, fmt.Sprintf("%s=%s (exec de %s) pid=%d", name, val, comm, pid))
				if isWritablePathLD(val) {
					emitProc("ENV_HIJACK_HIJACK (T1574.006)", comm, pid, fmt.Sprintf("%s ruta escribible: %s", name, val))
				}
				break
			}
		}
		// Gap #9 (race post-mortem del cmdline): el tracepoint copia argv en la
		// misma ventana right-aligned del evento (arg_end == env_start: argv y
		// env son contiguos en el stack del exec, ver probe.bpf.c). e->flags =
		// bytes válidos de argv → cmdline de fallback cuando el proceso efímero
		// murió antes de que el reader procese el evento (verifyExecBinary
		// hashea el binario y agrega lag) y /proc/PID/cmdline ya no existe.
		argLen := 0
		if len(raw) >= 80 {
			argLen = int(le.Uint64(raw[72:80]))
		}
		var evCmdline string
		if argLen > 0 && argLen <= 4096 && envLen >= 0 && envLen <= 4096 &&
			envLen+argLen <= 4096 && len(raw) >= 256+envLen+argLen {
			// argv ocupa los argLen bytes inmediatamente debajo de env en la
			// ventana copiada (right-aligned a env_end): mismo formato
			// NUL-separado que /proc/PID/cmdline.
			argv := raw[len(raw)-envLen-argLen : len(raw)-envLen]
			evCmdline = strings.ReplaceAll(string(argv), "\x00", " ")
		}
		if filelessExec(pid, processStartTime(pid)) {
			emitProc("FILELESS_EXECUTION (T1620)", comm, pid, "exec posterior a memfd_create")
		}
		// Predisposición a evasión de tracepoints vía io_uring (una sola vez por
		// PID; auditoría, no bloqueo — un contenedor de debug legítimo puede
		// correr sin seccomp).
		if apps[comm] {
			seccompMu.Lock()
			warned := seccompWarned[pid]
			if !warned {
				seccompWarned[pid] = true
			}
			seccompMu.Unlock()
			if !warned && seccompDisabled(pid) {
				emitProc("SECCOMP_DESHABILITADO (io_uring bypass)", comm, pid, "sin seccomp: sys_enter_* no ve I/O vía io_uring_enter")
			}
		}
		// Supervisores de la defensa lanzando docker (ps/start) → sin alerta.
		if comm == "docker" && isAllowedDocker(ppid) {
			break
		}
		if shells[comm] && apps[pcomm] {
			emitProc("SHELL (RCE) (T1059/T1190)", pcomm, pid, fmt.Sprintf("comm=%s ppid=%d", comm, ppid))
		} else if comm == "docker" && apps[pcomm] {
			emitProc("DOCKER_CLI", pcomm, pid, fmt.Sprintf("comm=docker ppid=%d", ppid))
		} else if shells[comm] {
			// T1059/T1027: shell SIN ARGS leyendo stdin = pipe-to-shell
			// (curl | sh, base64 -d | sh) o shell interactivo — un DROPPER
			// basado en archivo no lo ve (no hay binario que descargar). argv
			// desnudo (== comm o ruta absoluta a comm) distingue de `sh -c ...`
			// (batería y contenedores legítimos). En un pipe, el sh final es
			// HERMANO de curl (mismo padre), por eso pcomm no sirve aquí.
			cl := strings.TrimSpace(cmdlineOr(pid, evCmdline))
			if cl != "" && (cl == comm || strings.HasSuffix(cl, "/"+comm)) {
				emitProc("SHELL_STDIN (T1059)", comm, pid, fmt.Sprintf("shell sin args leyendo stdin (pipe-to-shell): %s", cl))
			}
		}
		// Capa 4: negative selection + selección clonal (sustituye a la regla
		// estática APP_PROCESO_INESPERADO cuando hay baseline entrenado).
		bl.execLearn(pcomm, comm)
		if apps[pcomm] && !allowedChildren[comm] && comm != "" && !bl.isTraining() {
			if !bl.hasLearned() {
				emitProc("APP_PROCESO_INESPERADO", pcomm, pid, fmt.Sprintf("comm=%s ppid=%d", comm, ppid))
			} else if bl.execDeviation(pcomm, comm) {
				n, newly := cl.observe(pcomm, comm)
				switch {
				case newly:
					emitProc("CLONAL_MADURO", pcomm, pid, fmt.Sprintf("antigen=%s generalizado a todas las apps (clon %d)", comm, n))
				case cl.isMature(comm):
					emitProc("CLONAL_RECONOCIDO", pcomm, pid, fmt.Sprintf("antigen=%s ya conocido de otra app", comm))
				default:
					emitProc("BASELINE_DESVIACION", pcomm, pid, fmt.Sprintf("hijo=%s clon=%d/%d", comm, n, cloneThreshold))
				}
			}
		}
		// Reglas Falco restantes (ofuscación/persistencia/discovery/archive/cifrado).
		checkBehavior(pcomm, comm, pid, evCmdline)
	case 2: // connect
		family := le.Uint16(raw[44:46])
		if family == 1 { // AF_UNIX: sockets locales (docker.sock, etc.)
			fname := cstr(raw[92:252])
			if strings.Contains(fname, ".sock") {
				emitProc("DOCKER_SOCK (T1611)", comm, pid, fmt.Sprintf("path=%s", fname))
			}
			break
		}
		port := binary.BigEndian.Uint16(raw[46:48]) // network byte order
		addr := raw[48:64]
		// Puerto 53 (DNS): se vigila con reglas dedicadas en el path sendmsg
		// (DNS_EXFIL/TXID_COVERT/entropía/beaconing). Una conexión a :53 es
		// resolución de nombres, no exfil de datos (FP fila 82).
		if port == 53 {
			break
		}
		// Wildcard (0.0.0.0 IPv4 / :: IPv6) o puerto sin destino (0): sonda de
		// arranque de daemons (postgres conecta a ::/0.0.0.0:65535 al subir),
		// nunca exfil. Mismo filtro que el hook LSM connect (FP que mataba
		// postgres-vuln al subir).
		if isWildcardAddr(family, addr) || port == 0 {
			break
		}
		loopback := isLoopbackAddr(family, addr)
		if !loopback {
			ip := netIP(family, addr)
			dest := fmt.Sprintf("%s:%d", ip, port)
			// Dedupe simétrico con el hook LSM connect: la misma connect(2)
			// dispara tp_connect Y socket_connect (ringbufs distintos). El
			// claim atómico evita doble conteo (quorum KILL_CHAIN, baseline,
			// beaconing). El LSM queda con lo que tp_connect NO vio (io_uring).
			if !connClaim(pid, dest) {
				break
			}
			// Destino allowlisteado (egress-allow / baseline): tráfico legítimo
			// del lab, no exfil — no emitir ni matar.
			if isEgressAllowed(ip) {
				break
			}
			if apps[comm] {
				bl.connLearn(comm, dest)
				emitProc("EXFIL_CONNECT", comm, pid, fmt.Sprintf("dst=%s", dest))
				if !bl.isTraining() && bl.connDeviation(comm, dest) {
					emitProc("BASELINE_DEST_DESVIACION", comm, pid, fmt.Sprintf("dst=%s no visto en entrenamiento", dest))
				}
				if be.observeConnect(comm, dest) {
					emit("BEACONING", comm, fmt.Sprintf("dst=%s cadencia regular", dest))
				}
			} else {
				// Cierra el gap del "binario propio" y de la SUPLANTACIÓN de nombre:
				// un proceso cuyo comm está en systemNet se excluye SOLO si su binario
				// real (readlink /proc/pid/exe) está en una ruta de sistema. Un
				// "NetworkManager" falso en /tmp sigue disparando.
				if !systemNet[comm] || !isSystemPath(pid) {
					emitProc("EXFIL_CONNECT_GENERAL", comm, pid, fmt.Sprintf("dst=%s", dest))
				}
			}
		}
	case 3: // mmap RWX
		emitProc("MMAP_RWX", comm, pid, fmt.Sprintf("prot=0x%x flags=0x%x", le.Uint64(raw[64:72]), le.Uint64(raw[72:80])))
	case 4: // ptrace
		req := le.Uint64(raw[80:88])
		target := le.Uint32(raw[88:92])
		// PTRACE_TRACEME(0) es anti-debug propio; el resto sobre OTRO proceso = inyección
		if req != 0 {
			emitProc("PTRACE (inyección T1055)", comm, pid, fmt.Sprintf("target=%d request=0x%x", target, req))
		}
	case 5: // openat
		fname := cstr(raw[92:252])
		// Dedupe simétrico con el hook LSM file_open: la misma syscall
		// openat(2) dispara tp_openat Y file_open (ringbufs distintos, race
		// de goroutines). claim atómico: exactamente una sonda procesa cada
		// open; el LSM queda con lo que tp_openat NO vio (rutas io_uring).
		// flags en arg1 (raw[80:88]): O_WRONLY=1, O_RDWR=2 → escritura.
		flags := le.Uint64(raw[80:88])
		write := flags&3 != 0
		if !fopenClaim(pid, fname, write) {
			return
		}
		checkSensitive(comm, pid, fname, write)
	case 6: // DNS query (sendto/sendmmsg a puerto 53)
		name := dnsName(raw[92:252])
		txid := le.Uint32(raw[88:92]) & 0xFFFF
		// Dedupe simétrico con el hook LSM sendmsg: la misma consulta dispara
		// tp_sendto/sendmmsg Y socket_sendmsg (ringbufs distintos, race de
		// goroutines). claim atómico: exactamente una sonda procesa cada envío.
		if !dnsClaim(pid, name) {
			return
		}
		checkDnsRate(comm, pid)
		if name != "" {
			checkDnsExfil(comm, pid, name, txid)
		}
	case 10: // UDP sendto a puerto no-DNS sin connect (gap #6, T1048)
		family := le.Uint16(raw[44:46])
		port := binary.BigEndian.Uint16(raw[46:48]) // network byte order
		ip := netIP(family, raw[48:64])
		dest := fmt.Sprintf("%s:%d", ip, port)
		emitProc("EXFIL_UDP_SENDTO (T1048)", comm, pid, fmt.Sprintf("dst=%s (sendto UDP sin connect)", dest))
	case 11: // socket de captura (T1040): AF_PACKET o SOCK_RAW
		family := le.Uint16(raw[44:46])
		stype := le.Uint16(raw[46:48])
		proto := le.Uint32(raw[48:52])
		if family == 17 { // AF_PACKET: captura de TODO el tráfico del enlace
			emitProc("SNIFFER_RED (T1040)", comm, pid, fmt.Sprintf("socket(AF_PACKET, tipo=%d, proto=%#x): captura de tráfico ajeno (tcpdump/sniffer)", stype, proto))
		} else { // SOCK_RAW sobre IP: sniffer raw / preparación de túnel ICMP
			emitProc("RAW_SOCKET_CREACION (T1040/T1095)", comm, pid, fmt.Sprintf("socket(AF_INET/6, SOCK_RAW, proto=%#x): socket raw creado", proto))
		}
	case 7: // memfd_create: primitiva de ejecución fileless
		name := cstr(raw[92:252])
		memfdMu.Lock()
		if len(memfdPids) >= maxMemfdObservations {
			for stalePID := range memfdPids {
				delete(memfdPids, stalePID)
				break
			}
		}
		memfdPids[pid] = memfdObservation{seen: time.Now(), startTime: processStartTime(pid)}
		memfdMu.Unlock()
		emit("FILELESS_MEMFD (T1620)", comm, fmt.Sprintf("pid=%d name=%s flags=0x%x (primitiva; sin bloqueo)", pid, name, le.Uint64(raw[80:88])))
	case 8: // process_vm_writev: escritura de memoria ajena sin pasar por ptrace
		target := le.Uint32(raw[88:92])
		if target != 0 && target != pid {
			emitProc("MEMORIA_AJENA_WRITEV (T1055)", comm, pid, fmt.Sprintf("target=%d", target))
		}
	case 12: // process_vm_readv: scraping de memoria ajena (T1003)
		// El hermano LECTOR del writev: vuelca la memoria de OTRO proceso para
		// extraer secretos en claro (mimipenguin-style). El writev ya tenía su
		// tracepoint; el readv es la primitiva del DUMP masivo pre-exfiltración.
		target := le.Uint32(raw[88:92])
		if target != 0 && target != pid {
			emitProc("LECTURA_MEMORIA_AJENA (T1003)", comm, pid, fmt.Sprintf("target=%d (scraping de memoria de otro proceso)", target))
		}
	case 9: // utimensat con times explícitos (T1070.006 timestomp)
		fname := cstr(raw[92:252])
		if fname == "" {
			return
		}
		atime := le.Uint64(raw[80:88]) // ts[0].tv_sec fijado
		mtime := uint64(le.Uint32(raw[88:92]))
		// El BPF ya filtró times=NULL y UTIME_NOW: esto es un timestamp FIJADO.
		// emit (auditoría) sin kill: escribir/setear fechas de archivos PROPIOS
		// tras crearlos es legítimo (build systems lo hacen); el kill va por
		// reglas de ruta si el objetivo es sensible.
		emit("TIMESTOMP (T1070.006)", comm, fmt.Sprintf("path=%s atime=%d mtime=%d (fechas fijadas)", fname, atime, mtime))
	}
}

// isWritablePathLD decide si un valor LD_PRELOAD/LD_AUDIT apunta a una ruta
// escribible por un atacante (/tmp, /dev/shm, /var/tmp, /home, /run/user) o
// usa formas de evasión (ruta relativa, file:, /proc/self/fd). El valor puede
// listar varias libs separadas por ':' o ' ' — con una sola basta.
func isWritablePathLD(v string) bool {
	for _, part := range strings.FieldsFunc(v, func(r rune) bool { return r == ':' || r == ' ' }) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// Formas de evasión sin ruta absoluta: file: (glibc ≥2.34) o montaje
		// de fd heredado; ruta relativa carga desde el CWD del proceso.
		if strings.HasPrefix(part, "file:") || strings.HasPrefix(part, "/proc/") {
			return true
		}
		if !strings.HasPrefix(part, "/") {
			return true // relativa: CWD desconocido → tratar como peligrosa
		}
		for _, pref := range writablePrefixes {
			if strings.HasPrefix(part, pref) {
				return true
			}
		}
	}
	return false
}

var writablePrefixes = []string{
	"/tmp", "/dev/shm", "/var/tmp", "/run/shm", "/run/user",
	"/home/", "/root/", "/srv/", "/media/", "/mnt/",
}

func filelessExec(pid uint32, startTime uint64) bool {
	memfdMu.Lock()
	defer memfdMu.Unlock()
	observation, ok := memfdPids[pid]
	delete(memfdPids, pid)
	if !ok {
		return false
	}
	return observation.startTime != 0 && observation.startTime == startTime && time.Since(observation.seen) <= memfdExecWindow
}

func processStartTime(pid uint32) uint64 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) <= 21 {
		return 0
	}
	value, err := strconv.ParseUint(fields[21], 10, 64)
	if err != nil {
		return 0
	}
	return value
}

// checkDnsRate: un ID encriptado parece aleatorio (evade DNS_TXID_COVERT), pero
// mover datos reales exige MUCHAS consultas. La tasa por proceso lo caza igual.
var dnsRateMu sync.Mutex
var dnsRate = map[uint32][]time.Time{}

func checkDnsRate(comm string, pid uint32) {
	dnsRateMu.Lock()
	defer dnsRateMu.Unlock()
	now := time.Now()
	cut := 0
	for i, t := range dnsRate[pid] {
		if now.Sub(t) <= 60*time.Second {
			cut = i
			break
		}
	}
	times := append(dnsRate[pid][cut:], now)
	dnsRate[pid] = times
	if len(times) >= 30 {
		emitProc("DNS_QUERY_FLOOD (T1048.003)", comm, pid, fmt.Sprintf("consultas=%d en 60s (posible túnel/exfil DNS de alto volumen)", len(times)))
		dnsRate[pid] = nil
	}
}

// dnsName parsea el QNAME crudo (secuencia [len][chars]... 0x00) a "a.b.c".
func dnsName(raw []byte) string {
	var sb strings.Builder
	for i := 0; i < len(raw); {
		l := raw[i]
		if l == 0 {
			break
		}
		if l > 63 || i+1+int(l) > len(raw) {
			break
		}
		i++
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(raw[i : i+int(l)])
		i += int(l)
	}
	return sb.String()
}

// looksEncodedLabel: heurística de "label codificado" para strings cortos,
// donde la entropía de Shannon de muestra satura en log2(len) y no discrimina
// (medido: base32 de 18 chars da 3.2-3.7 b/c, mismo rango que texto natural).
// Señales alcanzables: proporción de vocales y de caracteres distintos.
// base32 aleatorio: vocales ≈ 16%, chars únicos ≈ 85-95%. Texto natural:
// vocales ≥ 35%, únicos ≈ 55-70%. Umbrales: vocales ≤ 20%, únicos ≥ 75%.
func looksEncodedLabel(s string) bool {
	n := len(s)
	vowels := 0
	seen := [256]bool{}
	unique := 0
	for i := 0; i < n; i++ {
		c := s[i]
		switch c {
		case 'a', 'e', 'i', 'o', 'u', 'A', 'E', 'I', 'O', 'U':
			vowels++
		}
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			if !seen[c] {
				seen[c] = true
				unique++
			}
		} else {
			return false // guiones/hyphen7 ya delatan; aquí exigimos alfanum
		}
	}
	vowelRatio := float64(vowels) / float64(n)
	uniqueRatio := float64(unique) / float64(n)
	return vowelRatio <= 0.20 && uniqueRatio >= 0.75
}

// dnsEntropyHit registra un label de alta entropía por pid; true al segundo
// hit en ≤60s (dos labels codificados del mismo proceso = túnel, no ruido).
var dnsEntropyMu sync.Mutex
var dnsEntropy = map[uint32]time.Time{}

func dnsEntropyHit(pid uint32) bool {
	dnsEntropyMu.Lock()
	defer dnsEntropyMu.Unlock()
	if t, ok := dnsEntropy[pid]; ok && time.Since(t) <= 60*time.Second {
		delete(dnsEntropy, pid)
		return true
	}
	dnsEntropy[pid] = time.Now()
	return false
}

// dnsTxidHit: igual que dnsEntropyHit pero para el canal encubierto en el
// transaction ID. Un solo lookup con txid ambos-imprimible es ~14% de
// probabilidad natural (coincidencia); DOS en 60s del mismo pid es ~2% →
// reduce el FP de matar procesos legítimos por una coincidencia de txid.
var dnsTxidMu sync.Mutex
var dnsTxidSeen = map[uint32]time.Time{}

func dnsTxidHit(pid uint32) bool {
	dnsTxidMu.Lock()
	defer dnsTxidMu.Unlock()
	if t, ok := dnsTxidSeen[pid]; ok && time.Since(t) <= 60*time.Second {
		delete(dnsTxidSeen, pid)
		return true
	}
	dnsTxidSeen[pid] = time.Now()
	return false
}

// Detección de exfil por DNS (comportamiento): etiquetas largas de alta
// entropía (chunked/tunneling) y muchos subdominios bajo una misma raíz (DGA).
type dnsBucket struct {
	start time.Time
	names map[string]bool
}

var dnsMu sync.Mutex
var dnsBuckets = map[string]dnsBucket{}

func checkDnsExfil(comm string, pid uint32, name string, txid uint32) {
	name = strings.Trim(name, ".")
	if name == "" || strings.Contains(name, ".local") || strings.Contains(name, ".lan") {
		return // ignorar mDNS/LLMNR local
	}

	// Canal encubierto en el transaction ID: un ID aleatorio casi nunca tiene
	// sus DOS bytes en rango imprimible. Si ambos son ASCII imprimible, los datos
	// viajan en el ID (no en el nombre), y el análisis de nombres no lo vería.
	// Se exigen DOS hits del mismo pid en 60s: un solo lookup con txid ambos-
	// imprimible es ~14% de coincidencia natural (documentado, fila 19) y
	// mataba procesos legítimos por azar.
	hi, lo := byte(txid>>8), byte(txid&0xFF)
	if hi >= 0x20 && hi <= 0x7E && lo >= 0x20 && lo <= 0x7E {
		if dnsTxidHit(pid) {
			emitProc("DNS_TXID_COVERT (T1048.003)", comm, pid, fmt.Sprintf("domain=%s txid=0x%04x", name, txid))
			return
		}
		// primer hit: no emitir; seguir analizando el nombre (podría además
		// ser un túnel clásico de etiquetas largas).
	}

	// Etiqueta larga (chunked/tunneling clásico).
	for _, label := range strings.Split(name, ".") {
		if len(label) >= 20 {
			emitProc("DNS_EXFIL (T1048.003)", comm, pid, fmt.Sprintf("domain=%s label=%d", name, len(label)))
			return
		}
	}

	// Túnel low-and-slow con labels de 14-19 chars: evade el umbral de 20 y,
	// con roots distintos por consulta, también evade DGA_RAIZ. OJO: la
	// entropía de MUESTRA de un string corto satura en log2(len) (18 chars →
	// máx 4.17 b/c); un umbral absoluto de Shannon es inalcanzable (medido:
	// base32 real da 3.2-3.7). Señales alcanzables: pocas vocales (base32
	// aleatorio ≈ 16%, texto natural ≥ 35%) + casi sin repeticiones. Se
	// exigen DOS labels codificados del mismo pid en 60s.
	for _, label := range strings.Split(name, ".") {
		if len(label) >= 14 && looksEncodedLabel(label) {
			if dnsEntropyHit(pid) {
				emitProc("DNS_EXFIL_ENTROPY (T1048.003)", comm, pid, fmt.Sprintf("domain=%s label=%d (label codificado: túnel low-and-slow)", name, len(label)))
				return
			}
		}
	}

	// Muchos subdominios bajo la misma raíz (DGA/exfil troceado).
	parts := strings.Split(name, ".")
	if len(parts) < 3 {
		return
	}
	suffix := parts[len(parts)-2] + "." + parts[len(parts)-1]
	dnsMu.Lock()
	defer dnsMu.Unlock()
	b := dnsBuckets[suffix]
	if b.names == nil || time.Since(b.start) > 60*time.Second {
		b = dnsBucket{start: time.Now(), names: map[string]bool{}}
	}
	b.names[name] = true
	dnsBuckets[suffix] = b
	if len(b.names) >= 6 {
		emitProc("DNS_DGA_RAIZ (T1568.002)", comm, pid, fmt.Sprintf("suffix=%s subdominios=%d", suffix, len(b.names)))
		dnsBuckets[suffix] = dnsBucket{start: time.Now(), names: map[string]bool{}}
	}
}

// /proc/<pid>/mem de OTRO proceso (T1055). Solo `mem`, no `maps`: leer los maps
// de otro proceso es introspección benigna (ps/top/monitores); leer su MEMORIA
// sí es inyección. `/proc/self/*` no matchea (self no es numérico).
var procMemRe = regexp.MustCompile(`/proc/[0-9]+/mem`)
var procEnvironRe = regexp.MustCompile(`/proc/([0-9]+)/environ`)
var procCmdlineRe = regexp.MustCompile(`/proc/([0-9]+)/cmdline`)

// Herramientas del sistema que leen /proc/PID/cmdline de TODOS los procesos de
// forma legítima (ps/top/hot/htop/pgrep...): se excluyen de la regla T1003.007
// para no matar el monitoreo normal. El resto de lectores de un cmdline ajeno
// es dump de credenciales (el cmdline puede llevar --password, tokens, etc.).
var procReaders = map[string]bool{
	"ps": true, "top": true, "htop": true, "pgrep": true, "pidof": true,
	"pkill": true, "killall": true, "w": true, "who": true, "systemd": true,
	"systemd-coredum": true, "journalctl": true, "lsof": true,
}

func checkSensitive(comm string, pid uint32, fname string, write bool) {
	if fname == "" {
		return
	}
	// Las herramientas de defensa (incluido el propio detector recorriendo
	// /host/cgroup) leen rutas sensibles de forma legítima; debe excluirse
	// ANTES de cualquier regla, o un self-scan puede autodispararse un kill.
	if defenseTools[comm] {
		return
	}
	// T1546.004: persistencia por modificación de perfil de shell. Leer el
	// perfil es normal (todo bash lo hace al arrancar); SOLO la ESCRITURA
	// (FMODE_WRITE / O_WRONLY|O_RDWR) es el ataque. Incluye el perfil de
	// SISTEMA (/etc/profile y /etc/profile.d/*), que afecta a TODO login.
	if write && (strings.HasSuffix(fname, ".bashrc") || strings.HasSuffix(fname, ".profile") || strings.HasSuffix(fname, ".bash_profile") || strings.HasSuffix(fname, ".zshrc") || strings.Contains(fname, "/etc/profile")) {
		emitProc("PERSISTENCIA_PERFIL (T1546.004)", comm, pid, fmt.Sprintf("path=%s", fname))
		return
	}
	// T1505.003: web shell — escribir un script ejecutable por el servidor en
	// el web root del lab (/var/www). Solo ESCRITURA (la lectura de .php es
	// normal: el servidor los lee para servirlos). Extensiones variantes
	// (.phtml/.php5 — el servidor las ejecuta igual) y config de directorio
	// que inyecta código (.user.ini auto_prepend_file, .htaccess AddType→php).
	if write && strings.Contains(fname, "/var/www/") && (strings.HasSuffix(fname, ".php") ||
		strings.HasSuffix(fname, ".phtml") || strings.HasSuffix(fname, ".php5")) {
		emitProc("WEBSHELL (T1505.003)", comm, pid, fmt.Sprintf("path=%s", fname))
		return
	}
	if write && (strings.HasSuffix(fname, "/.user.ini") || strings.HasSuffix(fname, "/.htaccess")) {
		emitProc("WEBSHELL (T1505.003)", comm, pid, fmt.Sprintf("path=%s (config de directorio web)", fname))
		return
	}
	// T1491.001: defacement — escribir contenido web (index.html, .htm...) en el
	// webroot. Las extensiones ejecutables ya van por WEBSHELL; esto cubre la
	// alteración/sabotaje del contenido servido.
	if write && strings.Contains(fname, "/var/www/") {
		emitProc("DEFACEMENT (T1491.001)", comm, pid, fmt.Sprintf("path=%s (contenido web modificado)", fname))
		return
	}
	// T1566.001: adjunto de phishing — plantar un documento con macros o un
	// script (.docm/.xlsm/.vbs/.hta) es el artefacto que el usuario abrirá.
	if write && (strings.HasSuffix(fname, ".docm") || strings.HasSuffix(fname, ".xlsm") ||
		strings.HasSuffix(fname, ".vbs") || strings.HasSuffix(fname, ".hta")) {
		emitProc("PHISHING_ATTACHMENT (T1566.001)", comm, pid, fmt.Sprintf("path=%s (adjunto malicioso plantado)", fname))
		return
	}
	// T1574.001: hijack de librerías — escribir/reemplazar un .so en un
	// directorio de búsqueda del cargador dinámico hace que las apps carguen
	// código del atacante al ejecutarse. LD_PRELOAD (fila 14) y ld.so.preload
	// (fila 30) ya cubiertos; el directorio de librerías no lo estaba.
	if write && (strings.HasPrefix(fname, "/usr/lib/") || strings.HasPrefix(fname, "/lib/") || strings.HasPrefix(fname, "/usr/local/lib/")) && strings.HasSuffix(fname, ".so") {
		emitProc("LIB_HIJACK (T1574.001)", comm, pid, fmt.Sprintf("path=%s (librería compartida plantada)", fname))
		return
	}
	// T1014: rootkit — módulo de kernel (.ko) plantado en los dirs de módulos.
	// El .so (fila 65) no cubría .ko; un módulo cargado (insmod) da control del
	// kernel del host.
	if write && strings.HasPrefix(fname, "/lib/modules/") && strings.HasSuffix(fname, ".ko") {
		emitProc("ROOTKIT_MODULE (T1014)", comm, pid, fmt.Sprintf("path=%s (módulo de kernel plantado)", fname))
		return
	}
	// T1574.006-ext: /etc/environment — env de TODO el sistema, lo lee PAM en
	// cada login. LD_PRELOAD/PATH aquí inyecta código en cada proceso futuro
	// (misma familia que ld.so.preload, distinto archivo).
	if write && strings.HasSuffix(fname, "/etc/environment") {
		emitProc("ENV_SYSTEMWIDE (T1574.006)", comm, pid, fmt.Sprintf("path=%s (env global del sistema)", fname))
		return
	}
	// T1036.005: masquerading — plantar un binario con nombre de comando de
	// sistema en /usr/bin|/bin|/sbin|/usr/sbin suplanta al binario legítimo.
	// Fila 62 cubrió /usr/local/bin; estos dirs de sistema no.
	if write && (strings.HasPrefix(fname, "/usr/bin/") || strings.HasPrefix(fname, "/bin/") ||
		strings.HasPrefix(fname, "/sbin/") || strings.HasPrefix(fname, "/usr/sbin/")) {
		emitProc("MASQUERADING (T1036.005)", comm, pid, fmt.Sprintf("path=%s (binario de sistema suplantado)", fname))
		return
	}
	// T1547.007: registro de módulo PKCS#11 (p11-kit) — un .module en estos
	// directorios registra un módulo cripto malicioso que las librerías cargan
	// en cada uso (persistencia a nivel de crypto).
	if write && (strings.HasPrefix(fname, "/etc/pkcs11/") || strings.HasPrefix(fname, "/usr/share/p11-kit/")) && strings.HasSuffix(fname, ".module") {
		emitProc("PKCS11_MODULE (T1547.007)", comm, pid, fmt.Sprintf("path=%s (módulo PKCS#11 registrado)", fname))
		return
	}
	// T1546.005: backdoor SSH — AuthorizedKeysCommand/PermitRootLogin en
	// sshd_config (o su drop-in dir) ejecuta el comando del atacante en cada
	// login SSH. La fila 39 cubría authorized_keys, no la config del daemon.
	if write && (strings.HasSuffix(fname, "/sshd_config") || strings.HasPrefix(fname, "/etc/ssh/sshd_config.d/")) {
		emitProc("SSHD_BACKDOOR (T1546.005)", comm, pid, fmt.Sprintf("path=%s (config del daemon SSH modificada)", fname))
		return
	}
	// T1556: backdoor PAM — escribir /etc/pam.d/ (auth sufficient pam_permit.so)
	// deshabilita la autenticación en TODO login (backdoor de acceso).
	if write && strings.HasPrefix(fname, "/etc/pam.d/") {
		emitProc("PAM_BACKDOOR (T1556)", comm, pid, fmt.Sprintf("path=%s (config de autenticación PAM modificada)", fname))
		return
	}
	// T1574.006: preload a nivel de sistema — escribir /etc/ld.so.preload (o
	// /etc/ld.so.conf.d/*.conf) hace que TODO proceso futuro cargue una .so
	// atacante. Distinto del env var LD_PRELOAD (fila 14): este es persistente.
	if write && (strings.Contains(fname, "ld.so.preload") || strings.Contains(fname, "ld.so.conf.d")) {
		emitProc("LD_PRELOAD_PERSISTENCIA (T1574.006)", comm, pid, fmt.Sprintf("path=%s", fname))
		return
	}
	// T1547.006: persistencia de arranque — /etc/rc.local (o /etc/rc.d/*) se
	// ejecuta en cada boot. Solo ESCRITURA.
	if write && strings.Contains(fname, "rc.local") {
		emitProc("PERSISTENCIA_BOOT (T1547.006)", comm, pid, fmt.Sprintf("path=%s", fname))
		return
	}
	// T1037.004: script de init — /etc/init.d/* corre al inicio (SysV). Solo ESCRITURA.
	if write && strings.Contains(fname, "/etc/init.d/") {
		emitProc("PERSISTENCIA_INIT (T1037.004)", comm, pid, fmt.Sprintf("path=%s", fname))
		return
	}
	// T1547.009: autostart XDG — un .desktop en /etc/xdg/autostart o
	// ~/.config/autostart ejecuta un binario en cada login gráfico.
	if write && strings.HasSuffix(fname, ".desktop") &&
		(strings.Contains(fname, "/etc/xdg/autostart/") || strings.Contains(fname, "/.config/autostart/")) {
		emitProc("AUTOSTART (T1547.009/T1547.013)", comm, pid, fmt.Sprintf("path=%s (autostart de escritorio)", fname))
		return
	}
	// T1611: /proc/sys/kernel/* es GLOBAL del kernel — escribirlo desde un
	// contenedor (privileged) cambia el comportamiento del HOST entero:
	// core_pattern = ejecución arbitraria en el host al primer coredump,
	// modprobe = carga de módulos atacantes, unprivileged_userfaultfd, kexec...
	// El hook file_open ya DENIEGA in-kernel; aquí queda la auditoría.
	if write && strings.HasPrefix(fname, "/proc/sys/kernel/") {
		emitProc("PROC_SYS_KERNEL (T1611)", comm, pid, fmt.Sprintf("path=%s (sysctl del kernel escrito desde contenedor)", fname))
		return
	}
	// T1553.004: subversión de controles de confianza — escribir una CA falsa
	// en el trust store del sistema (/etc/ssl/certs/, /usr/local/share/
	// ca-certificates/ o /etc/ca-certificates.conf) hace que el sistema CONFÍE
	// en certificados del atacante (MITM de TLS). Solo ESCRITURA: leer certs
	// es lo normal (todo cliente TLS los lee al validar).
	if write && (strings.Contains(fname, "/etc/ssl/certs/") || strings.Contains(fname, "ca-certificates") || strings.Contains(fname, "/etc/pki/ca-trust/")) {
		emitProc("CA_MALICIOSA (T1553.004)", comm, pid, fmt.Sprintf("path=%s (CA inyectada en trust store)", fname))
		return
	}
	// T1548.003: escalada vía sudoers — escribir /etc/sudoers (o sudoers.d/*)
	// concede sudo sin password. Solo ESCRITURA (leerlo es normal para sudo/visudo).
	if write && strings.Contains(fname, "sudoers") {
		emitProc("SUDOERS_MODIFICACION (T1548.003)", comm, pid, fmt.Sprintf("path=%s", fname))
		return
	}
	// T1136.001 (bypass de useradd): escribir directamente /etc/passwd añade una
	// cuenta (p.ej. uid 0) sin pasar por el comando useradd/adduser. La LECTURA
	// de passwd es normal (id, ls -l); solo la ESCRITURA es el ataque.
	if write && strings.Contains(fname, "/etc/passwd") {
		emitProc("CREACION_CUENTA (T1136.001)", comm, pid, fmt.Sprintf("path=%s (escritura directa a passwd)", fname))
		return
	}
	// T1055: escribir /proc/<pid>/mem es la inyección de memoria por ARCHIVO
	// (hermana de process_vm_writev): parchea un proceso vivo sin ptrace. El
	// open en escritura ya se NIEGA in-kernel (sensitive_write_path); esto
	// audita quién lo intentó. La LECTURA de /proc/self/mem es legítima (gdb,
	// JITs): solo la escritura a proceso AJENO es ataque.
	if write && strings.HasPrefix(fname, "/proc/") && strings.HasSuffix(fname, "/mem") {
		emitProc("INYECCION_MEM (T1055)", comm, pid, fmt.Sprintf("path=%s (escritura de memoria de proceso vivo, denegada)", fname))
		return
	}
	// T1529/T1611: /proc/sysrq-trigger ejecuta comandos SysRq del kernel — 'b'
	// reinicia el host al instante desde un contenedor privileged. Denegado
	// in-kernel; aquí queda la auditoría del intento (el host sigue vivo).
	if write && strings.HasSuffix(fname, "/sysrq-trigger") {
		emitProc("HOST_CRASH (T1529/T1611)", comm, pid, fmt.Sprintf("path=%s (SysRq del kernel, denegado)", fname))
		return
	}
	// T1557: hijack del resolver — reescribir /etc/hosts o /etc/resolv.conf
	// redirige la resolución de nombres de todo el sistema (con /:/host
	// montado, envenena el HOST). Denegado in-kernel; la LECTURA ya está
	// cubierta como DISCOVERY_SENSIBLE (fila 48).
	if write && (strings.HasSuffix(fname, "/etc/hosts") || strings.HasSuffix(fname, "/etc/resolv.conf")) {
		emitProc("RESOLVER_HIJACK (T1557)", comm, pid, fmt.Sprintf("path=%s (resolución de nombres envenenada, denegado)", fname))
		return
	}
	// ".sock" exacto al final de un componente de ruta: evita que
	// "docker.socket" (unidad systemd) haga falso match por substring.
	base := fname
	if i := strings.LastIndexByte(fname, '/'); i >= 0 {
		base = fname[i+1:]
	}
	if base == "docker.sock" || strings.HasSuffix(base, ".sock") {
		emitProc("DOCKER_SOCK (T1611)", comm, pid, fmt.Sprintf("path=%s", fname))
		return
	} // T1056.001: captura de entrada — abrir /dev/input/event* (teclado/ratón)
	// o /dev/uinput desde un contenedor es keylogging (el lector legítimo
	// libinput corre en el host, fuera de los cgroups del lab; el hook ya
	// DENIEGA in-kernel — aquí queda la auditoría del intento).
	if strings.HasPrefix(fname, "/dev/input/") || strings.HasSuffix(fname, "uinput") {
		emitProc("CAPTURA_INPUT (T1056.001)", comm, pid, fmt.Sprintf("path=%s (open denegado)", fname))
		return
	}
	// T1113: captura de pantalla — leer el framebuffer (/dev/fb*, /dev/graphics).
	if !write && (strings.HasPrefix(fname, "/dev/fb") || strings.Contains(fname, "/dev/graphics/")) {
		emitProc("SCREEN_CAPTURE (T1113)", comm, pid, fmt.Sprintf("path=%s (framebuffer)", fname))
		return
	}
	// T1123: captura de audio — leer dispositivos de audio (/dev/snd/, /dev/audio, /dev/dsp).
	if !write && (strings.HasPrefix(fname, "/dev/snd/") || strings.HasPrefix(fname, "/dev/audio") || strings.HasPrefix(fname, "/dev/dsp")) {
		emitProc("AUDIO_CAPTURE (T1123)", comm, pid, fmt.Sprintf("path=%s (dispositivo de audio)", fname))
		return
	}
	// T1115: portapapeles — leer el socket X11 (xclip/xsel) o /dev/clipboard.
	if !write && (strings.Contains(fname, "/.X11-unix/") || strings.Contains(fname, "clipboard")) {
		emitProc("CLIPBOARD_CAPTURE (T1115)", comm, pid, fmt.Sprintf("path=%s (portapapeles)", fname))
		return
	} // /etc/shadow: siempre sensible (requiere root). /etc/passwd: solo si lo lee
	// una app (un binario del sistema leyéndolo es normal: id, ls -l, cron...).
	if strings.Contains(fname, "/etc/shadow") {
		emitProc("LECTURA_SENSIBLE", comm, pid, fmt.Sprintf("path=%s", fname))
		return
	}
	// T1087: enumeración de cuentas — cat/grep/head/tail sobre /etc/passwd o
	// /etc/group. Los binarios de sistema (id, ls, cron) los leen de forma
	// normal; un lector manual es reconocimiento de cuentas.
	if !write && (strings.Contains(fname, "/etc/passwd") || strings.Contains(fname, "/etc/group")) {
		if apps[comm] || comm == "cat" || comm == "grep" || comm == "head" || comm == "tail" ||
			comm == "less" || comm == "more" || comm == "sed" || comm == "awk" {
			emitProc("ACCOUNT_DISCOVERY (T1087/T1033)", comm, pid, fmt.Sprintf("path=%s (lectura de cuentas)", fname))
			return
		}
	}
	// T1613: descubrimiento de contenedor — leer /.dockerenv o /proc/*/cgroup
	// revela que se está en un contenedor (y qué recursos del daemon hay).
	if !write && (fname == "/.dockerenv" || strings.Contains(fname, "/proc/self/cgroup") ||
		strings.Contains(fname, "/proc/1/cgroup")) {
		if comm == "cat" || comm == "grep" || comm == "head" || comm == "tail" ||
			comm == "less" || comm == "more" || comm == "sed" || comm == "awk" {
			emitProc("CONTAINER_DISCOVERY (T1613)", comm, pid, fmt.Sprintf("path=%s (detección de contenedor)", fname))
			return
		}
	}
	// T1082: descubrimiento del sistema — cat/grep sobre os-release, /.dockerenv,
	// /proc/cpuinfo, /proc/*/cgroup, resolv.conf, hosts, krb5.conf. Path-based
	// (robusto aunque el proceso ya haya salido: el openat captura la ruta en
	// kernel). Los binarios de sistema los leen normalmente; cat/grep = enum.
	if !write && (strings.Contains(fname, "/etc/os-release") ||
		strings.Contains(fname, "/etc/alpine-release") ||
		strings.Contains(fname, "/etc/debian_version") ||
		fname == "/.dockerenv" ||
		strings.Contains(fname, "/proc/cpuinfo") ||
		strings.Contains(fname, "/proc/1/cgroup") ||
		strings.Contains(fname, "/etc/resolv.conf") ||
		strings.Contains(fname, "/etc/krb5.conf") ||
		strings.Contains(fname, "/etc/hosts")) {
		if comm == "cat" || comm == "grep" || comm == "head" || comm == "tail" ||
			comm == "less" || comm == "more" || comm == "sed" || comm == "awk" {
			emitProc("DISCOVERY_SENSIBLE (T1082/T1087)", comm, pid, fmt.Sprintf("path=%s (lectura de sistema)", fname))
			return
		}
	}
	// --- Credenciales en archivos (T1552 / T1555) ---
	// Lectura MANUAL de claves SSH, historial, keyrings y credenciales cloud.
	// Los clientes legítimos (ssh/sshd/scp/sftp/rsync/ssh-agent) se excluyen.
	if !write && comm != "ssh" && comm != "sshd" && comm != "scp" && comm != "sftp" &&
		comm != "rsync" && comm != "ssh-agent" && comm != "ssh-keysign" {
		lowf := strings.ToLower(fname)
		if strings.Contains(lowf, "/.ssh/") {
			if strings.Contains(lowf, "id_rsa") || strings.Contains(lowf, "id_ed25519") ||
				strings.Contains(lowf, "id_dsa") || strings.Contains(lowf, "id_ecdsa") ||
				strings.Contains(lowf, "authorized_keys") {
				emitProc("CRED_SSH_KEYS (T1552.004)", comm, pid, fmt.Sprintf("path=%s (clave privada SSH)", fname))
				return
			}
			if strings.Contains(lowf, "known_hosts") {
				emitProc("KNOWN_HOSTS_ENUM (T1018)", comm, pid, fmt.Sprintf("path=%s (enumeración de hosts conocidos)", fname))
				return
			}
		}
		if strings.Contains(lowf, ".bash_history") || strings.Contains(lowf, ".zsh_history") ||
			strings.Contains(lowf, ".python_history") {
			emitProc("CRED_HISTORIAL (T1552.003)", comm, pid, fmt.Sprintf("path=%s (historial de comandos)", fname))
			return
		}
		if strings.Contains(lowf, "keyring") || strings.Contains(lowf, "/.gnupg/") ||
			strings.Contains(lowf, ".password-store") {
			emitProc("CRED_KEYRING (T1555.001)", comm, pid, fmt.Sprintf("path=%s (almacén de secretos)", fname))
			return
		}
		if strings.Contains(lowf, ".aws/credentials") || strings.Contains(lowf, ".aws/config") ||
			strings.Contains(lowf, "gcloud") || strings.Contains(lowf, "/azure/") ||
			strings.Contains(lowf, "/.kube/config") || strings.Contains(lowf, "application_default_credentials.json") {
			emitProc("CRED_CLOUD (T1552)", comm, pid, fmt.Sprintf("path=%s (credencial cloud)", fname))
			return
		}
	}
	if procMemRe.MatchString(fname) {
		emitProc("MEMORIA_AJENA (T1055)", comm, pid, fmt.Sprintf("path=%s", fname))
		return
	}
	// T1003.008: dump de credenciales vía /proc/<pid>/environ de OTRO proceso.
	// El hook reporta el pid HOST (--pid=host); el path está en el namespace del
	// contenedor. Se mapea con NSpid (último campo = pid del ns más interno).
	// El open de /proc/self/environ resuelve a /proc/<tgid>/environ → pid del
	// path == pid del lector (en el mismo ns) ⇒ lectura propia (normal, se salta).
	if m := procEnvironRe.FindStringSubmatch(fname); m != nil {
		targetPid, _ := strconv.ParseUint(m[1], 10, 32)
		if nsPid(pid) != uint32(targetPid) && targetPid != 0 {
			emitProc("CREDENCIALES_ENVIRON (T1003.008)", comm, pid, fmt.Sprintf("path=%s (environ de pid %d)", fname, targetPid))
		}
		return
	}
	// T1003.007: dump de credenciales vía /proc/<pid>/cmdline de OTRO proceso
	// (el cmdline puede llevar secretos: --password, tokens...). ps/top/htop
	// leen cmdline de todos de forma legítima → excluidos con procReaders.
	if m := procCmdlineRe.FindStringSubmatch(fname); m != nil {
		targetPid, _ := strconv.ParseUint(m[1], 10, 32)
		if !procReaders[comm] && nsPid(pid) != uint32(targetPid) && targetPid != 0 {
			emitProc("CREDENCIALES_CMDLINE (T1003.007)", comm, pid, fmt.Sprintf("path=%s (cmdline de pid %d)", fname, targetPid))
		}
		return
	}
	// T1552.001/.004: robo de credenciales — claves SSH (.ssh/id_*), historial
	// y credenciales de cloud/herramientas (.aws/, .netrc, .git-credentials,
	// .docker/config.json, .kube/config, .npmrc, .pypirc, .pgpass, .my.cnf).
	// La LECTURA ajena de estos archivos es el ataque (el shell leyendo su
	// propia history es normal).
	credPath := strings.Contains(fname, "bash_history") ||
		strings.Contains(fname, ".ssh") ||
		strings.Contains(fname, "authorized_keys") ||
		strings.Contains(fname, ".aws/") ||
		strings.Contains(fname, ".netrc") ||
		strings.Contains(fname, ".git-credentials") ||
		strings.Contains(fname, ".docker/config.json") ||
		strings.Contains(fname, ".kube/config") ||
		strings.Contains(fname, ".npmrc") ||
		strings.Contains(fname, ".pypirc") ||
		strings.Contains(fname, ".pgpass") ||
		strings.Contains(fname, ".my.cnf")
	if credPath {
		// Persistencia (T1098.004): ESCRIBIR authorized_keys = puerta trasera
		// SSH. La LECTURA la hace sshd en CADA login (normal) — solo la
		// escritura es el ataque; la lectura ajena es robo de credenciales.
		if strings.Contains(fname, "authorized_keys") {
			if write {
				emitProc("PERSISTENCIA_SSH (T1098.004)", comm, pid, fmt.Sprintf("path=%s", fname))
			} else if comm != "sshd" {
				emitProc("CREDENCIALES", comm, pid, fmt.Sprintf("path=%s", fname))
			}
			return
		}
		// El shell leyendo SU propia history es funcionamiento normal; lo raro
		// es que la lea otro proceso (cat, una app, un binario robado).
		if shells[comm] && strings.Contains(fname, "bash_history") {
			return
		}
		// T1136.003: ESCRIBIR credenciales cloud no es robo — es PLANTAR
		// acceso persistente. Misma familia de rutas que la lectura, pero
		// semántica opuesta: se audita con regla propia y el write queda
		// denegado in-kernel (sensitive_write_path).
		if write && (strings.HasSuffix(fname, "/.aws/credentials") ||
			strings.HasSuffix(fname, "/.azure/servicePrincipal.json") ||
			strings.HasSuffix(fname, "/.gcp/credentials.json") ||
			strings.HasSuffix(fname, "/.config/gcloud/credentials")) {
			emitProc("CREDENCIALES_CLOUD_WRITE (T1136.003)", comm, pid, fmt.Sprintf("path=%s (acceso cloud plantado)", fname))
			return
		}
		emitProc("CREDENCIALES", comm, pid, fmt.Sprintf("path=%s", fname))
	}
	// T1555.003: robo de credenciales del NAVEGADOR — leer logins.json/key4.db/
	// cookies de Firefox o Login Data/Cookies de Chrome roba contraseñas y
	// sesiones guardadas. El navegador legítimo corre en el HOST (fuera de los
	// cgroups filtrados) — cualquier LECTURA desde un contenedor es robo.
	// (La ESCRITURA al perfil ya se deniega in-kernel, fila 61.)
	if !write {
		browserCred := (strings.Contains(fname, "/.mozilla/firefox/") &&
			(strings.HasSuffix(fname, "logins.json") || strings.HasSuffix(fname, "key4.db") ||
				strings.HasSuffix(fname, "cookies.sqlite") || strings.HasSuffix(fname, "signons.sqlite"))) ||
			((strings.Contains(fname, "/.config/google-chrome/") || strings.Contains(fname, "/.config/chromium/")) &&
				(strings.HasSuffix(fname, "Login Data") || strings.HasSuffix(fname, "Cookies") ||
					strings.HasSuffix(fname, "Web Data")))
		if browserCred {
			emitProc("CREDENCIALES_NAVEGADOR (T1555.003)", comm, pid, fmt.Sprintf("path=%s (robo de credenciales del navegador)", fname))
			return
		}
		// T1555.004: credenciales en VAULT/keyring — leer llaveros de
		// contraseñas (KeePass .kdbx/.kdb, gnome-keyring keyrings/*.keyring,
		// 1Password .opvault/.agilekeychain, claves privadas GPG en ~/.gnupg)
		// roba las contraseñas guardadas. Mismo patrón de lectura que fila 44.
		vaultCred := strings.HasSuffix(fname, ".kdbx") ||
			strings.HasSuffix(fname, ".kdb") ||
			(strings.Contains(fname, "/keyrings/") && strings.HasSuffix(fname, ".keyring")) ||
			strings.Contains(fname, ".opvault") ||
			strings.Contains(fname, ".agilekeychain") ||
			(strings.Contains(fname, "/.gnupg/") && (strings.HasSuffix(fname, "secring.gpg") ||
				strings.Contains(fname, "private-keys-v1.d")))
		if vaultCred {
			emitProc("CREDENCIALES_VAULT (T1555.004)", comm, pid, fmt.Sprintf("path=%s (vault/keyring de contraseñas)", fname))
			return
		}
	}
	// Persistencia (T1053): ESCRIBIR a cron (fuera del propio cron del sistema).
	// Leer cron lo hace el daemon en cada tick — solo la escritura es el ataque.
	if write && strings.Contains(fname, "cron") && comm != "cron" && comm != "systemd" && comm != "anacron" {
		emitProc("PERSISTENCIA_CRON (T1053)", comm, pid, fmt.Sprintf("path=%s", fname))
	}
	// Persistencia (T1543/T1053.006): creación de unidad systemd. Solo
	// ESCRITURA: systemd lee unidades en cada daemon-reload (normal). El .timer
	// (tarea programada) y el .service (servicio persistente) se clasifican por
	// separado; el hook ya DENIEGA in-kernel cualquier write al dir.
	if write && strings.Contains(fname, "/etc/systemd/system/") {
		if strings.HasSuffix(fname, ".timer") {
			emitProc("TAREA_PROGRAMADA (T1053.006)", comm, pid, fmt.Sprintf("path=%s (timer de systemd)", fname))
		} else {
			emitProc("PERSISTENCIA_SERVICIO (T1543)", comm, pid, fmt.Sprintf("path=%s", fname))
		}
	}
	// Persistencia (T1176): extensión de navegador o hijack de preferencias.
	// Un .xpi en el perfil de Firefox o un Preferences/prefs.js modificado
	// ejecutan código en cada arranque del navegador. El navegador legítimo
	// corre en el HOST (fuera de cgroups filtrados) — cualquier write a
	// perfil desde un contenedor es persistencia.
	if write && (strings.HasSuffix(fname, ".xpi") ||
		strings.HasSuffix(fname, "/google-chrome/Default/Preferences") ||
		strings.HasSuffix(fname, "/chromium/Default/Preferences") ||
		(strings.Contains(fname, "/.mozilla/firefox/") && strings.HasSuffix(fname, "prefs.js"))) {
		emitProc("NAVEGADOR_EXT (T1176)", comm, pid, fmt.Sprintf("path=%s (persistencia en navegador)", fname))
	}
	// Persistencia (T1574.007): PATH planting — /usr/local/bin precede a
	// /usr/bin en el PATH por defecto; un binario con nombre de comando
	// común ahí se ejecuta en el siguiente uso del comando (hijack de la
	// próxima ejecución del admin). Sin filtro de nombre: cualquier write
	// de binario desde un contenedor de app es anómalo.
	if write && strings.HasPrefix(fname, "/usr/local/bin/") {
		emitProc("PATH_PLANT (T1574.007)", comm, pid, fmt.Sprintf("path=%s (binario en dir temprano del PATH)", fname))
	}
}

// nsPid devuelve el pid del proceso en su namespace más interno (el del
// contenedor) leyendo /proc/<hostPid>/status. NSpid lista los pids de afuera
// hacia adentro: el ÚLTIMO campo es el del namespace más interno. El hook
// reporta el pid HOST (--pid=host), pero los paths /proc/<pid>/... están en el
// namespace del contenedor → hay que mapear antes de comparar.
func nsPid(hostPid uint32) uint32 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", hostPid))
	if err != nil {
		return hostPid
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "NSpid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if v, err := strconv.ParseUint(fields[len(fields)-1], 10, 32); err == nil {
					return uint32(v)
				}
			}
		}
	}
	return hostPid
}

func netIP(family uint16, addr []byte) string {
	if family == 2 {
		return fmt.Sprintf("%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3])
	}
	// IPv6 resumido (solo para el log)
	return fmt.Sprintf("%x:%x:...", addr[0], addr[1])
}

// isLoopbackAddr indica si daddr es loopback: 127.0.0.0/8 (IPv4) o ::1 (IPv6).
// La comunicación con el propio localhost nunca es exfiltración de datos.
func isLoopbackAddr(family uint16, addr []byte) bool {
	if family == 2 { // AF_INET
		return len(addr) > 0 && addr[0] == 127
	}
	// AF_INET6: ::1 = 15 bytes en 0 y el último en 1.
	if len(addr) >= 16 {
		for i := 0; i < 15; i++ {
			if addr[i] != 0 {
				return false
			}
		}
		return addr[15] == 1
	}
	return false
}

// startHeartbeat escribe un latido (timestamp Unix) cada 2s en `path`. Un
// watchdog EXTERNO monitoriza el mtime del archivo: si deja de actualizarse, el
// detector está caído o colgado (SIGKILL no capturable in-situ). Cierra el gap
// del "punto único de fallo" (PENDIENTES #1) sin depender de que el detector
// pueda loguear su propia muerte.
func startHeartbeat(path string) {
	go func() {
		for {
			if err := os.WriteFile(path, []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0644); err != nil {
				log.Printf("heartbeat: %v", err)
			}
			time.Sleep(2 * time.Second)
		}
	}()
	log.Printf("heartbeat activo en %s (watchdog externo)", path)
}

func main() {
	flag.Parse()

	// Dry-run de política: valida firma/serial/selectores y sale SIN arrancar eBPF.
	if policyCheck {
		loadPolicy()
		fmt.Println("policy: check OK (sin arrancar eBPF)")
		os.Exit(0)
	}

	// Allowlist de egress en Go (para la detección userspace de connect).
	refreshEgressAllowed()

	// Activación contra el servidor central (capa 3), si -activate está activo.
	doActivate()

	// Licencia (ligado a máquina + firma + expiración) — si -license está activo.
	checkLicense()

	// Política runtime firmada (P0.2): fija sujeto/reglas/sinks con fail-closed.
	loadPolicy()

	// Invariantes de escape (P1): watcher de UID/exec/migración del sujeto.
	startEscapeInvariants()

	// Latido periódico para un watchdog EXTERNO: cierra el gap del "punto único
	// de fallo" (PENDIENTES #1). Un SIGKILL al detector no es capturable in-situ;
	// el watchdog detecta el cese del latido y alerta/reinicia.
	if heartbeatPath != "" {
		startHeartbeat(heartbeatPath)
	}

	if n := resolveTrustedPids(); n > 0 {
		log.Printf("trusted: %d PIDs de supervisores resueltos desde %s", n, configPath)
	}
	startTrustedRefresher()

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(probeO))
	if err != nil {
		log.Fatalf("load spec: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("new collection: %v (¿falta privilegios eBPF?)", err)
	}
	defer coll.Close()

	// Con -only-docker, restringe el kernel a los cgroups de los contenedores del lab.
	enableCgroupFilter(coll)

	execTP, err := link.Tracepoint("sched", "sched_process_exec", coll.Programs["tp_exec"], nil)
	if err != nil {
		log.Fatalf("attach sched_process_exec: %v", err)
	}
	defer execTP.Close()
	connTP, err := link.Tracepoint("syscalls", "sys_enter_connect", coll.Programs["tp_connect"], nil)
	if err != nil {
		log.Fatalf("attach sys_enter_connect: %v", err)
	}
	defer connTP.Close()
	mmapTP, err := link.Tracepoint("syscalls", "sys_enter_mmap", coll.Programs["tp_mmap"], nil)
	if err != nil {
		log.Fatalf("attach sys_enter_mmap: %v", err)
	}
	defer mmapTP.Close()
	ptraceTP, err := link.Tracepoint("syscalls", "sys_enter_ptrace", coll.Programs["tp_ptrace"], nil)
	if err != nil {
		log.Fatalf("attach sys_enter_ptrace: %v", err)
	}
	defer ptraceTP.Close()
	openatTP, err := link.Tracepoint("syscalls", "sys_enter_openat", coll.Programs["tp_openat"], nil)
	if err != nil {
		log.Fatalf("attach sys_enter_openat: %v", err)
	}
	defer openatTP.Close()
	sendtoTP, err := link.Tracepoint("syscalls", "sys_enter_sendto", coll.Programs["tp_sendto"], nil)
	if err != nil {
		log.Fatalf("attach sys_enter_sendto: %v", err)
	}
	defer sendtoTP.Close()
	sendmmsgTP, err := link.Tracepoint("syscalls", "sys_enter_sendmmsg", coll.Programs["tp_sendmmsg"], nil)
	if err != nil {
		log.Fatalf("attach sys_enter_sendmmsg: %v", err)
	}
	defer sendmmsgTP.Close()
	if memfdTP, err := link.Tracepoint("syscalls", "sys_enter_memfd_create", coll.Programs["tp_memfd_create"], nil); err != nil {
		log.Printf("attach sys_enter_memfd_create: no disponible (%v); se mantiene el resto del detector", err)
	} else {
		defer memfdTP.Close()
	}
	if vmWritevTP, err := link.Tracepoint("syscalls", "sys_enter_process_vm_writev", coll.Programs["tp_process_vm_writev"], nil); err != nil {
		log.Printf("attach sys_enter_process_vm_writev: no disponible (%v); se mantiene el resto del detector", err)
	} else {
		defer vmWritevTP.Close()
	}
	// T1003: scraping de memoria ajena vía process_vm_readv (mimipenguin).
	if vmReadvTP, err := link.Tracepoint("syscalls", "sys_enter_process_vm_readv", coll.Programs["tp_process_vm_readv"], nil); err != nil {
		log.Printf("attach sys_enter_process_vm_readv: no disponible (%v); se mantiene el resto del detector", err)
	} else {
		defer vmReadvTP.Close()
	}
	// T1040: creación de socket de captura (AF_PACKET / SOCK_RAW). Degradación
	// graciosa: sin este tracepoint el resto del detector sigue vivo.
	if sockTP, err := link.Tracepoint("syscalls", "sys_enter_socket", coll.Programs["tp_socket"], nil); err != nil {
		log.Printf("attach sys_enter_socket: no disponible (%v); se mantiene el resto del detector", err)
	} else {
		defer sockTP.Close()
	}
	// T1070.006: timestomp vía utimensat con times explícitos (touch -r/-t).
	if utimensatTP, err := link.Tracepoint("syscalls", "sys_enter_utimensat", coll.Programs["tp_utimensat"], nil); err != nil {
		log.Printf("attach sys_enter_utimensat: no disponible (%v); se mantiene el resto del detector", err)
	} else {
		defer utimensatTP.Close()
	}

	// Sonda XDP (L2/L3): ARP, fragmentación, protocolos desconocidos/modificados.
	xdpLink, nc, err := attachNet()
	if err != nil {
		log.Fatalf("XDP: %v", err)
	}
	if xdpLink != nil {
		defer xdpLink.Close()
		defer nc.Close()
		netColl = nc
		go runNetMonitor(nc)
		startVolumeWatch(nc)
		fmt.Fprintf(os.Stderr, "motor-go XDP activo en %s (ARP/frag/protocolo vigilados)\n", netCfg.iface)
	}
	// El sniff HTTP (AF_PACKET) es independiente de XDP: funciona también en lo.
	startSniff(netColl)
	// Hooks LSM (colección aislada): cierran los puntos ciegos de
	// sys_enter_connect/openat/sendto ante io_uring (IORING_OP_*); un solo
	// reader con dispatch. Se degrada con gracia si el kernel no los soporta.
	startLSMHooks()

	// Capa 4: entrenamiento de baseline (negative selection).
	if trainSecs > 0 {
		bl.begin(time.Duration(trainSecs) * time.Second)
		log.Printf("baseline: entrenando %ds (negative selection)...", trainSecs)
	}
	startIntegrityWatch()
	startGuardian()
	startAuthLog()
	go scanArgvSpoof(nil)

	rb, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		log.Fatalf("ringbuf: %v", err)
	}
	defer rb.Close()

	fmt.Fprintln(os.Stderr, "motor-go activo: execve/connect/mmap/ptrace/openat vigilados")

	// salida limpia con Ctrl+C
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() { <-sig; os.Exit(0) }()

	for {
		rec, err := rb.Read()
		if err != nil {
			log.Fatalf("ringbuf read: %v", err)
		}
		handle(rec.RawSample)
	}
}
