package main

// lsm.go — hooks LSM que cierran los puntos ciegos de los tracepoints
// sys_enter_* ante io_uring: IORING_OP_CONNECT/OPENAT/SENDMSG no pasan por
// esas syscalls, pero security_socket_connect/file_open/socket_sendmsg corren
// en la ruta común del kernel y los ven por igual.
//
// Un SOLO reader del ringbuf lsm_events con dispatch por campo `type`
// (dos readers sobre un mismo ringbuf compartirían la página de consumidor
// y se perderían eventos entre ellos).
//
// Aislamiento deliberado: si el kernel no expone BTF para un hook, su fallo
// se loggea y el resto del detector (y los otros hooks) sigue intacto.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// startLSMHooks carga lsm.bpf.o, adjunta todos los hooks disponibles y deja
// UN solo reader de lsm_events que reparte por type. Filtro cgroup en-kernel
// para los hooks de alta frecuencia (file_open/sendmsg disparan para todo el
// host); Go lo llena con el mismo escaneo de contenedores que probe.bpf.o.
func startLSMHooks() {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(lsmO))
	if err != nil {
		log.Printf("lsm: no disponible (load spec: %v); sigue el resto del detector", err)
		return
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Printf("lsm: no disponible (new collection: %v); sigue el resto del detector", err)
		return
	}

	// Filtro cgroup en-kernel ANTES de adjuntar (file_open/sendmsg son hot).
	allowed := coll.Maps["lsm_allowed_cgroups"]
	cfg := coll.Maps["lsm_filter_cfg"]
	if allowed != nil && cfg != nil && subjectCgroup != "" {
		ino, ok := resolveCgroupInode(subjectCgroup)
		if !ok {
			log.Fatalf("subject-cgroup: no se pudo resolver /sys/fs/cgroup/%s", subjectCgroup)
		}
		var one uint8 = 1
		_ = allowed.Put(ino, one)
		var k uint32 = 0
		var f uint32 = 1
		_ = cfg.Put(k, f)
		log.Printf("lsm: filtro cgroup activo (sujeto inode %d)", ino)
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
	} else if allowed != nil && cfg != nil && onlyDocker {
		n := scanDockerCgroups(allowed)
		var k uint32 = 0
		var one uint32 = 1
		_ = cfg.Put(k, one)
		log.Printf("lsm: filtro cgroup activo (%d contenedores)", n)
		go func() {
			for {
				time.Sleep(5 * time.Second)
				scanDockerCgroups(allowed)
			}
		}()
	}

	// T1562.001 anti-tampering: registrar el PROPIO pid como protegido —
	// task_kill deniega in-kernel cualquier señal hacia el detector.
	// También el pid del proceso principal (el main puede re-executar).
	if prot := coll.Maps["lsm_protected_pids"]; prot != nil {
		var pk uint32 = uint32(os.Getpid())
		var pv uint8 = 1
		if err := prot.Put(pk, pv); err != nil {
			log.Printf("lsm: aviso: no se pudo registrar pid protegido: %v", err)
		} else {
			log.Printf("lsm: anti-tampering activo (pid %d protegido contra señales)", pk)
		}
	}

	// Egress default-deny: tras el entrenamiento del baseline, poblar el
	// allowlist de IPs y activar la denegación en kernel (bloquea exfil de red).
	if trainSecs > 0 {
		egAllow := coll.Maps["lsm_egress_allow"]
		egCfg := coll.Maps["lsm_egress_cfg"]
		if egAllow != nil && egCfg != nil {
			go func() {
				time.Sleep(time.Duration(trainSecs)*time.Second + 2*time.Second)
				for bl.isTraining() {
					time.Sleep(500 * time.Millisecond)
				}
				refreshEgressAllowed()
				if egressAllowAll {
					log.Printf("egress allow-all ACTIVO (default-deny desactivado: cualquier destino permitido)")
					return
				}
				ips := bl.learnedIPs()
				for ip := range ips {
					var one uint8 = 1
					_ = egAllow.Put(u32ToKey(ip), one)
				}
				extra := egressAllowIPs()
				for _, ip := range extra {
					var one uint8 = 1
					_ = egAllow.Put(u32ToKey(ip), one)
				}
				var k uint32 = 0
				var one uint32 = 1
				_ = egCfg.Put(k, one)
				log.Printf("egress default-deny ACTIVO (%d IPs del baseline + %d extra allowlisteadas)", len(ips), len(extra))
			}()
		}
	}

	hooks := []struct {
		prog   string
		nombre string
	}{
		{"motor_lsm_connect", "socket_connect: connect() e IORING_OP_CONNECT"},
		{"motor_lsm_file_open", "file_open: openat(2) e IORING_OP_OPENAT (d_path)"},
		{"motor_lsm_sendmsg", "socket_sendmsg: sendto/sendmmsg e IORING_OP_SENDMSG (DNS)"},
		{"motor_lsm_chmod", "path_chmod: chmod(2)/fchmodat(2) setuid/setgid (T1222.002)"},
		{"motor_lsm_rename", "path_rename: rename(2) hacia ruta sensible (TOCTOU)"},
		{"motor_lsm_truncate", "path_truncate: truncate(2) de evidencia (T1070)"},
		{"motor_lsm_unlink", "path_unlink: unlink(2)/unlinkat(2) de evidencia (T1070)"},
		{"motor_lsm_uring_cmd", "uring_cmd: passthrough NVMe bajo el VFS (T1005)"},
		{"motor_lsm_file_ioctl", "file_ioctl: passthrough NVMe por ioctl(2) (T1005)"},
		{"motor_lsm_setxattr", "inode_setxattr: file capabilities security.* (T1548)"},
		{"motor_lsm_task_kill", "task_kill: anti-tampering señales al detector (T1562.001)"},
		{"motor_lsm_symlink", "path_symlink: symlink en dir de persistencia (T1037.005)"},
	}
	adjuntos := 0
	var links []link.Link
	for _, h := range hooks {
		prog := coll.Programs[h.prog]
		if prog == nil {
			log.Printf("lsm %s: programa ausente en el objeto; sigue el resto", h.nombre)
			continue
		}
		lk, err := link.AttachLSM(link.LSMOptions{Program: prog})
		if err != nil {
			log.Printf("lsm %s: no disponible (attach: %v); sigue el resto", h.nombre, err)
			continue
		}
		links = append(links, lk)
		adjuntos++
		log.Printf("lsm %s activo", h.nombre)
	}
	if adjuntos == 0 {
		coll.Close()
		return
	}

	rb, err := ringbuf.NewReader(coll.Maps["lsm_events"])
	if err != nil {
		log.Printf("lsm: ringbuf: %v", err)
		for _, lk := range links {
			lk.Close()
		}
		coll.Close()
		return
	}
	go func() {
		defer rb.Close()
		defer func() {
			for _, lk := range links {
				lk.Close()
			}
		}()
		defer coll.Close()
		for {
			rec, err := rb.Read()
			if err != nil {
				return
			}
			handleLSMEvent(rec.RawSample)
		}
	}()
}

// handleLSMEvent: evento unificado 304 bytes.
// type(4) pid(4) comm[16] family(2) port(2) txid(2) pad(2) daddr[16] path[256]
func handleLSMEvent(raw []byte) {
	if len(raw) < 304 {
		return
	}
	le := binary.LittleEndian
	typ := le.Uint32(raw[0:4])
	pid := le.Uint32(raw[4:8])
	comm := cstr(raw[8:24])
	family := le.Uint16(raw[24:26])

	switch typ {
	case 1: // connect (el hook no filtra cgroup en kernel: baja frecuencia;
		// se filtra aquí igual que antes, via /proc/<pid>/cgroup)
		if onlyDocker && (!inDockerCgroup(pid) || inExcludedCgroup(pid)) {
			return
		}
		if subjectCgroup != "" && !inSubjectCgroup(pid) {
			return
		}
		handleLSMConnect(comm, pid, family, le.Uint16(raw[26:28]), raw[32:48], raw[48:304])
	case 2: // file_open
		path := cstr(raw[48:304])
		if path == "" {
			return
		}
		// f_mode viene en raw[26:28] (campo port del evento unificado):
		// FMODE_WRITE=2 distingue apertura en ESCRITURA (persistencia).
		write := le.Uint16(raw[26:28])&2 != 0
		// T1485: escritura a dispositivo de BLOQUE = limpieza de disco. El hook
		// YA DENIEGA in-kernel; aquí se audita quién lo intentó.
		if write && (strings.HasPrefix(path, "/dev/sd") || strings.HasPrefix(path, "/dev/nvme") ||
			strings.HasPrefix(path, "/dev/vd") || strings.HasPrefix(path, "/dev/xvd") ||
			strings.HasPrefix(path, "/dev/hd") || strings.HasPrefix(path, "/dev/mmcblk")) {
			emitProc("DATA_WIPE (T1485)", comm, pid, fmt.Sprintf("path=%s (escritura a disco denegada)", path))
			return
		}
		// D3FEND File Path Level Controls: acceso a MEMORIA del kernel
		// (/dev/mem, /dev/kmem, /dev/port, /proc/kcore) = escape/rootkit.
		// El hook YA DENIEGA in-kernel (lectura incluida); aquí se audita.
		if path == "/dev/mem" || path == "/dev/kmem" || path == "/dev/port" || path == "/proc/kcore" {
			emitProc("KERNEL_MEM_ACCESS (T1611/escape)", comm, pid, fmt.Sprintf("path=%s (acceso a memoria del kernel denegado)", path))
			return
		}
		// O_TRUNC viene en raw[28:30] (txid): truncación de evidencia (T1070).
		// El hook ya DENIEGA in-kernel; emitir la alerta ANTES del dedupe
		// (tp_openat no distingue O_TRUNC y no emitiría nada para /var/log).
		otrunc := le.Uint16(raw[28:30]) != 0
		if write && otrunc && (strings.HasPrefix(path, "/var/log/") || strings.HasSuffix(path, "bash_history")) {
			emitProc("LIMPIEZA_EVIDENCIA (T1070)", comm, pid, fmt.Sprintf("path=%s (truncate denegado)", path))
			return
		}
		if !fopenClaim(pid, path, write) {
			return // tp_openat ya procesó este open exacto
		}
		// D3-SCA: registrar escrituras para la correlación write→exec (dropper).
		if write {
			recordDropperWrite(path)
		}
		// T1486: cifrado/destrucción masiva — un proceso escribe muchos archivos
		// DISTINTOS en poco tiempo (ransomware/wiper). Se evalúa sobre opens
		// únicos (post-dedupe) y solo en ESCRITURA. Los motores de base de datos
		// (postgres/mysqld/...) escriben decenas de archivos de forma legítima
		// (WAL/data/temp) en carga/checkpoint: se excluyen para no matarlos.
		// Los runtimes también compilan bytecode al vuelo: python escribe 20+
		// .pyc temporales (__pycache__/x.pyc.NNN) en segundos cuando el cache
		// está ausente — es compilación normal, no cifrado masivo. Un ransomware
		// real cifra archivos de DATOS (que sí disparan la heurística).
		if write && !dbDaemons[comm] && !isBytecodeCache(path) {
			if n, hit := checkMassWrite(pid, path); hit {
				emitProc("RANSOMWARE (T1486)", comm, pid, fmt.Sprintf("%d archivos distintos escritos en 5s (cifrado/destrucción masiva)", n))
				return
			}
		}
		checkSensitive(comm, pid, path, write)
	case 3: // sendmsg DNS
		qname := dnsName(raw[48:304])
		txid := le.Uint32(raw[28:32]) & 0xFFFF
		if qname == "" {
			return
		}
		if !dnsClaim(pid, qname) {
			return // tp_sendto/tp_sendmmsg ya procesó este envío exacto
		}
		checkDnsRate(comm, pid)
		checkDnsExfil(comm, pid, qname, txid)
	case 14: // UDP sendmsg a puerto no-DNS sin connect (gap #6, T1048)
		dstPort := binary.BigEndian.Uint16(raw[26:28])
		ip := netIP(family, raw[32:48])
		// Destino allowlisteado (egress-allow / baseline / allow-all): tráfico
		// legítimo del lab, no exfil — no emitir ni matar.
		if isEgressAllowed(ip) {
			return
		}
		dest := fmt.Sprintf("%s:%d", ip, dstPort)
		emitProc("EXFIL_UDP_SENDTO_LSM (T1048)", comm, pid, fmt.Sprintf("dst=%s (sendmsg UDP sin connect vía LSM)", dest))
	case 4: // raw socket (ICMP/ICMPv6/UDP/TCP): exfil low-and-slow por contenido
		// El hook ya descartó la cabecera L4 (8B ICMP/UDP, 20B TCP): path = datos.
		data := cstr(raw[48:304])
		// Longitud total del envío (it3.count) en raw[26:28]: canal encubierto
		// por TAMAÑO (el dato va en la longitud, el contenido puede ser natural).
		plen := le.Uint16(raw[26:28])
		if n, ok := checkIcmpLength(pid, plen); ok {
			emitProc("ICMP_LENGTH_COVERT (T1048.003)", comm, pid, fmt.Sprintf("tamaños=%d/60s (dato codificado en longitud de paquete)", n))
			return
		}
		// Canal encubierto por TIMING (T1048.003): el dato va en los INTERVALOS
		// entre paquetes (dos delays distintos = bits), invisible al contenido
		// y al tamaño.
		if checkIcmpTiming(pid) {
			emitProc("ICMP_TIMING_COVERT (T1048.003)", comm, pid, "intervalos bimodales (dato codificado en cadencia)")
			return
		}
		// Ráfaga de raw sockets (≥30 envíos/5s del mismo pid) = escaneo de red /
		// reconocimiento (T1046). Un SYN scan envía cientos de paquetes/segundo
		// con payload vacío (evade contenido/tamaño/timing); un ping normal va a
		// ~1 pps y nunca llega al umbral.
		if checkRawFlood(pid) {
			emitProc("PORT_SCAN (T1046)", comm, pid, "ráfaga de raw sockets (≥30 envíos/5s)")
			return
		}
		if len(data) < 24 {
			return
		}
		checkRawExfil(comm, pid, data)
	case 5: // chmod setuid/setgid (T1222.002/T1548.001) o disable-tool (T1562.004)
		path := cstr(raw[48:304])
		mode := le.Uint16(raw[28:30])
		flag := le.Uint16(raw[26:28]) // port: 1 = disable tool (sin bit x)
		if path == "" {
			return
		}
		if flag == 1 {
			// T1562.004: chmod que quita el bit de ejecución a un binario de
			// sistema. El hook YA DENEGÓ in-kernel (chmod retorna EPERM).
			emitProc("DISABLE_TOOL (T1562.004)", comm, pid, fmt.Sprintf("path=%s mode=%#o (denegado: quitar ejecución a herramienta de defensa)", path, mode))
			return
		}
		if mode&0x800 != 0 || mode&0x400 != 0 { // S_ISUID=04000, S_ISGID=02000
			emitProc("CHMOD_SETUID (T1222.002/T1548.001)", comm, pid, fmt.Sprintf("path=%s mode=%#o", path, mode))
		}
	case 6: // rename (TOCTOU): dir en path, nombre del dentry en daddr
		dir := cstr(raw[48:304])
		name := cstr(raw[32:48])
		if dir == "" || name == "" {
			return
		}
		full := strings.TrimSuffix(dir, "/") + "/" + name
		// Reusa las reglas de ruta sensible con write=true: un rename hacia
		// /etc/sudoers, ld.so.preload, .bashrc, /var/www/*.php... equivale a
		// una ESCRITURA atacante (cierra el bypass de escribir-a-temp+rename).
		checkSensitive(comm, pid, full, true)
	case 7: // truncate de log/historial (T1070): el hook ya DENIEGA in-kernel
		path := cstr(raw[48:304])
		if path == "" {
			return
		}
		emitProc("LIMPIEZA_EVIDENCIA (T1070)", comm, pid, fmt.Sprintf("path=%s (truncate denegado)", path))
	case 8: // unlink de log/historial (T1070) o backup/snapshot (T1490)
		dir := cstr(raw[48:304])
		name := cstr(raw[32:48])
		if dir == "" || name == "" {
			return
		}
		// T1490: borrar backups/snapshots impide la recuperación. El hook YA
		// DENIEGA in-kernel; aquí se clasifica por qué.
		backupName := strings.HasSuffix(name, ".bak") || strings.HasSuffix(name, ".backup") ||
			strings.HasSuffix(name, ".old") || strings.HasSuffix(name, ".orig") ||
			strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".tgz")
		trimDir := strings.TrimSuffix(dir, "/")
		backupDir := strings.HasPrefix(dir, "/var/backups/") || strings.HasPrefix(dir, "/.snapshots/") ||
			strings.HasSuffix(trimDir, "/.snapshots") || strings.HasPrefix(dir, "/backup/") ||
			strings.HasSuffix(trimDir, "/backup")
		if backupName || backupDir {
			emitProc("INHIBITOR_RECUPERACION (T1490)", comm, pid, fmt.Sprintf("path=%s/%s (backup/snapshot borrado denegado)", trimDir, name))
			return
		}
		emitProc("LIMPIEZA_EVIDENCIA (T1070)", comm, pid, fmt.Sprintf("path=%s/%s (unlink denegado)", trimDir, name))
	case 9: // uring_cmd: passthrough NVMe por DEBAJO del VFS (T1005). El hook
		// YA DENIEGA in-kernel (CQE con EPERM); aquí se audita con el comando
		// NVMe que el hook extrajo del SQE128 (path[0]=opcode, path[4]=nsid,
		// path[40..48]=LBA cdw10/11, path[48..52]=NLB cdw12).
		cmdOp := uint32(le.Uint16(raw[26:28])) | uint32(le.Uint16(raw[28:30]))<<16
		if le.Uint16(raw[30:32]) == 1 {
			op := raw[48]
			nsid := le.Uint32(raw[52:56])
			slba := uint64(le.Uint32(raw[88:92])) | uint64(le.Uint32(raw[92:96]))<<32
			nlb := (le.Uint32(raw[96:100]) & 0xFFFF) + 1
			emitProc("URING_CMD_NVME (T1005)", comm, pid, fmt.Sprintf("cmd_op=%#x op=%02x nsid=%d lba=%d nlb=%d (denegado)", cmdOp, op, nsid, slba, nlb))
		} else {
			emitProc("URING_CMD_NVME (T1005)", comm, pid, fmt.Sprintf("cmd_op=%#x (comando no legible; denegado)", cmdOp))
		}
	case 10: // file_ioctl: passthrough NVMe por ioctl(2), por DEBAJO del VFS
		// (T1005). El hook YA DENIEGA in-kernel (ioctl retorna EPERM); aquí se
		// audita con el comando NVMe leído del puntero user (mismo layout que
		// nvme_uring_cmd: opcode 0, nsid 4, cdw10/11 = LBA, cdw12 = NLB).
		cmdIo := uint32(le.Uint16(raw[26:28])) | uint32(le.Uint16(raw[28:30]))<<16
		if le.Uint16(raw[30:32]) == 1 {
			op := raw[48]
			nsid := le.Uint32(raw[52:56])
			slba := uint64(le.Uint32(raw[88:92])) | uint64(le.Uint32(raw[92:96]))<<32
			nlb := (le.Uint32(raw[96:100]) & 0xFFFF) + 1
			emitProc("PASSTHROUGH_NVME (T1005)", comm, pid, fmt.Sprintf("ioctl=%#x op=%02x nsid=%d lba=%d nlb=%d (denegado)", cmdIo, op, nsid, slba, nlb))
		} else {
			emitProc("PASSTHROUGH_NVME (T1005)", comm, pid, fmt.Sprintf("ioctl=%#x (comando no legible; denegado)", cmdIo))
		}
	case 11: // inode_setxattr security.* (T1548): file capabilities. El hook
		// YA DENIEGA in-kernel (setxattr retorna EPERM); aquí se audita. El
		// xattr name va completo en path[256], el archivo objetivo en
		// daddr[16] (el hook no recibe struct path → sin d_path absoluta).
		xattr := cstr(raw[48:304])
		target := cstr(raw[32:48])
		if xattr == "" {
			return
		}
		if xattr == "security.capability" {
			emitProc("FILE_CAPABILITIES (T1548)", comm, pid, fmt.Sprintf("xattr=%s archivo=%s (denegado: cap_setuid al ejecutar sin setuid-bit)", xattr, target))
		} else {
			emitProc("XATTR_SEGURIDAD (T1548)", comm, pid, fmt.Sprintf("xattr=%s archivo=%s (denegado)", xattr, target))
		}
	case 12: // task_kill (T1562.001): intento de señal contra un pid
		// protegido (el propio detector). El hook YA DENEGÓ in-kernel
		// (kill retorna EPERM); aquí se audita quién lo intentó y con qué
		// señal. port=sig, txid=tgid objetivo.
		sig := le.Uint16(raw[26:28])
		target := le.Uint16(raw[28:30])
		emitProc("TAMPERING_KILL (T1562.001)", comm, pid, fmt.Sprintf("señal %d hacia pid protegido %d (denegada)", sig, target))
	case 13: // path_symlink (T1037.005): symlink creado en un directorio de
		// persistencia (init.d/rc*.d/cron.d/sudoers.d/...). El hook YA
		// DENEGÓ in-kernel; aquí se audita. path=directorio destino,
		// daddr=nombre del enlace.
		dir := cstr(raw[48:304])
		link := cstr(raw[32:48])
		emitProc("INIT_SYMLINK (T1037.005)", comm, pid, fmt.Sprintf("dir=%s enlace=%s (denegado: symlink en dir de persistencia)", dir, link))
	}
}

// checkRawExfil: exfil low-and-slow por raw socket (T1048/T1095) — ICMP,
// ICMPv6, UDP y TCP con cabecera a mano. El umbral pps del XDP (8/s) no ve
// 1 paquete/2s; se detecta por CONTENIDO del payload: token codificado + 2
// hits/60s mismo pid. Un ping natural (payload "abcdef...") no dispara:
// vocales ≈ 30%+ o alfanum corto.
var icmpMu sync.Mutex
var icmpHits = map[uint32][]time.Time{}

// checkIcmpLength: exfil por LONGITUD de paquete (T1048.003). Un ping normal
// tiene tamaño constante (1 longitud); codificar datos en la longitud produce
// MUCHAS longitudes distintas. Se dispara con ≥4 tamaños distintos del mismo
// pid en 60s (el contenido puede ser natural y evadir RAW_EXFIL).
var icmpLenMu sync.Mutex
var icmpLens = map[uint32]map[uint16]time.Time{}

func checkIcmpLength(pid uint32, plen uint16) (int, bool) {
	icmpLenMu.Lock()
	defer icmpLenMu.Unlock()
	now := time.Now()
	m, ok := icmpLens[pid]
	if !ok {
		m = map[uint16]time.Time{}
		icmpLens[pid] = m
	}
	for l, t := range m {
		if now.Sub(t) > 60*time.Second {
			delete(m, l)
		}
	}
	m[plen] = now
	return len(m), len(m) >= 4
}

// checkIcmpTiming: exfil por TIMING/cadencia (T1048.003). El dato va en los
// INTERVALOS entre paquetes (dos delays distintos = bits), no en contenido ni
// tamaño. Se detecta bimodalidad: los intervalos se separan en DOS clusters
// compactos con un hueco grande entre ellos. Un ping normal (cadencia fija)
// no dispara; el jitter natural no forma dos clusters limpios.
var timingMu sync.Mutex
var timingPkt = map[uint32][]time.Time{}

func checkIcmpTiming(pid uint32) bool {
	now := time.Now()
	timingMu.Lock()
	defer timingMu.Unlock()
	times := timingPkt[pid]
	times = append(times, now)
	// ventana de 30s: descartar paquetes viejos
	cutoff := now.Add(-30 * time.Second)
	for len(times) > 0 && times[0].Before(cutoff) {
		times = times[1:]
	}
	timingPkt[pid] = times
	if len(times) < 9 {
		return false
	}
	iats := make([]float64, 0, len(times)-1)
	for i := 1; i < len(times); i++ {
		iats = append(iats, times[i].Sub(times[i-1]).Seconds())
	}
	return isBimodal(iats)
}

// isBimodal: ¿los intervalos forman dos clusters compactos separados por un
// hueco claro? (firma de canal por timing). Conservador: hueco ≥150ms, ≥3
// muestras por cluster y dispersión intra-cluster ≤ la mitad del hueco.
func isBimodal(iats []float64) bool {
	n := len(iats)
	if n < 8 {
		return false
	}
	sort.Float64s(iats)
	bestGap, bestIdx := 0.0, -1
	for i := 1; i < n; i++ {
		g := iats[i] - iats[i-1]
		if g > bestGap {
			bestGap = g
			bestIdx = i
		}
	}
	if bestGap < 0.15 || bestIdx <= 0 || bestIdx >= n {
		return false
	}
	lo := iats[:bestIdx]
	hi := iats[bestIdx:]
	if len(lo) < 3 || len(hi) < 3 {
		return false
	}
	loSpread := lo[len(lo)-1] - lo[0]
	hiSpread := hi[len(hi)-1] - hi[0]
	if loSpread > bestGap*0.5 || hiSpread > bestGap*0.5 {
		return false
	}
	return true
}

// checkRawFlood: ráfaga de raw sockets (≥30 envíos/5s del mismo pid) — proxy
// de escaneo de red/reconocimiento (T1046). El payload vacío/constante de un
// SYN scan no dispara las reglas de contenido/tamaño/timing.
var rawFloodMu sync.Mutex
var rawFlood = map[uint32][]time.Time{}

// checkMassWrite: cifrado/destrucción masiva (T1486) — un proceso que ESCRIBE
// muchos archivos DISTINTOS en poco tiempo (≥20/5s) es ransomware o wiper. Se
// cuentan rutas ÚNICAS (escribir 30 veces el mismo archivo no es masivo); un
// cifrador propio no usa openssl/gpg → la regla CIFRADO (fila 43) no lo ve.
// Devuelve (n, debeAlertar): alerta UNA vez por ráfaga (se re-arma al caer <20).
var massWriteMu sync.Mutex
var massWrite = map[uint32]map[string]time.Time{}
var massWarned = map[uint32]bool{}

// isBytecodeCache: python (y otros runtimes) escriben bytecode compilado al
// importar — .pyc finales, .pyc.<pid> temporales o cualquier archivo dentro
// de __pycache__/ — y pueden superar el umbral de masa del T1486 en un solo
// arranque sin que sea cifrado/destrucción.
func isBytecodeCache(p string) bool {
	return strings.Contains(p, "__pycache__/") || strings.HasSuffix(p, ".pyc") ||
		strings.Contains(p, ".pyc.")
}

func checkMassWrite(pid uint32, path string) (int, bool) {
	now := time.Now()
	massWriteMu.Lock()
	defer massWriteMu.Unlock()
	m := massWrite[pid]
	if m == nil {
		m = map[string]time.Time{}
		massWrite[pid] = m
	}
	m[path] = now
	cutoff := now.Add(-5 * time.Second)
	for p, t := range m {
		if t.Before(cutoff) {
			delete(m, p)
		}
	}
	n := len(m)
	if n < 20 {
		massWarned[pid] = false // ráfaga terminó → re-armar la alerta
		return n, false
	}
	if massWarned[pid] {
		return n, false // ya alertado en esta ráfaga
	}
	massWarned[pid] = true
	return n, true
}

// D3-SCA: secuencia "escribir + ejecutar el mismo archivo" (dropper/downloader,
// T1105). Se registra cada ruta ESCRITA (vista del contenedor) y, en el exec, se
// compara el binario resuelto (readlink /proc/<pid>/exe) contra las escrituras
// recientes (<10s). Un binario en /tmp que se escribe y ejecuta en ráfaga no es
// visto por ninguna regla por-path — este patrón temporal sí.
var dropperMu sync.Mutex
var dropperWrites = map[string]time.Time{}

func recordDropperWrite(path string) {
	now := time.Now()
	dropperMu.Lock()
	defer dropperMu.Unlock()
	dropperWrites[path] = now
	cutoff := now.Add(-10 * time.Second)
	for p, t := range dropperWrites {
		if t.Before(cutoff) {
			delete(dropperWrites, p)
		}
	}
}

func checkDropper(pid uint32, comm string) {
	target, _, ok := execBinResolved(pid)
	if !ok || target == "" {
		return
	}
	dropperMu.Lock()
	t, seen := dropperWrites[target]
	dropperMu.Unlock()
	if seen && time.Since(t) < 10*time.Second {
		emitProc("DROPPER (T1105)", comm, pid, fmt.Sprintf("bin=%s (escrito y ejecutado en <10s)", target))
	}
}

func checkRawFlood(pid uint32) bool {
	now := time.Now()
	rawFloodMu.Lock()
	defer rawFloodMu.Unlock()
	t := rawFlood[pid]
	t = append(t, now)
	cutoff := now.Add(-5 * time.Second)
	for len(t) > 0 && t[0].Before(cutoff) {
		t = t[1:]
	}
	rawFlood[pid] = t
	return len(t) >= 30
}

// looksBase32ICMP: token largo (≥24 chars) con vocales ≤20% y solo alfanum.
// Un token base32 aleatorio largo tiene ~15.6% vocales (alfabeto A-Z 2-7);
// el texto natural y el payload "abcdef..." de ping tienen ≥30%. A diferencia
// de looksEncodedLabel (diseñada para strings CORTOS 14-18), no exige ratio
// de únicos: a 48 chars la paradoja del cumpleaños satura ~25/48 ≈ 52%.
func looksBase32ICMP(s string) bool {
	n := len(s)
	if n < 24 {
		return false
	}
	vowels := 0
	for i := 0; i < n; i++ {
		c := s[i]
		switch c {
		case 'a', 'e', 'i', 'o', 'u', 'A', 'E', 'I', 'O', 'U':
			vowels++
		}
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return float64(vowels)/float64(n) <= 0.20
}

func checkRawExfil(comm string, pid uint32, data string) {
	if !looksBase32ICMP(data) {
		return
	}
	icmpMu.Lock()
	now := time.Now()
	ts := icmpHits[pid]
	kept := ts[:0]
	for _, t := range ts {
		if now.Sub(t) < 60*time.Second {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	icmpHits[pid] = kept
	n := len(kept)
	icmpMu.Unlock()
	if n >= 2 {
		emitProc("RAW_EXFIL (T1048/T1095)", comm, pid, fmt.Sprintf("token=%.32q hits=%d/60s", data, n))
	}
}

// isWildcardAddr indica si daddr es una dirección wildcard (0.0.0.0 IPv4 o
// :: IPv6). No es un destino enrutable: un connect ahí es sonda de arranque
// de daemons, nunca exfiltración de datos.
func isWildcardAddr(family uint16, daddr []byte) bool {
	if len(daddr) == 0 {
		return true
	}
	if family == 2 { // AF_INET: solo los 4 primeros bytes importan
		return daddr[0] == 0 && daddr[1] == 0 && daddr[2] == 0 && daddr[3] == 0
	}
	// AF_INET6 u otras familias: wildcard si TODOS los bytes son 0.
	for _, b := range daddr {
		if b != 0 {
			return false
		}
	}
	return true
}

// handleLSMConnect procesa type=1: connect AF_UNIX (.sock → T1611) y
// AF_INET/6 (exfil). daddr y path llegan ya rebanados del evento unificado.
func handleLSMConnect(comm string, pid uint32, family uint16, port uint16, daddr, path []byte) {
	if family == 1 {
		p := cstr(path)
		base := p
		if i := strings.LastIndexByte(p, '/'); i >= 0 {
			base = p[i+1:]
		}
		if base == "docker.sock" || strings.HasSuffix(base, ".sock") {
			emitProc("DOCKER_SOCK (T1611)", comm, pid, fmt.Sprintf("path=%s vía io_uring-safe LSM", p))
		}
		return
	}
	loopback := isLoopbackAddr(family, daddr)
	if loopback {
		return
	}
	dstPort := binary.BigEndian.Uint16([]byte{byte(port), byte(port >> 8)}) // a host order
	// El puerto 53 (DNS) se vigila con reglas dedicadas en el path sendmsg
	// (DNS_EXFIL/TXID_COVERT/entropía/beaconing). Una conexión a :53 es
	// resolución de nombres, no un socket de exfil de datos: EXFIL_CONNECT
	// no debe disparar aquí (FP que mataba nslookup/aria2c/QEMU legítimos).
	if dstPort == 53 {
		return
	}
	ip := netIP(family, daddr)
	// Wildcard (0.0.0.0 IPv4 o :: IPv6) o puerto sin destino real (0): sonda de
	// arranque de daemons (postgres conecta a ::/0.0.0.0:65535 al subir), nunca
	// exfil de datos. Excluir aquí también (además del default-deny in-kernel
	// para IPv4) para no emitir ni responder con kill a infraestructura legítima.
	if isWildcardAddr(family, daddr) || dstPort == 0 {
		return
	}
	dest := fmt.Sprintf("%s:%d", ip, dstPort)
	// Dedupe simétrico con tp_connect (connClaim): la misma conexión solo la
	// procesa una de las dos sondas.
	if !connClaim(pid, dest) {
		return
	}
	// Destino allowlisteado (egress-allow / baseline): tráfico legítimo del
	// lab, no exfil — no emitir ni matar.
	if isEgressAllowed(ip) {
		return
	}
	if apps[comm] {
		emitProc("EXFIL_CONNECT_LSM (io_uring-safe)", comm, pid, fmt.Sprintf("dst=%s", dest))
		return
	}
	if !systemNet[comm] {
		emitProc("EXFIL_CONNECT_GENERAL_LSM (io_uring-safe)", comm, pid, fmt.Sprintf("dst=%s", dest))
	}
}

// connSeen deduplica el hook LSM connect contra tp_connect: la misma
// conexión dispara ambos (ringbufs distintos, race de goroutines). claim =
// check-and-set ATÓMICO: exactamente una de las dos sondas la procesa.
var connMu sync.Mutex
var connSeen = map[string]time.Time{}

func connClaim(pid uint32, dest string) bool {
	connMu.Lock()
	defer connMu.Unlock()
	now := time.Now()
	key := fmt.Sprintf("%d|%s", pid, dest)
	if t, ok := connSeen[key]; ok && now.Sub(t) < 2*time.Second {
		return false // ya procesada por la otra sonda
	}
	if len(connSeen) >= 8192 {
		cutoff := now.Add(-2 * time.Second)
		for k, t := range connSeen {
			if t.Before(cutoff) {
				delete(connSeen, k)
			}
		}
		if len(connSeen) >= 8192 {
			connSeen = map[string]time.Time{}
		}
	}
	connSeen[key] = now
	return true
}

// lsmDnsSeen deduplica sendmsg LSM contra tp_sendto/tp_sendmmsg: la misma
// consulta DNS dispara el tracepoint Y el hook LSM (ringbufs distintos, race
// de goroutines). claim = check-and-set ATÓMICO: exactamente uno de los dos
// procesa cada envío.
var lsmDnsMu sync.Mutex
var lsmDnsSeen = map[string]time.Time{}

func dnsClaim(pid uint32, qname string) bool {
	lsmDnsMu.Lock()
	defer lsmDnsMu.Unlock()
	now := time.Now()
	key := fmt.Sprintf("%d|%s", pid, qname)
	if t, ok := lsmDnsSeen[key]; ok && now.Sub(t) < 2*time.Second {
		return false // ya procesado por la otra sonda
	}
	if len(lsmDnsSeen) >= 8192 {
		cutoff := now.Add(-2 * time.Second)
		for k, t := range lsmDnsSeen {
			if t.Before(cutoff) {
				delete(lsmDnsSeen, k)
			}
		}
		if len(lsmDnsSeen) >= 8192 {
			lsmDnsSeen = map[string]time.Time{}
		}
	}
	lsmDnsSeen[key] = now
	return true
}

// fopenSeen registra el último instante en que una sonda (tp_openat o el hook
// LSM file_open) procesó un open del mismo pid+archivo. claim = check-and-set
// ATÓMICO: exactamente una de las dos sondas procesa cada open.
var fopenMu sync.Mutex
var fopenSeen = map[string]time.Time{}

func fopenClaim(pid uint32, fname string, write bool) bool {
	fopenMu.Lock()
	defer fopenMu.Unlock()
	now := time.Now()
	// write en la clave: un open en LECTURA (p.ej. bash leyendo /etc/passwd
	// vía NSS al arrancar) no debe deduplicar el open en ESCRITURA del mismo
	// path hecho 1s después (append atacante).
	w := 0
	if write {
		w = 1
	}
	key := fmt.Sprintf("%d|%s|%d", pid, fname, w)
	if t, ok := fopenSeen[key]; ok && now.Sub(t) < 2*time.Second {
		return false // ya procesado por la otra sonda
	}
	if len(fopenSeen) >= 8192 {
		cutoff := now.Add(-2 * time.Second)
		for k, t := range fopenSeen {
			if t.Before(cutoff) {
				delete(fopenSeen, k)
			}
		}
		if len(fopenSeen) >= 8192 { // sigue lleno (tormenta): reset defensivo
			fopenSeen = map[string]time.Time{}
		}
	}
	fopenSeen[key] = now
	return true
}
