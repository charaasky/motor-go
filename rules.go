package main

// Reglas de comportamiento adicionales — equivalen a las reglas Falco que
// motor-go aún no cubría: ofuscación (base64), limpieza de evidencia
// (shred/truncate/rm), discovery, archive y cifrado. Devuelve true si emitió.

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// reLongSleep: sleep >= 120s o time.sleep(>=120) = evasión por tiempo (T1497.003).
var reLongSleep = regexp.MustCompile(`(?i)(sleep\s+1[2-9][0-9]|sleep\s+[2-9][0-9]{2,}|time\.sleep\(\s*(1[2-9][0-9]|[2-9][0-9]{2,}))`)

// procCmdlineStr lee /proc/PID/cmdline como texto (NUL → espacio).
func procCmdlineStr(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	return strings.ReplaceAll(string(data), "\x00", " ")
}

// cmdlineOr: cmdline de /proc; si el proceso ya murió (race post-mortem, gap
// #9 — el reader laggea por el hasheo de verifyExecBinary y los procesos
// efímeros desaparecen antes del procesamiento), usa el argv que el tracepoint
// copió dentro del propio evento exec (ventana right-aligned, ver main.go).
func cmdlineOr(pid uint32, evCmdline string) string {
	if cl := procCmdlineStr(pid); cl != "" {
		return cl
	}
	return evCmdline
}

func checkBehavior(pcomm, comm string, pid uint32, evCmdline string) bool {
	// app = app origen del proceso (a través de la cadena app→shell→tool), no
	// solo el padre inmediato. Un tool lanzado por el shell de una app sigue
	// atribuyéndose a la app (el RCE típico es php→sh→tool).
	app := appAncestor(pid)
	// shellParent: el proceso fue lanzado por un shell (sh/bash/...). En un
	// contenedor monitoreado (-only-docker, objetivos excluidos), un shell que
	// dispara herramientas de descubrimiento/enumeración ES el patrón del
	// atacante (sh -c "id; cat /etc/passwd"), aunque no descienda de una app web.
	shellParent := shells[pcomm]
	sus := app != "" || shellParent
	// ---- Brechas cerradas: reconocimiento, credenciales, evasión, exfil ----
	// Van ANTES del switch para no "tragar" las reglas existentes: cada una
	// devuelve true SOLO cuando coincide su patrón exacto.
	switch comm {
	case "nmap", "masscan", "zmap", "nikto", "nuclei", "gobuster", "dirb", "ffuf",
		"wfuzz", "sqlmap", "enum4linux", "nbtscan", "dnsrecon", "dnsenum", "fierce",
		"snmpwalk", "onesixtyone", "smbclient", "massdns":
		emitProc("SCANNING_TOOL (T1595/T1018/T1590)", comm, pid, fmt.Sprintf("comm=%s (reconocimiento activo)", comm))
		return true
	case "telnet":
		emitProc("BANNER_GRAB (T1595.002)", comm, pid, "telnet (banner grabbing)")
		return true
	case "hydra", "medusa", "ncrack", "patator", "crackmapexec":
		emitProc("BRUTE_FORCE (T1110.001)", comm, pid, fmt.Sprintf("comm=%s (fuerza bruta online)", comm))
		return true
	// T1110.002 (offline cracking): john/hashcat descifran hashes YA ROBADOS
	// (shadow, DB) en local — sin tocar el servicio real. Distinto de la fuerza
	// bruta online (T1110.001): aquí el ataque es post-exfiltración y la señal
	// es la herramienta de cracking corriendo en un contenedor, donde nunca es
	// legítima (no hay offset de FP: ningún servicio corre crackers).
	case "john", "hashcat":
		emitProc("CRACK_OFFLINE (T1110.002)", comm, pid, fmt.Sprintf("comm=%s (cracking offline de hashes)", comm))
		return true
	case "aa-disable", "aa-teardown", "apparmor_parser", "setenforce":
		emitProc("DISABLE_MAC (T1562.006)", comm, pid, fmt.Sprintf("comm=%s (deshabilitar MAC)", comm))
		return true
	case "systemd-detect-virt", "dmidecode":
		emitProc("SANDBOX_EVASION (T1497.001)", comm, pid, fmt.Sprintf("comm=%s (detección de VM/sandbox)", comm))
		return true
	case "split":
		emitProc("EXFIL_CHUNKED (T1030)", comm, pid, "split (troceado de datos)")
		return true
	}
	if sus {
		cl := cmdlineOr(pid, evCmdline)
		low := strings.ToLower(cl)
		// T1567.004: exfiltración por webhook (Discord/Slack/Telegram/webhook.site).
		if (comm == "curl" || comm == "wget" || comm == "python3" || comm == "python") &&
			(strings.Contains(low, "hooks.slack.com") || strings.Contains(low, "discord.com/api/webhooks") ||
				strings.Contains(low, "api.telegram.org") || strings.Contains(low, "webhook.site") ||
				strings.Contains(low, "/api/webhooks/")) {
			emitProc("EXFIL_WEBHOOK (T1567.004)", app, pid, fmt.Sprintf("webhook: %s", cl))
			return true
		}
		// T1567.003: exfiltración a servicios de paste (pastebin y similares) —
		// canal legítimo de salida que la regla de webhook no cubre.
		if (comm == "curl" || comm == "wget" || comm == "python3" || comm == "python" || comm == "git") &&
			(strings.Contains(low, "pastebin.com") || strings.Contains(low, "transfer.sh") ||
				strings.Contains(low, "0x0.st") || strings.Contains(low, "catbox.moe") ||
				strings.Contains(low, "paste.ee") || strings.Contains(low, "ghostbin.com")) {
			emitProc("EXFIL_PASTEBIN (T1567.003)", app, pid, fmt.Sprintf("paste: %s", cl))
			return true
		}
		// T1567.001: exfiltración a repositorio de código — git push envía datos
		// a un remoto por HTTPS/SSH (canal corporativo legítimo).
		if comm == "git" && (strings.Contains(low, "push") || strings.Contains(low, "remote add")) {
			emitProc("EXFIL_GIT (T1567.001)", app, pid, fmt.Sprintf("git: %s", cl))
			return true
		}
		// T1518: enumeración de software instalado.
		if (comm == "dpkg" || comm == "rpm" || comm == "apk" || comm == "npm") &&
			(strings.Contains(cl, "-l") || strings.Contains(cl, "-qa") || strings.Contains(cl, "info") ||
				strings.Contains(cl, "list") || strings.Contains(cl, "ls")) {
			emitProc("SOFTWARE_DISCOVERY (T1518)", app, pid, fmt.Sprintf("comm=%s (enumeración de software)", comm))
			return true
		}
		// T1195.002: supply chain — instalar paquete desde un índice no oficial.
		if comm == "pip" && (strings.Contains(cl, "--index-url") || strings.Contains(cl, "--extra-index-url")) {
			emitProc("SUPPLY_CHAIN (T1195.002)", app, pid, fmt.Sprintf("índice de paquetes no oficial: %s", cl))
			return true
		}
		// T1114.001 / T1213: recolección de email / repos / db vía find.
		if comm == "find" {
			if strings.Contains(cl, "/var/mail") || strings.Contains(cl, "mbox") || strings.Contains(cl, ".eml") {
				emitProc("EMAIL_COLLECTION (T1114.001)", app, pid, fmt.Sprintf("búsqueda de buzones: %s", cl))
				return true
			}
			if strings.Contains(cl, ".git") || strings.Contains(cl, ".svn") ||
				strings.Contains(cl, "*.sqlite") || strings.Contains(cl, "*.db") {
				emitProc("REPO_DB_DATA (T1213)", app, pid, fmt.Sprintf("búsqueda de repos/db: %s", cl))
				return true
			}
		}
		// T1036.002: nombre con Right-to-Left Override (U+202E).
		if strings.ContainsRune(cl, 0x202E) && (comm == "sh" || comm == "bash" || comm == "python3" || comm == "python") {
			emitProc("RLO_NAME (T1036.002)", app, pid, "carácter RLO (U+202E)")
			return true
		}
		// T1497.003: sleep largo (evasión por tiempo de sandbox).
		if reLongSleep.MatchString(cl) && (comm == "sh" || comm == "bash" || comm == "python3" || comm == "python") {
			emitProc("SANDBOX_SLEEP (T1497.003)", app, pid, "sleep largo (evasión por tiempo)")
			return true
		}
		// Reglas de shell (sh/bash): inspección de cmdline.
		if comm == "sh" || comm == "bash" {
			if strings.Contains(cl, "unset HISTFILE") || strings.Contains(cl, "set +o history") ||
				strings.Contains(cl, "HISTSIZE=0") || strings.Contains(cl, "HISTFILESIZE=0") {
				emitProc("HISTORY_DISABLE (T1690)", app, pid, "historial de comandos deshabilitado")
				return true
			}
			if strings.Contains(cl, "> /tmp/.") || strings.Contains(cl, ">/tmp/.") || strings.Contains(cl, "> /var/tmp/.") {
				emitProc("HIDDEN_FILE (T1564.001)", app, pid, fmt.Sprintf("archivo oculto: %s", cl))
				return true
			}
			if strings.Contains(cl, "chmod +x /tmp/") || strings.Contains(cl, "chmod +x /var/tmp/") {
				emitProc("USER_EXEC (T1204.002)", app, pid, fmt.Sprintf("binario preparado en /tmp: %s", cl))
				return true
			}
			if strings.Contains(cl, "sleep") && (strings.Contains(cl, " nc ") || strings.Contains(cl, "curl") || strings.Contains(cl, "wget")) {
				emitProc("SCHEDULED_TRANSFER (T1029)", app, pid, "transferencia retardada (sleep + transfer)")
				return true
			}
			if strings.Contains(cl, "while") && (strings.Contains(cl, "wget") || strings.Contains(cl, "curl")) {
				emitProc("ENDPOINT_DOS (T1499.004)", app, pid, "bucle de peticiones (DoS de endpoint)")
				return true
			}
			if strings.Contains(cl, "export") && (strings.Contains(cl, "API_KEY") || strings.Contains(cl, "PASSWORD=") ||
				strings.Contains(cl, "SECRET=") || strings.Contains(cl, "TOKEN=") || strings.Contains(cl, "AWS_SECRET") ||
				strings.Contains(cl, "API_TOKEN")) {
				emitProc("CRED_ENV (T1552)", app, pid, "secreto en variable de entorno")
				return true
			}
		}
	}
	switch {
	case comm == "base64" && app != "":
		emitProc("OFUSCACION_BASE64 (T1027)", app, pid, fmt.Sprintf("comm=%s", comm))
		return true
	case comm == "shred" || comm == "truncate" || (comm == "rm" && app != ""):
		emitProc("LIMPIEZA_EVIDENCIA (T1070)", app, pid, fmt.Sprintf("comm=%s", comm))
		return true
	case (comm == "find" || comm == "locate" || comm == "grep" || comm == "ps" ||
		comm == "ip" || comm == "ifconfig" || comm == "route" || comm == "netstat" || comm == "arp" || comm == "tcpdump" ||
		comm == "lscpu" || comm == "lsblk" || comm == "dmesg" || comm == "free" || comm == "mount" || comm == "lsb_release" ||
		comm == "uname" || comm == "hostname") && sus:
		emitProc("DISCOVERY (T1016/T1082/T1083/T1057)", app, pid, fmt.Sprintf("comm=%s", comm))
		return true
	// T1087 Account Discovery: enumerar las cuentas/grupos del sistema (id,
	// whoami, w, users, finger, last, logname) revela qué usuarios existen,
	// sus grupos y privilegios — paso previo a escalada o movimiento lateral.
	// Solo desde una app (appAncestor): un shell interactivo del admin no es
	// ataque; el RCE de una app ejecutando id/whoami es reconocimiento.
	case (comm == "id" || comm == "whoami" || comm == "w" || comm == "users" ||
		comm == "finger" || comm == "last" || comm == "logname") && sus:
		emitProc("ACCOUNT_DISCOVERY (T1087/T1033)", app, pid, fmt.Sprintf("comm=%s (enumeración de cuentas)", comm))
		return true
	// T1007 System Service Discovery: enumerar los servicios del sistema
	// (systemctl/rc-status/service/chkconfig...) revela qué corre en el host
	// y qué atacar/desactivar. Mismo espíritu que la regla DISCOVERY pero con
	// su propia técnica: es reconocimiento del SOFTWARE instalado, no de red.
	// Alpine no trae systemctl: el vector real del lab es OpenRC (rc-*).
	case (comm == "systemctl" || comm == "service" || comm == "rc-status" ||
		comm == "rc-update" || comm == "rc-service" || comm == "chkconfig" ||
		comm == "initctl" || comm == "sv") && sus:
		emitProc("SERVICIOS_SISTEMA (T1007)", app, pid, fmt.Sprintf("comm=%s (enumeración de servicios)", comm))
		return true
	case (comm == "tar" || comm == "gzip" || comm == "zip" || comm == "7z") && app != "":
		emitProc("ARCHIVE (T1560)", app, pid, fmt.Sprintf("comm=%s", comm))
		return true
	case (comm == "openssl" || comm == "gpg") && app != "":
		emitProc("CIFRADO (T1573)", app, pid, fmt.Sprintf("comm=%s", comm))
		return true
	case comm == "nc" || comm == "ncat" || comm == "netcat" || comm == "socat":
		emitProc("REVERSE_SHELL (T1059/T1571)", pcomm, pid, fmt.Sprintf("comm=%s", comm))
		return true
	case comm == "useradd" || comm == "adduser" || comm == "usermod":
		// Persistencia (T1136.001): crear/modificar cuentas locales en runtime
		// es una puerta trasera clásica (no es parte del ciclo normal de una app).
		emitProc("CREACION_CUENTA (T1136.001)", comm, pid, fmt.Sprintf("comm=%s ppid=%s", comm, pcomm))
		return true
	case comm == "userdel" || comm == "groupdel":
		// T1531: eliminar cuentas/grupos — borrado de acceso (anti-forense o
		// sabotaje). Espejo de CREACION_CUENTA: no es parte del ciclo normal.
		emitProc("ELIMINACION_CUENTA (T1531)", comm, pid, fmt.Sprintf("comm=%s ppid=%s", comm, pcomm))
		return true
	case (comm == "ssh" || comm == "scp" || comm == "sftp" || comm == "rsync") && app != "":
		// T1572 Protocol Tunneling: ssh con reenvío de puertos (-R remoto, -L
		// local, -D dinámico) tunela protocolos que la inspección de egress no
		// ve. Más específico que el movimiento lateral: se clasifica primero.
		if comm == "ssh" {
			cl := cmdlineOr(pid, evCmdline)
			if strings.Contains(cl, " -R ") || strings.Contains(cl, " -L ") || strings.Contains(cl, " -D ") {
				emitProc("TUNEL_SSH (T1572)", app, pid, fmt.Sprintf("túnel ssh: %s", cl))
				return true
			}
		}
		emitProc("MOVIMIENTO_LATERAL_SSH (T1021.004/T1570/T1078)", app, pid, fmt.Sprintf("comm=%s", comm))
		return true
	// T1689 Downgrade Attack: curl/wget forzando TLS 1.0 o cifrados débiles
	// (@SECLEVEL=0) para esquivar la inspección o abusar de compatibilidad vieja.
	case (comm == "curl" || comm == "wget") && app != "":
		cl := cmdlineOr(pid, evCmdline)
		if strings.Contains(cl, "--tlsv1.0") || strings.Contains(cl, "--tls-max 1.0") ||
			strings.Contains(cl, "@SECLEVEL=0") || strings.Contains(cl, "--ssl-no-revoke") ||
			strings.Contains(cl, "--ciphers") {
			emitProc("DOWNGRADE_TLS (T1689)", app, pid, fmt.Sprintf("cifrado degradado: %s", cl))
			return true
		}
	// T1564.013 Bind Mount: montar un directorio sobre otro para ocultar artefactos.
	case comm == "mount" && app != "":
		cl := cmdlineOr(pid, evCmdline)
		if strings.Contains(cl, "--bind") || strings.Contains(cl, "-o bind") || strings.Contains(cl, " -B ") {
			emitProc("BIND_MOUNT (T1564.013)", app, pid, fmt.Sprintf("mount bind: %s", cl))
			return true
		}
	// T1027.018 Invisible Unicode: ofuscación con caracteres zero-width o chr(0x200b).
	case (comm == "python3" || comm == "python") && app != "":
		cl := cmdlineOr(pid, evCmdline)
		if strings.Contains(cl, "chr(0x200b)") || strings.Contains(cl, "chr(8203)") ||
			strings.Contains(cl, "\\u200b") || strings.ContainsRune(cl, 0x200b) {
			emitProc("OFUSCACION_UNICODE (T1027.018)", app, pid, "unicode invisible en cmdline")
			return true
		}
	// HTTP request smuggling artesanal: python abriendo socket con TE chunked a mano.
	case (comm == "python3" || comm == "python") && app != "":
		cl := cmdlineOr(pid, evCmdline)
		if strings.Contains(strings.ToLower(cl), "transfer-encoding: chunked") {
			emitProc("CRLF_DESYNC (request smuggling)", app, pid, "request smuggling en cmdline")
			return true
		}
	// ---- Reglas de herramientas de ataque sin dependencia de app ----
	// T1548.001: escalada vía capabilities — setcap/setfattr otorgan
	// capabilities a un binario; getcap -r las enumera para abusar.
	case comm == "setcap":
		emitProc("FILE_CAPS (T1548.001)", comm, pid, "capabilities otorgadas (setcap)")
		return true
	case comm == "setfattr":
		emitProc("XATTR_CAPS (T1548.001)", comm, pid, "xattr security.capability plantada (setfattr)")
		return true
	case comm == "getcap":
		emitProc("CAPABILITY_ABUSE (T1548.001)", comm, pid, "enumeración de capabilities (getcap -r)")
		return true
	// T1548.003: sudo -l enumera los permisos sudo del usuario (escalada).
	case comm == "sudo":
		cl := cmdlineOr(pid, evCmdline)
		if strings.Contains(cl, "-l") || strings.Contains(cl, "--list") {
			emitProc("SUDO_ABUSE (T1548.003)", comm, pid, "sudo -l (enumeración de sudoers)")
			return true
		}
	// T1531: usermod -L bloquea cuentas (sabotaje/DoS de acceso). Antes del
	// caso CREACION_CUENTA para no clasificarlo como creación.
	case comm == "usermod":
		cl := cmdlineOr(pid, evCmdline)
		if strings.Contains(cl, "-L") || strings.Contains(cl, "--lock") {
			emitProc("ACCOUNT_LOCKOUT (T1531)", comm, pid, "usermod -L (bloqueo de cuenta)")
			return true
		}
	// T1053.002: at — ejecución programada puntual (at now).
	case comm == "at":
		emitProc("EJECUCION_AT (T1053.002)", comm, pid, "trabajo at programado")
		return true
	// T1569.002: systemd-run — unidad de servicio efímera (evade alta de servicio).
	case comm == "systemd-run":
		emitProc("EJECUCION_SYSTEMD_RUN (T1569.002)", comm, pid, "unidad systemd efímera")
		return true
	// T1489: detener servicios — pkill/killall terminan procesos de servicio.
	case comm == "pkill" || comm == "killall":
		emitProc("SERVICE_STOP (T1489)", comm, pid, fmt.Sprintf("comm=%s (terminación de servicios)", comm))
		return true
	// T1113: captura de pantalla — herramientas de screenshot (scrot/import/xwd).
	case comm == "scrot" || comm == "import" || comm == "xwd" || comm == "gnome-screenshot":
		emitProc("SCREEN_CAPTURE (T1113)", comm, pid, fmt.Sprintf("comm=%s (captura de pantalla)", comm))
		return true
	// T1115: portapapeles — herramientas de clipboard (xclip/xsel/wl-paste).
	case comm == "xclip" || comm == "xsel" || comm == "wl-paste":
		emitProc("CLIPBOARD_CAPTURE (T1115)", comm, pid, fmt.Sprintf("comm=%s (lectura de portapapeles)", comm))
		return true
	// T1123: captura de audio — herramientas de grabación (arecord/ffmpeg/sox).
	case comm == "arecord" || comm == "ffmpeg" || comm == "sox":
		emitProc("AUDIO_CAPTURE (T1123)", comm, pid, fmt.Sprintf("comm=%s (captura de audio)", comm))
		return true
	// T1059: intérpretes (awk/sed) ejecutando código vía system() — ejecución
	// sin shell directo.
	case (comm == "awk" || comm == "sed") && sus:
		cl := cmdlineOr(pid, evCmdline)
		if strings.Contains(cl, "system(") || strings.Contains(cl, "BEGIN") {
			emitProc("INTERPRETE_EXEC (T1059)", app, pid, fmt.Sprintf("comm=%s (ejecución vía intérprete)", comm))
			return true
		}
	// T1135: showmount — enumeración de comparticiones NFS.
	case comm == "showmount" && sus:
		emitProc("SHARE_DISCOVERY (T1135)", app, pid, "enumeración de comparticiones NFS")
		return true
	// T1496: criptominería — binarios mineros o script que los invoca.
	case comm == "xmrig" || comm == "minerd" || comm == "cgminer" || comm == "cpuminer":
		emitProc("CRYPTO_MINING (T1496)", comm, pid, fmt.Sprintf("comm=%s (minería)", comm))
		return true
	case (comm == "sh" || comm == "bash" || comm == "python3" || comm == "python"):
		cl := cmdlineOr(pid, evCmdline)
		if strings.Contains(cl, "xmrig") || strings.Contains(cl, "minerd") || strings.Contains(cl, "cgminer") {
			emitProc("CRYPTO_MINING (T1496)", comm, pid, "script de minería en cmdline")
			return true
		}
	// ---- Evasión del detector (EDR) en Linux ----
	// T1562.001: desacoplar los programas eBPF del detector (bpftool prog
	// detach/unload), borrar el qdisc/filtro XDP (tc qdisc del), o descargar
	// módulos del kernel (rmmod). Un admin legítimo no hace esto durante la
	// operación normal de un contenedor vigilado.
	case comm == "bpftool":
		cl := cmdlineOr(pid, evCmdline)
		if strings.Contains(cl, "detach") || strings.Contains(cl, "unload") ||
			strings.Contains(cl, "unlink") || strings.Contains(cl, "pin del") {
			emitProc("EDR_TAMPER_EBPF (T1562.001)", comm, pid, fmt.Sprintf("desacople/borrado de programa eBPF: %s", cl))
			return true
		}
	case comm == "rmmod":
		emitProc("EDR_TAMPER_MODULE (T1562.001)", comm, pid, "descarga de módulo del kernel (rmmod)")
		return true
	case comm == "insmod":
		emitProc("ROOTKIT_LOAD (T1014)", comm, pid, "carga de módulo del kernel (insmod)")
		return true
	case comm == "modprobe" && sus:
		cl := cmdlineOr(pid, evCmdline)
		if strings.Contains(cl, ".ko") || strings.Contains(cl, "-f") {
			emitProc("ROOTKIT_LOAD (T1014)", app, pid, fmt.Sprintf("modprobe forzado/módulo propio: %s", cl))
			return true
		}
	case comm == "tc" && sus:
		cl := cmdlineOr(pid, evCmdline)
		if strings.Contains(cl, "qdisc del") || strings.Contains(cl, "filter del") {
			emitProc("EDR_TAMPER_XDP (T1562.001)", app, pid, fmt.Sprintf("borrado de qdisc/filtro XDP: %s", cl))
			return true
		}
	// T1082/T1087: lectura de archivos sensibles de sistema/cuentas desde un
	// shell o app de contenedor (cat/grep/head/tail sobre passwd, group,
	// os-release, /.dockerenv, /proc/cpuinfo, resolv.conf, hosts...).
	case (comm == "cat" || comm == "grep" || comm == "head" || comm == "tail") && sus:
		cl := cmdlineOr(pid, evCmdline)
		for _, p := range []string{
			"/etc/passwd", "/etc/group", "/etc/shadow",
			"/.dockerenv", "/proc/1/cgroup", "/proc/self/cgroup",
			"/etc/os-release", "/etc/alpine-release", "/etc/debian_version",
			"/proc/cpuinfo", "/etc/hosts", "/etc/resolv.conf", "/etc/krb5.conf",
		} {
			if strings.Contains(cl, p) {
				emitProc("DISCOVERY_SENSIBLE (T1082/T1087)", app, pid, fmt.Sprintf("comm=%s path=%s", comm, p))
				return true
			}
		}
	}
	return false
}
