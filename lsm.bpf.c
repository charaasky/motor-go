// SPDX-License-Identifier: GPL-2.0
// lsm.bpf.c — hooks LSM que cierran los puntos ciegos de los tracepoints
// sys_enter_* ante io_uring (IORING_OP_CONNECT/OPENAT/SENDMSG no pasan por
// esas syscalls). Cada hook se dispara en la ruta común del kernel:
//   - security_socket_connect: connect(2) e IORING_OP_CONNECT
//   - security_file_open:      openat(2) e IORING_OP_OPENAT/OPENAT2
//   - security_socket_sendmsg: sendto/sendmmsg(2) e IORING_OP_SENDMSG
// Todos emiten al MISMO ringbuf `lsm_events` con un campo `type` al inicio:
// UN solo reader en Go reparte por tipo (dos readers sobre un ringbuf
// compartirían la página de consumidor y se perderían eventos).
// Objeto separado de probe.bpf.o: si el kernel no soporta un hook BTF, el
// fallo de carga/adjunto no debe tirar el resto del detector.
#include "vmlinux.h"

#define SEC(name) __attribute__((section(name), used))
#define __always_inline inline __attribute__((always_inline))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define AF_INET 2
#define AF_INET6 10
#define AF_UNIX 1
#define UNIX_PATH_MAX 108
#define ITER_UBUF 0
#define ITER_IOVEC 1
#define S_ISUID 04000
#define S_ISGID 02000

static void *(*bpf_ringbuf_reserve)(void *map, unsigned long long size, unsigned long long flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, unsigned long long flags) = (void *)132;
static void (*bpf_ringbuf_discard)(void *data, unsigned long long flags) = (void *)133;
static unsigned long long (*bpf_get_current_pid_tgid)(void) = (void *)14;
static unsigned long long (*bpf_get_current_uid_gid)(void) = (void *)15;
static unsigned int (*bpf_get_current_comm)(void *buf, unsigned int size) = (void *)16;
static long (*bpf_probe_read_kernel)(void *dst, unsigned int size, const void *src) = (void *)113;
static long (*bpf_probe_read_kernel_str)(void *dst, unsigned int size, const void *src) = (void *)115;
static long (*bpf_probe_read_user)(void *dst, unsigned int size, const void *src) = (void *)112;
static long (*bpf_probe_read_user_str)(void *dst, unsigned int size, const void *src) = (void *)114;
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static unsigned long long (*bpf_get_current_cgroup_id)(void) = (void *)80;
static long (*bpf_d_path)(void *path, char *buf, unsigned int size) = (void *)147;

// Evento unificado: type(4) pid(4) comm[16] family(2) port(2) txid(2) pad(2)
// daddr[16] path[256] = 304 bytes. path según type: sun_path / camino d_path
// / qname DNS (wire format, igual que tp_sendto).
struct motor_lsm_event {
    unsigned int type; // 1=connect 2=file_open 3=sendmsg_dns 4=raw_socket 5=chmod 6=rename 7=truncate 8=unlink
    unsigned int pid;
    char comm[16];
    unsigned short family;
    unsigned short port; // network byte order
    unsigned short txid; // DNS transaction ID
    unsigned short pad;
    unsigned char daddr[16];
    char path[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} lsm_events SEC(".maps");

// Filtro cgroup en-kernel para los hooks de ALTA frecuencia (file_open y
// sendmsg disparan para TODO el host). Go llena `lsm_allowed_cgroups` con
// los cgroup del lab y activa `lsm_filter_cfg[0]=1` (mismo esquema que
// probe.bpf.o, mapas propios de esta colección).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned long long);
    __type(value, unsigned char);
    __uint(max_entries, 4096);
} lsm_allowed_cgroups SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, unsigned int);
    __type(value, unsigned int);
    __uint(max_entries, 1);
} lsm_filter_cfg SEC(".maps");

// T1562.001 anti-tampering: pids de la DEFENSA (el propio detector y su
// responder). task_kill deniega CUALQUIER señal hacia ellos desde un
// contenedor filtrado — matar al detector (kill -9 desde --pid=host o tras
// un escape) es el primer paso de todo ataque sofisticado. Go lo llena con
// os.Getpid() al arrancar (y lo refresca si se re-ejecuta).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned int);
    __type(value, unsigned char);
    __uint(max_entries, 8);
} lsm_protected_pids SEC(".maps");

// Egress default-deny: allowlist de IPs IPv4 aprendidas durante el
// entrenamiento (baseline). Tras el entrenamiento Go activa lsm_egress_cfg[0]=1
// y socket_connect deniega conexiones IPv4 a destinos no allowlisteados (no
// loopback, no DNS). Bloquea el exfil de red ANTES de que el dato salga
// (medido: attack01 exfiltró el hostname antes del kill async).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned int);   // IPv4 destino en network order (u32 BE)
    __type(value, unsigned char);
    __uint(max_entries, 65536);
} lsm_egress_allow SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, unsigned int);
    __type(value, unsigned int);
    __uint(max_entries, 1);
} lsm_egress_cfg SEC(".maps");

static __always_inline int lsm_should_report(void)
{
    unsigned int k = 0;
    unsigned int *en = bpf_map_lookup_elem(&lsm_filter_cfg, &k);
    if (!en || *en == 0)
        return 1; // filtro desactivado (modo host completo)
    unsigned long long cgid = bpf_get_current_cgroup_id();
    return bpf_map_lookup_elem(&lsm_allowed_cgroups, &cgid) != 0;
}

// lsm_should_block: ¿el proceso actual es del LAB y puede denegársele? Igual
// que lsm_should_report pero devuelve 0 cuando el filtro está DESACTIVADO
// (modo host completo): así los DENY in-kernel nunca rompen el host, solo
// aplican a los contenedores del lab cuando -only-docker está activo.
static __always_inline int lsm_should_block(void)
{
    unsigned int k = 0;
    unsigned int *en = bpf_map_lookup_elem(&lsm_filter_cfg, &k);
    if (!en || *en == 0)
        return 0; // filtro inactivo: NO denegar (no romper procesos del host)
    unsigned long long cgid = bpf_get_current_cgroup_id();
    return bpf_map_lookup_elem(&lsm_allowed_cgroups, &cgid) != 0;
}

// ends_with: ¿el string (NUL-terminated) termina con el sufijo dado?
// Optimizado para el verifier: escanea la longitud por PALABRAS de 8 bytes
// (≤8 iteraciones para paths ≤64) y compara el sufijo también por palabras.
// El bucle unroll de 128 por byte hacía explotar el límite de 1M insns al
// inlinearse en cada llamada (motor_lsm_rename superó "program too large").
static __always_inline int str_len8(const char *s, int max)
{
    // Escanea el buffer LOCAL (stack del programa) por palabras de 8 bytes:
    // acceso directo válido (es memoria propia, NO ajena — probe_read aquí
    // rebota en el verifier). La primera palabra con un byte 0 delimita el
    // final; comparación por bytes solo dentro del chunk final (≤8).
    #pragma unroll
    for (int w = 0; w < max / 8 + 1; w++) {
        unsigned long long v = *(const unsigned long long *)(s + w * 8);
        #pragma unroll
        for (int b = 0; b < 8; b++) {
            if (((const unsigned char *)&v)[b] == 0)
                return w * 8 + b;
        }
    }
    return max;
}

static __always_inline int ends_with(const char *s, const char *suffix, int slen)
{
    // max=128: las rutas SENSIBLES son todas <40 chars — un escaneo acotado a
    // 128 reduce a la mitad los jumps del verifier (cada str_len8 de 248 eran
    // ~256 jumps; el file_open inlineando a||b||c||d cruzó el límite de 8192
    // jumps del verifier). Un path >128 chars no matchea sufijos sensibles —
    // correcto, ninguna ruta sensible es tan larga.
    int len = str_len8(s, 128);
    if (len < slen)
        return 0;
    #pragma unroll
    for (int i = 0; i < 20; i++) {
        if (i >= slen)
            break;
        if (s[len - slen + i] != suffix[i])
            return 0;
    }
    return 1;
}

// ends_with16: ends_with sobre buffer corto (≤16B, NUL garantizado por
// bpf_probe_read_kernel_str). Escaneo por BYTES: 16 iteraciones ≈ 16 insns
// — el truco de palabras de str_len8 aquí no vale la pena y su lectura de
// palabra extra (+1) rebasa daddr[16] y revienta el verifier.
static __always_inline int ends_with16(const char *s, const char *suffix, int slen)
{
    int len = 0;
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        if (s[i] == 0) {
            len = i;
            break;
        }
    }
    if (len < slen)
        return 0;
    #pragma unroll
    for (int i = 0; i < 15; i++) {
        if (i >= slen)
            break;
        if (s[len - slen + i] != suffix[i])
            return 0;
    }
    return 1;
}

// starts_with: ¿s empieza con el prefijo (NUL-terminated, ≤39 chars)?
// El fallthrough retorna 0: un prefijo más largo que el ciclo nunca se
// verificó completo — un match parcial NO cuenta (bug latente del límite
// anterior: prefijos >24 salían del ciclo y retornaban 1).
static __always_inline int starts_with(const char *s, const char *prefix)
{
    #pragma unroll
    for (int i = 0; i < 40; i++) {
        if (prefix[i] == 0)
            return 1;
        if (s[i] == 0 || s[i] != prefix[i])
            return 0;
    }
    return 0;
}

// path_equals: ¿s es EXACTAMENTE str (siguiente byte NUL)? Escaneo acotado a
// slen (≤40) SIN str_len8: MUCHO más barato para el verifier que ends_with
// (que escanea 248B de memoria ringbuf desconocida). Para el rename, e->path
// es el DIRECTORIO sin slash final → el match de dir exacto ES igualdad.
static __always_inline int path_equals(const char *s, const char *str, int slen)
{
    #pragma unroll
    for (int i = 0; i < 40; i++) {
        if (i >= slen)
            return s[slen] == 0;
        if (s[i] != str[i])
            return 0;
    }
    return 0;
}

// sensitive_write_path: ¿escribir/renombrar a esta ruta establece
// persistencia, una cuenta o una webshell? Mismo criterio que checkSensitive
// (Go) para negar IN-KERNEL: la respuesta async (SIGKILL) llega TARDE y el
// write/rename ya se completó. Negar en kernel elimina la raza.
// NOINLINE (subprograma global): inlineado en file_open Y rename duplicaba
// todo el árbol de prefijos en cada uno — motor_lsm_rename superó el límite
// de 1M insns del verifier. Como subprograma se carga UNA vez. clang inlinea
// funciones static por heurística → atributo noinline EXPLÍCITO obligatorio.
// Partido en DOS subprogramas (sensitive_write_path_{a,b}): una sola función
// con ~35 condiciones hizo saltar "Branch target out of insn range" del
// BACKEND de clang (salto condicional BPF de 16 bits, ±16KB) — no era el
// verifier. Cada mitad debe mantenerse por debajo del rango de salto.
static __attribute__((noinline)) int sensitive_write_path_a(const char *p)
{
    if (ends_with(p, "/etc/passwd", 11) ||
        ends_with(p, "/etc/sudoers", 12) ||
        ends_with(p, "ld.so.preload", 13) ||
        // T1574.006-ext: /etc/environment — env de TODO el sistema, lo lee
        // PAM (pam_env) en cada login: LD_PRELOAD/PATH aquí inyecta en cada
        // proceso futuro. Misma familia que ld.so.preload, otro archivo.
        ends_with(p, "/etc/environment", sizeof("/etc/environment") - 1) ||
        // T1546.005: backdoor SSH — AuthorizedKeysCommand/PermitRootLogin en
        // sshd_config (o su drop-in dir) ejecuta el comando del atacante en
        // cada login SSH y/o abre root remoto. La fila 39 cubría authorized_keys
        // pero no la config del daemon.
        ends_with(p, "/sshd_config", sizeof("/sshd_config") - 1) ||
        starts_with(p, "/etc/ssh/sshd_config.d/") ||
        // T1556: backdoor PAM — escribir /etc/pam.d/ (auth sufficient
        // pam_permit.so) deshabilita la autenticación en TODO login. Un solo
        // starts_with cubre todos los ficheros de PAM.
        starts_with(p, "/etc/pam.d/") ||
        ends_with(p, ".bashrc", 7) ||
        ends_with(p, ".zshrc", 6) ||
        ends_with(p, ".profile", 8) ||
        ends_with(p, ".bash_profile", 13) ||
        ends_with(p, "authorized_keys", 15) ||
        ends_with(p, "/etc/profile", 12) ||
        ends_with(p, "rc.local", 8) ||
        starts_with(p, "/etc/sudoers.d/") ||
        starts_with(p, "/etc/cron") ||
        starts_with(p, "/var/spool/cron") ||
        starts_with(p, "/etc/profile.d/") ||
        starts_with(p, "/etc/init.d/") ||
        starts_with(p, "/etc/ld.so.conf.d/"))
        return 1;
    return 0;
}

static __attribute__((noinline)) int sensitive_write_path_b(const char *p)
{
    if (// T1553.004: trust store de CA del sistema — escribir una CA falsa
        // habilita MITM de TLS (el sistema confiará en certs del atacante).
        starts_with(p, "/etc/ssl/certs/") ||
        starts_with(p, "/usr/local/share/ca-certificates/") ||
        ends_with(p, "ca-certificates.conf", 20) ||
        (starts_with(p, "/var/www/") && ends_with(p, ".php", 4)) ||
        // T1505.003-ext: variantes PHP ejecutables (.phtml/.php5 — el
        // servidor las ejecuta igual que .php) y archivos de configuración
        // de directorio que inyectan código (.user.ini de PHP-FPM con
        // auto_prepend_file, .htaccess de Apache con AddType/maps a php).
        (starts_with(p, "/var/www/") && ends_with(p, ".phtml", 6)) ||
        (starts_with(p, "/var/www/") && ends_with(p, ".php5", 5)) ||
        ends_with(p, "/.user.ini", sizeof("/.user.ini") - 1) ||
        ends_with(p, "/.htaccess", sizeof("/.htaccess") - 1) ||
        // T1543/T1053.006: CUALQUIER unidad systemd (service/timer/socket/path/
        // mount...) — el .timer programa ejecución periódica. Prefijo de DIR
        // (sin sufijo): un contenedor no escribe nada legítimo ahí y un solo
        // starts_with cubre todos los tipos (menos jumps que N ends_with).
        starts_with(p, "/etc/systemd/system/") ||
        // T1611: /proc/sys/kernel/core_pattern es GLOBAL del kernel — escribirlo
        // desde un contenedor privileged cambia el handler de coredumps del
        // HOST (escape: un crash en el host ejecuta el pipe-handler atacante
        // en su contexto). También modprobe y otros sysctls del kernel.
        starts_with(p, "/proc/sys/kernel/") ||
        // T1136.003: plantar credenciales cloud en el home del usuario —
        // escribir ~/.aws/credentials (o .ssh/authorized_keys vía open, ya
        // cubierto por ends_with) da acceso cloud PERSISTENTE al atacante.
        // El directorio .aws/ se crea con mkdir (no cubierto) pero el archivo
        // credentials es el que contiene el secreto — se deniega el write.
        ends_with(p, "/.aws/credentials", 17) ||
        ends_with(p, "/.azure/servicePrincipal.json", 29) ||
        ends_with(p, "/.gcp/credentials.json", 22) ||
        ends_with(p, "/.config/gcloud/credentials", 27) ||
        // T1176: persistencia vía navegador — plantar una extensión (.xpi)
        // o secuestrar prefs.js/Preferences ejecuta código en CADA arranque
        // del navegador. Los sufijos completos valen para cualquier home;
        // prefs.js requiere prefijo .mozilla (nombre genérico). El navegador
        // legítimo corre en el HOST fuera de los cgroups filtrados.
        ends_with(p, ".xpi", 4) ||
        (starts_with(p, "/root/.mozilla/") && ends_with(p, "prefs.js", 8)) ||
        ends_with(p, "/google-chrome/Default/Preferences", 34) ||
        ends_with(p, "/chromium/Default/Preferences", 30) ||
        // T1574.007: PATH planting — /usr/local/bin va ANTES que /usr/bin
        // en el PATH por defecto: un binario malicioso con nombre de comando
        // común (ls, cat, sudo...) se ejecuta en el PRÓXIMO uso del comando.
        // Sin filtro de nombre: cualquier write de binario desde un
        // contenedor de app a /usr/local/bin es anómalo.
        starts_with(p, "/usr/local/bin/"))
        return 1;
    return 0;
}

// T1574.001: hijack de librerías — plantar/reemplazar un .so en un directorio
// de búsqueda del cargador dinámico hace que las apps carguen código del
// atacante al ejecutarse. LD_PRELOAD (fila 14) y /etc/ld.so.preload (fila 30)
// ya cubiertos; el DIRECTORIO de librerías no lo estaba. Subprograma aparte
// para no acercar _b al límite de rango de salto del backend.
static __attribute__((noinline)) int sensitive_write_path_c(const char *p)
{
    if ((starts_with(p, "/usr/lib/") ||
         starts_with(p, "/lib/") ||
         starts_with(p, "/usr/local/lib/")) &&
        (ends_with(p, ".so", 3) || ends_with(p, ".ko", 3)))
        return 1;
    // T1547.007: registro de módulo PKCS#11 (p11-kit) — un .module en estos
    // directorios registra un módulo cripto malicioso que las librerías
    // (NSS/GnuTLS/OpenSSL vía p11-kit) cargan en cada uso: persistencia a
    // nivel de crypto (puede exfiltrar claves en cada firma/descifrado).
    if ((starts_with(p, "/etc/pkcs11/") ||
         starts_with(p, "/usr/share/p11-kit/")) &&
        ends_with(p, ".module", 7))
        return 1;
    // T1055: escribir /proc/<pid>/mem es la primitiva de inyección por
    // archivo (hermana de process_vm_writev): parchea código/datos de un
    // proceso vivo sin ptrace. Solo en /proc/ para no matchear archivos
    // de datos que terminen en /mem.
    if (starts_with(p, "/proc/") && ends_with(p, "/mem", 4))
        return 1;
    // T1529/T1611: /proc/sysrq-trigger ejecuta comandos SysRq del KERNEL —
    // 'b' reinicia el host al instante desde un contenedor privileged. El
    // write de 'h' (help) es inofensivo, pero el path es el mismo: negar
    // SIEMPRE el open en escritura.
    if (ends_with(p, "/sysrq-trigger", sizeof("/sysrq-trigger") - 1))
        return 1;
    // T1557: hijack del resolver — escribir /etc/hosts o /etc/resolv.conf
    // redirige la resolución de TODOS los procesos (banco.com → IP del
    // atacante): MITM silencioso. Docker los escribe al CREAR el contenedor
    // (daemon del host, fuera de los cgroups monitoreados): ningún proceso
    // legítimo de un contenedor los reescribe en runtime.
    if (ends_with(p, "/etc/hosts", 10) ||
        ends_with(p, "/etc/resolv.conf", 16))
        return 1;
    return 0;
}

// T1036.005: masquerading — plantar un binario con nombre de comando de
// sistema (sshd, ls, systemd...) en /usr/bin|/bin|/sbin|/usr/sbin suplanta al
// binario legítimo: la próxima ejecución de ese comando corre el binario del
// atacante. Fila 62 cubrió /usr/local/bin; estos dirs de sistema no lo estaban.
static __attribute__((noinline)) int sensitive_write_path_d(const char *p)
{
    if (starts_with(p, "/usr/bin/") ||
        starts_with(p, "/bin/") ||
        starts_with(p, "/sbin/") ||
        starts_with(p, "/usr/sbin/"))
        return 1;
    return 0;
}

// Wrapper: OR de las mitades — mantenido aparte para que cada subprograma
// quede dentro del rango de salto del backend (ver comentario en _a).
static __attribute__((noinline)) int sensitive_write_path(const char *p)
{
    return sensitive_write_path_a(p) || sensitive_write_path_b(p) ||
           sensitive_write_path_c(p) || sensitive_write_path_d(p);
}

// sensitive_evidence_path: ¿truncar/borrar esta ruta destruye evidencia
// (T1070)? Logs del sistema (/var/log/*) y el historial del shell
// (bash_history). El truncate/unlink de evidencia se DENIEGA in-kernel:
// el audit+kill async llegaría TARDE y el log ya estaría vacío/borrado.
static __always_inline int sensitive_evidence_path(const char *p)
{
    if (starts_with(p, "/var/log/") || ends_with(p, "bash_history", 12))
        return 1;
    return 0;
}

// sensitive_cred_read: ¿leer esta ruta roba credenciales (T1003/T1552)?
// /etc/shadow (hashes), claves SSH privadas y archivos de credenciales cloud.
// La LECTURA se deniega in-kernel: el audit+kill async llegaría TARDE y el
// hash/clave ya se habría leído (medido: attack09 leía /etc/shadow y attack10
// las claves SSH antes de que el kill actuara).
static __always_inline int sensitive_cred_read(const char *p)
{
    if (path_equals(p, "/etc/shadow", sizeof("/etc/shadow") - 1))
        return 1;
    if (starts_with(p, "/root/.ssh/"))
        return 1;
    if (ends_with(p, "/.ssh/id_rsa", sizeof("/.ssh/id_rsa") - 1) ||
        ends_with(p, "/.ssh/id_dsa", sizeof("/.ssh/id_dsa") - 1) ||
        ends_with(p, "/.ssh/id_ecdsa", sizeof("/.ssh/id_ecdsa") - 1) ||
        ends_with(p, "/.ssh/id_ed25519", sizeof("/.ssh/id_ed25519") - 1) ||
        ends_with(p, "/.ssh/authorized_keys", sizeof("/.ssh/authorized_keys") - 1) ||
        ends_with(p, "/.ssh/known_hosts", sizeof("/.ssh/known_hosts") - 1))
        return 1;
    if (ends_with(p, ".aws/credentials", sizeof(".aws/credentials") - 1) ||
        ends_with(p, ".aws/config", sizeof(".aws/config") - 1) ||
        ends_with(p, ".netrc", sizeof(".netrc") - 1) ||
        ends_with(p, ".git-credentials", sizeof(".git-credentials") - 1) ||
        ends_with(p, ".docker/config.json", sizeof(".docker/config.json") - 1) ||
        ends_with(p, ".kube/config", sizeof(".kube/config") - 1) ||
        ends_with(p, ".npmrc", sizeof(".npmrc") - 1) ||
        ends_with(p, ".pypirc", sizeof(".pypirc") - 1) ||
        ends_with(p, ".pgpass", sizeof(".pgpass") - 1) ||
        ends_with(p, ".my.cnf", sizeof(".my.cnf") - 1))
        return 1;
    return 0;
}

// Firma: security_socket_connect(struct socket *sock,
// struct sockaddr *address, int addrlen). Trampolín BTF: args como u64[].
SEC("lsm/socket_connect")
int motor_lsm_connect(unsigned long long *ctx)
{
    struct sockaddr *address = (struct sockaddr *)ctx[1];
    if (!address)
        return 0;

    unsigned short family = 0;
    // address en memoria KERNEL tanto en connect(2) como en io_uring.
    bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family);
    if (family != AF_INET && family != AF_INET6 && family != AF_UNIX)
        return 0;

    struct motor_lsm_event *e = bpf_ringbuf_reserve(&lsm_events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->type = 1;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->family = family;
    if (family == AF_UNIX) {
        // T1611: docker.sock vía io_uring evade tp_connect; el LSM sí lo ve.
        struct sockaddr_un sun;
        __builtin_memset(&sun, 0, sizeof(sun));
        bpf_probe_read_kernel(&sun, sizeof(sun), (void *)address);
        __builtin_memcpy(e->path, sun.sun_path, UNIX_PATH_MAX);
        e->path[UNIX_PATH_MAX - 1] = '\0';
    } else if (family == AF_INET) {
        struct sockaddr_in sin;
        bpf_probe_read_kernel(&sin, sizeof(sin), (void *)address);
        e->port = sin.sin_port;
        __builtin_memcpy(e->daddr, &sin.sin_addr, 4);
    } else {
        struct sockaddr_in6 sin6;
        bpf_probe_read_kernel(&sin6, sizeof(sin6), (void *)address);
        e->port = sin6.sin6_port;
        __builtin_memcpy(e->daddr, &sin6.sin6_addr, 16);
    }
    // T1611: denegar in-kernel la conexión al socket de Docker (escape de
    // contenedor). El audit+kill async llegaría tarde y el socket ya se habría
    // abierto (medido: attack07 conectó a docker.sock sin bloqueo). Solo se
    // deniega a cgroups del LAB (lsm_should_block): nunca rompe el host.
    // NOTA: el path debe leerse ANTES del ringbuf_submit (el verifier invalida
    // el puntero del evento tras el submit).
    if (family == AF_UNIX && lsm_should_block() &&
        (ends_with(e->path, "docker.sock", sizeof("docker.sock") - 1) ||
         ends_with(e->path, "containerd.sock", sizeof("containerd.sock") - 1) ||
         ends_with(e->path, "podman.sock", sizeof("podman.sock") - 1))) {
        bpf_ringbuf_submit(e, 0); // auditar el intento
        return -1; // EPERM: denegar el escape vía socket docker
    }
    // Egress default-deny: tras el entrenamiento (lsm_egress_cfg[0]==1),
    // denegar conexiones IPv4 a destinos no allowlisteados (no loopback, no
    // DNS). Bloquea el exfil de red ANTES de que el dato salga (medido).
    if (family == AF_INET && lsm_should_block()) {
        unsigned int k2 = 0;
        unsigned int *deny = bpf_map_lookup_elem(&lsm_egress_cfg, &k2);
        if (deny && *deny == 1) {
            unsigned char *ip = e->daddr;
            unsigned short dport = e->port;
            if (ip[0] != 127 && dport != 0x3500) { // no loopback, no DNS(53)
                // Wildcard (0.0.0.0): no es un destino enrutable; un connect a
                // INADDR_ANY es sonda de arranque de daemons (postgres, etc.),
                // nunca exfiltración de datos. Excluir del default-deny para no
                // romper infraestructura (FP que mataba postgres-vuln al subir).
                if (!(ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0)) {
                    unsigned int key = 0;
                    __builtin_memcpy(&key, ip, 4);
                    unsigned char *al = bpf_map_lookup_elem(&lsm_egress_allow, &key);
                    if (!al) {
                        bpf_ringbuf_submit(e, 0); // auditar el intento
                        return -1; // EPERM: denegar egress
                    }
                }
            }
        }
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Firma: security_file_open(struct file *file). bpf_d_path resuelve el
// camino absoluto (mounted) del struct path; cubre openat(2) e
// IORING_OP_OPENAT/OPENAT2 por igual (ruta común del VFS).
SEC("lsm/file_open")
int motor_lsm_file_open(unsigned long long *ctx)
{
    if (!lsm_should_report())
        return 0;
    struct file *file = (struct file *)ctx[0];
    if (!file)
        return 0;

    struct motor_lsm_event *e = bpf_ringbuf_reserve(&lsm_events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->type = 2;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    // f_mode en port: distingue LECTURA (FMODE_READ=1) de ESCRITURA
    // (FMODE_WRITE=2) para las reglas de persistencia (bashrc, cron...).
    // f_flags en txid: marca el O_TRUNC REAL (0x200 Y contenido existente,
    // i_size > 0) para detectar la TRUNCACIÓN de evidencia (T1070) — el
    // O_TRUNC de open(2) NO pasa por path_truncate (security_file_truncate es
    // un hook cgroup SIN bpf_d_path); aquí sí. Crear un archivo NUEVO con
    // O_CREAT (i_size=0) no destruye evidencia → no se marca ni se deniega.
    unsigned int fmode = 0, fflags = 0;
    bpf_probe_read_kernel(&fmode, sizeof(fmode), &file->f_mode);
    bpf_probe_read_kernel(&fflags, sizeof(fflags), &file->f_flags);
    e->port = (unsigned short)fmode;
    unsigned long long isz = 0;
    if (fflags & 0x200) {
        struct inode *ino = 0;
        bpf_probe_read_kernel(&ino, sizeof(ino), &file->f_inode);
        if (ino)
            bpf_probe_read_kernel(&isz, sizeof(isz), &ino->i_size);
    }
    unsigned int otrunc = (fflags & 0x200) && isz > 0;
    e->txid = (unsigned short)(otrunc ? 1 : 0);
    // path[159] menos el NUL: d_path cabe en el campo path del evento.
    if (bpf_d_path(&file->f_path, e->path, sizeof(e->path) - 1) < 0) {
        bpf_ringbuf_discard(e, 0); // path no resuelto: se descarta en kernel
        return 0;
    }
    // Bloqueo in-kernel del O_TRUNC de evidencia (logs/historial): la
    // truncación destruiría el rastro antes del kill async.
    if ((fmode & 2) && otrunc && sensitive_evidence_path(e->path)) {
        bpf_ringbuf_submit(e, 0);
        return -1; // EPERM: denegar la truncación (preservar evidencia)
    }
    // Bloqueo in-kernel de escrituras a rutas de persistencia críticas: la
    // respuesta async (SIGKILL) llega tarde y el write ya se completó. Negar
    // el open evita que la persistencia se establezca. Solo ESCRITURA directa
    // (useradd/visudo usan temp+rename → no los rompe; el rename lo ve path_rename).
    if ((fmode & 2) && sensitive_write_path(e->path)) {
        bpf_ringbuf_submit(e, 0); // auditar el intento
        return -1;                 // EPERM: denegar el open
    }
    // T1056.001: captura de entrada — abrir /dev/input/event* (teclado/ratón)
    // o /dev/uinput desde un contenedor es keylogging/inyección. El lector
    // legítimo (libinput) corre en el host, FUERA de los cgroups del lab →
    // el filtro lsm_should_report ya lo excluye. Denegado in-kernel: ni un
    // solo evento de teclado fluye al atacante.
    if (starts_with(e->path, "/dev/input/") || ends_with(e->path, "uinput", 6)) {
        bpf_ringbuf_submit(e, 0); // auditar el intento
        return -1;                 // EPERM: denegar el open
    }
    // T1485: escritura a dispositivo de BLOQUE (dd of=/dev/sda, /dev/nvme0n1,
    // /dev/vd*, /dev/mmcblk*...) = limpieza de disco/destrucción de datos. Solo
    // ESCRITURA; la LECTURA de bloques (dd if=/dev/sda) es exfil de disco y se
    // audita en Go (no se niega aquí para no romper lecturas legítimas de fs).
    if ((fmode & 2) && (starts_with(e->path, "/dev/sd") ||
                        starts_with(e->path, "/dev/nvme") ||
                        starts_with(e->path, "/dev/vd") ||
                        starts_with(e->path, "/dev/xvd") ||
                        starts_with(e->path, "/dev/hd") ||
                        starts_with(e->path, "/dev/mmcblk"))) {
        bpf_ringbuf_submit(e, 0); // auditar el intento
        return -1;                 // EPERM: denegar la escritura al disco
    }
    // D3FEND System Call Filtering → File Path Level Controls: bloquear el
    // acceso a MEMORIA/IO del KERNEL — /dev/mem, /dev/kmem, /dev/port (lectura/
    // escritura directa de memoria física y puertos IO) y /proc/kcore (imagen
    // completa de la memoria del kernel). Primitive de escape/rootkit (familia
    // de las filas 6/7: escape runc): desde un contenedor NUNCA es legítimo.
    // Se deniega CUALQUIER acceso (lectura incluida: la lectura ya es robo de
    // memoria del kernel).
    if (path_equals(e->path, "/dev/mem", sizeof("/dev/mem") - 1) ||
        path_equals(e->path, "/dev/kmem", sizeof("/dev/kmem") - 1) ||
        path_equals(e->path, "/dev/port", sizeof("/dev/port") - 1) ||
        path_equals(e->path, "/proc/kcore", sizeof("/proc/kcore") - 1)) {
        bpf_ringbuf_submit(e, 0); // auditar el intento
        return -1;                 // EPERM: denegar el acceso a memoria del kernel
    }
    // T1003/T1552: LECTURA de credenciales (hash de /etc/shadow, claves SSH,
    // credenciales cloud). Denegar in-kernel ANTES de que el read devuelva
    // datos: el kill async llegaría tarde (medido: attack09 leía /etc/shadow).
    if ((fmode & 1) && sensitive_cred_read(e->path)) {
        bpf_ringbuf_submit(e, 0); // auditar el intento
        return -1;                 // EPERM: denegar la lectura de credenciales
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Firma: security_path_chmod(const struct path *path, umode_t mode). Ruta
// común de notify_change → chmod(2)/fchmodat(2). Interesa SOLO chmod que fija
// setuid/setgid (T1222.002/T1548.001): un binario setuid es escalada de
// privilegio clásica. No hay tracepoint sys_enter_fchmodat en el motor → este
// hook cierra el gap. El path llega como struct path* → bpf_d_path directo.
// T1562.004: también chmod que QUITA el bit de ejecución a un binario de
// sistema (chmod -x sobre herramientas de defensa) — se deniega in-kernel.
SEC("lsm/path_chmod")
int motor_lsm_chmod(unsigned long long *ctx)
{
    if (!lsm_should_report())
        return 0;
    struct path *path = (struct path *)ctx[0];
    unsigned int mode = (unsigned int)ctx[1];
    if (!path)
        return 0;
    int setuid_hit = (mode & (S_ISUID | S_ISGID)) != 0;
    int noexec = (mode & 0111) == 0; // candidato a T1562.004 (sin bit x)
    if (!setuid_hit && !noexec)
        return 0;

    struct motor_lsm_event *e = bpf_ringbuf_reserve(&lsm_events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->type = 5;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->family = 0;
    e->txid = (unsigned short)mode;
    if (bpf_d_path(path, e->path, sizeof(e->path) - 1) < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    // T1562.004: solo binarios de SISTEMA (no un data file cualquiera).
    // Cubre /usr/bin|/bin|/sbin|/usr/sbin (via _d) y /usr/local/bin (fila 62).
    // port=1 marca "disable tool" (el handler Go lo distingue de setuid).
    int disable_tool = noexec && (sensitive_write_path_d(e->path) ||
                                  starts_with(e->path, "/usr/local/bin/"));
    e->port = disable_tool ? 1 : 0;
    bpf_ringbuf_submit(e, 0);
    if (disable_tool)
        return -1; // EPERM: impedir deshabilitar la herramienta de defensa
    return 0;      // setuid/setgid: solo auditar (fila 26)
}

// Firma: security_path_symlink(const struct path *dir, struct dentry *dentry,
// const char *old_name). Cierra T1037.005: crear un SYMLINK en un directorio
// de persistencia (/etc/init.d/, /etc/rc*.d/, /etc/cron.d/...) elude el
// bloqueo write de file_open — la syscall symlink(2) NO abre el target, y
// cuando init resuelve el enlace ejecuta el script atacante. ctx[0] es el
// DIRECTORIO (path* → bpf_d_path directo), ctx[1] el dentry del nuevo enlace.
SEC("lsm/path_symlink")
int motor_lsm_symlink(unsigned long long *ctx)
{
    if (!lsm_should_report())
        return 0;
    struct path *dir = (struct path *)ctx[0];
    struct dentry *dentry = (struct dentry *)ctx[1];
    if (!dir || !dentry)
        return 0;

    struct motor_lsm_event *e = bpf_ringbuf_reserve(&lsm_events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->type = 13;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->family = 0;
    e->port = 0;
    e->txid = 0;
    __builtin_memset(e->daddr, 0, sizeof(e->daddr));

    if (bpf_d_path(dir, e->path, sizeof(e->path) - 1) < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    // Nombre del nuevo enlace (hasta 15 bytes + NUL en daddr).
    const unsigned char *name = 0;
    bpf_probe_read_kernel(&name, sizeof(name), &dentry->d_name.name);
    if (name)
        bpf_probe_read_kernel_str(e->daddr, sizeof(e->daddr), (void *)name);

    // Directorios de persistencia: un symlink aquí establece ejecución en
    // boot/runlevel (T1037.005) o redirige config/datos (mismos árboles que
    // sensitive_write_path pero SOLO los que admiten entradas NUEVAS por
    // nombre — passwd/sudoers existentes no se pueden symlinkear).
    int sym_hit = starts_with(e->path, "/etc/init.d/") ||
                  ends_with(e->path, "/etc/init.d", sizeof("/etc/init.d") - 1) ||
                  starts_with(e->path, "/etc/rc") ||
                  starts_with(e->path, "/etc/cron") ||
                  starts_with(e->path, "/var/spool/cron") ||
                  starts_with(e->path, "/etc/sudoers.d/") ||
                  ends_with(e->path, "/etc/sudoers.d", sizeof("/etc/sudoers.d") - 1) ||
                  starts_with(e->path, "/etc/profile.d/") ||
                  ends_with(e->path, "/etc/profile.d", sizeof("/etc/profile.d") - 1) ||
                  starts_with(e->path, "/etc/ld.so.conf.d/") ||
                  ends_with(e->path, "/etc/ld.so.conf.d", sizeof("/etc/ld.so.conf.d") - 1) ||
                  starts_with(e->path, "/etc/systemd/system/") ||
                  ends_with(e->path, "/systemd/system", sizeof("/systemd/system") - 1) ||
                  starts_with(e->path, "/etc/ssl/certs/") ||
                  ends_with(e->path, "/etc/ssl/certs", sizeof("/etc/ssl/certs") - 1) ||
                  starts_with(e->path, "/usr/local/share/ca-certificates/") ||
                  starts_with(e->path, "/usr/local/bin/") ||
                  ends_with(e->path, "/usr/local/bin", sizeof("/usr/local/bin") - 1) ||
                  starts_with(e->path, "/var/www/");
    bpf_ringbuf_submit(e, 0); // auditar SIEMPRE (Go también reacciona)
    if (sym_hit)
        return -1; // EPERM: denegar la creación del symlink
    return 0;
}

// Firma: security_path_rename(struct path *old_dir, struct dentry *old_dentry,
// struct path *new_dir, struct dentry *new_dentry, unsigned int flags).
// Cierra el TOCTOU de rename: sed -i / "escribir-a-temp + rename" evade las
// reglas write (el temp tiene otro nombre). Aquí se emite el directorio
// destino (d_path) en path y el nombre final del dentry en daddr; Go
// reconstruye dir/nombre y reusa las mismas reglas de rutas sensibles.
SEC("lsm/path_rename")
int motor_lsm_rename(unsigned long long *ctx)
{
    if (!lsm_should_report())
        return 0;
    struct path *new_dir = (struct path *)ctx[2];
    struct dentry *new_dentry = (struct dentry *)ctx[3];
    if (!new_dir || !new_dentry)
        return 0;

    struct motor_lsm_event *e = bpf_ringbuf_reserve(&lsm_events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->type = 6;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->family = 0;
    e->port = 0;
    e->txid = 0;
    __builtin_memset(e->daddr, 0, sizeof(e->daddr));

    if (bpf_d_path(new_dir, e->path, sizeof(e->path) - 1) < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    // Nombre final del dentry (hasta 15 bytes + NUL en daddr): los nombres
    // sensibles (sudoers, ld.so.preload, .bashrc, authorized_keys, *.php,
    // *.service) caben; los más largos se truncan y no matchean en Go.
    const unsigned char *name = 0;
    bpf_probe_read_kernel(&name, sizeof(name), &new_dentry->d_name.name);
    if (name)
        bpf_probe_read_kernel_str(e->daddr, sizeof(e->daddr), (void *)name);
    // Bloqueo IN-KERNEL del rename hacia rutas sensibles (TOCTOU): el
    // audit+kill async llega TARDE y el rename ya se completó. Negar aquí
    // evita que la persistencia se establezca. El árbol de prefijos sobre
    // el buffer LOCAL concatenado (239+15 unroll) disparaba el límite de 1M
    // insns del verifier: aquí se aplica sobre los DOS buffers ya resueltos
    // — dir (ringbuf, d_path con NUL) y name (daddr[16] con NUL de
    // probe_read_kernel_str) — con el MISMO predicado semántico.
    // Sufijos que aplican al NOMBRE final (≈15B): passwd, sudoers, shells...
    // OJO: leer e->daddr/e->path ANTES de bpf_ringbuf_submit — tras el
    // submit el puntero de reserva queda invalidado (verifier: scalar).
    int name_hit = ends_with16(e->daddr, "passwd", 6) ||
                   ends_with16(e->daddr, "sudoers", 7) ||
                   ends_with16(e->daddr, ".bashrc", 7) ||
                   ends_with16(e->daddr, ".zshrc", 6) ||
                   ends_with16(e->daddr, ".profile", 8) ||
                   ends_with16(e->daddr, ".bash_profile", 13) ||
                   ends_with16(e->daddr, "authorized_keys", 15) ||
                   ends_with16(e->daddr, "rc.local", 8) ||
                   ends_with16(e->daddr, ".php", 4) ||
                   ends_with16(e->daddr, ".phtml", 6) ||
                   ends_with16(e->daddr, ".user.ini", 9) ||
                   ends_with16(e->daddr, ".htaccess", 9) ||
                   ends_with16(e->daddr, ".service", 8) ||
                   ends_with16(e->daddr, "ld.so.preload", 13) ||
                   ends_with16(e->daddr, "ld.so.conf", 10) ||
                   ends_with16(e->daddr, "ca-certificates.conf", 20) ||
                   // T1136.003: plantar credenciales cloud (rename a
                   // ~/.aws/credentials etc.) — mismo árbol que file_open.
                   ends_with16(e->daddr, "credentials", 11) ||
                   ends_with16(e->daddr, "servicePrincipal", 16);
    // Sufijos/prefijos que aplican al DIRECTORIO destino (ringbuf).
    // OJO: e->path es el d_path del DIRECTORIO (sin slash final) — los
    // starts_with con slash final solo matchean SUBdirectorios; el dir
    // exacto se chequea con path_equals (IGUALDAD, sin str_len8: barato
    // para el verifier — lección fila 65: los ends_with sobre path completo
    // explotaron el límite de 1M insns).
    int dir_hit = path_equals(e->path, "/etc/profile", sizeof("/etc/profile") - 1) ||
                  starts_with(e->path, "/etc/sudoers.d/") ||
                  path_equals(e->path, "/etc/sudoers.d", sizeof("/etc/sudoers.d") - 1) ||
                  starts_with(e->path, "/etc/cron") ||
                  starts_with(e->path, "/var/spool/cron") ||
                  starts_with(e->path, "/etc/profile.d/") ||
                  path_equals(e->path, "/etc/profile.d", sizeof("/etc/profile.d") - 1) ||
                  starts_with(e->path, "/etc/init.d/") ||
                  path_equals(e->path, "/etc/init.d", sizeof("/etc/init.d") - 1) ||
                  starts_with(e->path, "/etc/ld.so.conf.d/") ||
                  path_equals(e->path, "/etc/ld.so.conf.d", sizeof("/etc/ld.so.conf.d") - 1) ||
                  starts_with(e->path, "/etc/ssl/certs/") ||
                  path_equals(e->path, "/etc/ssl/certs", sizeof("/etc/ssl/certs") - 1) ||
                  starts_with(e->path, "/usr/local/share/ca-certificates/") ||
                  path_equals(e->path, "/usr/local/share/ca-certificates", sizeof("/usr/local/share/ca-certificates") - 1) ||
                  starts_with(e->path, "/etc/systemd/system/") ||
                  path_equals(e->path, "/etc/systemd/system", sizeof("/etc/systemd/system") - 1) ||
                  // T1611: sysctls del kernel (core_pattern, modprobe...)
                  starts_with(e->path, "/proc/sys/kernel/") ||
                  path_equals(e->path, "/proc/sys/kernel", sizeof("/proc/sys/kernel") - 1) ||
                  // T1574.007: PATH planting — rename hacia /usr/local/bin
                  // (dir temprano del PATH, precede a /usr/bin).
                  starts_with(e->path, "/usr/local/bin/") ||
                  path_equals(e->path, "/usr/local/bin", sizeof("/usr/local/bin") - 1) ||
                  // T1036.005: masquerading — rename hacia los dirs de binarios
                  // de sistema (suplantar sshd/ls/systemd...).
                  starts_with(e->path, "/usr/bin/") ||
                  path_equals(e->path, "/usr/bin", sizeof("/usr/bin") - 1) ||
                  starts_with(e->path, "/bin/") ||
                  path_equals(e->path, "/bin", sizeof("/bin") - 1) ||
                  starts_with(e->path, "/sbin/") ||
                  path_equals(e->path, "/sbin", sizeof("/sbin") - 1) ||
                  starts_with(e->path, "/usr/sbin/") ||
                  path_equals(e->path, "/usr/sbin", sizeof("/usr/sbin") - 1);
    // T1136.003: rename hacia credenciales cloud — nombre genérico
    // ("credentials") SOLO cuenta si el DIRECTORIO destino es el directorio
    // cloud del home (sin combinar nombre+dir se denegaría cualquier archivo
    // llamado credentials en cualquier ruta). Los contenedores del lab corren
    // como root → home = /root; path_equals (barato, sin str_len8).
    int cloud_name = ends_with16(e->daddr, "credentials", 11) ||
                     ends_with16(e->daddr, "servicePrincipal", 16);
    int cloud_dir = path_equals(e->path, "/root/.aws", sizeof("/root/.aws") - 1) ||
                    path_equals(e->path, "/root/.azure", sizeof("/root/.azure") - 1) ||
                    path_equals(e->path, "/root/.gcp", sizeof("/root/.gcp") - 1) ||
                    path_equals(e->path, "/root/.config/gcloud", sizeof("/root/.config/gcloud") - 1);
    // T1176: rename hacia .xpi — el sufijo es específico suficiente (nadie
    // renombra legítimamente hacia .xpi desde una app contenerizada).
    int ext_name = ends_with16(e->daddr, ".xpi", 4);
    // T1574.001: rename hacia un .so en un directorio de librerías —
    // reemplazar/plantar una librería (nombre genérico .so, SOLO cuenta en
    // contexto de dir de búsqueda del cargador dinámico). e->path es el DIR
    // sin slash final → starts_with con slash solo matchea subdirs, el dir
    // exacto se cubre con path_equals (lección fila 62).
    int so_name = ends_with16(e->daddr, ".so", 3);
    int so_dir = starts_with(e->path, "/usr/lib/") ||
                 path_equals(e->path, "/usr/lib", sizeof("/usr/lib") - 1) ||
                 starts_with(e->path, "/lib/") ||
                 path_equals(e->path, "/lib", sizeof("/lib") - 1) ||
                 starts_with(e->path, "/usr/local/lib/") ||
                 path_equals(e->path, "/usr/local/lib", sizeof("/usr/local/lib") - 1);
    // T1574.006-ext: rename hacia /etc/environment — nombre "environment" en
    // el dir exacto /etc (nombre genérico, SOLO cuenta en ese contexto).
    int env_name = ends_with16(e->daddr, "environment", 11);
    int env_dir = path_equals(e->path, "/etc", sizeof("/etc") - 1);
    bpf_ringbuf_submit(e, 0); // auditar SIEMPRE (Go también reacciona)
    if (name_hit || dir_hit || (cloud_name && cloud_dir) || ext_name ||
        (so_name && so_dir) || (env_name && env_dir))
        return -1; // EPERM: denegar el rename
    return 0;
}

// Firma: security_path_truncate(const struct path *path). Cubre SOLO el
// truncate(2) path-based (do_truncate sin filp). El ftruncate(2)/O_TRUNC va
// por security_file_truncate (hook cgroup SIN bpf_d_path) — ese caso se cubre
// en file_open marcando O_TRUNC. Truncar logs/historial destruye evidencia
// (T1070): se DENIEGA in-kernel.
SEC("lsm/path_truncate")
int motor_lsm_truncate(unsigned long long *ctx)
{
    if (!lsm_should_report())
        return 0;
    struct path *path = (struct path *)ctx[0];
    if (!path)
        return 0;
    char p[256];
    __builtin_memset(p, 0, sizeof(p));
    if (bpf_d_path(path, p, sizeof(p) - 1) < 0)
        return 0;
    if (!sensitive_evidence_path(p))
        return 0; // truncar un archivo normal es legítimo

    struct motor_lsm_event *e = bpf_ringbuf_reserve(&lsm_events, sizeof(*e), 0);
    if (!e)
        return -1; // sin evento: DENEGAR igual (la evidencia importa)
    e->type = 7;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->family = 0;
    e->port = 0;
    e->txid = 0;
    __builtin_memset(e->daddr, 0, sizeof(e->daddr));
    __builtin_memcpy(e->path, p, sizeof(p) - 1);
    bpf_ringbuf_submit(e, 0);
    return -1; // EPERM: denegar el truncate (preservar la evidencia)
}

// Firma: security_path_unlink(struct path *dir, struct dentry *dentry).
// Ruta común de do_unlinkat → unlink(2)/unlinkat(2) e IORING_OP_UNLINKAT.
// Borrar logs (/var/log/*) o el historial (bash_history) destruye evidencia
// (T1070): se DENIEGA in-kernel. El dir se resuelve con d_path y el nombre
// final con el dentry (mismo patrón que path_rename).
SEC("lsm/path_unlink")
int motor_lsm_unlink(unsigned long long *ctx)
{
    if (!lsm_should_report())
        return 0;
    struct path *dir = (struct path *)ctx[0];
    struct dentry *dentry = (struct dentry *)ctx[1];
    if (!dir || !dentry)
        return 0;
    char d[256];
    __builtin_memset(d, 0, sizeof(d));
    if (bpf_d_path(dir, d, sizeof(d) - 1) < 0)
        return 0;
    char name[16];
    __builtin_memset(name, 0, sizeof(name));
    const unsigned char *nm = 0;
    bpf_probe_read_kernel(&nm, sizeof(nm), &dentry->d_name.name);
    if (nm)
        bpf_probe_read_kernel_str(name, sizeof(name), (void *)nm);
    // T1490: borrar backups/snapshots impide la recuperación (inhibitor).
    // Sufijos de copia de seguridad + directorios de backup/snapshot.
    int backup_name = ends_with16(name, ".bak", 4) ||
                      ends_with16(name, ".backup", 7) ||
                      ends_with16(name, ".old", 4) ||
                      ends_with16(name, ".orig", 5) ||
                      ends_with16(name, ".tar.gz", 7) ||
                      ends_with16(name, ".tgz", 4);
    int backup_dir = starts_with(d, "/var/backups/") ||
                     starts_with(d, "/.snapshots/") ||
                     ends_with(d, "/.snapshots", sizeof("/.snapshots") - 1) ||
                     starts_with(d, "/backup/") ||
                     ends_with(d, "/backup", sizeof("/backup") - 1);
    if (!starts_with(d, "/var/log") && !ends_with(name, "bash_history", 12) &&
        !backup_name && !backup_dir)
        return 0; // borrar un archivo normal es legítimo

    struct motor_lsm_event *e = bpf_ringbuf_reserve(&lsm_events, sizeof(*e), 0);
    if (!e)
        return -1; // sin evento: DENEGAR igual
    e->type = 8;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->family = 0;
    e->port = 0;
    e->txid = 0;
    __builtin_memset(e->daddr, 0, sizeof(e->daddr));
    __builtin_memcpy(e->path, d, sizeof(d) - 1);
    __builtin_memcpy(e->daddr, name, sizeof(name) - 1);
    bpf_ringbuf_submit(e, 0);
    return -1; // EPERM: denegar el unlink (preservar la evidencia)
}
// Firma: security_task_kill(struct task_struct *p, struct kernel_siginfo
// *info, int sig, const struct cred *cred). T1562.001 impair defenses:
// matar al detector (o su responder) apaga TODA la defensa en silencio —
// primer paso del atacante tras conseguir ejecución con --pid=host o tras
// un escape. Se DENIEGA in-kernel toda señal hacia los pids protegidos
// (mapa lsm_protected_pids, llenado por Go con su propio pid). No se puede
// confiar en comm ("px-motor" se clona con exec -a): solo pid del mapa.
SEC("lsm/task_kill")
int motor_lsm_task_kill(unsigned long long *ctx)
{
    // Sin filtro de cgroup: la protección aplica contra CUALQUIER origen
    // (un proceso del host comprometido también podría apuntar al
    // detector). El costo es mínimo: lookup por pid target en cada kill.
    struct task_struct *p = (struct task_struct *)ctx[0];
    if (!p)
        return 0;
    unsigned int tgid = 0;
    bpf_probe_read_kernel(&tgid, sizeof(tgid), &p->tgid);
    if (tgid == 0)
        return 0;
    unsigned char *prot = bpf_map_lookup_elem(&lsm_protected_pids, &tgid);
    if (!prot)
        return 0;

    int sig = (int)ctx[2];
    // SIGURG (23): el runtime de Go lo usa para preemption asíncrona de
    // gorutinas y lo envía a sus propios hilos (mismo tgid que el detector).
    // No es un ataque: se ignora para no auto-flaggearse.
    if (sig == 23)
        return 0;
    // Auto-señal: el detector señalando su propio grupo de hilos tampoco es
    // tampering (cualquier atacante externo tendría un tgid distinto).
    unsigned int self = bpf_get_current_pid_tgid() >> 32;
    if (self == tgid)
        return 0;

    // Allow root (systemd/operator) to signal the detector. In the task_kill hook,
    // "current" is the SENDER; bpf_get_current_uid_gid() returns its real UID in the
    // low 32 bits. systemd (PID 1) and sudo both run with real UID 0, so this allows
    // legitimate shutdown/restart while still blocking unprivileged processes (the
    // escaped agent runs as hcma-firecracker/995, never root).
    unsigned int uid = (unsigned int)(bpf_get_current_uid_gid() & 0xFFFFFFFFu);
    if (uid == 0)
        return 0;

    struct motor_lsm_event *e = bpf_ringbuf_reserve(&lsm_events, sizeof(*e), 0);
    if (!e)
        return -1; // sin evento: DENEGAR igual
    e->type = 12;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->family = 0;
    e->port = (unsigned short)(sig & 0xffff); // señal en port
    e->txid = (unsigned short)(tgid & 0xffff); // target tgid en txid
    __builtin_memset(e->daddr, 0, sizeof(e->daddr));
    __builtin_memset(e->path, 0, sizeof(e->path));
    bpf_ringbuf_submit(e, 0);
    return -1; // EPERM: denegar la señal contra la defensa
}
// Firma: security_inode_setxattr(struct mnt_idmap *idmap, struct dentry
// *dentry, const char *name, const void *value, size_t size, int flags) —
// kernels ≥6.3 (idmap PRIMERO: ctx[0]=idmap, ctx[1]=dentry, ctx[2]=name).
// T1548 file capabilities: escribir security.capability sobre un binario le
// da capabilities (p.ej. cap_setuid) AL EJECUTAR — evasión directa del
// control chmod setuid (fila 26: solo vigilaba path_chmod) y CAP_SETFCAP es
// capability DEFAULT de Docker (no requiere --privileged). También se
// vigilan security.ima/evm (manipulación de integridad). Se DENIEGA
// in-kernel: el audit async llega tras el xattr ya asentado.
SEC("lsm/inode_setxattr")
int motor_lsm_setxattr(unsigned long long *ctx)
{
    if (!lsm_should_report())
        return 0;
    struct dentry *dentry = (struct dentry *)ctx[1];
    const char *xname = (const char *)ctx[2];
    if (!dentry || !xname)
        return 0;

    // Solo xattrs del namespace security.* (capability/ima/evm) — user.*
    // y trusted.* normales pasan.
    char xn[24];
    __builtin_memset(xn, 0, sizeof(xn));
    bpf_probe_read_kernel_str(xn, sizeof(xn), xname);
    if (!starts_with(xn, "security."))
        return 0;

    struct motor_lsm_event *e = bpf_ringbuf_reserve(&lsm_events, sizeof(*e), 0);
    if (!e)
        return -1; // sin evento: DENEGAR igual
    e->type = 11;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->family = 0;
    e->port = 0;
    e->txid = 0;
    __builtin_memset(e->daddr, 0, sizeof(e->daddr));
    // xattr name completo en path[256] ("security.capability" = 19 chars);
    // nombre del archivo objetivo en daddr[16] (el hook no recibe struct
    // path — sin vfsmount no hay d_path; el nombre basta para auditoría).
    bpf_probe_read_kernel_str(e->path, sizeof(e->path), xname);
    const unsigned char *nm = 0;
    bpf_probe_read_kernel(&nm, sizeof(nm), &dentry->d_name.name);
    if (nm)
        bpf_probe_read_kernel_str(e->daddr, sizeof(e->daddr), (void *)nm);
    bpf_ringbuf_submit(e, 0);
    return -1; // EPERM: denegar el setxattr de security.*
}

// Firma: security_socket_sendmsg(struct socket *sock, struct msghdr *msg,
// int size). Ruta común sock_sendmsg: sendto(2)/sendmmsg(2) e
// IORING_OP_SENDMSG. Solo interesa DNS (dport 53) con header de query
// válido (QR=0, opcode=0, QDCOUNT=1): mismo criterio que tp_sendmmsg.
SEC("lsm/socket_sendmsg")
int motor_lsm_sendmsg(unsigned long long *ctx)
{
    if (!lsm_should_report())
        return 0;
    struct socket *sock = (struct socket *)ctx[0];
    struct msghdr *msg = (struct msghdr *)ctx[1];
    if (!msg)
        return 0;

    // Raw socket PRIMERO (CAP_NET_RAW — capability default de Docker): exfil
    // low-and-slow por payload codificado (echo ICMP/ICMPv6 o datagrama
    // UDP/TCP con cabecera a mano), invisible al umbral pps del XDP. Tipo de
    // evento 4: payload con pid/comm. Debe ir antes del filtro dport==53: el
    // sockaddr del raw socket lleva puerto 0 y sk_protocol no es 53.
    {
        struct sock *sk3 = 0;
        if (sock)
            bpf_probe_read_kernel(&sk3, sizeof(sk3), &sock->sk);
        if (sk3) {
            unsigned short skproto = 0, sktype2 = 0;
            bpf_probe_read_kernel(&skproto, sizeof(skproto), &sk3->sk_protocol);
            bpf_probe_read_kernel(&sktype2, sizeof(sktype2), &sk3->sk_type);
            if (sktype2 == 3) { // SOCK_RAW: ICMP(1)/ICMPv6(58)/UDP(17)/TCP(6)...
                int hdroff = 8; // ICMP/ICMPv6/UDP: cabecera L4 de 8B
                if (skproto == 6)
                    hdroff = 20; // TCP: cabecera mínima de 20B
                struct iov_iter it3;
                __builtin_memset(&it3, 0, sizeof(it3));
                bpf_probe_read_kernel(&it3, sizeof(it3), &msg->msg_iter);
                void *base3 = 0;
                if (it3.iter_type == ITER_UBUF) {
                    bpf_probe_read_kernel(&base3, sizeof(base3), &it3.ubuf);
                } else if (it3.iter_type == ITER_IOVEC) {
                    struct iovec *iov3 = 0;
                    bpf_probe_read_kernel(&iov3, sizeof(iov3), &it3.__iov);
                    struct iovec io3;
                    __builtin_memset(&io3, 0, sizeof(io3));
                    if (iov3 && bpf_probe_read_kernel(&io3, sizeof(io3), iov3) == 0)
                        base3 = io3.iov_base;
                    else if (iov3 && bpf_probe_read_user(&io3, sizeof(io3), iov3) == 0)
                        base3 = io3.iov_base;
                }
                if (base3) {
                    struct motor_lsm_event *e4 = bpf_ringbuf_reserve(&lsm_events, sizeof(*e4), 0);
                    if (!e4)
                        return 0;
                    e4->type = 4;
                    e4->pid = bpf_get_current_pid_tgid() >> 32;
                    bpf_get_current_comm(e4->comm, sizeof(e4->comm));
                    e4->family = (skproto == 58) ? AF_INET6 : AF_INET;
                    // Longitud total del envío (it3.count): el canal encubierto
                    // por TAMAÑO de paquete codifica datos en la longitud sin
                    // tocar el contenido (que puede ser natural). Go detecta
                    // varianza anómala de longitudes por pid.
                    e4->port = (unsigned short)(it3.count > 65535 ? 65535 : it3.count);
                    e4->txid = 0;
                    // Datos tras la cabecera L4: read_user_str desde base
                    // truncaría en code/checksum=0x00 (byte 1). La heurística
                    // de contenido va en Go (límites del verifier).
                    if (bpf_probe_read_user_str(e4->path, sizeof(e4->path), (char *)base3 + hdroff) < 0) {
                        bpf_ringbuf_discard(e4, 0);
                        return 0;
                    }
                    bpf_ringbuf_submit(e4, 0);
                }
                return 0;
            }
        }
    }

    // Solo sockets UDP (SOCK_DGRAM=2): el connect TCP ya lo cubre el hook
    // socket_connect, y el send() de un socket TCP conectado (wget/curl sobre
    // TCP) NO es exfil UDP — sin este filtro, un envío TCP disparaba
    // EXFIL_UDP_SENDTO_LSM con dport/daddr del socket conectado (FP medido).
    {
        struct sock *sk0 = 0;
        if (sock)
            bpf_probe_read_kernel(&sk0, sizeof(sk0), &sock->sk);
        if (sk0) {
            unsigned short sktype0 = 0;
            bpf_probe_read_kernel(&sktype0, sizeof(sktype0), &sk0->sk_type);
            if (sktype0 != 2) // no SOCK_DGRAM → no es UDP sendmsg
                return 0;
        }
    }

    // Destino: msg_name (copia kernel del sockaddr) o, si el socket ya está
    // conectado (send sin dest), sk_common del sock.
    unsigned short family = 0;
    unsigned short dport = 0;
    unsigned char daddr[16] = {0};
    void *name = 0;
    bpf_probe_read_kernel(&name, sizeof(name), &msg->msg_name);
    if (name) {
        bpf_probe_read_kernel(&family, sizeof(family), (void *)name);
        if (family != AF_INET)
            return 0;
        struct sockaddr_in sin;
        __builtin_memset(&sin, 0, sizeof(sin));
        bpf_probe_read_kernel(&sin, sizeof(sin), name);
        dport = sin.sin_port;
        __builtin_memcpy(daddr, &sin.sin_addr, 4);
    } else {
        if (!sock)
            return 0;
        struct sock *sk = 0;
        bpf_probe_read_kernel(&sk, sizeof(sk), &sock->sk);
        if (!sk)
            return 0;
        unsigned short skfam = 0;
        bpf_probe_read_kernel(&skfam, sizeof(skfam), &sk->__sk_common.skc_family);
        if (skfam != AF_INET)
            return 0;
        family = skfam;
        bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
        bpf_probe_read_kernel(daddr, 4, &sk->__sk_common.skc_daddr);
    }
    if (dport != 0x3500) { // no-DNS: UDP sendmsg sin connect (gap #6, T1048)
        // Saltar loopback (127/8) y wildcard (0.0.0.0): no son exfil.
        if (daddr[0] == 127)
            return 0;
        if (daddr[0] == 0 && daddr[1] == 0 && daddr[2] == 0 && daddr[3] == 0)
            return 0;
        struct motor_lsm_event *e = bpf_ringbuf_reserve(&lsm_events, sizeof(*e), 0);
        if (!e)
            return 0;
        e->type = 14; // udp_sendmsg_general (no DNS, no loopback)
        e->pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(e->comm, sizeof(e->comm));
        e->family = family;
        e->port = dport;
        __builtin_memcpy(e->daddr, daddr, 16);
        // Egress default-deny (mismo allowlist que connect): tras el
        // entrenamiento denegar UDP a destinos no allowlisteados.
        if (lsm_should_block()) {
            unsigned int k2 = 0;
            unsigned int *deny = bpf_map_lookup_elem(&lsm_egress_cfg, &k2);
            if (deny && *deny == 1) {
                unsigned int key = 0;
                __builtin_memcpy(&key, daddr, 4);
                unsigned char *al = bpf_map_lookup_elem(&lsm_egress_allow, &key);
                if (!al) {
                    bpf_ringbuf_submit(e, 0);
                    return -1; // EPERM: denegar egress UDP
                }
            }
        }
        bpf_ringbuf_submit(e, 0);
        return 0;
    }

    // DNS-over-TCP (RFC 7766/1035): el mensaje va precedido de un prefijo
    // de longitud de 2 bytes → header DNS en base+2. Se distingue por
    // sk_type del socket: SOCK_STREAM=1, SOCK_DGRAM=2.
    int off = 0;
    {
        struct sock *sk2 = 0;
        if (sock)
            bpf_probe_read_kernel(&sk2, sizeof(sk2), &sock->sk);
        if (sk2) {
            unsigned short sktype = 0;
            bpf_probe_read_kernel(&sktype, sizeof(sktype), &sk2->sk_type);
            if (sktype == 1) // SOCK_STREAM
                off = 2;
        }
    }

    // Payload base: msg_iter según iter_type. En la syscall el array iovec
    // vive en memoria USER; io_uring lo copia a memoria KERNEL (io->iovec):
    // se intenta kernel primero y user como fallback. El buffer del paquete
    // es USER en ambos casos.
    struct iov_iter it;
    __builtin_memset(&it, 0, sizeof(it));
    bpf_probe_read_kernel(&it, sizeof(it), &msg->msg_iter);
    void *base = 0;
    if (it.iter_type == ITER_UBUF) {
        bpf_probe_read_kernel(&base, sizeof(base), &it.ubuf);
    } else if (it.iter_type == ITER_IOVEC) {
        struct iovec *iov = 0;
        bpf_probe_read_kernel(&iov, sizeof(iov), &it.__iov);
        struct iovec io;
        __builtin_memset(&io, 0, sizeof(io));
        if (iov && bpf_probe_read_kernel(&io, sizeof(io), iov) == 0) {
            base = io.iov_base;
        } else if (iov && bpf_probe_read_user(&io, sizeof(io), iov) == 0) {
            base = io.iov_base;
        }
    }
    if (!base)
        return 0;

    unsigned char hdr[16];
    __builtin_memset(hdr, 0, sizeof(hdr));
    if (bpf_probe_read_user(hdr, sizeof(hdr), base) < 0) {
        if (bpf_probe_read_kernel(hdr, sizeof(hdr), base) < 0)
            return 0;
    }
    // Header DNS query: QR=0, opcode=0, QDCOUNT=1 (igual que tp_sendmmsg).
    // Con TCP (off=2) el header real empieza tras el prefijo de longitud.
    if ((hdr[2 + off] & 0x80) != 0)
        return 0;
    if ((hdr[2 + off] & 0x78) != 0)
        return 0;
    if (hdr[5 + off] != 1)
        return 0;

    struct motor_lsm_event *e = bpf_ringbuf_reserve(&lsm_events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->type = 3;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->family = family;
    e->port = dport;
    e->txid = (unsigned short)((hdr[0 + off] << 8) | hdr[1 + off]);
    // QNAME wire format en offset 12 (+off con TCP por el prefijo de longitud).
    if (bpf_probe_read_user_str(e->path, sizeof(e->path), (char *)base + 12 + off) < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Firma: security_uring_cmd(struct io_uring_cmd *ioucmd). IORING_OP_URING_CMD
// ejecuta comandos passthrough EMbebidos en el SQE128 directamente contra el
// driver del file: NVME_URING_CMD_IO lee/escribe BLOQUES CRUDOS del disco por
// DEBAJO del VFS — file_open/rename/unlink/truncate NO ven nada tras el open
// del char dev /dev/ng* (T1005: swap, shadow, archivos borrados... todo
// legible por LBA). Se audita y se DENIEGA in-kernel: el CQE vuelve con EPERM
// y el buffer del usuario jamás recibe datos del disco (sin raza de kill).
SEC("lsm/uring_cmd")
int motor_lsm_uring_cmd(unsigned long long *ctx)
{
    if (!lsm_should_report())
        return 0;
    struct io_uring_cmd *ioucmd = (struct io_uring_cmd *)ctx[0];
    if (!ioucmd)
        return 0;

    unsigned int cmd_op = 0;
    bpf_probe_read_kernel(&cmd_op, sizeof(cmd_op), &ioucmd->cmd_op);
    // Solo los 4 comandos passthrough NVMe (NVME_URING_CMD_IO/IO_VEC/ADMIN/
    // ADMIN_VEC = _IOWR('N', 0x80..0x83, 72B)). Cualquier otro uring_cmd del
    // host no nos concierne aún (ruido cero esperado en el lab).
    if (cmd_op != 0xc0484e80 && cmd_op != 0xc0484e81 &&
        cmd_op != 0xc0484e82 && cmd_op != 0xc0484e83)
        return 0;

    struct motor_lsm_event *e = bpf_ringbuf_reserve(&lsm_events, sizeof(*e), 0);
    if (!e)
        return -1; // sin ringbuf igual se deniega: bloqueo antes que auditoría
    e->type = 9;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->family = 0;
    e->port = (unsigned short)(cmd_op & 0xFFFF); // cmd_op partido en 2 campos
    e->txid = (unsigned short)(cmd_op >> 16);
    // Comando NVMe embebido en el SQE128 (offset 64..135 del sqe): el SQE
    // vive en el ring COMPARTIDO con usuario (probe_read_user; el fallback
    // kernel cubre el path deferido con copia en async_data). opcode/nsid y
    // cdw10-12 (LBA inicial y nº de bloques) van en path para el detalle.
    const struct io_uring_sqe *sqep = 0;
    bpf_probe_read_kernel(&sqep, sizeof(sqep), &ioucmd->sqe);
    unsigned char cmdbuf[72];
    __builtin_memset(cmdbuf, 0, sizeof(cmdbuf));
    e->pad = 0;
    if (sqep) {
        if (bpf_probe_read_user(cmdbuf, sizeof(cmdbuf), (const char *)sqep + 64) == 0)
            e->pad = 1;
        else if (bpf_probe_read_kernel(cmdbuf, sizeof(cmdbuf), (const char *)sqep + 64) == 0)
            e->pad = 1;
    }
    __builtin_memcpy(e->path, cmdbuf, sizeof(cmdbuf));
    bpf_ringbuf_submit(e, 0);
    return -1; // EPERM: denegar el passthrough (el disco no se entrega)
}

// Firma: security_file_ioctl(struct file *file, unsigned int cmd,
// unsigned long arg). El passthrough NVMe por ioctl(2) (NVME_IOCTL_IO_CMD/
// ADMIN_CMD/SUBMIT_IO/RESET/IO64...) lee/escribe BLOQUES CRUDOS por DEBAJO
// del VFS: file_open solo ve el open del char dev /dev/ng* y NINGÚN hook de
// path ve el acceso (T1005). Se filtra por el encoding del ioctl: type='N'
// (0x4E) y nr>=0x41 deja pasar solo NVME_IOCTL_ID (0x40, inofensivo) y niega
// TODO el passthrough/destructivo. El arg apunta al nvme_passthru_cmd en
// memoria USER: se extrae opcode/nsid/cdw10-12 para el detalle de la alerta.
SEC("lsm/file_ioctl")
int motor_lsm_file_ioctl(unsigned long long *ctx)
{
    if (!lsm_should_report())
        return 0;
    struct file *file = (struct file *)ctx[0];
    unsigned int cmd = (unsigned int)ctx[1];
    if (!file)
        return 0;
    if (((cmd >> 8) & 0xFF) != 0x4E || (cmd & 0xFF) < 0x41)
        return 0; // no es passthrough NVMe: ioctl común del sistema

    struct motor_lsm_event *e = bpf_ringbuf_reserve(&lsm_events, sizeof(*e), 0);
    if (!e)
        return -1; // sin ringbuf igual se deniega: bloqueo antes que auditoría
    e->type = 10;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->family = 0;
    e->port = (unsigned short)(cmd & 0xFFFF); // cmd partido en 2 campos
    e->txid = (unsigned short)(cmd >> 16);
    e->pad = 0;
    // nvme_passthru_cmd en memoria user: opcode(0) nsid(4) cdw10(40) cdw11(44)
    // cdw12(48) — mismo layout que nvme_uring_cmd. 56 bytes bastan.
    unsigned char cmdbuf[56];
    __builtin_memset(cmdbuf, 0, sizeof(cmdbuf));
    if (bpf_probe_read_user(cmdbuf, sizeof(cmdbuf), (const void *)ctx[2]) == 0)
        e->pad = 1;
    __builtin_memcpy(e->path, cmdbuf, sizeof(cmdbuf));
    // El d_path del char dev NO cabe junto al comando: se reconstruye en Go
    // como /dev/ng* implícito; el comando es lo forense.
    bpf_ringbuf_submit(e, 0);
    return -1; // EPERM: denegar el passthrough (el disco no se entrega)
}

char LICENSE[] SEC("license") = "GPL";
