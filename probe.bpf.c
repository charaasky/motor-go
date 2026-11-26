// SPDX-License-Identifier: GPL-2.0
// probe.bpf.c — captura mínima de eventos (exec, connect, mmap, ptrace, openat).
// Autocontenido: solo vmlinux.h + helpers BPF declaradas por ID. Escrito desde cero.
#include "vmlinux.h"

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __always_inline inline __attribute__((always_inline))
#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2

#define TASK_COMM_LEN 16
#define AF_INET 2
#define AF_INET6 10
#define AF_UNIX 1
#define AF_PACKET 17
#define SOCK_RAW 3
#define UTIME_NOW ((long)0x3ffffffe)

struct ktime_ts { long tv_sec; long tv_nsec; }; // timespec64 (utimensat times[2])

// Helpers BPF (IDs estándar del kernel Linux)
static void *(*bpf_ringbuf_reserve)(void *map, unsigned long long size, unsigned long long flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, unsigned long long flags) = (void *)132;
static unsigned long long (*bpf_get_current_pid_tgid)(void) = (void *)14;
static unsigned int (*bpf_get_current_comm)(void *buf, unsigned int size) = (void *)16;
static unsigned long long (*bpf_get_current_task)(void) = (void *)35;
static long (*bpf_probe_read_user)(void *dst, unsigned int size, const void *src) = (void *)112;
static long (*bpf_probe_read_kernel)(void *dst, unsigned int size, const void *src) = (void *)113;
static long (*bpf_probe_read_user_str)(void *dst, unsigned int size, const void *src) = (void *)114;
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static unsigned long long (*bpf_get_current_cgroup_id)(void) = (void *)80;

// Evento unificado (ringbuf). Layout:
//   type(4) pid(4) ppid(4) comm[16] pcomm[16] family(2) port(2) daddr[16]
//   prot(8) flags(8) arg1(8) arg2(4) fname[160]
struct event {
    unsigned int type;            // 1=exec 2=connect 3=mmap 4=ptrace 5=openat 7=memfd_create 8=process_vm_writev 9=utimensat(timestomp) 11=socket(captura) 12=process_vm_readv(scraping)
    unsigned int pid;
    unsigned int ppid;
    char comm[TASK_COMM_LEN];
    char pcomm[TASK_COMM_LEN];
    unsigned short family;
    unsigned short port;          // network byte order
    unsigned char daddr[16];
    unsigned long long prot;
    unsigned long long flags;
    unsigned long long arg1;      // ptrace request / openat flags
    unsigned int arg2;            // ptrace target pid
    char fname[160];              // openat filename
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

// Filtro por cgroup (activo solo con -only-docker): Go llena `allowed_cgroups`
// con los cgroup de los contenedores del lab y pone filter_cfg[0]=1. El kernel
// descarta en origen todo evento de procesos fuera de esos cgroups, evitando el
// flood del host y que la respuesta activa mate procesos legítimos.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned long long);
    __type(value, unsigned char);
    __uint(max_entries, 4096);
} allowed_cgroups SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, unsigned int);
    __type(value, unsigned int);
    __uint(max_entries, 1);
} filter_cfg SEC(".maps");

static __always_inline int should_report(void)
{
    unsigned int k = 0;
    unsigned int *en = bpf_map_lookup_elem(&filter_cfg, &k);
    if (!en || *en == 0)
        return 1; // filtro desactivado (modo host completo)
    unsigned long long cgid = bpf_get_current_cgroup_id();
    return bpf_map_lookup_elem(&allowed_cgroups, &cgid) != 0;
}

SEC("tracepoint/sched/sched_process_exec")
int tp_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    if (!should_report())
        return 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);

    // T1574.006 (LD_PRELOAD hijack): copia acotada del entorno del nuevo exec
    // (mm->env_start..env_end). El tracepoint se dispara DENTRO de execve,
    // antes de que ld.so cargue la lib → si el motor mata aquí, el constructor
    // del payload nunca corre. El matching (LD_PRELOAD=/LD_AUDIT= y ruta
    // escribible) se hace en userspace: el escaneo byte a byte en kernel
    // excede el límite de saltos del verifier. Evento de longitud variable:
    // struct base + env redondeado a 256 (chunks fijos).
    struct mm_struct *task_mm = 0;
    unsigned long env_start = 0, env_end = 0;
    unsigned long arg_start = 0, arg_end = 0;
    bpf_probe_read_kernel(&task_mm, sizeof(task_mm), &task->mm);
    if (task_mm) {
        bpf_probe_read_kernel(&env_start, sizeof(env_start), &task_mm->env_start);
        bpf_probe_read_kernel(&env_end, sizeof(env_end), &task_mm->env_end);
        bpf_probe_read_kernel(&arg_start, sizeof(arg_start), &task_mm->arg_start);
        bpf_probe_read_kernel(&arg_end, sizeof(arg_end), &task_mm->arg_end);
    }
    unsigned long env_len = 0; // bytes válidos reales del entorno
    if (task_mm && env_end > env_start) {
        env_len = env_end - env_start;
        if (env_len > 4096)
            env_len = 4096; // cap: entornos gigantes se truncan (ver matriz)
    }
    // Gap #9 (race post-mortem del cmdline): argv [arg_start, arg_end) vive en
    // el stack INMEDIATAMENTE debajo del env (arg_end == env_start: el kernel
    // empaqueta argv y env contiguos en el exec — misma fuente que
    // /proc/PID/cmdline y /proc/PID/environ). La ventana right-aligned de 4096B
    // que copia el loop de chunks ABAJO termina en env_end, por lo que INCLUYE
    // argv cuando cabe: env no truncado (env_len < 4096) y el total entra en la
    // ventana. e->flags lleva los bytes válidos de argv → userspace lo usa como
    // cmdline de fallback cuando el proceso efímero murió antes de que el
    // reader procese el evento y /proc/PID/cmdline ya no existe.
    unsigned long arg_len = 0;
    if (task_mm && arg_end > arg_start && arg_end == env_start && env_len < 4096) {
        arg_len = arg_end - arg_start;
        if (arg_len > 4096 - env_len)
            arg_len = 0; // argv no cabe completo en la ventana → sin fallback
    }

    // ringbuf_reserve exige tamaño CONSTANTE por call site → registro de
    // tamaño fijo: struct base (256) + entorno máx (4096).
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e) + 4096, 0);
    if (!e)
        return 0;
    e->type = 1;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_kernel(&e->ppid, sizeof(e->ppid), &parent->tgid);
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_probe_read_kernel(e->pcomm, sizeof(e->pcomm), &parent->comm);
    __builtin_memset(e->fname, 0, sizeof(e->fname));
    // Copia de exactamente 16 chunks de 256B con offsets de destino
    // CONSTANTES (el verifier rechaza destinos variables en ringbuf) y
    // fuentes right-aligned: el bloque copiado TERMINA en env_end. El
    // entorno [env_start, env_end) está garantizado mapeado → los chunks que
    // contienen env (los superiores) nunca fallan; los inferiores pueden leer
    // argv/pila o fallar con EFAULT, pero userspace solo parsea los ÚLTIMOS
    // prot bytes, que son exactamente los de env. Motivo del right-align: el
    // env vive en el tope del stack VMA; un chunk start-anchored cruza el
    // tope → EFAULT (medido: docker exec -e ANEXA las vars al final del env,
    // justo donde el truncamiento perdía el LD_PRELOAD).
    for (int i = 0; i < 16; i++) {
        if (bpf_probe_read_user((char *)e + sizeof(*e) + (unsigned long)i * 256, 256,
                                (const void *)(env_end - 4096 + (unsigned long)i * 256)) != 0)
            continue; // chunk inferior no mapeado: irrelevante para el parseo
    }
    e->prot = env_len;
    e->flags = arg_len; // bytes de argv copiados (gap #9): 0 = sin fallback
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int tp_connect(struct trace_event_raw_sys_enter *ctx)
{
    if (!should_report())
        return 0;
    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
    if (!addr)
        return 0;
    unsigned short family = 0;
    bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
    if (family != AF_INET && family != AF_INET6 && family != AF_UNIX)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->type = 2;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->family = family;

    if (family == AF_INET) {
        struct sockaddr_in sin;
        bpf_probe_read_user(&sin, sizeof(sin), (void *)ctx->args[1]);
        e->port = sin.sin_port;
        __builtin_memcpy(e->daddr, &sin.sin_addr, 4);
    } else if (family == AF_INET6) {
        struct sockaddr_in6 sin6;
        bpf_probe_read_user(&sin6, sizeof(sin6), (void *)ctx->args[1]);
        e->port = sin6.sin6_port;
        __builtin_memcpy(e->daddr, &sin6.sin6_addr, 16);
    } else {
        // AF_UNIX: copiar la ruta del socket (p. ej. /var/run/docker.sock)
        struct sockaddr_un sun;
        bpf_probe_read_user(&sun, sizeof(sun), (void *)ctx->args[1]);
        bpf_probe_read_user_str(e->fname, sizeof(e->fname), sun.sun_path);
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// T1040 (network sniffing): capturar tráfico ajeno exige un socket de captura —
// AF_PACKET (todo el enlace: tcpdump/python sniffer) o SOCK_RAW sobre IP (raw
// IP sniffer / túneles ICMP). recvfrom() NO pasa por connect/sendmsg, así que
// las sondas de exfil son CIEGAS al sniffer: esta es la única señal en origen.
// socket(2) es la única vía de creación (io_uring no crea sockets): el
// tracepoint ve todas. El resto de familias (TCP/UDP/UNIX normales) se
// descarta EN KERNEL: socket() dispara por cada conexión y ahogaría el ringbuf.
SEC("tracepoint/syscalls/sys_enter_socket")
int tp_socket(struct trace_event_raw_sys_enter *ctx)
{
    if (!should_report())
        return 0;
    int family = (int)ctx->args[0];
    int type = (int)ctx->args[1];
    int is_af_packet = (family == AF_PACKET);
    int is_raw_ip = (family == AF_INET || family == AF_INET6) &&
                    (type & 0xF) == SOCK_RAW; // 0xF: sin SOCK_NONBLOCK/CLOEXEC
    if (!is_af_packet && !is_raw_ip)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->type = 11;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->family = (unsigned short)family;
    e->port = (unsigned short)(type & 0xF); // tipo base del socket
    e->daddr[0] = (unsigned char)(ctx->args[2] & 0xFF);      // protocolo (ETH_P_*/IPPROTO_*)
    e->daddr[1] = (unsigned char)((ctx->args[2] >> 8) & 0xFF);
    e->daddr[2] = (unsigned char)((ctx->args[2] >> 16) & 0xFF);
    e->daddr[3] = (unsigned char)((ctx->args[2] >> 24) & 0xFF);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int tp_mmap(struct trace_event_raw_sys_enter *ctx)
{
    if (!should_report())
        return 0;
    unsigned long long prot = ctx->args[2];
    if ((prot & 0x6) != 0x6)   // solo RWX
        return 0;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->type = 3;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->prot = prot;
    e->flags = ctx->args[3];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int tp_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    if (!should_report())
        return 0;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->type = 4;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->arg1 = ctx->args[0];   // request
    e->arg2 = ctx->args[1];   // target pid
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_openat(struct trace_event_raw_sys_enter *ctx)
{    if (!should_report())
        return 0;
    const char *fname = (const char *)ctx->args[1];
    if (!fname)
        return 0;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->type = 5;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->arg1 = ctx->args[2];   // flags
    bpf_probe_read_user_str(e->fname, sizeof(e->fname), fname);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// memfd_create permite cargar código desde memoria sin crear un ejecutable
// persistente en disco. Es una primitiva fileless relevante aunque el exploit
// o la carga útil concreta sea desconocida para las firmas L7.
SEC("tracepoint/syscalls/sys_enter_memfd_create")
int tp_memfd_create(struct trace_event_raw_sys_enter *ctx)
{
    if (!should_report())
        return 0;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->type = 7;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(e->fname, sizeof(e->fname), (const void *)ctx->args[0]);
    e->arg1 = ctx->args[1];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// process_vm_writev escribe directamente en la memoria de OTRO proceso sin
// pasar por ptrace: inyección de código/datos que evade la detección basada
// solo en sys_enter_ptrace. args: pid, local_iov, liovcnt, remote_iov, riovcnt, flags.
SEC("tracepoint/syscalls/sys_enter_process_vm_writev")
int tp_process_vm_writev(struct trace_event_raw_sys_enter *ctx)
{
    if (!should_report())
        return 0;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->type = 8;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->arg2 = (unsigned int)ctx->args[0]; // target pid
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// T1003 (scraping de memoria): process_vm_readv es el hermano LECTOR del
// writev — vuelca la memoria de OTRO proceso (sshd, python con secretos en
// heap) sin abrir un solo archivo. El scraping masivo de regiones es el
// paso previo a extraer credenciales en claro (mimipenguin-style).
SEC("tracepoint/syscalls/sys_enter_process_vm_readv")
int tp_process_vm_readv(struct trace_event_raw_sys_enter *ctx)
{
    if (!should_report())
        return 0;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->type = 12;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->arg2 = (unsigned int)ctx->args[0]; // target pid
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// T1070.006 timestomp: utimensat(2) con times EXPLÍCITOS (times != NULL y
// times[0].tv_nsec != UTIME_NOW) fija timestamps arbitrarios — `touch -r`
// clona los de otro archivo para disimular un payload recién dropeado como
// antiguo (anti-forense). times=NULL o UTIME_NOW es el caso legítimo
// (touch normal). args: dirfd, filename, times*, flags.
SEC("tracepoint/syscalls/sys_enter_utimensat")
int tp_utimensat(struct trace_event_raw_sys_enter *ctx)
{
    if (!should_report())
        return 0;
    const void *times = (const void *)ctx->args[2];
    if (!times)
        return 0; // touch sin -t/-r: fija "ahora" — caso normal
    struct ktime_ts ts[2];
    if (bpf_probe_read_user(&ts, sizeof(ts), times) != 0)
        return 0;
    // tv_nsec == UTIME_NOW(UTIME_OMIT también explícito pero raro): "ahora"
    // explícito; solo reporta timestamps FIJADOS por el atacante.
    if (ts[0].tv_nsec == UTIME_NOW || ts[1].tv_nsec == UTIME_NOW)
        return 0;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->type = 9;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->arg1 = (unsigned long long)ts[0].tv_sec; // atime fijado
    e->arg2 = (unsigned int)ts[1].tv_sec;       // mtime fijado (truncado)
    bpf_probe_read_user_str(e->fname, sizeof(e->fname), (const void *)ctx->args[1]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Captura consultas DNS (sendto a puerto 53) para detectar exfil por DNS.
// args de sendto: fd, buff, len, flags, addr, addrlen.
SEC("tracepoint/syscalls/sys_enter_sendto")
int tp_sendto(struct trace_event_raw_sys_enter *ctx)
{
    if (!should_report())
        return 0;
    struct sockaddr *addr = (struct sockaddr *)ctx->args[4];
    if (!addr)
        return 0;
    unsigned short family = 0;
    bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
    unsigned short dport = 0;
    unsigned char daddr[16] = {0};
    if (family == AF_INET) {
        struct sockaddr_in sin;
        bpf_probe_read_user(&sin, sizeof(sin), (void *)ctx->args[4]);
        dport = sin.sin_port;
        __builtin_memcpy(daddr, &sin.sin_addr, 4);
    } else if (family == AF_INET6) {
        struct sockaddr_in6 sin6;
        bpf_probe_read_user(&sin6, sizeof(sin6), (void *)ctx->args[4]);
        dport = sin6.sin6_port;
        __builtin_memcpy(daddr, &sin6.sin6_addr, 16);
    } else {
        return 0;
    }
    // 53 en network byte order = 0x3500 leído little-endian.
    if (dport != 0x3500) {
        // UDP sendto a puerto NO-DNS sin connect (gap #6): exfil por protocolo
        // alternativo (T1048) invisible al path connect. Emitir tipo 10 salvo
        // loopback (127/8, ::1) y wildcard (0.0.0.0, ::).
        if (family == AF_INET) {
            if (daddr[0] == 127)
                return 0;
            if (daddr[0] == 0 && daddr[1] == 0 && daddr[2] == 0 && daddr[3] == 0)
                return 0;
        } else { // AF_INET6: salta :: (wildcard) y ::1 (loopback)
            int i = 0;
            int zero15 = 1;
#pragma unroll
            for (i = 0; i < 15; i++) {
                if (daddr[i] != 0)
                    zero15 = 0;
            }
            if (zero15 && (daddr[15] == 0 || daddr[15] == 1))
                return 0;
        }
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e)
            return 0;
        e->type = 10; // udp_sendto (no DNS, no loopback)
        e->pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(e->comm, sizeof(e->comm));
        e->family = family;
        e->port = dport;
        __builtin_memcpy(e->daddr, daddr, 16);
        bpf_ringbuf_submit(e, 0);
        return 0;
    }

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->type = 6;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->family = family;
    e->port = dport;

    // Extraer el QNAME crudo del payload DNS (offset 12 tras el header): es una
    // secuencia [len][chars]... terminada en 0x00. El parseo de labels se hace
    // en Go (más simple y evita reventar el límite de 1M insn del verifier).
    bpf_probe_read_user_str(e->fname, sizeof(e->fname), (const void *)(ctx->args[1] + 12));
    // Guardar también el transaction ID (2 bytes) para detectar covert channel.
    unsigned short txid = 0;
    bpf_probe_read_user(&txid, sizeof(txid), (const void *)ctx->args[1]);
    e->arg2 = (unsigned int)txid;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// El resolver de glibc (systemd-resolved stub) envía DNS por `connect`+`sendmmsg`
// (NO por sendto). Capturamos sendmmsg y extraemos el QNAME del primer mensaje.
SEC("tracepoint/syscalls/sys_enter_sendmmsg")
int tp_sendmmsg(struct trace_event_raw_sys_enter *ctx)
{
    if (!should_report())
        return 0;
    struct mmsghdr mm;
    bpf_probe_read_user(&mm, sizeof(mm), (void *)ctx->args[1]);
    struct iovec iov;
    bpf_probe_read_user(&iov, sizeof(iov), mm.msg_hdr.msg_iov);
    if (iov.iov_len < 16)
        return 0;
    unsigned char hdr[16];
    bpf_probe_read_user(hdr, sizeof(hdr), iov.iov_base);
    // Cabecera DNS: QR=0 (query), opcode=0, QDCOUNT=1. Evita parsear no-DNS.
    if ((hdr[2] & 0x80) != 0)
        return 0;
    if ((hdr[2] & 0x78) != 0)
        return 0;
    if (hdr[5] != 1)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->type = 6;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->family = AF_INET;
    e->port = 0x3500; // 53
    e->arg2 = (unsigned int)((hdr[0] << 8) | hdr[1]); // transaction ID
    bpf_probe_read_user_str(e->fname, sizeof(e->fname), (const void *)((unsigned long)iov.iov_base + 12));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
