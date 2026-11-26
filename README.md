# motor-go — detector original (Go + eBPF): comportamiento + red

Detector **escrito desde cero** (no deriva de Falco/Suricata). Dos sondas eBPF
mínimas; **toda la lógica de detección vive en Go** (tu IP, licenciable como
quieras).

## Descripción

`px-motor` es un **detector de intrusiones (IDS/HIDS)** de host y de red, escrito en Go y montado
sobre eBPF: observa el kernel sin módulos ni agentes, clasifica lo que ve en reglas con umbrales y
emite una alerta JSONL por evento.

Qué hace, una línea por capa:

- **Comportamiento**: vigila syscalls (`exec`, `connect`, `mmap`, `ptrace`, `openat`) y hooks LSM
  (`io_uring`, `task_kill`, `chmod/rename/unlink/setxattr`) para detectar ejecución de shells,
  exfiltración, lectura de credenciales, `mmap` RWX, `ptrace`, persistencia y borrado de evidencia.
- **Red**: cuenta tráfico en XDP (L2/L3) para detectar tormentas ARP, fragmentación y protocolos
  anómalos, y hace *sniffing* HTTP L7 con firmas propias (SQLi, XSS, SSTI, traversal, webshell…).
- **Adaptación**: entrena un baseline (negative selection), madura "clones" (antígenos repetidos)
  y correlaciona en kill-chain / beaconing.
- **Respuesta activa**: puede matar el proceso ofensor (y su árbol) o descartar la IP origen en XDP.
- **Integridad y anti-tampering**: vigila archivos por SHA-256 y se protege a sí mismo de ser
  matado por señales (hook `task_kill`).

Es un binario **estático** (`CGO_ENABLED=0`) que embebe las sondas eBPF: no necesita runtime de
lenguaje en el host y corre tanto como proceso de host como en contenedor privilegiado.

## Alcances

**Cubierto (in scope):**

- Detección de comportamiento por syscalls y hooks LSM (RCE, exfil, credenciales, persistencia, evasión).
- Red L2/L3 en XDP (ARP/fragmentación/protocolos anómalos) y firmas HTTP L7 en claro (SQLi/XSS/SSTI/…).
- Correlación adaptativa: baseline, maduración clonal, kill-chain, beaconing, osmosis de volumen.
- Integridad de archivos (SHA-256) y defensa anti-tampering de sí mismo.
- Respuesta activa: SIGKILL de árboles de procesos y drop XDP de IPs.
- Salida JSONL (stdout o `-output`) compatible con un `responder` externo.
- Licenciamiento firmado (Ed25519) ligado a la máquina (`-license` / `-activate`).

**Fuera de alcance (out of scope):**

- **No es un sandbox**: detecta escapes, no los contiene (eso es gVisor/Firecracker/namespaces).
- **No inspecciona TLS**: las firmas HTTP L7 operan sobre tráfico en claro; no hay MITM/descifrado.
- **No reemplaza un firewall/WAF completo**: el drop XDP es puntual (IP + TTL), no una política de red.
- **No persiste ni correlaciona a largo plazo**: emite eventos; el SIEM/almacenamiento es externo.
- **No es ML por flujo**: las anomalías de red son heurísticas (umbrales/baseline), no un modelo
  entrenado sobre tráfico etiquetado.
- **Linux/x86_64 únicamente**: requiere kernel con BTF/eBPF y `clang -target bpf`; XDP necesita una
  interfaz con driver que lo soporte (no `lo`).

## Arquitectura

```
kernel (eBPF)                          userspace (Go)
├─ probe.bpf.c  (tracepoints)          lógica de detección
│   ├─ sched_process_exec  ─▶ ringbuf ─▶ SHELL / DOCKER_CLI / APP_PROCESO
│   ├─ sys_enter_connect   ─▶ ringbuf ─▶ EXFIL_CONNECT / DOCKER_SOCK
│   ├─ sys_enter_mmap      ─▶ ringbuf ─▶ MMAP_RWX
│   ├─ sys_enter_ptrace    ─▶ ringbuf ─▶ PTRACE (T1055)
│   └─ sys_enter_openat    ─▶ ringbuf ─▶ LECTURA_SENSIBLE / MEMORIA_AJENA / CREDENCIALES
│
└─ net.bpf.c   (XDP, L2/L3)
    └─ contadores PERCPU  ─▶ polling 1 s (Go) ─▶ ARP_STORM / FRAG_FLOOD /
                                                 PROTOCOLO_DESCONOCIDO /
                                                 PROTOCOLO_MODIFICADO

├─ lsm.bpf.c   (LSM hooks; cierra io_uring y protege la defensa)
│   ├─ task_kill         ─▶ ringbuf ─▶ TAMPERING_KILL (deniega señales al detector, salvo root)
│   ├─ file_open/sendmsg ─▶ ringbuf ─▶ IORING_OPENAT/SENDMSG (bypass de tracepoints)
│   └─ chmod/rename/unlink/setxattr ─▶ ringbuf ─▶ SETUID / DISABLE_TOOL / DELETE_EVIDENCE

La separación es deliberada: el kernel **solo captura y cuenta**; las reglas
(qué es sospechoso, con qué umbral) son código Go fácil de extender, testear y
proteger.

## Detecciones

**Comportamiento (syscalls):**

| Regla | Señal | Verificado |
|---|---|---|
| `SHELL (RCE)` | una app web ejecuta `sh`/`bash`/... | ✅ python3 → sh |
| `DOCKER_CLI` | una app ejecuta el binario `docker` | ✅ |
| `APP_PROCESO_INESPERADO` | una app lanza un proceso fuera de whitelist | ✅ |
| `EXFIL_CONNECT` | una app conecta a un destino NO-loopback | ✅ python3 → 192.168.1.1:80 |
| `DOCKER_SOCK (T1611)` | open/connect de `*.sock` (docker.sock) | ✅ python3 → /var/run/docker.sock |
| `MMAP_RWX` | mmap con PROT_EXEC\|PROT_WRITE | ✅ prot=0x7 |
| `PTRACE (T1055)` | ptrace sobre OTRO proceso (ATTACH/POKE/...) | ✅ request=0x11 |
| `LECTURA_SENSIBLE` | open de /etc/shadow, /etc/passwd | ✅ cat /etc/shadow |
| `MEMORIA_AJENA (T1055)` | open de /proc/\<pid\>/mem de OTRO proceso | ✅ /proc/1/mem |
| `CREDENCIALES` | open de bash_history, .ssh, authorized_keys (no la del propio shell) | (mismo path que LECTURA_SENSIBLE) |

**Red (XDP, L2/L3):**

| Regla | Señal | Verificado |
|---|---|---|
| `ARP_STORM` | ráfaga ARP ≥ umbral pps | ✅ arp=1/2 pps en docker0 |
| `FRAG_FLOOD` | paquetes IPv4/IPv6 fragmentados ≥ umbral pps | ✅ ping -s 2000 → frag=4/8 pps |
| `PROTOCOLO_DESCONOCIDO` | EtherType no esperado (trama no-IP) | ✅ ethertype_inesperado=2 |
| `PROTOCOLO_MODIFICADO` | IPv4 con L4 ≠ TCP/UDP/ICMP (GRE/ESP/...) | ✅ GRE proto=47 → l4_raro=10 |

**Firmas HTTP (L7, AF_PACKET) — reemplaza Suricata:**

| Regla | Señal | Verificado |
|---|---|---|
| `SIG_HTTP (SQLi)` | `union select`, `or 1=1`, `pg_sleep`... | (patrón XSS verificado) |
| `SIG_HTTP (XSS)` | `<script`, `javascript:` | ✅ wget `<script>` → SIG_HTTP |
| `SIG_HTTP (SSTI/XXE/PathTraversal/CmdInjection/WebShell/Log4Shell/Shellshock/OpenRedirect/SSRF)` | firmas propias en Go | (mismas reglas) |

**Capa 4 (anomalía adaptativa):**

| Regla | Señal | Verificado |
|---|---|---|
| `BASELINE_DESVIACION` | hijo/destino fuera del baseline entrenado (negative selection) | ✅ whoami no aprendido → desviación |
| `CLONAL_MADURO` | antígeno repetido 3× → maduración y generalización cross-app | ✅ whoami ×3 → clon 3 maduró |
| `KILL_CHAIN (quorum)` | ≥4 eventos del mismo origen en 10 s | ✅ 4 acciones → kill-chain |
| `BEACONING` | conexiones con cadencia regular (CV ≤ 0.25) | (misma lógica) |
| `OSMOSIS_VOLUMEN` | ≥1 MB/s en XDP | (misma lógica) |
| `ENDOSIMBIOSIS_*` | archivo nuevo/modificado/borrado (SHA-256) | ✅ modificación + archivo nuevo |
| `DEFENSA_APAGADA` | pieza de defensa desaparece | (misma lógica) |

**Reglas Falco restantes (persistencia/ofuscación/discovery/archive/cifrado):**

| Regla | Señal | Verificado |
|---|---|---|
| `OFUSCACION_BASE64 (T1027)` | app usa base64 | ✅ base64 |
| `LIMPIEZA_EVIDENCIA (T1070)` | shred/truncate/rm desde app | ✅ shred |
| `DISCOVERY (T1083/T1057)` | find/grep/ps desde app | ✅ find |
| `ARCHIVE (T1560)` | tar/gzip/zip desde app | ✅ tar |
| `CIFRADO (T1573)` | openssl/gpg desde app | (misma lógica) |
| `PERSISTENCIA_SSH/CRON` | escritura a authorized_keys/cron | (misma lógica) |
| `REVERSE_SHELL (T1059/T1571)` | ejecución de nc/ncat/netcat/socat | ✅ nc |
| `MOVIMIENTO_LATERAL_SSH (T1021.004/T1570)` | app lanza ssh/scp/sftp/rsync | ✅ python3 → ssh |

**Respuesta activa:**

| Mecanismo | Efecto |
|---|---|
| `-kill` | SIGKILL al proceso ofensor y su árbol (kill_tree vía /proc) |
| drop XDP | la IP origen de una firma HTTP se añade a un mapa LRU `blocked` y se descarta en L2 (TTL 60 s) |
| `-respond` | escribe eventos compatibles con `fase-c/bloqueo/responder.py` (rule + output_fields.proc.pid/pname) |

## Build

```bash
# 1. generar vmlinux.h (una vez)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 2. compilar las sondas eBPF (requiere clang con soporte -target bpf)
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c probe.bpf.c -o probe.bpf.o
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c net.bpf.c -o net.bpf.o
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c lsm.bpf.c -o lsm.bpf.o

# 3. compilar el binario Go (estático; embebe los .bpf.o vía go:embed)
CGO_ENABLED=0 go build -o px-motor .
```
Si tocás un `.bpf.c`, tenés que **recompilar su `.bpf.o`** antes del `go build` (el binario embebe
el `.o`, no el `.c`). Sin `clang`, `go build` reusa el `.o` viejo en silencio.

## Anti-tampering (task_kill)

El hook LSM `task_kill` registra el propio PID del detector en `lsm_protected_pids` y **deniega
in-kernel** toda señal hacia él, para que un atacante no mate la defensa (T1562.001). Excepciones:
señales propias (mismo tgid), `SIGURG` (preemption de Go) y **root** (sender con UID real 0, vía
`bpf_get_current_uid_gid`). Esto último es deliberado: `systemctl stop`/`restart` (que corre como
root) debe poder detener el detector; la protección sigue cerrando la vía del proceso no
privilegiado (el agente escapado corre como `hcma-firecracker`/995, nunca root).

## Ejecutar (requiere eBPF)

```bash
# comportamiento (syscalls): sin -iface
docker run --rm --privileged --pid=host \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v "$(pwd)/px-motor:/px-motor" --entrypoint /px-motor alpine:latest

# + red (XDP): añadir --network host y -iface <interfaz física o bridge>
# (XDP NO se ancla a 'lo': loopback no tiene driver XDP)
docker run --rm --privileged --pid=host --network host \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v "$(pwd)/px-motor:/px-motor" --entrypoint /px-motor alpine:latest \
  -iface docker0
```

Flags de red (umbrales por segundo):

| Flag | Default | Alerta |
|---|---|---|
| `-arp-pps` | 50 | ARP_STORM |
| `-frag-pps` | 20 | FRAG_FLOOD |
| `-unknown-pps` | 5 | PROTOCOLO_DESCONOCIDO |
| `-other-pps` | 10 | PROTOCOLO_MODIFICADO |

Otros flags:

| Flag | Uso |
|---|---|
| `-config px-motor.conf` | Archivo de config con patrones de cmdline de padres legítimos (uno por línea, `#` comentarios). Se re-resuelve cada 10 s, así no importa si el supervisor cambia de PID al reiniciar. |
| `-allow-docker-pid 2176704,3298130` | PIDs explícitos de padres legítimos (alternativa rápida, sin archivo). |
| `-sniff docker0` | Activa firmas HTTP L7 vía AF_PACKET en esa interfaz. |
| `-authlog /var/log/auth.log` | Tail del log de autenticación (paridad con el log Security de Windows): logons fallidos + fuerza bruta por IP + sudo + useradd/groupadd. Vacío = autodetectar `/var/log/auth.log` o `/var/log/secure`. Requiere montar `/var/log:/var/log:ro` en el contenedor. |
| `-train 60` | Segundos de entrenamiento del baseline (negative selection) al arrancar. |
| `-integrity /ruta1,/ruta2` | Directorios a vigilar por integridad (SHA-256). |
| `-kill` | Respuesta activa directa: SIGKILL al ofensor y su árbol. |
| `-respond` + `-respond-path` | Escribe eventos compatibles con responder.py (por defecto `../fase-c/bloqueo/events.jsonl`). |
| `-output file` | Anexa alertas JSONL a un archivo de auditoría. |
| `-license lic.json` + `-fingerprint` | Licencia firmada ligada a máquina. `-fingerprint` imprime el fingerprint y sale. |

## Licenciamiento

- **`-license archivo.json`** valida una licencia firmada (Ed25519) ligada al
  fingerprint de la máquina (machine-id + MAC + hostname) con fecha de expiración.
- **Generar licencias** (solo el vendedor, con `vendor.key` — nunca distribuir):
  ```bash
  cd licgen && go run . -autofp -days 30 -key ../vendor.key -o license.json
  ```
- La licencia es un JSON chico, apto para entregarse como **QR**. Si vence, por
  defecto avisa y sigue (modo gracia); `-license-strict` la corta.

**Servidor central con autorización manual (capa 3):**

```bash
cd licserver && go build -o licserver .
./licserver -key ../vendor.key -port 8443 -data licserver-data &

# en la máquina del cliente:
px-motor -activate http://TU-SERVIDOR:8443   # envía fingerprint, espera aprobación

# vos (vendedor):
curl http://TU-SERVIDOR:8443/admin/pending            # ver solicitudes
curl -X POST 'http://TU-SERVIDOR:8443/admin/approve/<id>?days=30'   # firmar y entregar
```

Whitelists internos (sin flags): las herramientas de defensa (`falco`,
`suricata`, `tetragon`, `px-motor`, …) no se auto-detectan en lecturas de
archivos sensibles; `/etc/passwd` solo alerta si lo lee una app (los binarios
del sistema lo leen normal), mientras que `/etc/shadow` alerta siempre.

Salida: una línea JSON por alerta en stdout (redirigible a events.jsonl y
conectable al responder de la suite).

## Por qué es "igual o mejor"

- **Comportamiento**: cubre la capa 2 de Falco (shell, exfil, mmap RWX, lectura
  sensible, docker.sock, ptrace) con 5 tracepoints y lógica en Go.
- **Red**: cubre lo que Suricata no cubre en el lab (0 reglas ARP/frag/decoder)
  y lo hace en **XDP**, antes de que se asigne el SKB — más rápido que Suricata
  (AF_PACKET) y ve ARP/L2 que en `lo` es invisible.
- **Lógica en Go**: umbrales y reglas mantenibles, testables, **bajo tu licencia**.
- **Sin motor de reglas en kernel**: cambiar qué es sospechoso no recompila la sonda.
- **Firmas L7 propias** (SQLi/XSS/SSTI/...) — reemplaza las reglas HTTP de Suricata.
- **Capa 4 adaptativa** (baseline + clonal) — aprende y generaliza como el Python original.
- **Respuesta activa** — drop XDP de IPs + SIGKILL de árboles + integración con responder.py.
- Extensible: agregar tracepoints, contadores XDP o firmas HTTP es trivial (una línea por lado).


## Licencia del repositorio

- **Lógica de detección en Go** (`*.go`, excepto las dependencias de terceros):
  **CC BY-NC-SA 4.0** (Atribución – NoComercial – CompartirIgual). Podés usar,
  estudiar y redistribuir (y derivar, manteniendo la misma licencia), **no** con
  fines comerciales. Ver `LICENSE`.
- **Sondas eBPF** (`*.bpf.c`): **GPL-2.0**. Al enlazarse con headers/estructuras del
  kernel, se distribuyen bajo GPL-2.0 (es lo que exige el `char LICENSE[] = "GPL"`
  del verificador). Ver los comentarios en cada `*.bpf.c`.
- **Dependencia** `github.com/cilium/ebpf`: **MIT** (declarada en `go.mod`).

El binario resultante que embebe las sondas GPL debe, por coherencia, distribuirse
teniendo en cuenta esas obligaciones GPL sobre las sondas. La lógica de reglas
propia (Go) queda bajo CC BY-NC-SA 4.0.
