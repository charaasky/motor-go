package main

// Detección de anomalías de red (L2/L3) con XDP.
//
// La sonda net.bpf.o solo CUENTA paquetes por categoría en un mapa PERCPU_ARRAY.
// Aquí (Go) se lee el mapa cada segundo, se calculan tasas y se emiten alertas
// con los mismos umbrales y formato que el resto del motor. La lógica es 100 %
// tuya y testeable; el kernel solo agrega contadores.

import (
	"bytes"
	_ "embed"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:embed net.bpf.o
var netO []byte

// Índices del mapa `counters` (PERCPU_ARRAY) — deben coincidir con net.bpf.c.
const (
	cntARP = iota
	cntIPv4
	cntIPv4Frag
	cntIPv6
	cntIPv6Frag
	cntUnknown
	cntTCP
	cntUDP
	cntICMP
	cntIPv4Other
	cntTotal
	cntBytes
	cntMax
)

var netCfg struct {
	iface      string
	arpPPS     int
	fragPPS    int
	unknownPPS int
	otherPPS   int
	icmpPPS    int
}

func init() {
	flag.StringVar(&netCfg.iface, "iface", "", "interfaz para la sonda XDP (L2/L3); vacío = desactivar")
	flag.IntVar(&netCfg.arpPPS, "arp-pps", 50, "umbral tormenta ARP (paquetes/s)")
	flag.IntVar(&netCfg.fragPPS, "frag-pps", 20, "umbral flood de fragmentos (paquetes/s)")
	flag.IntVar(&netCfg.unknownPPS, "unknown-pps", 5, "umbral protocolo desconocido (paquetes/s)")
	flag.IntVar(&netCfg.otherPPS, "other-pps", 10, "umbral protocolo L4 raro (paquetes/s)")
	flag.IntVar(&netCfg.icmpPPS, "icmp-pps", 8, "umbral de ICMP (posible tunneling) (paquetes/s)")
}

// attachNet carga y ancla la sonda XDP a la interfaz indicada.
// Devuelve nil, nil, nil si -iface está vacío.
func attachNet() (link.Link, *ebpf.Collection, error) {
	if netCfg.iface == "" {
		return nil, nil, nil
	}
	if netCfg.iface == "lo" {
		return nil, nil, fmt.Errorf("XDP no se puede anclar a 'lo' (loopback sin soporte XDP); usa la bridge del lab (docker0)")
	}
	if isUplink(netCfg.iface) {
		return nil, nil, fmt.Errorf("XDP NO se ancla a la interfaz física %q: bloquear ahí cortaría la conectividad del host; usá docker0", netCfg.iface)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(netO))
	if err != nil {
		return nil, nil, fmt.Errorf("cargar spec net: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, nil, fmt.Errorf("cargar colección net: %w", err)
	}
	prog := coll.Programs["xdp_probe"]
	if prog == nil {
		coll.Close()
		return nil, nil, fmt.Errorf("programa xdp_probe no encontrado en net.bpf.o")
	}
	ifi, err := net.InterfaceByName(netCfg.iface)
	if err != nil {
		coll.Close()
		return nil, nil, fmt.Errorf("interfaz %q: %w", netCfg.iface, err)
	}

	xdp, err := link.AttachXDP(link.XDPOptions{Program: prog, Interface: ifi.Index})
	if err != nil {
		// respaldo: modo genérico (SKB) para drivers sin XDP nativo
		xdp, err = link.AttachXDP(link.XDPOptions{Program: prog, Interface: ifi.Index, Flags: link.XDPGenericMode})
		if err != nil {
			coll.Close()
			return nil, nil, fmt.Errorf("anclar XDP a %q: %w", netCfg.iface, err)
		}
	}
	return xdp, coll, nil
}

// isUplink detecta interfaces físicas del host (WiFi/Ethernet). La sonda XDP y
// el sniff deben vivir en la bridge del lab (docker0), nunca en el uplink, para
// no cortar la conectividad de la máquina que ejecuta la defensa.
func isUplink(name string) bool {
	for _, p := range []string{"enp", "eth", "ens", "eno", "enx", "wlp", "wlan", "wwan", "wlx"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// readCounters suma los contadores PERCPU de cada CPU.
func readCounters(m *ebpf.Map) []uint64 {
	cur := make([]uint64, cntMax)
	for i := 0; i < cntMax; i++ {
		var vals []uint64
		if err := m.Lookup(uint32(i), &vals); err == nil {
			var sum uint64
			for _, v := range vals {
				sum += v
			}
			cur[i] = sum
		}
	}
	return cur
}

// runNetMonitor lee el mapa cada segundo y emite alertas cuando una tasa
// supera su umbral. Bloquea: ejecutar en goroutine.
func runNetMonitor(coll *ebpf.Collection) {
	m := coll.Maps["counters"]
	if m == nil {
		log.Printf("XDP: mapa counters no encontrado")
		return
	}

	prev := readCounters(m)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for range ticker.C {
		cur := readCounters(m)

		arp := cur[cntARP] - prev[cntARP]
		frag := (cur[cntIPv4Frag] - prev[cntIPv4Frag]) + (cur[cntIPv6Frag] - prev[cntIPv6Frag])
		unknown := cur[cntUnknown] - prev[cntUnknown]
		other := cur[cntIPv4Other] - prev[cntIPv4Other]
		icmp := cur[cntICMP] - prev[cntICMP]
		total := cur[cntTotal] - prev[cntTotal]

		if arp > 0 && arp >= uint64(netCfg.arpPPS) {
			emit("ARP_STORM", "xdp", fmt.Sprintf("iface=%s arp=%d pps (umbral %d) total=%d", netCfg.iface, arp, netCfg.arpPPS, total))
		}
		if frag > 0 && frag >= uint64(netCfg.fragPPS) {
			emit("FRAG_FLOOD", "xdp", fmt.Sprintf("iface=%s frag=%d pps (umbral %d)", netCfg.iface, frag, netCfg.fragPPS))
		}
		if unknown > 0 && unknown >= uint64(netCfg.unknownPPS) {
			emit("PROTOCOLO_DESCONOCIDO", "xdp", fmt.Sprintf("iface=%s ethertype_inesperado=%d pps (umbral %d)", netCfg.iface, unknown, netCfg.unknownPPS))
		}
		if other > 0 && other >= uint64(netCfg.otherPPS) {
			emit("PROTOCOLO_MODIFICADO", "xdp", fmt.Sprintf("iface=%s ipv4_l4_raro=%d pps (umbral %d; no TCP/UDP/ICMP)", netCfg.iface, other, netCfg.otherPPS))
		}
		if icmp > 0 && icmp >= uint64(netCfg.icmpPPS) {
			emit("ICMP_TUNNELING", "xdp", fmt.Sprintf("iface=%s icmp=%d pps (umbral %d; posible túnel/exfil ICMP)", netCfg.iface, icmp, netCfg.icmpPPS))
		}

		prev = cur
	}
}
