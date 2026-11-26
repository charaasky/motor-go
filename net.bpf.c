// SPDX-License-Identifier: GPL-2.0
// net.bpf.c — sonda XDP (L2/L3) para anomalías de red.
//
// Cuenta paquetes por categoría en un mapa PERCPU_ARRAY. NO decide nada:
// la lógica de detección (umbrales, ventanas, alertas) vive en Go (net.go).
// Escrito desde cero; autocontenido (sin libbpf), helpers BPF por ID.
#include "vmlinux.h"

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __always_inline inline __attribute__((always_inline))

#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_MAP_TYPE_LRU_HASH 9
#define XDP_PASS 2
#define XDP_DROP 1

// helper BPF: bpf_map_lookup_elem
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;

// Índices del mapa `counters` — deben coincidir con net.go.
enum {
    IDX_ARP = 0,       // paquetes ARP (L2)
    IDX_IPV4 = 1,      // paquetes IPv4
    IDX_IPV4_FRAG = 2, // IPv4 con MF o offset != 0 (fragmentado)
    IDX_IPV6 = 3,      // paquetes IPv6
    IDX_IPV6_FRAG = 4, // IPv6 con extension header Fragment (nexthdr=44)
    IDX_UNKNOWN = 5,   // EtherType no esperado
    IDX_TCP = 6,       // IPv4 protocolo 6
    IDX_UDP = 7,       // IPv4 protocolo 17
    IDX_ICMP = 8,      // IPv4 protocolo 1
    IDX_IPV4_OTHER = 9,// IPv4 con otro protocolo L4 (posible protocolo modificado)
    IDX_TOTAL = 10,    // total de paquetes
    IDX_BYTES = 11,    // total de bytes (para ósmosis por volumen)
    IDX_MAX = 12,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, unsigned int);
    __type(value, unsigned long long);
    __uint(max_entries, 32);
} counters SEC(".maps");

// IPs origen bloqueadas (respuesta activa). key = iphdr->saddr (u32 en memoria).
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, unsigned int);
    __type(value, unsigned long long);
    __uint(max_entries, 4096);
} blocked SEC(".maps");

static __always_inline void inc(unsigned int idx)
{
    unsigned long long *v = bpf_map_lookup_elem(&counters, &idx);
    if (v)
        __sync_fetch_and_add(v, 1);
}

static __always_inline void add(unsigned int idx, unsigned long long val)
{
    unsigned long long *v = bpf_map_lookup_elem(&counters, &idx);
    if (v)
        __sync_fetch_and_add(v, val);
}

SEC("xdp")
int xdp_probe(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    inc(IDX_TOTAL);
    add(IDX_BYTES, (void *)(long)ctx->data_end - (void *)(long)ctx->data);

    unsigned short etype = __builtin_bswap16(eth->h_proto);

    if (etype == 0x0806) {                 // ARP
        inc(IDX_ARP);
        return XDP_PASS;
    }

    if (etype == 0x86DD) {                 // IPv6
        inc(IDX_IPV6);
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;
        if (ip6->nexthdr == 44)            // extension header Fragment
            inc(IDX_IPV6_FRAG);
        return XDP_PASS;
    }

    if (etype == 0x0800) {                 // IPv4
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;
        if (bpf_map_lookup_elem(&blocked, &ip->saddr))  // IP bloqueada (respuesta activa)
            return XDP_DROP;
        inc(IDX_IPV4);
        unsigned short frag = __builtin_bswap16(ip->frag_off);
        if (frag & 0x3FFF)                 // MF (0x2000) o fragment offset != 0
            inc(IDX_IPV4_FRAG);
        switch (ip->protocol) {
        case 6:   inc(IDX_TCP); break;
        case 17:  inc(IDX_UDP); break;
        case 1:   inc(IDX_ICMP); break;
        default:  inc(IDX_IPV4_OTHER); break;
        }
        return XDP_PASS;
    }

    if (etype == 0x8100 || etype == 0x88A8)  // VLAN: se pasa sin inspeccionar inner
        return XDP_PASS;

    inc(IDX_UNKNOWN);                      // EtherType no esperado (p. ej. trama no-IP)
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
