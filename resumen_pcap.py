#!/usr/bin/env python3
"""Resumen rápido de una captura .pcap/.pcapng (por ejemplo, del Packet Sniffer de MikroTik).

Muestra: duración, subida/bajada, conversaciones más grandes, puertos, consultas DNS,
nombres TLS (SNI) y coincidencias con patrones sospechosos.

Uso:
    pip install dpkt
    python3 resumen_pcap.py --cliente 198.51.100.10 captura.pcap [otra.pcap ...]

--cliente es la IP de la línea o equipo analizado; con ella se distingue la subida
(lo que envía) de la bajada (lo que recibe).
"""
import argparse
import collections
import datetime
import socket

import dpkt

PUERTOS_SOSPECHOSOS = {9377: "canal de control (caso 2)", 9100: "canal de control (caso 2)",
                       51820: "WireGuard/VPN"}


def leer(path):
    with open(path, "rb") as f:
        magia = f.read(4)
    f = open(path, "rb")
    lector = dpkt.pcapng.Reader(f) if magia == b"\x0a\x0d\x0d\x0a" else dpkt.pcap.Reader(f)
    for ts, raw in lector:
        ip = None
        try:
            eth = dpkt.ethernet.Ethernet(raw)
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
        except Exception:
            pass
        if ip is None:
            try:
                cand = dpkt.ip.IP(raw)
                if cand.v == 4:
                    ip = cand
            except Exception:
                pass
        if ip is not None:
            yield ts, ip


def sni(payload):
    try:
        if len(payload) < 6 or payload[0] != 0x16:
            return None
        hs = dpkt.ssl.TLSHandshake(dpkt.ssl.TLSRecord(payload).data)
        if isinstance(hs.data, dpkt.ssl.TLSClientHello):
            for tipo, valor in hs.data.extensions:
                if tipo == 0:
                    return valor[5:].decode(errors="replace")
    except Exception:
        return None
    return None


def resumir(path, cliente):
    conv = collections.defaultdict(lambda: [0, 0, 0, None, None])  # subida, bajada, paquetes, inicio, fin
    dns, nombres_tls = collections.Counter(), collections.Counter()
    subida = bajada = 0
    t0 = t1 = None
    for ts, ip in leer(path):
        t0 = ts if t0 is None else t0
        t1 = ts
        src, dst = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
        l4 = ip.data
        proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(ip.p, str(ip.p))
        sport, dport = getattr(l4, "sport", 0), getattr(l4, "dport", 0)
        sube = src == cliente
        clave = (dst, dport, proto) if sube else (src, sport, proto)
        c = conv[clave]
        if sube:
            c[0] += ip.len
            subida += ip.len
        else:
            c[1] += ip.len
            bajada += ip.len
        c[2] += 1
        c[3] = ts if c[3] is None else c[3]
        c[4] = ts
        datos = bytes(getattr(l4, "data", b""))
        if proto == "UDP" and dport == 53 and sube:
            try:
                for q in dpkt.dns.DNS(datos).qd:
                    dns[q.name] += 1
            except Exception:
                pass
        if proto == "TCP" and sube and datos:
            n = sni(datos)
            if n:
                nombres_tls[n] += 1

    if t0 is None:
        print(f"{path}: sin paquetes IP")
        return
    hora = lambda t: datetime.datetime.fromtimestamp(t).strftime("%H:%M:%S")
    print(f"\n=== {path}")
    print(f"Duración: {t1 - t0:.0f} s  ({hora(t0)} - {hora(t1)})")
    print(f"Subida: {subida / 1e6:.2f} MB  Bajada: {bajada / 1e6:.2f} MB  "
          f"Bajada/Subida: {bajada / max(subida, 1):.1f}")
    print(f"IP remotas: {len({k[0] for k in conv})}  Conversaciones: {len(conv)}")

    print("\nConversaciones más grandes:")
    for k, v in sorted(conv.items(), key=lambda kv: -(kv[1][0] + kv[1][1]))[:20]:
        print(f"  {k[0]:>15}:{k[1]:<5} {k[2]:4} subida={v[0] / 1e6:7.3f} MB "
              f"bajada={v[1] / 1e6:7.3f} MB paquetes={v[2]}")

    print("\nDNS consultados:", dns.most_common(30))
    print("Nombres TLS (SNI):", nombres_tls.most_common(30))

    print("\nPatrones sospechosos:")
    hallado = False
    for (ip_r, puerto, proto), v in conv.items():
        motivo = PUERTOS_SOSPECHOSOS.get(puerto)
        if proto == "TCP" and 100 <= puerto <= 299:
            motivo = "TCP a puerto 100-299 (caso 1)"
        if motivo:
            hallado = True
            print(f"  {ip_r}:{puerto} {proto} -> {motivo}")
    if subida > bajada and subida > 1e6:
        hallado = True
        print("  La subida supera a la bajada: posible proxy residencial o P2P intenso")
    if not hallado:
        print("  Ninguno")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cliente", required=True, help="IP de la línea/equipo analizado")
    ap.add_argument("capturas", nargs="+")
    a = ap.parse_args()
    for p in a.capturas:
        resumir(p, a.cliente)
