#!/usr/bin/env python3
"""
shodan_enum.py — Herramienta de enumeración Shodan para pentesting
Uso:
  python3 shodan_enum.py 8.8.8.8
  python3 shodan_enum.py 8.8.8.8 1.1.1.1
  python3 shodan_enum.py ips.txt
  python3 shodan_enum.py 8.8.8.8 --no-color
"""

import sys
import json
import os
import requests
from datetime import datetime

# ─────────────────────────────────────────
#  CONFIGURACIÓN
#  Recomendado: define la variable de entorno SHODAN_API_KEY
#  en tu terminal:  export SHODAN_API_KEY="tu_key_aqui"
#  O pégala directamente abajo como respaldo:
# ─────────────────────────────────────────
API_KEY = os.environ.get("SHODAN_API_KEY", "TU_API_KEY_AQUI")
API_URL = "https://api.shodan.io/shodan/host/{}"

# ─── Colores ANSI ─────────────────────────────────────────────────────────────
USE_COLOR = "--no-color" not in sys.argv

def c(text, code):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text

def verde(t):   return c(t, "92")
def rojo(t):    return c(t, "91")
def amarillo(t):return c(t, "93")
def azul(t):    return c(t, "94")
def cyan(t):    return c(t, "96")
def blanco_bold(t): return c(t, "1")
def gris(t):    return c(t, "90")
def magenta(t): return c(t, "95")

# ─── Helpers ──────────────────────────────────────────────────────────────────
def sep(char="─", width=70):
    return gris(char * width)

def banner():
    print()
    print(blanco_bold("╔══════════════════════════════════════════════════════════════════════╗"))
    print(blanco_bold("║") + cyan("         🔍  SHODAN ENUMERATOR — Pentesting Recon Tool              ") + blanco_bold("║"))
    print(blanco_bold("╚══════════════════════════════════════════════════════════════════════╝"))
    print(gris(f"  Inicio: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
    print()

def load_ips(path):
    with open(path, "r", encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]

# ─── Consulta a Shodan ────────────────────────────────────────────────────────
def query_ip(ip):
    try:
        r = requests.get(API_URL.format(ip), params={"key": API_KEY}, timeout=10)
        if r.status_code == 200:
            data = r.json()
            return {"ip": ip, "ok": True, "data": data}
        elif r.status_code == 404:
            return {"ip": ip, "ok": False, "status": 404, "msg": "Sin resultados en Shodan"}
        elif r.status_code == 401:
            return {"ip": ip, "ok": False, "status": 401, "msg": "API key inválida o sin permisos"}
        else:
            return {"ip": ip, "ok": False, "status": r.status_code, "msg": r.text[:200]}
    except requests.exceptions.Timeout:
        return {"ip": ip, "ok": False, "msg": "Timeout al conectar con Shodan"}
    except Exception as e:
        return {"ip": ip, "ok": False, "msg": str(e)}

# ─── Impresión de resultados ──────────────────────────────────────────────────
def print_result(res):
    ip = res["ip"]

    if not res.get("ok"):
        print(f"  {rojo('✗')} {blanco_bold(ip)}  →  {amarillo(res.get('msg', 'Error desconocido'))}")
        print()
        return

    d = res["data"]

    # Encabezado
    print(sep())
    print(f"  {verde('✔')}  {blanco_bold(ip)}")
    print(sep())

    # Información general
    org      = d.get("org") or d.get("isp") or "—"
    asn      = d.get("asn", "—")
    country  = d.get("country_name", "—")
    city     = d.get("city", "—")
    os_name  = d.get("os") or "—"
    hostnames= d.get("hostnames", [])
    domains  = d.get("domains", [])
    tags     = d.get("tags", [])
    vulns    = d.get("vulns", {})
    ports    = d.get("ports", [])
    last_update = d.get("last_update", "—")

    print(f"  {cyan('Organización')}  : {org}")
    print(f"  {cyan('ASN')}           : {asn}")
    print(f"  {cyan('Ubicación')}     : {city}, {country}")
    print(f"  {cyan('Sistema Op.')}   : {os_name}")
    print(f"  {cyan('Última scan')}   : {last_update}")

    if hostnames:
        print(f"  {cyan('Hostnames')}     : {', '.join(hostnames)}")
    if domains:
        print(f"  {cyan('Dominios')}      : {', '.join(domains)}")
    if tags:
        tag_str = "  ".join([amarillo(t) for t in tags])
        print(f"  {cyan('Tags')}          : {tag_str}")

    # Puertos abiertos
    if ports:
        ports_str = "  ".join([verde(str(p)) for p in sorted(ports)])
        print(f"\n  {blanco_bold('Puertos abiertos')} ({len(ports)}):")
        print(f"    {ports_str}")

    # Servicios / Banners
    services = d.get("data", [])
    if services:
        print(f"\n  {blanco_bold('Servicios detectados')}:")
        for svc in services:
            port      = svc.get("port", "?")
            transport = svc.get("transport", "tcp").upper()
            product   = svc.get("product", "")
            version   = svc.get("version", "")
            module    = svc.get("_shodan", {}).get("module", "")
            raw_banner = (svc.get("data") or "").strip()
            banner = " ".join(raw_banner.split())[:100]  # colapsa whitespace/newlines
            cpes      = svc.get("cpe", [])

            product_str = f"{product} {version}".strip() if product else module
            print(f"    {verde(str(port))}/{gris(transport)}  {azul(product_str or '—')}")
            if banner:
                print(f"      {gris('Banner:')} {gris(banner)}")
            if cpes:
                print(f"      {gris('CPE:')}    {gris(', '.join(cpes[:3]))}")

    # Vulnerabilidades
    if vulns:
        print(f"\n  {blanco_bold('Vulnerabilidades')} ({len(vulns)}):")
        for cve_id, info in list(vulns.items())[:10]:
            cvss    = info.get("cvss", "?")
            summary = info.get("summary", "")[:90]
            color   = rojo if float(cvss or 0) >= 7 else amarillo
            print(f"    {color(cve_id)}  CVSS: {color(str(cvss))}")
            if summary:
                print(f"      {gris(summary)}")
        if len(vulns) > 10:
            print(f"    {gris(f'... y {len(vulns)-10} más en el JSON completo')}")

    print()

# ─── Resumen final ─────────────────────────────────────────────────────────────
def print_summary(results):
    total   = len(results)
    ok      = sum(1 for r in results if r.get("ok"))
    err     = total - ok
    all_ports = {}
    total_vulns = 0

    for r in results:
        if r.get("ok"):
            total_vulns += len(r.get("vulns", []))
            for p in r.get("ports", []):
                all_ports[p] = all_ports.get(p, 0) + 1

    top_ports = sorted(all_ports.items(), key=lambda x: -x[1])[:10]

    print(sep("═"))
    print(blanco_bold("  RESUMEN FINAL"))
    print(sep("═"))
    print(f"  IPs consultadas  : {blanco_bold(str(total))}")
    print(f"  Con resultados   : {verde(str(ok))}")
    print(f"  Sin resultados   : {rojo(str(err))}")
    print(f"  Total CVEs       : {(rojo if total_vulns > 0 else verde)(str(total_vulns))}")

    if top_ports:
        top_str = "  ".join([f"{verde(str(p))}({n})" for p, n in top_ports])
        print(f"  Puertos frecuentes: {top_str}")
    print(sep("═"))
    print()

# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]

    if not args:
        print(__doc__)
        sys.exit(0)

    if API_KEY == "TU_API_KEY_AQUI":
        print(rojo("⚠  No se encontró la API key de Shodan."))
        print("   Define la variable de entorno SHODAN_API_KEY o edita el script.")
        sys.exit(1)

    banner()

    if len(args) == 1 and args[0].endswith(".txt"):
        ips = load_ips(args[0])
        print(gris(f"  Cargadas {len(ips)} IPs desde {args[0]}\n"))
    else:
        ips = args

    raw_results = []
    for ip in ips:
        print(gris(f"  Consultando {ip} ..."))
        res = query_ip(ip)
        print_result(res)

        # Guardar versión limpia para JSON
        entry = {"ip": ip, "ok": res.get("ok")}
        if res.get("ok"):
            d = res["data"]
            entry.update({
                "org": d.get("org") or d.get("isp"),
                "asn": d.get("asn"),
                "country": d.get("country_name"),
                "city": d.get("city"),
                "os": d.get("os"),
                "ports": d.get("ports", []),
                "hostnames": d.get("hostnames", []),
                "domains": d.get("domains", []),
                "tags": d.get("tags", []),
                "vulns": list(d.get("vulns", {}).keys()),
                "services": [
                    {
                        "port": s.get("port"),
                        "transport": s.get("transport"),
                        "product": s.get("product"),
                        "version": s.get("version"),
                        "banner": (s.get("data") or "").strip()[:200],
                        "cpe": s.get("cpe", []),
                    }
                    for s in d.get("data", [])
                ],
                "raw": d,
            })
        else:
            entry["error"] = res.get("msg")
        raw_results.append(entry)

    print_summary(raw_results)

    # Guardar JSON
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = f"shodan_results_{ts}.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(raw_results, f, ensure_ascii=False, indent=2)
    print(verde(f"  ✔ Resultados guardados en: {out_file}"))
    print()

if __name__ == "__main__":
    main()
