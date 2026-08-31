from __future__ import annotations

import ipaddress
import json
import urllib.request


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True


def locate_ip(ip: str) -> dict:
    if not ip or ip in ("local", "-", "None"):
        return {"ip": ip, "kind": "local", "lat": None, "lon": None, "label": "local"}
    if is_private_ip(ip):
        parts = ip.split(".")
        last = int(parts[-1]) if parts[-1].isdigit() else 0
        prev = int(parts[-2]) if len(parts) > 1 and parts[-2].isdigit() else 0
        lat = 38.7 + (last % 50) * 0.01
        lon = -9.1 + (prev % 50) * 0.01
        return {
            "ip": ip,
            "kind": "lan",
            "lat": lat,
            "lon": lon,
            "label": f"{ip} (LAB / LAN)",
        }
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,query"
        with urllib.request.urlopen(url, timeout=6) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        if data.get("status") != "success":
            return {"ip": ip, "kind": "public", "lat": None, "lon": None, "label": ip}
        city = data.get("city") or ""
        country = data.get("country") or ""
        label = ", ".join(x for x in (city, country) if x) or ip
        return {
            "ip": ip,
            "kind": "public",
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "label": label,
        }
    except Exception:
        return {"ip": ip, "kind": "public", "lat": None, "lon": None, "label": ip}


def locate_many(ips: list[str]) -> list[dict]:
    seen, out = [], []
    for ip in ips:
        if not ip or ip in seen:
            continue
        seen.append(ip)
        out.append(locate_ip(ip))
    return out