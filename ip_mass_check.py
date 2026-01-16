#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ip_mass_check.py — Массовая проверка репутации IP-адресов + бенчмарк прокси.

Режимы:
  • Обычный: IP и/или CIDR (аргументы/--input).
  • Прокси (--proxies): резолв exit IP → проверка → (опц.) DNSLeak + бенчмарк.

Источники (ядро):
  - ipwho.is       → geo/ASN/ORG + security: vpn/proxy/tor/hosting (без ключа)
  - ip-api.com     → контроль geo/ISP/ORG + proxy/hosting (без ключа)
  - AbuseIPDB (опц)→ история жалоб (ключ в окружении ABUSEIPDB_KEY)

Опциональные плагины (флагами CLI):
  - IPinfo (--ipinfo-token)          → privacy proxy/vpn/tor/hosting/anycast, ASN/ORG
  - IPQualityScore (--ipqs-key)      → fraud_score 0..100 + proxy/vpn/tor/recent_abuse
  - Spamhaus ZEN (--spamhaus)        → DNSBL через dnspython (мягкая зависимость)
  - Scamalytics (--scamalytics-scrape) → щадящий HTML-скрейп публичной страницы

DNS Leak (только для --proxies):
  - Маркер схемы: socks5 (локальный DNS) vs socks5h (удалённый DNS)
  - DoH sanity-check (Cloudflare DoH) через прокси

Бенчмарк производительности (только для --proxies, по флагу --bench):
  - RTT_ms   — время установления соединения (HEAD)
  - TTFB_ms  — время до первого байта (GET stream)
  - DL_Mbps  — средняя скорость скачивания первых N байт
  - BenchURL — тестовый URL (по умолчанию https://speed.hetzner.de/100MB.bin)

Жёсткий режим:
  - Единый RiskScore (0–100) и RiskTier (low/medium/elevated/high/critical)
  - Verdict → SUSPICIOUS при RiskTier ∈ {high, critical}

Зависимости:
  pip install requests
  pip install "requests[socks]"     # при использовании SOCKS-прокси
  pip install dnspython             # для --spamhaus (DNSBL)
"""

from __future__ import annotations

import os, sys, csv, time, random, re, math, io
import argparse
import ipaddress
from typing import Any, Dict, List, Optional, Tuple, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# ───────────────────────── Константы ─────────────────────────

IPWHO_URL = "https://ipwho.is/{ip}"
IPAPI_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,proxy,hosting,query"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# Новые провайдеры
IPINFO_URL = "https://ipinfo.io/{ip}?token={token}"
IPQS_URL   = "https://ipqualityscore.com/api/json/ip/{key}/{ip}?strictness=1&allow_public_access_points=true"
SCAMALYTICS_URL = "https://scamalytics.com/ip/{ip}"
SCAMALYTICS_RX  = re.compile(r"Fraud Score:\s*([0-9]{1,3})", re.IGNORECASE)

DEFAULT_TIMEOUT = 12
DEFAULT_THREADS_FACTOR = 5
DEFAULT_SLEEP_MIN = 0.15
DEFAULT_SLEEP_MAX = 0.35
DEFAULT_RETRIES = 2
CSV_DEFAULT = "ip_report.csv"
INPUT_DEFAULT = "ips.txt"

# Резолв внешнего IP через прокси:
PROXY_RESOLVE_URL_1 = "http://ip-api.com/json"              # быстрый http
PROXY_RESOLVE_URL_2 = "https://api.ipify.org?format=json"   # https fallback

# DoH sanity-check
DOH_TEST_URL = "https://cloudflare-dns.com/dns-query?name=example.com&type=A"
DOH_HDRS = {"accept": "application/dns-json"}

HOSTING_KEYWORDS = [
    "amazon", "aws", "amazon.com", "google cloud", "gcp", "google llc", "google",
    "digitalocean", "ovh", "hetzner", "contabo", "linode", "scaleway", "leaseweb",
    "m247", "akamai", "vultr", "choopa", "azure", "microsoft", "oracle cloud",
    "equinix", "ovhcloud", "lease web", "ovh sas", "ovhhosting", "ovh sp", "cloudflare",
    "do-sp", "hetzner online", "hcloud", "choopa llc", "frantech", "buyvm", "ovh ltd"
]

# ────────────────────── Утилиты ──────────────────────

def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def expand_target(token: str) -> Iterable[str]:
    token = token.strip()
    if not token:
        return []
    if "/" in token:
        try:
            net = ipaddress.ip_network(token, strict=False)
            return (str(ip) for ip in net.hosts()) if net.num_addresses > 2 else (str(ip) for ip in net)
        except ValueError:
            return []
    return [token] if is_ip(token) else []

def bounded_expand(tokens: Iterable[str], max_expand: int) -> List[str]:
    out: List[str] = []
    for t in tokens:
        for ip in expand_target(t):
            out.append(ip)
            if len(out) >= max_expand:
                return out
    return out

def jitter_sleep(a: float, b: float) -> None:
    time.sleep(random.uniform(a, b))

def http_get_json(session: requests.Session, url: str, headers: Optional[Dict[str, str]] = None,
                  timeout: int = DEFAULT_TIMEOUT, retries: int = DEFAULT_RETRIES,
                  proxies: Optional[Dict[str,str]] = None) -> Dict[str, Any]:
    last_err: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            r = session.get(url, headers=headers or {}, timeout=timeout, proxies=proxies)
            if r.status_code in (429, 502, 503, 504):
                raise requests.HTTPError(f"HTTP {r.status_code}")
            r.raise_for_status()
            try:
                return r.json()
            except Exception:
                return {"_raw": r.text}
        except Exception as e:
            last_err = e
            sleep_s = min(2.0 * (attempt + 1), 6.0) + random.uniform(0.05, 0.25)
            time.sleep(sleep_s)
    raise last_err if last_err else RuntimeError("Unknown network error")

def contains_hosting_keyword(s: Optional[str]) -> bool:
    if not s:
        return False
    low = s.lower()
    return any(k in low for k in HOSTING_KEYWORDS)

def normalize(s: Optional[Any]) -> str:
    if s is None:
        return ""
    try:
        return str(s).replace("\n", " ").strip()
    except Exception:
        return ""

# ──────────────── Парсинг прокси и резолв IP ────────────────

def parse_proxy_line(line: str, default_scheme: str = "http") -> Optional[str]:
    s = (line or "").strip()
    if not s:
        return None
    if "://" in s:
        return s
    parts = s.split(":")
    if len(parts) == 2:
        host, port = parts
        return f"{default_scheme}://{host}:{port}"
    if len(parts) == 4:
        host, port, user, pwd = parts
        return f"{default_scheme}://{user}:{pwd}@{host}:{port}"
    return None

def resolve_proxy_exit_ip(proxy_url: str, timeout: float = 8.0) -> Tuple[Optional[str], Dict[str, Any]]:
    sess = requests.Session()
    proxies = {"http": proxy_url, "https": proxy_url}
    try:
        data = http_get_json(sess, PROXY_RESOLVE_URL_1, timeout=timeout, retries=1, proxies=proxies)
        ip = data.get("query") or None
        meta = {"country": data.get("country"), "region": data.get("regionName"), "city": data.get("city")}
        if ip:
            return ip, meta
    except Exception:
        pass
    try:
        data2 = http_get_json(sess, PROXY_RESOLVE_URL_2, timeout=timeout, retries=1, proxies=proxies)
        ip2 = (data2.get("ip") if isinstance(data2, dict) else None)
        if ip2:
            return ip2, {}
    except Exception:
        pass
    return None, {}

# ────────────────────── Провайдеры ──────────────────────

def fetch_ipwho(session: requests.Session, ip: str) -> Dict[str, Any]:
    data = http_get_json(session, IPWHO_URL.format(ip=ip))
    return {
        "ok": bool(data.get("success", False)),
        "country": data.get("country"),
        "region": data.get("region"),
        "city": data.get("city"),
        "org": (data.get("connection") or {}).get("org") or data.get("org"),
        "isp": (data.get("connection") or {}).get("isp") or data.get("isp"),
        "asn": (data.get("connection") or {}).get("asn") or data.get("asn"),
        "security": data.get("security") or {},
        "_raw": data
    }

def fetch_ipapi(session: requests.Session, ip: str) -> Dict[str, Any]:
    data = http_get_json(session, IPAPI_URL.format(ip=ip))
    ok = data.get("status") == "success"
    return {
        "ok": ok,
        "country": data.get("country"),
        "region": data.get("regionName"),
        "city": data.get("city"),
        "org": data.get("org"),
        "isp": data.get("isp"),
        "asn": data.get("as"),
        "proxy": data.get("proxy"),
        "hosting": data.get("hosting"),
        "_raw": data
    }

def fetch_abuseipdb(session: requests.Session, ip: str, key: Optional[str]) -> Dict[str, Any]:
    if not key:
        return {"enabled": False}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
    headers = {"Key": key, "Accept": "application/json"}
    try:
        r = session.get(ABUSEIPDB_URL, params=params, headers=headers, timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()
        payload = r.json().get("data", {}) if r.text else {}
        score = int(payload.get("abuseConfidenceScore", 0)) if payload else 0
        total_reports = int(payload.get("totalReports", 0)) if payload else 0
        return {
            "enabled": True,
            "score": score,
            "total_reports": total_reports,
            "is_whitelisted": bool(payload.get("isWhitelisted", False)),
            "isp": payload.get("isp"),
            "domain": payload.get("domain"),
            "_raw": payload
        }
    except Exception as e:
        return {"enabled": True, "error": str(e)}

def fetch_ipinfo(session: requests.Session, ip: str, token: Optional[str]) -> Dict[str, Any]:
    if not token:
        return {"enabled": False}
    try:
        data = http_get_json(session, IPINFO_URL.format(ip=ip, token=token))
        privacy = data.get("privacy") or {}
        org = data.get("org") or ""
        asn = org.split()[0] if org.startswith("AS") else ""
        return {
            "enabled": True,
            "asn": asn,
            "org": org,
            "hosting": bool(privacy.get("hosting")),
            "proxy": bool(privacy.get("proxy")),
            "vpn": bool(privacy.get("vpn")),
            "tor": bool(privacy.get("tor")),
            "anycast": bool(data.get("anycast")),
            "_raw": data
        }
    except Exception as e:
        return {"enabled": True, "error": f"ipinfo: {e}"}

def fetch_ipqs(session: requests.Session, ip: str, key: Optional[str]) -> Dict[str, Any]:
    if not key:
        return {"enabled": False}
    try:
        data = http_get_json(session, IPQS_URL.format(key=key, ip=ip))
        return {
            "enabled": True,
            "fraud_score": data.get("fraud_score"),
            "proxy": bool(data.get("proxy")),
            "vpn": bool(data.get("vpn")),
            "tor": bool(data.get("tor")),
            "recent_abuse": bool(data.get("recent_abuse")),
            "_raw": data
        }
    except Exception as e:
        return {"enabled": True, "error": f"ipqs: {e}"}

def fetch_scamalytics(session: requests.Session, ip: str, enabled: bool) -> Dict[str, Any]:
    if not enabled:
        return {"enabled": False}
    try:
        r = session.get(SCAMALYTICS_URL.format(ip=ip), timeout=DEFAULT_TIMEOUT)
        if r.status_code != 200:
            return {"enabled": True, "error": f"http {r.status_code}"}
        m = SCAMALYTICS_RX.search(r.text or "")
        score = int(m.group(1)) if m else None
        return {"enabled": True, "fraud_score": score}
    except Exception as e:
        return {"enabled": True, "error": f"scamalytics: {e}"}

def spamhaus_lookup(ip: str, resolver_ip: str = "8.8.8.8") -> Dict[str, Any]:
    try:
        import dns.resolver
        reversed_ip = ".".join(reversed(ip.split(".")))
        qname = f"{reversed_ip}.zen.spamhaus.org"
        res = dns.resolver.Resolver(configure=True)
        res.nameservers = [resolver_ip]
        answers = res.resolve(qname, "A")
        listed = [str(r) for r in answers]
        txt = []
        try:
            txt_ans = res.resolve(qname, "TXT")
            for rr in txt_ans:
                try:
                    parts = getattr(rr, "strings", None)
                    if parts:
                        txt.append(b"".join(parts).decode("utf-8", "ignore"))
                    else:
                        txt.append(rr.to_text().strip('"'))
                except Exception:
                    pass
        except Exception:
            pass
        return {"enabled": True, "listed": True, "codes": listed, "txt": "|".join(txt)}
    except Exception:
        return {"enabled": True, "listed": False}

# ────────────────────── Базовый вердикт ──────────────────────

def verdict_for(ipwho: Dict[str, Any], ipapi: Dict[str, Any], abuse: Dict[str, Any]) -> Tuple[str, List[str]]:
    reasons: List[str] = []
    sec = ipwho.get("security") or {}
    if sec.get("proxy") is True:   reasons.append("Proxy flag (ipwho.is)")
    if sec.get("vpn") is True:     reasons.append("VPN flag (ipwho.is)")
    if sec.get("tor") is True:     reasons.append("TOR flag (ipwho.is)")
    if sec.get("hosting") is True: reasons.append("Hosting flag (ipwho.is)")
    if ipapi.get("proxy") is True: reasons.append("Proxy flag (ip-api)")
    if ipapi.get("hosting") is True: reasons.append("Hosting flag (ip-api)")
    org = normalize(ipwho.get("org")) or normalize(ipwho.get("isp")) or normalize(ipapi.get("org")) or normalize(ipapi.get("isp"))
    asn = normalize(ipwho.get("asn")) or normalize(ipapi.get("asn"))
    if contains_hosting_keyword(org) or contains_hosting_keyword(asn):
        reasons.append("Hosting ASN/ORG heuristic")
    if ipwho.get("ok") and ipapi.get("ok"):
        c1, c2 = ipwho.get("country"), ipapi.get("country")
        if c1 and c2 and c1 != c2:
            reasons.append(f"Geo mismatch ({c1} vs {c2})")
    if abuse.get("enabled"):
        if "error" in abuse:
            reasons.append("AbuseIPDB error: " + abuse["error"])
        else:
            score = int(abuse.get("score", 0)); reports = int(abuse.get("total_reports", 0))
            if score >= 25 and reports >= 3:
                reasons.append(f"AbuseIPDB score={score}, reports={reports}")
    return ("SUSPICIOUS", reasons) if reasons else ("CLEAN", ["No red flags found"])

# ────────────────────── Жёсткий режим: единый риск ──────────────────────

def compute_risk(ipwho, ipapi, abuse, ipqs, scam, spam) -> Tuple[int, str, List[str]]:
    score = 0
    reasons: List[str] = []
    if ipqs.get("enabled") and "error" not in ipqs:
        fs = ipqs.get("fraud_score")
        if isinstance(fs, int):
            if fs >= 90: score += 40; reasons.append(f"IPQS {fs} (critical)")
            elif fs >= 75: score += 30; reasons.append(f"IPQS {fs} (high)")
            elif fs >= 50: score += 15; reasons.append(f"IPQS {fs} (elevated)")
            elif fs >= 25: score += 5;  reasons.append(f"IPQS {fs} (medium)")
        if ipqs.get("recent_abuse"): score += 10; reasons.append("IPQS:recent_abuse")
        if ipqs.get("proxy"): reasons.append("IPQS:proxy")
        if ipqs.get("vpn"):   reasons.append("IPQS:vpn")
        if ipqs.get("tor"):   reasons.append("IPQS:tor")
    if spam.get("enabled") and spam.get("listed"):
        score += 25; reasons.append(f"Spamhaus listed {','.join(spam.get('codes', []))}".strip())
    if abuse.get("enabled") and "error" not in abuse:
        ab_score = int(abuse.get("score", 0)); reports = int(abuse.get("total_reports", 0))
        if ab_score >= 25 and reports >= 3:
            score += 20; reasons.append(f"AbuseIPDB score={ab_score}, reports={reports}")
    sec = (ipwho or {}).get("security") or {}
    if sec.get("proxy") or ipapi.get("proxy"):      score += 8; reasons.append("Proxy flag (who/api)")
    if sec.get("vpn"):                               score += 8; reasons.append("VPN flag (who)")
    if sec.get("tor"):                               score += 8; reasons.append("TOR flag (who)")
    if sec.get("hosting") or ipapi.get("hosting"):   score += 6; reasons.append("Hosting flag (who/api)")
    if scam.get("enabled") and "error" not in scam:
        sc = scam.get("fraud_score")
        if isinstance(sc, int):
            if sc >= 70: score += 12; reasons.append(f"Scamalytics {sc} (high)")
            elif sc >= 40: score += 6;  reasons.append(f"Scamalytics {sc} (med)")
    score = max(0, min(100, score))
    if score >= 85: tier = "critical"
    elif score >= 70: tier = "high"
    elif score >= 50: tier = "elevated"
    elif score >= 25: tier = "medium"
    else: tier = "low"
    return score, tier, reasons

# ────────────────────── DNS Leaks ──────────────────────

def detect_dns_leak_marker(proxy_url: Optional[str]) -> str:
    if not proxy_url: return "N/A"
    if proxy_url.startswith("socks5://"):  return "LOCAL_DNS?"
    if proxy_url.startswith("socks5h://"): return "OK"
    return "OK"

def doh_sanity_check(session: requests.Session, proxy_url: Optional[str]) -> bool:
    try:
        proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
        r = session.get(DOH_TEST_URL, headers=DOH_HDRS, timeout=6, proxies=proxies)
        return r.ok
    except Exception:
        return False

# ────────────────────── Бенчмарк прокси ──────────────────────

def benchmark_proxy(proxy_url: str, url: str, nbytes: int, timeout: float) -> Dict[str, Any]:
    """
    Возвращает: {"RTT_ms":..., "TTFB_ms":..., "DL_Mbps":..., "BenchURL": url}
    RTT_ms  — время HEAD (соединение+заголовки).
    TTFB_ms — время до первого байта контента (GET stream=True).
    DL_Mbps — средняя скорость скачивания первых nbytes.
    """
    proxies = {"http": proxy_url, "https": proxy_url}
    s = requests.Session()

    t0 = time.perf_counter()
    r_head = s.head(url, timeout=timeout, proxies=proxies, allow_redirects=True)
    r_head.raise_for_status()
    rtt_ms = (time.perf_counter() - t0) * 1000.0

    t1 = time.perf_counter()
    r_get = s.get(url, timeout=timeout, proxies=proxies, stream=True, allow_redirects=True)
    r_get.raise_for_status()
    first_byte = None
    total = 0
    for chunk in r_get.iter_content(chunk_size=64_000):
        now = time.perf_counter()
        if first_byte is None:
            first_byte = now
        if not chunk:
            continue
        total += len(chunk)
        if total >= nbytes:
            break
    try:
        r_get.close()
    except Exception:
        pass

    ttfb_ms = (first_byte - t1) * 1000.0 if first_byte else float("nan")
    elapsed = (now - first_byte) if first_byte else float("nan")
    dl_mbps = (total * 8 / 1_000_000) / elapsed if first_byte and elapsed > 0 else 0.0

    return {
        "RTT_ms": round(rtt_ms, 1),
        "TTFB_ms": round(ttfb_ms, 1) if not math.isnan(ttfb_ms) else "",
        "DL_Mbps": round(dl_mbps, 2),
        "BenchURL": url
    }

# ────────────────────── Обработка IP/прокси ──────────────────────

def process_ip(
    ip: str,
    abuse_key: Optional[str],
    sleep_min: float,
    sleep_max: float,
    session_ipwho: requests.Session,
    session_ipapi: requests.Session,
    session_abuse: requests.Session,
    session_extra: requests.Session,
    ipinfo_token: Optional[str],
    ipqs_key: Optional[str],
    scamalytics_enabled: bool,
    spamhaus_enabled: bool,
    spamhaus_resolver: str
) -> Dict[str, Any]:
    jitter_sleep(sleep_min, sleep_max)
    try:   ipwho = fetch_ipwho(session_ipwho, ip)
    except Exception as e: ipwho = {"ok": False, "_error": f"ipwho.is: {e}"}

    jitter_sleep(sleep_min, sleep_max)
    try:   ipapi = fetch_ipapi(session_ipapi, ip)
    except Exception as e: ipapi = {"ok": False, "_error": f"ip-api.com: {e}"}

    abuse = fetch_abuseipdb(session_abuse, ip, abuse_key)
    ipinfo = fetch_ipinfo(session_extra, ip, ipinfo_token)
    ipqs   = fetch_ipqs(session_extra, ip, ipqs_key)
    scam   = fetch_scamalytics(session_extra, ip, scamalytics_enabled)
    spam   = spamhaus_lookup(ip, spamhaus_resolver) if spamhaus_enabled else {"enabled": False}

    verdict, reasons = verdict_for(ipwho, ipapi, abuse)
    risk_score, risk_tier, extra_reasons = compute_risk(ipwho, ipapi, abuse, ipqs, scam, spam)
    if risk_tier in ("high", "critical"):
        verdict = "SUSPICIOUS"
    if extra_reasons:
        reasons.extend(extra_reasons)

    country = normalize(ipwho.get("country") or ipapi.get("country"))
    region  = normalize(ipwho.get("region")  or ipapi.get("region"))
    city    = normalize(ipwho.get("city")    or ipapi.get("city"))
    org     = normalize(ipwho.get("org")     or ipapi.get("org"))
    isp     = normalize(ipwho.get("isp")     or ipapi.get("isp"))
    asn     = normalize(ipwho.get("asn")     or ipapi.get("asn"))

    sec = ipwho.get("security") or {}
    flags_short: List[str] = []
    if sec.get("proxy"):   flags_short.append("ipwho:proxy")
    if sec.get("vpn"):     flags_short.append("ipwho:vpn")
    if sec.get("tor"):     flags_short.append("ipwho:tor")
    if sec.get("hosting"): flags_short.append("ipwho:hosting")
    if ipapi.get("proxy"):   flags_short.append("ipapi:proxy")
    if ipapi.get("hosting"): flags_short.append("ipapi:hosting")
    if ipinfo.get("enabled") and "error" not in ipinfo:
        if ipinfo.get("proxy"):   flags_short.append("ipinfo:proxy")
        if ipinfo.get("vpn"):     flags_short.append("ipinfo:vpn")
        if ipinfo.get("tor"):     flags_short.append("ipinfo:tor")
        if ipinfo.get("hosting"): flags_short.append("ipinfo:hosting")
    if ipqs.get("enabled") and "error" not in ipqs:
        fs = ipqs.get("fraud_score")
        if isinstance(fs, int): flags_short.append(f"ipqs:{fs}")
    if risk_tier in ("high","critical"):
        flags_short.append(f"risk:{risk_tier}")

    row: Dict[str, Any] = {
        "IP": ip,
        "Country": country,
        "Region": region,
        "City": city,
        "ORG": org,
        "ISP": isp,
        "ASN": asn,
        "ipwho_proxy":   int(bool(sec.get("proxy"))) if sec else 0,
        "ipwho_vpn":     int(bool(sec.get("vpn"))) if sec else 0,
        "ipwho_tor":     int(bool(sec.get("tor"))) if sec else 0,
        "ipwho_hosting": int(bool(sec.get("hosting"))) if sec else 0,
        "ipapi_proxy":   int(bool(ipapi.get("proxy"))),
        "ipapi_hosting": int(bool(ipapi.get("hosting"))),
        "Abuse_Score":   (abuse.get("score") if abuse.get("enabled") and "error" not in abuse else ""),
        "Abuse_Reports": (abuse.get("total_reports") if abuse.get("enabled") and "error" not in abuse else ""),
        "RiskScore":     risk_score,
        "RiskTier":      risk_tier,
        "IPQS_FraudScore":  ipqs.get("fraud_score") if ipqs.get("enabled") and "error" not in ipqs else "",
        "IPQS_Proxy":       int(bool(ipqs.get("proxy"))) if ipqs.get("enabled") and "error" not in ipqs else "",
        "IPQS_VPN":         int(bool(ipqs.get("vpn"))) if ipqs.get("enabled") and "error" not in ipqs else "",
        "IPQS_Tor":         int(bool(ipqs.get("tor"))) if ipqs.get("enabled") and "error" not in ipqs else "",
        "IPQS_RecentAbuse": int(bool(ipqs.get("recent_abuse"))) if ipqs.get("enabled") and "error" not in ipqs else "",
        "IPINFO_PrivacyProxy": int(bool(ipinfo.get("proxy"))) if ipinfo.get("enabled") and "error" not in ipinfo else "",
        "IPINFO_PrivacyVpn":   int(bool(ipinfo.get("vpn"))) if ipinfo.get("enabled") and "error" not in ipinfo else "",
        "IPINFO_Hosting":      int(bool(ipinfo.get("hosting"))) if ipinfo.get("enabled") and "error" not in ipinfo else "",
        "IPINFO_Anycast":      int(bool(ipinfo.get("anycast"))) if ipinfo.get("enabled") and "error" not in ipinfo else "",
        "IPINFO_ASN":          ipinfo.get("asn") if ipinfo.get("enabled") and "error" not in ipinfo else "",
        "SpamhausListed":      (1 if spam.get("enabled") and spam.get("listed") else 0) if spam.get("enabled") else "",
        "SpamhausZones":       "|".join(spam.get("codes", [])) if spam.get("enabled") else "",
        "Scamalytics_FraudScore": scam.get("fraud_score") if scam.get("enabled") and "error" not in scam else "",
        "Verdict": verdict,
        "Flags": "; ".join(reasons),
        "FlagsShort": ", ".join(flags_short) if flags_short else "-",
        # В режиме прокси добавим позже: Proxy, DNSLeak, RTT_ms, TTFB_ms, DL_Mbps, BenchURL
    }

    for prov in (ipinfo, ipqs, scam):
        if prov.get("enabled") and prov.get("error"):
            row["Flags"] += f"; {prov['error']}"
    if spam.get("enabled") and spam.get("listed"):
        row["Flags"] += "; Spamhaus: listed"
    return row

def process_proxy(
    proxy_line: str,
    default_scheme: str,
    resolve_timeout: float,
    abuse_key: Optional[str],
    sleep_min: float,
    sleep_max: float,
    session_ipwho: requests.Session,
    session_ipapi: requests.Session,
    session_abuse: requests.Session,
    session_extra: requests.Session,
    ipinfo_token: Optional[str],
    ipqs_key: Optional[str],
    scamalytics_enabled: bool,
    spamhaus_enabled: bool,
    spamhaus_resolver: str,
    dns_leak_check: bool,
    bench_enabled: bool,
    bench_url: str,
    bench_bytes: int,
    bench_timeout: float
) -> Dict[str, Any]:
    proxy_url = parse_proxy_line(proxy_line, default_scheme=default_scheme)
    if not proxy_url:
        return {
            "IP": "", "Verdict": "ERROR", "Flags": "Bad proxy line format",
            "Country": "", "Region": "", "City": "", "ORG": "", "ISP": "", "ASN": "",
            "ipwho_proxy": "", "ipwho_vpn": "", "ipwho_tor": "", "ipwho_hosting": "",
            "ipapi_proxy": "", "ipapi_hosting": "",
            "Abuse_Score": "", "Abuse_Reports": "",
            "RiskScore": "", "RiskTier": "",
            "IPQS_FraudScore": "", "IPQS_Proxy": "", "IPQS_VPN": "", "IPQS_Tor": "", "IPQS_RecentAbuse": "",
            "IPINFO_PrivacyProxy": "", "IPINFO_PrivacyVpn": "", "IPINFO_Hosting": "", "IPINFO_Anycast": "", "IPINFO_ASN": "",
            "SpamhausListed": "", "SpamhausZones": "", "Scamalytics_FraudScore": "",
            "FlagsShort": "-", "Proxy": proxy_line.strip(), "DNSLeak": "",
            "RTT_ms": "", "TTFB_ms": "", "DL_Mbps": "", "BenchURL": ""
        }
    ip, _meta = resolve_proxy_exit_ip(proxy_url, timeout=resolve_timeout)
    if not ip:
        return {
            "IP": "", "Verdict": "ERROR", "Flags": "Cannot resolve exit IP via proxy",
            "Country": "", "Region": "", "City": "", "ORG": "", "ISP": "", "ASN": "",
            "ipwho_proxy": "", "ipwho_vpn": "", "ipwho_tor": "", "ipwho_hosting": "",
            "ipapi_proxy": "", "ipapi_hosting": "",
            "Abuse_Score": "", "Abuse_Reports": "",
            "RiskScore": "", "RiskTier": "",
            "IPQS_FraudScore": "", "IPQS_Proxy": "", "IPQS_VPN": "", "IPQS_Tor": "", "IPQS_RecentAbuse": "",
            "IPINFO_PrivacyProxy": "", "IPINFO_PrivacyVpn": "", "IPINFO_Hosting": "", "IPINFO_Anycast": "", "IPINFO_ASN": "",
            "SpamhausListed": "", "SpamhausZones": "", "Scamalytics_FraudScore": "",
            "FlagsShort": "-", "Proxy": proxy_url, "DNSLeak": "",
            "RTT_ms": "", "TTFB_ms": "", "DL_Mbps": "", "BenchURL": ""
        }

    row = process_ip(
        ip, abuse_key, sleep_min, sleep_max,
        session_ipwho, session_ipapi, session_abuse,
        session_extra, ipinfo_token, ipqs_key,
        scamalytics_enabled, spamhaus_enabled, spamhaus_resolver
    )
    row["Proxy"] = proxy_url

    if dns_leak_check:
        marker = detect_dns_leak_marker(proxy_url)
        doh_ok = doh_sanity_check(session_ipwho, proxy_url)
        row["DNSLeak"] = "OK" if (marker == "OK" and doh_ok) else marker

    if bench_enabled:
        try:
            m = benchmark_proxy(proxy_url, bench_url, bench_bytes, bench_timeout)
            row.update(m)
        except Exception as e:
            row["RTT_ms"] = row["TTFB_ms"] = row["DL_Mbps"] = ""
            row["BenchURL"] = bench_url
            row["Flags"] += f"; bench_error: {e}"
    return row

# ────────────────────── Вывод ──────────────────────

def print_table(rows: List[Dict[str, Any]]) -> None:
    cols = ["IP", "Country", "City", "ORG", "ASN", "Verdict", "RiskTier"]
    widths = [max(len(col), max((len(str(r.get(col,""))) for r in rows), default=0)) for col in cols]
    line = " | ".join(col.ljust(w) for col, w in zip(cols, widths))
    sep = "-+-".join("-" * w for w in widths)
    print(line); print(sep)
    for r in rows:
        print(" | ".join(str(r.get(col, "")).ljust(w) for col, w in zip(cols, widths)))

def save_csv(rows: List[Dict[str, Any]], path: str) -> None:
    cols = [
        "IP", "Country", "Region", "City", "ORG", "ISP", "ASN",
        "ipwho_proxy", "ipwho_vpn", "ipwho_tor", "ipwho_hosting",
        "ipapi_proxy", "ipapi_hosting",
        "Abuse_Score", "Abuse_Reports",
        "RiskScore", "RiskTier",
        "IPQS_FraudScore", "IPQS_Proxy", "IPQS_VPN", "IPQS_Tor", "IPQS_RecentAbuse",
        "IPINFO_PrivacyProxy", "IPINFO_PrivacyVpn", "IPINFO_Hosting", "IPINFO_Anycast", "IPINFO_ASN",
        "SpamhausListed", "SpamhausZones",
        "Scamalytics_FraudScore",
        "Verdict", "Flags", "FlagsShort",
        "Proxy", "DNSLeak",
        "RTT_ms", "TTFB_ms", "DL_Mbps", "BenchURL"
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in cols})

# ────────────────────── main ──────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="Mass IP reputation checker + proxy benchmark (hard risk mode)")
    # Старые параметры (IP/CIDR)
    parser.add_argument("targets", nargs="*", help="Список IP или CIDR (например, 192.0.2.0/30)")
    parser.add_argument("--input", help=f"Файл со списком IP/CIDR (по одному на строке). По умолчанию {INPUT_DEFAULT}")
    parser.add_argument("--csv", help=f"Путь для CSV (по умолчанию {CSV_DEFAULT})", default=CSV_DEFAULT)
    parser.add_argument("--threads", type=int, help="Количество потоков (по умолчанию CPU*5)")
    parser.add_argument("--sleep-min", type=float, default=DEFAULT_SLEEP_MIN, help="Минимальная пауза между запросами (сек)")
    parser.add_argument("--sleep-max", type=float, default=DEFAULT_SLEEP_MAX, help="Максимальная пауза между запросами (сек)")
    parser.add_argument("--max-expand", type=int, default=100000, help="Лимит общего кол-ва IP после развёртки CIDR")
    parser.add_argument("--no-abuse", action="store_true", help="Отключить AbuseIPDB даже при наличии ключа")
    parser.add_argument("--init", action="store_true", help=f"Создать файл {INPUT_DEFAULT} с примерами IP/CIDR и выйти")
    # Режим прокси
    parser.add_argument("--proxies", help="Файл со списком прокси: host:port[:user:pass] или URL (http(s)/socks5/socks5h)")
    parser.add_argument("--proxy-scheme", default="http", help="Схема по умолчанию для строк host:port[:user:pass] (http|https|socks5|socks5h)")
    parser.add_argument("--proxy-timeout", type=float, default=8.0, help="Таймаут резолва exit IP через прокси (сек)")
    # Плагины
    parser.add_argument("--ipinfo-token", help="IPinfo token (включить IPinfo)")
    parser.add_argument("--ipqs-key", help="IPQualityScore ключ (включить IPQS)")
    parser.add_argument("--scamalytics-scrape", action="store_true", help="Скраппинг Scamalytics публичной страницы")
    parser.add_argument("--spamhaus", action="store_true", help="Проверка DNSBL zen.spamhaus.org (требует dnspython)")
    parser.add_argument("--dns-resolver", default="8.8.8.8", help="DNS резолвер для Spamhaus (по умолчанию 8.8.8.8)")
    parser.add_argument("--dns-leak-check", action="store_true", help="Для прокси: маркер socks5/socks5h + DoH sanity-check")
    # Бенчмарк
    parser.add_argument("--bench", action="store_true", help="Включить бенчмарк через прокси (RTT, TTFB, DL)")
    parser.add_argument("--bench-url", default="https://speed.hetzner.de/100MB.bin", help="URL для бенчмарка")
    parser.add_argument("--bench-bytes", type=int, default=5_000_000, help="Сколько байт скачать для замера скорости (по умолчанию ≈5MB)")
    parser.add_argument("--bench-timeout", type=float, default=12.0, help="Таймаут бенч-запросов (сек)")

    args = parser.parse_args()

    if args.init:
        path = INPUT_DEFAULT
        if os.path.exists(path):
            print(f"{path} уже существует.")
        else:
            with open(path, "w", encoding="utf-8") as f:
                f.write("8.8.8.8\n1.1.1.1\n203.0.113.0/30\n")
            print(f"Создан {path} с примерами.")
        print(f"Теперь запустите: python {os.path.basename(__file__)} --input {path} --csv report.csv")
        return 0

    try: cpu = os.cpu_count() or 4
    except Exception: cpu = 4
    threads = args.threads if args.threads and args.threads > 0 else cpu * DEFAULT_THREADS_FACTOR

    abuse_key = None if args.no_abuse else os.environ.get("ABUSEIPDB_KEY")

    session_ipwho = requests.Session()
    session_ipapi = requests.Session()
    session_abuse = requests.Session()
    session_extra = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=threads, pool_maxsize=threads, max_retries=0)
    for s in (session_ipwho, session_ipapi, session_abuse, session_extra):
        s.mount("http://", adapter); s.mount("https://", adapter)

    rows_csv: List[Dict[str, Any]] = []
    rows_console: List[Dict[str, Any]] = []

    # ───── Режим прокси ─────
    if args.proxies:
        proxy_path = args.proxies
        if not os.path.exists(proxy_path):
            print(f"Файл с прокси не найден: {proxy_path}")
            return 2
        with open(proxy_path, "r", encoding="utf-8") as f:
            proxy_lines = [ln.strip() for ln in f if ln.strip()]
        if not proxy_lines:
            print("В файле прокси нет ни одной строки.")
            return 2

        total = len(proxy_lines)
        print(f"Прокси: {total} | Потоков: {threads} | AbuseIPDB: {'ON' if abuse_key else 'OFF'} | "
              f"IPinfo: {'ON' if args.ipinfo_token else 'OFF'} | IPQS: {'ON' if args.ipqs_key else 'OFF'} | "
              f"Spamhaus: {'ON' if args.spamhaus else 'OFF'} | Scamalytics: {'ON' if args.scamalytics_scrape else 'OFF'} | "
              f"DNSLeak: {'ON' if args.dns_leak_check else 'OFF'} | Bench: {'ON' if args.bench else 'OFF'}")
        print("Старт проверки (резолв exit IP → репутация → (опц.) DNSLeak/Bench)…\n")

        def job(line: str):
            return process_proxy(
                line, args.proxy_scheme, args.proxy_timeout,
                abuse_key, args.sleep_min, args.sleep_max,
                session_ipwho, session_ipapi, session_abuse,
                session_extra, args.ipinfo_token, args.ipqs_key,
                args.scamalytics_scrape, args.spamhaus, args.dns_resolver,
                args.dns_leak_check,
                args.bench, args.bench_url, args.bench_bytes, args.bench_timeout
            )

        with ThreadPoolExecutor(max_workers=threads) as ex:
            futs = [ex.submit(job, line) for line in proxy_lines]
            done = 0
            for fut in as_completed(futs):
                try:
                    row = fut.result()
                    rows_csv.append(row)
                    rows_console.append({
                        "IP": row.get("IP") or "<no-ip>",
                        "Country": row.get("Country",""),
                        "City": row.get("City",""),
                        "ORG": row.get("ORG","") or row.get("ISP",""),
                        "ASN": row.get("ASN",""),
                        "Verdict": row.get("Verdict",""),
                        "RiskTier": row.get("RiskTier","")
                    })
                except Exception as e:
                    rows_console.append({
                        "IP": "<error>", "Country": "", "City": "", "ORG": "", "ASN": "",
                        "Verdict": f"ERROR: {e}", "RiskTier": ""
                    })
                done += 1
                if done % max(1, total // 20) == 0 or done == total:
                    print(f"Готово {done}/{total} ({done*100//total}%)")

        print("\nРезультаты (сводка):")
        print_table(rows_console)
        save_csv(rows_csv, args.csv)
        print(f"\nCSV сохранён: {args.csv}")
        return 0

    # ───── Обычный режим: IP/CIDR ─────
    raw_tokens: List[str] = []
    input_path = args.input or INPUT_DEFAULT
    if os.path.exists(input_path):
        with open(input_path, "r", encoding="utf-8") as f:
            for line in f:
                t = line.strip()
                if t:
                    raw_tokens.append(t)
    for t in args.targets:
        if t.strip():
            raw_tokens.append(t.strip())

    if not raw_tokens:
        print(f"Не найден входной файл '{input_path}' и не переданы IP/CIDR аргументами.")
        print("Быстрый старт: python {} --init".format(os.path.basename(__file__)))
        return 2

    targets = bounded_expand(raw_tokens, args.max_expand)
    if not targets:
        print("Не удалось получить ни одного IP после развёртки входных данных.")
        return 2

    rows_csv.clear(); rows_console.clear()
    total = len(targets)
    print(f"Всего целей: {total} | Потоков: {threads} | AbuseIPDB: {'ON' if abuse_key else 'OFF'} | "
          f"IPinfo: {'ON' if args.ipinfo_token else 'OFF'} | IPQS: {'ON' if args.ipqs_key else 'OFF'} | "
          f"Spamhaus: {'ON' if args.spamhaus else 'OFF'} | Scamalytics: {'ON' if args.scamalytics_scrape else 'OFF'}")
    print("Старт проверки...\n")

    def job_ip(ip: str):
        return process_ip(
            ip, abuse_key, args.sleep_min, args.sleep_max,
            session_ipwho, session_ipapi, session_abuse,
            session_extra, args.ipinfo_token, args.ipqs_key,
            args.scamalytics_scrape, args.spamhaus, args.dns_resolver
        )

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(job_ip, ip) for ip in targets]
        done = 0
        for fut in as_completed(futures):
            try:
                row = fut.result()
                rows_csv.append(row)
                rows_console.append({
                    "IP": row["IP"],
                    "Country": row["Country"],
                    "City": row["City"],
                    "ORG": row["ORG"] or row["ISP"],
                    "ASN": row["ASN"],
                    "Verdict": row["Verdict"],
                    "RiskTier": row.get("RiskTier","")
                })
            except Exception as e:
                rows_console.append({
                    "IP": "<error>", "Country": "", "City": "", "ORG": "", "ASN": "",
                    "Verdict": f"ERROR: {e}", "RiskTier": ""
                })
            done += 1
            if done % max(1, total // 20) == 0 or done == total:
                print(f"Готово {done}/{total} ({done*100//total}%)")

    print("\nРезультаты (сводка):")
    print_table(rows_console)
    save_csv(rows_csv, args.csv)
    print(f"\nCSV сохранён: {args.csv}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
