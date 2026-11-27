#!/usr/bin/env python3
"""
nodehunt v3 - wide harvest, real latency + bandwidth, country filtering.

RULES
  vless / trojan : transport must be ws or httpupgrade
  any ws/httpupgrade : must carry a real non-empty Host header
  trojan : httpupgrade ranked ABOVE ws, bigger quota
  vmess / ss / hysteria2 / wireguard : any transport
  country : server IP must geolocate to the selected country
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import datetime
import gzip
import ipaddress
import itertools
import json
import os
import platform
import re
import shutil
import socket
import statistics
import subprocess
import sys
import tarfile
import tempfile
import time
import traceback
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import parse_qs, unquote, quote, urlencode

try:
    import httpx
except ImportError:
    print("Run: pip install -r requirements.txt")
    sys.exit(0)
try:
    import h2  # noqa: F401
    HTTP2 = True
except Exception:
    HTTP2 = False
try:
    import maxminddb
except Exception:
    maxminddb = None

UA = {"User-Agent": "nodehunt/3.0"}
SCHEMES = {"vless": "vless", "vmess": "vmess", "trojan": "trojan", "ss": "ss",
           "hysteria2": "hysteria2", "hy2": "hysteria2",
           "wireguard": "wireguard", "wg": "wireguard"}
PROTOS = ["vless", "vmess", "trojan", "ss", "hysteria2", "wireguard"]
SPLIT_PROTOS = {"vless", "trojan"}
UDP_PROTOS = {"hysteria2", "wireguard"}
VT_ONLY = {"ws", "httpupgrade"}

SPEED_URL = "https://speed.cloudflare.com/__down?bytes=262144"
MAXFILE = 6_000_000
TIERS = ("GOLD", "SILVER", "BRONZE")

LINK_RE = re.compile(r"(?:vless|vmess|trojan|ss|hysteria2|hy2|wireguard|wg)://[^\s\"'<>`\\]+", re.I)
B64_RE = re.compile(r"[A-Za-z0-9+/=_-]{120,}")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?"
                     r"[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]*$")
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")
B64KEY_RE = re.compile(r"^[A-Za-z0-9+/]{42,44}={0,2}$")

NET_MAP = {"tcp": "tcp", "raw": "tcp", "ws": "ws", "websocket": "ws",
           "httpupgrade": "httpupgrade", "http-upgrade": "httpupgrade",
           "h2": "http", "http": "http", "grpc": "grpc", "gun": "grpc"}
BAD_NET = {"kcp", "mkcp", "quic", "xhttp", "splithttp", "h3", "hysteria", ""}
FP_OK = {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq",
         "random", "randomized", "randomizedalpn", "randomizednoalpn"}
FLOWS = {"xtls-rprx-vision", "xtls-rprx-vision-udp443"}
VMESS_SEC = {"auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305", "aes-128-ctr"}
SS_METHODS = {"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
              "2022-blake3-chacha20-poly1305", "aes-128-gcm", "aes-192-gcm",
              "aes-256-gcm", "chacha20-ietf-poly1305",
              "xchacha20-ietf-poly1305", "none", "plain"}
TEST_URLS = ["https://www.gstatic.com/generate_204",
             "https://cp.cloudflare.com/generate_204",
             "http://www.qualcomm.cn/generate_204"]

TREE_SKIP = re.compile(r"(^|/)(\.github|docs?|img|images|assets|node_modules)/", re.I)
TREE_KEY = re.compile(r"(\.txt$|\.conf$|/sub|^sub|base64|list|node|prox|config|subscribe|"
                      r"protocols/|Splitted-By-Protocol|Eternity|v2ray|wireguard|wg|"
                      r"^README\.md$)", re.I)
SEARCH_Q = ["v2ray configs", "v2ray subscription", "free v2ray", "vless",
            "vmess", "trojan proxy", "hysteria2", "wireguard configs",
            "proxy collector", "free nodes", "telegram v2ray", "sing-box configs"]

PORTS = itertools.count(19100)
IN_BASE = itertools.count(31000, 120)
WG_LP = itertools.count(13000, 120)
API_OK = False
DNS_CACHE: dict = {}
TCP_CACHE: set = set()
TCP_DONE: set = set()


def log(*a):
    print(*a, flush=True)


def b64d(s):
    s = re.sub(r"\s+", "", s).replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8", "replace")


def is_b64ish(s):
    return len(s) > 24 and re.fullmatch(r"[A-Za-z0-9+/=_\-\s]+", s) is not None


def is_ip(h):
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def bad_host(h):
    if not h or " " in h or h.lower() in ("localhost", "0.0.0.0"):
        return True
    if is_ip(h):
        ip = ipaddress.ip_address(h)
        return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast
    return "." not in h


def split_hp(hp):
    hp = hp.strip().rstrip("/")
    if hp.startswith("["):
        h, _, rest = hp[1:].partition("]")
        p = rest.lstrip(":")
    else:
        h, sep, p = hp.rpartition(":")
        if not sep:
            return "", 0
    try:
        return h.strip(), int(p)
    except ValueError:
        return h.strip(), 0


def truthy(v):
    return str(v).lower() in ("1", "true", "yes", "on")


def gh_headers():
    h = dict(UA)
    t = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    if t:
        h["Authorization"] = "Bearer " + t
    return h


def flag(cc):
    if not cc or len(cc) != 2 or not cc.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - 65) for c in cc.upper())


def parse_country(s):
    s = (s or "").strip()
    codes = re.findall(r"[A-Za-z]{2}", s) if s else []
    out = {c.upper() for c in codes if c.upper() not in ("AN", "NY")}
    if not out or "ANY" in s.upper():
        return None
    return out


# ------------------------------------------------------------------ geo
def geo_urls():
    n = datetime.date.today()
    u = []
    for k in range(3):
        y, m = n.year, n.month - k
        while m <= 0:
            m += 12
            y -= 1
        u.append("https://download.db-ip.com/free/dbip-country-lite-%04d-%02d.mmdb.gz" % (y, m))
    return u


def ensure_geo(bindir):
    bindir = Path(bindir)
    bindir.mkdir(parents=True, exist_ok=True)
    p = bindir / "country.mmdb"
    if p.exists() and p.stat().st_size > 100000:
        return p
    with httpx.Client(headers=gh_headers(), timeout=60, follow_redirects=True) as c:
        for u in geo_urls():
            try:
                r = c.get(u)
                if r.status_code == 200 and len(r.content) > 100000:
                    p.write_bytes(gzip.decompress(r.content))
                    log("[geo] database from db-ip")
                    return p
            except Exception:
                pass
        for repo, name in (("Dreamacro/maxmind-geoip", "Country.mmdb"),
                           ("P3TERX/GeoLite.mmdb", "GeoLite2-Country.mmdb")):
            try:
                rel = c.get("https://api.github.com/repos/%s/releases/latest" % repo).json()
                a = next(x for x in rel.get("assets", []) if x["name"] == name)
                r = c.get(a["browser_download_url"])
                if r.status_code == 200 and len(r.content) > 100000:
                    p.write_bytes(r.content)
                    log("[geo] database from %s" % repo)
                    return p
            except Exception:
                pass
    return None


def extract_cc(rec, depth=0):
    if not isinstance(rec, dict) or depth > 4:
        return None
    for k in ("country_iso_code", "iso_code"):
        v = rec.get(k)
        if isinstance(v, str) and len(v) == 2:
            return v.upper()
    for k in ("country", "registered_country", "represented_country"):
        v = rec.get(k)
        if isinstance(v, str) and len(v) == 2:
            return v.upper()
        if isinstance(v, dict):
            r = extract_cc(v, depth + 1)
            if r:
                return r
    for v in rec.values():
        if isinstance(v, dict):
            r = extract_cc(v, depth + 1)
            if r:
                return r
    return None


class Geo:
    def __init__(self, path):
        self.rd = None
        self.cache = {}
        if path and maxminddb:
            try:
                self.rd = maxminddb.open_database(str(path))
            except Exception:
                self.rd = None

    def cc(self, ip):
        if not self.rd or not ip:
            return None
        if ip in self.cache:
            return self.cache[ip]
        c = None
        try:
            c = extract_cc(self.rd.get(ip))
        except Exception:
            c = None
        self.cache[ip] = c
        return c


# ------------------------------------------------------------------ harvest
def load_sources(path="sources.txt"):
    repos, urls = {}, []
    p = Path(path)
    if not p.exists():
        return repos, urls
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("http://", "https://")):
            urls.append(line)
        elif ":" in line and "/" in line:
            r, _, f = line.partition(":")
            repos.setdefault(r.strip(), []).append(f.strip())
        elif "/" in line:
            repos.setdefault(line, [])
    return repos, urls


async def fetch_repo(client, repo, paths, maxfiles):
    texts, branch = [], None

    def url(p, br):
        return "https://raw.githubusercontent.com/%s/%s/%s" % (repo, br, p)

    async def grab(p, br):
        try:
            r = await client.get(url(p, br))
            if r.status_code == 200 and r.text.strip() and len(r.text) < MAXFILE:
                return r.text
        except Exception:
            pass
        return None

    if paths:
        for br in ("main", "master", "HEAD"):
            try:
                r = await client.get(url(paths[0], br))
                if r.status_code == 200:
                    branch = br
                    if r.text.strip() and len(r.text) < MAXFILE:
                        texts.append(r.text)
                    break
            except Exception:
                pass
        if branch and len(paths) > 1:
            got = await asyncio.gather(*(grab(p, branch) for p in paths[1:maxfiles]))
            texts += [g for g in got if g]
    if texts:
        return texts

    for ref in ("HEAD", "main", "master"):
        try:
            r = await client.get(
                "https://api.github.com/repos/%s/git/trees/%s?recursive=1" % (repo, ref),
                headers=gh_headers(), timeout=25)
            if r.status_code != 200:
                continue
            cand = []
            for e in r.json().get("tree", []):
                if e.get("type") != "blob":
                    continue
                path, size = e.get("path", ""), e.get("size", 0)
                if not (20 < size < MAXFILE) or TREE_SKIP.search(path):
                    continue
                nm = path.rsplit("/", 1)[-1]
                ext = Path(nm).suffix.lower()
                if ext not in ("", ".txt", ".conf", ".yaml", ".yml", ".md"):
                    continue
                if ext == ".md" and nm.lower() != "readme.md":
                    continue
                if TREE_KEY.search(path):
                    score = 0
                    low = path.lower()
                    for k, w in (("sub", 5), ("all", 4), ("mix", 4), ("list", 3),
                                 ("protocols/", 5), ("base64", 3), ("wireguard", 4),
                                 ("vless", 3), ("trojan", 3), ("hysteria", 3)):
                        if k in low:
                            score += w
                    cand.append((-score, path))
            cand = [p for _, p in sorted(cand)][:maxfiles]
            if cand:
                for br in ("main", "master", "HEAD"):
                    t = await grab(cand[0], br)
                    if t is not None:
                        branch = br
                        texts.append(t)
                        break
                if branch and len(cand) > 1:
                    got = await asyncio.gather(*(grab(p, branch) for p in cand[1:]))
                    texts += [g for g in got if g]
            break
        except Exception:
            continue
    return texts


async def discover(client, limit, max_age_days):
    cutoff = (datetime.date.today() - datetime.timedelta(days=max_age_days)).isoformat()
    jobs = [(q, s) for q in SEARCH_Q for s in ("stars", "updated")]
    sem = asyncio.Semaphore(6)

    async def one(q, sort):
        async with sem:
            try:
                r = await client.get(
                    "https://api.github.com/search/repositories",
                    params={"q": "%s pushed:>%s" % (q, cutoff), "sort": sort,
                            "order": "desc", "per_page": 100},
                    headers=gh_headers(), timeout=30)
                if r.status_code == 200:
                    return r.json().get("items", [])
            except Exception:
                pass
            return []

    found = {}
    for items in await asyncio.gather(*(one(q, s) for q, s in jobs)):
        for it in items:
            try:
                if it.get("archived") or it.get("disabled"):
                    continue
                if it.get("size", 0) > 400_000:
                    continue
                found[it["full_name"]] = it.get("stargazers_count", 0)
            except Exception:
                pass
    ranked = [k for k, _ in sorted(found.items(), key=lambda x: -x[1])]
    log("[discover] %d fresh repos found" % len(ranked))
    return ranked[:limit]


async def harvest(args):
    repos, urls = load_sources()
    seed = set(repos)
    texts = []
    total = 0
    stop = False
    hdeadline = time.time() + args.harvest_minutes * 60
    limits = httpx.Limits(max_connections=128, max_keepalive_connections=64)
    async with httpx.AsyncClient(headers=UA, timeout=25, http2=HTTP2,
                                 follow_redirects=True, limits=limits) as c:
        if args.discover:
            try:
                for r in await discover(c, args.discover, args.max_age_days):
                    repos.setdefault(r, [])
            except Exception:
                pass
        order = list(seed) + [r for r in repos if r not in seed]
        order = order[:args.max_repos]
        log("[sources] scanning %d repos (http2=%s)" % (len(order), HTTP2))
        sem = asyncio.Semaphore(24)
        done = 0

        async def one(repo):
            nonlocal total, stop, done
            if stop or time.time() > hdeadline:
                return
            async with sem:
                if stop or time.time() > hdeadline:
                    return
                try:
                    got = await fetch_repo(c, repo, repos.get(repo, []), args.files_per_repo)
                except Exception:
                    got = []
                for t in got:
                    total += len(t)
                texts.extend(got)
                done += 1
                if done % 25 == 0:
                    log("[sources] %d/%d repos  %.1f MB" % (done, len(order), total / 1048576))
                if total > args.harvest_mb * 1048576:
                    stop = True
                    log("[sources] byte budget reached - stopping harvest")

        await asyncio.gather(*(one(r) for r in order))
        if urls:
            async def gu(u):
                try:
                    r = await c.get(u)
                    if r.status_code == 200 and len(r.text) < MAXFILE:
                        return r.text
                except Exception:
                    pass
                return None
            texts += [t for t in await asyncio.gather(*(gu(u) for u in urls[:20])) if t]
    log("[sources] total %.1f MB from %d repos" % (total / 1048576, len(order)))
    return texts


def extract_links(text):
    out = []

    def scan(t):
        for m in LINK_RE.finditer(t):
            out.append(m.group(0).rstrip(".,;:)]}'\"`<>"))

    try:
        scan(text)
        if len(out) < 50:
            if is_b64ish(text):
                try:
                    d = b64d(text)
                    if "://" in d:
                        scan(d)
                except Exception:
                    pass
            for i, m in enumerate(B64_RE.finditer(text)):
                if i > 400:
                    break
                try:
                    d = b64d(m.group(0))
                    if "://" in d:
                        scan(d)
                except Exception:
                    pass
    except Exception:
        pass
    return out


def extract_wg_blocks(text):
    out = []
    if "[Interface]" not in text:
        return out
    try:
        idx = [m.start() for m in re.finditer(r"\[Interface\]", text)][:400]
        for i, s in enumerate(idx):
            e = idx[i + 1] if i + 1 < len(idx) else min(len(text), s + 4000)
            out.append(text[s:min(e, s + 4000)])
    except Exception:
        pass
    return out


# ------------------------------------------------------------------ parse
def norm_net(v):
    return NET_MAP.get(str(v).strip().lower(), str(v).strip().lower())


def wg_from_conf(block):
    iface, peer = {}, {}
    cur = None
    for ln in block.splitlines():
        ln = ln.strip()
        if ln.lower().startswith("[interface]"):
            cur = iface
            continue
        if ln.lower().startswith("[peer]"):
            cur = peer
            continue
        if ln.startswith("[") or "=" not in ln or cur is None:
            continue
        k, _, v = ln.partition("=")
        cur[k.strip().lower()] = v.split("#")[0].strip()
    pk = iface.get("privatekey", "")
    pub = peer.get("publickey", "")
    ep = peer.get("endpoint", "")
    if not (pk and pub and ep):
        return None
    host, port = split_hp(ep)
    addrs = [a.strip() for a in iface.get("address", "172.16.0.2/32").split(",") if a.strip()]
    try:
        mtu = int(iface.get("mtu", "1420"))
    except ValueError:
        mtu = 1420
    p = {"public_key": pub, "preshared_key": peer.get("presharedkey", ""),
         "address": addrs, "mtu": mtu}
    n = dict(proto="wireguard", host=host, port=port, secret=pk, net="udp",
             security="none", params=p, remark="wg-" + host, link="")
    n = finish(n)
    if n:
        n["link"] = wg_link(n)
    return n


def wg_link(n):
    p = n["params"]
    q = {"publickey": p["public_key"], "address": ",".join(p.get("address") or []),
         "mtu": str(p.get("mtu") or 1420)}
    if p.get("preshared_key"):
        q["presharedkey"] = p["preshared_key"]
    if p.get("reserved"):
        q["reserved"] = ",".join(str(x) for x in p["reserved"])
    return "wireguard://%s@%s:%d?%s#%s" % (
        quote(n["secret"], safe=""), n["host"], n["port"], urlencode(q),
        quote(n["remark"] or "wg"))


def wg_conf(n):
    p = n["params"]
    L = ["[Interface]", "PrivateKey = " + n["secret"],
         "Address = " + ", ".join(p.get("address") or ["172.16.0.2/32"])]
    if p.get("mtu"):
        L.append("MTU = %d" % p["mtu"])
    L += ["DNS = 1.1.1.1", "", "[Peer]", "PublicKey = " + p["public_key"]]
    if p.get("preshared_key"):
        L.append("PresharedKey = " + p["preshared_key"])
    L += ["AllowedIPs = 0.0.0.0/0, ::/0",
          "Endpoint = %s:%d" % (n["host"], n["port"]), "PersistentKeepalive = 25"]
    return "\n".join(L) + "\n"


def parse_link(link):
    try:
        scheme, rest = link.split("://", 1)
    except ValueError:
        return None
    proto = SCHEMES.get(scheme.lower())
    if not proto:
        return None

    if proto == "vmess":
        try:
            j = json.loads(b64d(rest.split("#")[0]))
        except Exception:
            return None
        if not isinstance(j, dict):
            return None
        host = str(j.get("add", "")).strip()
        try:
            port = int(j.get("port", 0))
        except (TypeError, ValueError):
            return None
        sec = "tls" if str(j.get("tls", "")).lower() in ("tls", "1", "true") else "none"
        p = {"sni": str(j.get("sni") or ""), "host": str(j.get("host") or ""),
             "path": str(j.get("path") or ""), "alpn": str(j.get("alpn") or ""),
             "fp": str(j.get("fp") or ""), "scy": str(j.get("scy") or "auto").lower(),
             "aid": str(j.get("aid") or 0), "allowInsecure": str(j.get("allowInsecure") or "")}
        net = norm_net(j.get("net", "tcp"))
        if net == "grpc":
            p["serviceName"] = p["path"]
        return finish(dict(proto=proto, host=host, port=port, secret=str(j.get("id", "")),
                           net=net, security=sec, params=p,
                           remark=str(j.get("ps", "")), link=link))

    frag = ""
    if "#" in rest:
        rest, frag = rest.split("#", 1)
    q = ""
    if "?" in rest:
        rest, q = rest.split("?", 1)
    params = {k: (v[0] if v else "")
              for k, v in parse_qs(q, keep_blank_values=True).items()}
    remark = unquote(frag)

    if proto == "wireguard":
        if "@" not in rest:
            try:
                return wg_from_conf(b64d(rest))
            except Exception:
                return None
        pk, hp = rest.rsplit("@", 1)
        host, port = split_hp(hp)
        lp = {k.lower(): v for k, v in params.items()}
        pub = lp.get("publickey") or lp.get("peer_public_key") or lp.get("pubkey") or ""
        addrs = [a.strip() for a in (lp.get("address") or lp.get("ip") or
                                     "172.16.0.2/32").split(",") if a.strip()]
        try:
            mtu = int(lp.get("mtu", "1420"))
        except ValueError:
            mtu = 1420
        res = []
        rv = lp.get("reserved", "")
        if rv:
            try:
                res = [int(x) for x in rv.split(",")]
            except Exception:
                try:
                    res = list(base64.b64decode(rv + "=" * (-len(rv) % 4)))
                except Exception:
                    res = []
        p = {"public_key": unquote(pub), "preshared_key": unquote(
                 lp.get("presharedkey") or lp.get("psk") or ""),
             "address": addrs, "mtu": mtu, "reserved": res}
        return finish(dict(proto=proto, host=host, port=port, secret=unquote(pk),
                           net="udp", security="none", params=p,
                           remark=remark or ("wg-" + host), link=link))

    if proto == "ss":
        try:
            if "@" in rest:
                ui, hp = rest.rsplit("@", 1)
                if ":" not in ui:
                    ui = b64d(ui)
            else:
                dec = b64d(rest)
                if "@" not in dec:
                    return None
                ui, hp = dec.rsplit("@", 1)
            if ":" not in ui:
                return None
            method, password = ui.split(":", 1)
            host, port = split_hp(hp)
        except Exception:
            return None
        params["method"] = unquote(method).strip().lower()
        return finish(dict(proto=proto, host=host, port=port, secret=unquote(password),
                           net="tcp", security="none", params=params,
                           remark=remark, link=link))

    if "@" not in rest:
        return None
    secret, hp = rest.rsplit("@", 1)
    host, port = split_hp(hp)
    secret = unquote(secret)
    if proto == "hysteria2":
        net, sec = "udp", "tls"
        if not params.get("sni"):
            params["sni"] = params.get("peer", "")
    else:
        net = norm_net(params.get("type", "tcp"))
        default = "tls" if proto == "trojan" else "none"
        sec = (params.get("security") or default).lower()
        if sec == "xtls":
            sec = "tls"
        if sec not in ("tls", "reality", "none"):
            sec = default
    return finish(dict(proto=proto, host=host, port=port, secret=secret, net=net,
                       security=sec, params=params, remark=remark, link=link))


def finish(n):
    if bad_host(n["host"]) or not (0 < n["port"] < 65536) or not n["secret"]:
        return None
    p = n["params"]
    if n["proto"] == "wireguard":
        if not B64KEY_RE.match(n["secret"]) or not B64KEY_RE.match(p.get("public_key", "")):
            return None
        p["address"] = [a if "/" in a else (a + ("/128" if ":" in a else "/32"))
                        for a in (p.get("address") or ["172.16.0.2/32"])]
        if not 576 <= p.get("mtu", 1420) <= 9000:
            p["mtu"] = 1420
        n["key"] = "wg|%s|%d|%s|%s" % (n["host"].lower(), n["port"],
                                       n["secret"], p["public_key"])
        return n
    if p.get("fp") and p["fp"].lower() not in FP_OK:
        p["fp"] = ""
    if n["proto"] not in UDP_PROTOS and n["net"] in BAD_NET:
        return None
    if n["proto"] in ("vless", "vmess") and not UUID_RE.match(n["secret"]):
        return None
    if n["proto"] == "vmess":
        if p["scy"] not in VMESS_SEC:
            return None
        try:
            aid = int(p["aid"])
        except ValueError:
            return None
        if not 0 <= aid <= 65535:
            return None
    if n["proto"] == "vless" and p.get("flow") and p["flow"] not in FLOWS:
        p["flow"] = ""
    if n["security"] == "reality":
        pbk, sid = p.get("pbk", ""), p.get("sid", "")
        try:
            k = base64.urlsafe_b64decode(pbk + "=" * (-len(pbk) % 4))
        except Exception:
            return None
        if len(k) != 32 or not HEX_RE.match(sid) or len(sid) > 16 or len(sid) % 2:
            return None
    if n["proto"] == "ss":
        if p.get("method") not in SS_METHODS or p.get("plugin"):
            return None
    if n["proto"] == "hysteria2" and p.get("obfs") and p["obfs"] != "salamander":
        return None
    n["key"] = "|".join(str(x) for x in [
        n["proto"], n["host"].lower(), n["port"], n["secret"], n["net"], n["security"],
        p.get("path", ""), p.get("host", ""), p.get("sni", ""), p.get("serviceName", ""),
        p.get("pbk", ""), p.get("sid", ""), p.get("flow", ""), p.get("method", ""),
        p.get("scy", ""), p.get("aid", ""), p.get("obfs-password", ""), p.get("mport", "")])
    return n


# ------------------------------------------------------------------ gates
def effective_host(n):
    h = (n["params"].get("host") or "").strip()
    if not h and not is_ip(n["host"]):
        h = n["host"].strip()
    if h.count(":") == 1:
        h = h.split(":")[0]
    return h.strip().strip(".")


def host_ok(n):
    if n["net"] not in VT_ONLY:
        return True
    h = effective_host(n)
    if not h or " " in h or is_ip(h) or "." not in h:
        return False
    return HOST_RE.match(h) is not None


def gate(n):
    if n["proto"] in SPLIT_PROTOS:
        return n["net"] in VT_ONLY
    return True


def unique_servers(pool):
    seen, out = set(), []
    for n in pool:
        k = (n["host"].lower(), n["port"], n["net"])
        if k in seen:
            continue
        seen.add(k)
        out.append(n)
    return out


def spread(pool, limit):
    if limit <= 0 or len(pool) <= limit:
        return pool
    step = len(pool) / float(limit)
    return [pool[int(i * step)] for i in range(limit)]


def allocate_quota(items, budget, split, hu_share):
    if budget <= 0 or len(items) <= budget:
        return items
    if not split:
        return spread(items, budget)
    ws = [n for n in items if n["net"] == "ws"]
    hu = [n for n in items if n["net"] == "httpupgrade"]
    nb = min(len(hu), int(budget * hu_share))
    na = min(len(ws), budget - nb)
    nb = min(len(hu), budget - na)
    return spread(ws, na) + spread(hu, nb)


# ------------------------------------------------------------------ preflight
async def preflight(nodes, timeout, conc):
    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(conc)
    for n in nodes:
        if is_ip(n["host"]):
            DNS_CACHE[n["host"]] = n["host"]
    names = sorted({n["host"] for n in nodes
                    if not is_ip(n["host"]) and n["host"] not in DNS_CACHE})
    done = 0

    async def res(h):
        nonlocal done
        async with sem:
            try:
                infos = await asyncio.wait_for(
                    loop.getaddrinfo(h, None, type=socket.SOCK_STREAM), timeout)
                v4 = [i for i in infos if i[0] == socket.AF_INET]
                DNS_CACHE[h] = (v4 or infos)[0][4][0]
            except Exception:
                DNS_CACHE[h] = None
            done += 1
            if done % 1000 == 0:
                log("      dns %d/%d" % (done, len(names)))

    if names:
        await asyncio.gather(*(res(h) for h in names))
    log("    dns: %d new names resolved (cache %d)" % (len(names), len(DNS_CACHE)))

    pairs = sorted({(DNS_CACHE[n["host"]], n["port"]) for n in nodes
                    if DNS_CACHE.get(n["host"]) and n["proto"] not in UDP_PROTOS
                    and (DNS_CACHE[n["host"]], n["port"]) not in TCP_DONE})
    done = 0

    async def tcp(ip, port):
        nonlocal done
        async with sem:
            TCP_DONE.add((ip, port))
            try:
                _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
                w.close()
                try:
                    await asyncio.wait_for(w.wait_closed(), 1)
                except Exception:
                    pass
                TCP_CACHE.add((ip, port))
            except Exception:
                pass
            done += 1
            if done % 1000 == 0:
                log("      tcp %d/%d open %d" % (done, len(pairs), len(TCP_CACHE)))

    if pairs:
        await asyncio.gather(*(tcp(ip, p) for ip, p in pairs))
    log("    tcp: %d new endpoints probed (open cache %d)" % (len(pairs), len(TCP_CACHE)))

    alive = []
    for n in nodes:
        ip = DNS_CACHE.get(n["host"])
        if not ip:
            continue
        if n["proto"] in UDP_PROTOS or (ip, n["port"]) in TCP_CACHE:
            n["ip"] = ip
            alive.append(n)
    return alive


# ------------------------------------------------------------------ engine
def ensure_singbox(bindir):
    bindir = Path(bindir)
    exe = shutil.which("sing-box")
    if exe:
        return exe
    local = bindir / ("sing-box.exe" if os.name == "nt" else "sing-box")
    if local.exists():
        return str(local)
    sn = {"Linux": "linux", "Darwin": "darwin", "Windows": "windows"}.get(platform.system())
    ar = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64",
          "arm64": "arm64"}.get(platform.machine().lower())
    if not sn or not ar:
        raise RuntimeError("cannot auto-install sing-box")
    ext = "zip" if sn == "windows" else "tar.gz"
    pat = re.compile(r"sing-box-[\d.]+-%s-%s\.%s$" % (sn, ar, ext.replace(".", r"\.")))
    with httpx.Client(headers=gh_headers(), timeout=90, follow_redirects=True) as c:
        rel = c.get("https://api.github.com/repos/SagerNet/sing-box/releases/latest").json()
        a = next(x for x in rel.get("assets", []) if pat.search(x["name"]))
        log("[engine] downloading " + a["name"])
        blob = c.get(a["browser_download_url"]).content
    bindir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / a["name"]
        p.write_bytes(blob)
        if ext == "zip":
            with zipfile.ZipFile(p) as z:
                m = next(x for x in z.namelist() if x.endswith("sing-box.exe"))
                local.write_bytes(z.read(m))
        else:
            with tarfile.open(p) as t:
                m = next(x for x in t.getmembers() if Path(x.name).name == "sing-box")
                local.write_bytes(t.extractfile(m).read())
    local.chmod(0o755)
    return str(local)


def tls_block(n):
    p = n["params"]
    if n["security"] == "none" and n["proto"] != "hysteria2":
        return None
    sni = p.get("sni") or effective_host(n)
    t = {"enabled": True, "insecure": truthy(p.get("allowInsecure") or p.get("insecure"))}
    if sni and not is_ip(sni):
        t["server_name"] = sni
    else:
        t["insecure"] = True
    if p.get("alpn"):
        t["alpn"] = [x for x in p["alpn"].split(",") if x]
    if p.get("fp"):
        t["utls"] = {"enabled": True, "fingerprint": p["fp"].lower()}
    if n["security"] == "reality":
        t["reality"] = {"enabled": True, "public_key": p["pbk"], "short_id": p.get("sid", "")}
    if n["proto"] == "hysteria2":
        t.setdefault("alpn", ["h3"])
    return t


def transport_block(n):
    p, net = n["params"], n["net"]
    hdr = effective_host(n)
    path = p.get("path") or "/"
    if net == "ws":
        t = {"type": "ws", "path": path, "headers": {"Host": hdr}}
        m = re.search(r"[?&]ed=(\d+)", path)
        if m:
            t["path"] = re.split(r"[?&]ed=", path)[0]
            t["max_early_data"] = int(m.group(1))
            t["early_data_header_name"] = "Sec-WebSocket-Protocol"
        return t
    if net == "httpupgrade":
        return {"type": "httpupgrade", "path": path, "host": hdr}
    if net == "grpc":
        return {"type": "grpc", "service_name": p.get("serviceName") or p.get("path", "")}
    if net == "http":
        t = {"type": "http", "path": path}
        if hdr:
            t["host"] = [hdr]
        return t
    return None


def to_outbound(n, tag):
    p = n["params"]
    o = {"tag": tag, "server": n.get("ip") or n["host"], "server_port": n["port"]}
    if n["proto"] == "vless":
        o["type"] = "vless"
        o["uuid"] = n["secret"]
        o["packet_encoding"] = "xudp"
        if p.get("flow") and n["net"] == "tcp" and n["security"] in ("tls", "reality"):
            o["flow"] = p["flow"]
    elif n["proto"] == "vmess":
        o["type"] = "vmess"
        o["uuid"] = n["secret"]
        o["security"] = "none" if p["scy"] == "zero" else p["scy"]
        o["alter_id"] = int(p["aid"])
        o["packet_encoding"] = "xudp"
    elif n["proto"] == "trojan":
        o["type"] = "trojan"
        o["password"] = n["secret"]
    elif n["proto"] == "ss":
        o["type"] = "shadowsocks"
        o["method"] = p["method"]
        o["password"] = n["secret"]
    elif n["proto"] == "hysteria2":
        o["type"] = "hysteria2"
        o["password"] = n["secret"]
        if p.get("obfs") == "salamander":
            o["obfs"] = {"type": "salamander", "password": p.get("obfs-password", "")}
        if p.get("mport"):
            o.pop("server_port", None)
            o["server_ports"] = [x.replace("-", ":") for x in p["mport"].split(",") if x]
            o["hop_interval"] = "30s"
    t = tls_block(n)
    if t:
        o["tls"] = t
    tr = transport_block(n)
    if tr:
        o["transport"] = tr
    return o


def wg_peer(n):
    p = n["params"]
    d = {"address": n.get("ip") or n["host"], "port": n["port"],
         "public_key": p["public_key"], "allowed_ips": ["0.0.0.0/0", "::/0"],
         "persistent_keepalive_interval": 25}
    if p.get("preshared_key"):
        d["pre_shared_key"] = p["preshared_key"]
    if p.get("reserved"):
        d["reserved"] = p["reserved"]
    return d


def wg_endpoint(n, tag, lp):
    p = n["params"]
    return {"type": "wireguard", "tag": tag, "system": False,
            "mtu": p.get("mtu", 1420), "address": p["address"],
            "private_key": n["secret"], "listen_port": lp, "peers": [wg_peer(n)]}


def wg_legacy(n, tag):
    p = n["params"]
    o = {"type": "wireguard", "tag": tag, "server": n.get("ip") or n["host"],
         "server_port": n["port"], "system_interface": False,
         "local_address": p["address"], "private_key": n["secret"],
         "peer_public_key": p["public_key"], "mtu": p.get("mtu", 1420)}
    if p.get("preshared_key"):
        o["pre_shared_key"] = p["preshared_key"]
    if p.get("reserved"):
        o["reserved"] = p["reserved"]
    return o


def sb_config(nodes, tags, port, use_urltest=False):
    outs = [to_outbound(n, t) for n, t in zip(nodes, tags)]
    if use_urltest and len(outs) >= 2:
        outs.append({"type": "urltest", "tag": "auto", "outbounds": list(tags),
                     "url": TEST_URLS[0], "interval": "1h", "tolerance": 50})
    return {"log": {"level": "error", "timestamp": False}, "outbounds": outs,
            "experimental": {"clash_api": {"external_controller": "127.0.0.1:%d" % port}}}


def proxy_config(nodes, tags, api_port, in_base, wg_mode=None, lp_base=None):
    ins, rules = [], []
    for i, t in enumerate(tags):
        it = "in%05d" % i
        ins.append({"type": "mixed", "tag": it, "listen": "127.0.0.1",
                    "listen_port": in_base + i})
        rules.append({"inbound": [it], "outbound": t})
    cfg = {"log": {"level": "error", "timestamp": False}, "inbounds": ins,
           "route": {"rules": rules, "final": tags[0]},
           "experimental": {"clash_api": {"external_controller": "127.0.0.1:%d" % api_port}}}
    if wg_mode == "endpoint":
        cfg["endpoints"] = [wg_endpoint(n, tags[i], lp_base + i) for i, n in enumerate(nodes)]
    elif wg_mode == "legacy":
        cfg["outbounds"] = [wg_legacy(n, t) for n, t in zip(nodes, tags)]
    else:
        cfg["outbounds"] = [to_outbound(n, t) for n, t in zip(nodes, tags)]
    return cfg


def check_cfg(exe, wd, cfg, name="chk"):
    f = wd / (name + ".json")
    try:
        f.write_text(json.dumps(cfg))
        r = subprocess.run([exe, "check", "-c", str(f)], capture_output=True, timeout=25)
        return r.returncode == 0
    except Exception:
        return False


def check_one(exe, wd, n, tag, i):
    ok = check_cfg(exe, wd, sb_config([n], [tag], 19099), "c%d" % i)
    try:
        (wd / ("c%d.json" % i)).unlink()
    except Exception:
        pass
    return ok


async def validate_parallel(exe, wd, nodes, tags):
    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor(max_workers=8) as pool:
        oks = await asyncio.gather(*[loop.run_in_executor(
            pool, check_one, exe, wd, n, tags[i], i) for i, n in enumerate(nodes)])
    keep = [i for i, ok in enumerate(oks) if ok]
    log("    config check: %d ok, %d dropped" % (len(keep), len(nodes) - len(keep)))
    return keep


def detect_wg_mode(exe, wd):
    k = base64.b64encode(bytes(32)).decode()
    n = {"proto": "wireguard", "host": "162.159.192.1", "ip": "162.159.192.1",
         "port": 2408, "secret": k, "net": "udp", "security": "none",
         "params": {"public_key": k, "address": ["172.16.0.2/32"], "mtu": 1280}}
    for mode in ("endpoint", "legacy"):
        try:
            cfg = proxy_config([n], ["wgtest"], next(PORTS), next(IN_BASE),
                               mode, next(WG_LP))
            if check_cfg(exe, wd, cfg, "wgmode"):
                log("[wireguard] engine mode: %s" % mode)
                return mode
        except Exception:
            pass
    log("[wireguard] not supported by this sing-box build - protocol disabled")
    return None


class Engine:
    def __init__(self, exe, wd, port):
        self.exe, self.wd, self.port = exe, wd, port
        self.proc = None
        self.base = "http://127.0.0.1:%d" % port

    async def start_cfg(self, cfg, client):
        p = self.wd / "sb.json"
        p.write_text(json.dumps(cfg))
        lf = open(self.wd / "sb.log", "ab")
        try:
            self.proc = subprocess.Popen([self.exe, "run", "-c", str(p)], stdout=lf, stderr=lf)
        except Exception:
            return False
        for _ in range(70):
            if self.proc.poll() is not None:
                return False
            try:
                r = await client.get(self.base + "/version", timeout=1.0)
                if r.status_code == 200:
                    return True
            except Exception:
                pass
            await asyncio.sleep(0.15)
        return False

    def stop(self):
        try:
            if self.proc and self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(5)
                except Exception:
                    self.proc.kill()
        except Exception:
            pass
        self.proc = None


async def try_run(exe, wd, nodes, tags, client, o, use_urltest):
    eng = Engine(exe, wd, next(PORTS))
    if not await eng.start_cfg(sb_config(nodes, tags, eng.port, use_urltest), client):
        eng.stop()
        return None
    res = {i: [] for i in range(len(nodes))}
    sem = asyncio.Semaphore(o["conc"])
    total = len(nodes) * o["rounds"]
    done = 0

    async def probe(i, url):
        nonlocal done
        async with sem:
            try:
                r = await client.get(eng.base + "/proxies/" + tags[i] + "/delay",
                                     params={"url": url, "timeout": o["timeout"]},
                                     timeout=o["timeout"] / 1000 + 5)
                if r.status_code == 200:
                    d = r.json().get("delay", 0)
                    if isinstance(d, (int, float)) and d > 0:
                        res[i].append(float(d))
            except Exception:
                pass
            done += 1
            if done % 60 == 0:
                log("      %s %d/%d" % (o["label"], done, total))

    try:
        for rd in range(o["rounds"]):
            await asyncio.gather(*(probe(i, o["urls"][rd % len(o["urls"])])
                                   for i in range(len(nodes))))
            log("    %s round %d/%d done" % (o["label"], rd + 1, o["rounds"]))
        if o["allow_history"]:
            miss = [i for i in range(len(nodes)) if not res[i]]
            if miss:
                try:
                    r = await client.get(eng.base + "/proxies", timeout=15)
                    if r.status_code == 200:
                        px = r.json().get("proxies", {})
                        for i in miss:
                            h = px.get(tags[i], {}).get("history") or []
                            if h and isinstance(h[-1].get("delay"), (int, float)) \
                                    and h[-1]["delay"] > 0:
                                res[i].append(float(h[-1]["delay"]))
                except Exception:
                    pass
    finally:
        eng.stop()
    return {i: v for i, v in res.items() if v}


async def measure_batch(exe, wd, nodes, client, o):
    global API_OK
    tags = ["n%05d" % i for i in range(len(nodes))]
    idx = list(range(len(nodes)))
    cn, ct = nodes, tags
    res = await try_run(exe, wd, cn, ct, client, o, False)
    if res is None:
        log("    bad config in batch - validating individually")
        keep = await validate_parallel(exe, wd, nodes, tags)
        if not keep:
            return {}
        idx = keep
        cn = [nodes[i] for i in keep]
        ct = [tags[i] for i in keep]
        res = await try_run(exe, wd, cn, ct, client, o, False)
        if res is None:
            return {}
    if not res and not API_OK:
        alt = await try_run(exe, wd, cn, ct, client, o, True)
        if alt:
            res = alt
    if res:
        API_OK = True
    return {idx[i]: v for i, v in res.items()}


def budget_left(args):
    return min(args.deadline, getattr(args, "proto_deadline", args.deadline)) - time.time()


async def measure_all(exe, nodes, args, rounds=None, label="test"):
    out = {}
    if not nodes:
        return out
    o = {"urls": TEST_URLS, "timeout": args.timeout,
         "rounds": max(1, rounds or args.rounds), "conc": args.concurrency,
         "label": label, "allow_history": True}
    work = Path(args.workdir)
    work.mkdir(parents=True, exist_ok=True)
    batches = [nodes[i:i + args.batch] for i in range(0, len(nodes), args.batch)]
    async with httpx.AsyncClient(timeout=o["timeout"] / 1000 + 10) as client:
        for bi, b in enumerate(batches, 1):
            if budget_left(args) < 20:
                log("[%s] time budget - keeping what we have" % label)
                break
            t0 = time.time()
            log("[%s] batch %d/%d (%d)" % (label, bi, len(batches), len(b)))
            try:
                with tempfile.TemporaryDirectory(dir=work) as td:
                    r = await measure_batch(exe, Path(td), b, client, o)
            except Exception:
                r = {}
            for i, s in r.items():
                out[b[i]["uid"]] = s
            log("[%s] batch %d/%d alive=%d %.1fs" % (label, bi, len(batches), len(r), time.time() - t0))
    return out


async def download_pass(exe, nodes, args, wg_mode=None, label="speed", want_lat=False):
    """Real proxy port per node -> real HTTP GET (+ optional latency rounds)."""
    lat, kbs = {}, {}
    if not nodes:
        return lat, kbs
    work = Path(args.workdir)
    work.mkdir(parents=True, exist_ok=True)
    size = args.wg_batch if wg_mode else args.batch
    batches = [nodes[i:i + size] for i in range(0, len(nodes), size)]
    sem = asyncio.Semaphore(args.speed_conc)
    rounds = args.wg_rounds if want_lat else 1
    async with httpx.AsyncClient(timeout=6) as rc:
        for bi, b in enumerate(batches, 1):
            if budget_left(args) < 25:
                break
            tags = ["p%05d" % i for i in range(len(b))]
            base, lp = next(IN_BASE), next(WG_LP)
            t0 = time.time()
            log("[%s] batch %d/%d (%d)" % (label, bi, len(batches), len(b)))
            with tempfile.TemporaryDirectory(dir=work) as td:
                wd = Path(td)
                eng = Engine(exe, wd, next(PORTS))
                try:
                    ok = await eng.start_cfg(
                        proxy_config(b, tags, eng.port, base, wg_mode, lp), rc)
                except Exception:
                    ok = False
                if not ok:
                    eng.stop()
                    log("[%s] engine would not start - skipping rest" % label)
                    return lat, kbs
                done = 0

                async def one(i):
                    nonlocal done
                    async with sem:
                        px = "http://127.0.0.1:%d" % (base + i)
                        uid = b[i]["uid"]
                        try:
                            async with httpx.AsyncClient(proxy=px, timeout=12,
                                                         follow_redirects=True) as c:
                                if want_lat:
                                    for rd in range(rounds):
                                        t = time.monotonic()
                                        try:
                                            r = await c.get(TEST_URLS[rd % len(TEST_URLS)])
                                            if r.status_code in (200, 204):
                                                lat.setdefault(uid, []).append(
                                                    (time.monotonic() - t) * 1000)
                                        except Exception:
                                            pass
                                t = time.monotonic()
                                r = await c.get(SPEED_URL)
                                dt = time.monotonic() - t
                                nb = len(r.content)
                                if r.status_code == 200 and nb > 2000 and dt > 0.001:
                                    kbs[uid] = (nb / 1024.0) / dt
                                    if want_lat and uid not in lat:
                                        lat[uid] = [dt * 1000]
                        except Exception:
                            pass
                        done += 1
                        if done % 30 == 0:
                            log("      %s %d/%d" % (label, done, len(b)))

                try:
                    await asyncio.gather(*(one(i) for i in range(len(b))))
                finally:
                    eng.stop()
            log("[%s] batch %d/%d %.1fs" % (label, bi, len(batches), time.time() - t0))
    return lat, kbs


# ------------------------------------------------------------------ ranking
def build_records(pool, screen, final, speed, args, proto):
    recs = []
    need = max(2, (args.rounds_final + 1) // 2)
    for n in pool:
        u = n["uid"]
        fs = final.get(u) or []
        samples = fs or screen.get(u) or []
        if not samples:
            continue
        m = statistics.median(samples)
        j = statistics.pstdev(samples) if len(samples) > 1 else 0.0
        k = speed.get(u)
        stable = len(fs) >= need
        fast = k is not None and k >= args.min_kbs
        tier = 0 if (fast and stable) else (1 if (fast or stable) else 2)
        tr = (0 if n["net"] == "httpupgrade" else 1) if proto == "trojan" else 0
        recs.append({"n": n, "lat": m, "jit": j, "kbs": k, "tier": tier,
                     "sort": (tier, tr, m + j)})
    recs.sort(key=lambda r: r["sort"])
    return recs


def select(recs, args, proto):
    top = args.top
    if proto not in SPLIT_PROTOS:
        return recs[:top]
    hu_t = args.hu_quota_trojan if proto == "trojan" else top - args.ws_quota
    hu_t = max(0, min(top, hu_t))
    ws_t = top - hu_t
    hu = [r for r in recs if r["n"]["net"] == "httpupgrade"]
    ws = [r for r in recs if r["n"]["net"] == "ws"]
    chosen = hu[:hu_t] + ws[:ws_t]
    if len(chosen) < top:
        used = {id(r) for r in chosen}
        chosen += [r for r in recs if id(r) not in used][:top - len(chosen)]
    chosen.sort(key=lambda r: r["sort"])
    return chosen[:top]


def export(proto, recs, args):
    od = Path(args.out_dir)
    od.mkdir(parents=True, exist_ok=True)
    chosen = select(recs, args, proto)
    lines, report = [], []
    for i, r in enumerate(chosen, 1):
        n = r["n"]
        tier = TIERS[r["tier"]]
        cc = n.get("cc") or ""
        if args.annotate:
            tag = (n["remark"] or n["host"]).strip()
            extra = ("%s " % flag(cc)) if cc else ""
            lines.append(n["link"].split("#")[0] + "#" + quote(
                "%s%s | %dms | %s" % (extra, tag, r["lat"], tier)))
        else:
            lines.append(n["link"])
        report.append({"rank": i, "protocol": proto, "tier": tier, "country": cc,
                       "transport": n["net"], "host_header": effective_host(n),
                       "server": n["host"], "ip": n.get("ip"), "port": n["port"],
                       "latency_ms": round(r["lat"], 1), "jitter_ms": round(r["jit"], 1),
                       "download_kbs": round(r["kbs"], 1) if r["kbs"] else None,
                       "remark": n["remark"], "link": n["link"]})
    txt = od / ("%s_top%d.txt" % (proto, args.top))
    txt.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    (od / ("%s_top%d_b64.txt" % (proto, args.top))).write_text(
        base64.b64encode("\n".join(lines).encode()).decode(), encoding="utf-8")
    (od / ("%s_report.json" % proto)).write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    if proto == "wireguard" and chosen:
        try:
            with zipfile.ZipFile(od / "wireguard_configs.zip", "w", zipfile.ZIP_DEFLATED) as z:
                for i, r in enumerate(chosen, 1):
                    n = r["n"]
                    nm = re.sub(r"[^A-Za-z0-9_-]", "_", (n["remark"] or "wg"))[:28]
                    z.writestr("%03d_%s_%s.conf" % (i, n.get("cc") or "XX", nm), wg_conf(n))
        except Exception:
            pass
    nws = sum(1 for r in chosen if r["n"]["net"] == "ws")
    nhu = sum(1 for r in chosen if r["n"]["net"] == "httpupgrade")
    ng = sum(1 for r in chosen if r["tier"] == 0)
    log("\n=== %s : %d configs" % (proto.upper(), len(chosen)))
    log("    ws=%d httpupgrade=%d GOLD=%d" % (nws, nhu, ng))
    for r in chosen[:8]:
        n = r["n"]
        log("  %7.1f ms %-11s %-6s %s %s" % (r["lat"], n["net"], TIERS[r["tier"]],
                                             flag(n.get("cc")), effective_host(n)))
    if len(chosen) > 8:
        log("  ... %d more in the file" % (len(chosen) - 8))
    log("  -> %s" % txt)
    return {"written": len(chosen), "ws": nws, "hu": nhu, "gold": ng,
            "best": chosen[0]["lat"] if chosen else None}


def write_summary(rows, out_dir, countries):
    md = ["# Proxy Hunter results", "",
          "Country filter: **%s**" % (", ".join(sorted(countries)) if countries else "Any"), "",
          "| Protocol | Servers | In country | Tested | Live | WS | HU | Gold | Written | Fastest |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        md.append("| %s | %d | %d | %d | %d | %d | %d | %d | %d | %s |" % (
            r["proto"], r["servers"], r["geo"], r["tested"], r["live"],
            r["ws"], r["hu"], r["gold"], r["written"],
            ("%.0f ms" % r["best"]) if r["best"] else "-"))
    md += ["", "**GOLD** = low latency + stable + real 256 KB download.",
           "Trojan lists HTTPUpgrade first. VLESS/Trojan are ws/httpupgrade only,",
           "and every ws/httpupgrade config has a real non-empty Host header.",
           "WireGuard also ships as `wireguard_configs.zip` (ready-to-import .conf).",
           "Country = geolocation of the server IP (Cloudflare-fronted nodes show the CDN country)."]
    text = "\n".join(md) + "\n"
    try:
        (Path(out_dir) / "STATUS.md").write_text(text, encoding="utf-8")
        s = os.getenv("GITHUB_STEP_SUMMARY")
        if s:
            with open(s, "a", encoding="utf-8") as f:
                f.write(text)
    except Exception:
        pass


# ------------------------------------------------------------------ main
async def main_async(args):
    args.deadline = time.time() + args.max_minutes * 60
    asyncio.get_running_loop().set_default_executor(ThreadPoolExecutor(max_workers=512))
    od = Path(args.out_dir)
    od.mkdir(parents=True, exist_ok=True)
    countries = parse_country(args.country)
    wanted = PROTOS if args.protocol.strip().lower() == "all" else [
        x.strip().lower() for x in args.protocol.split(",") if x.strip()]
    wanted = [p for p in wanted if p in PROTOS] or PROTOS
    log("[config] protocols=%s country=%s top=%d" %
        (wanted, sorted(countries) if countries else "ANY", args.top))

    def blank(p, servers=0, geo=0):
        return {"proto": p, "servers": servers, "geo": geo, "tested": 0, "live": 0,
                "ws": 0, "hu": 0, "gold": 0, "written": 0, "best": None}

    try:
        exe = ensure_singbox(Path(args.bindir))
        log("[engine] sing-box: %s" % exe)
    except Exception as e:
        log("!! sing-box unavailable: %s" % e)
        for p in wanted:
            export(p, [], args)
        write_summary([blank(p) for p in wanted], od, countries)
        return

    geo = Geo(ensure_geo(args.bindir))
    if geo.rd:
        log("[geo] country database ready")
    else:
        log("[geo] no country database available")
        if countries:
            log("!! Country filter requested but no database - cannot verify countries.")
            for p in wanted:
                export(p, [], args)
            write_summary([blank(p) for p in wanted], od, countries)
            return

    wg_mode = None
    if "wireguard" in wanted:
        with tempfile.TemporaryDirectory() as td:
            wg_mode = detect_wg_mode(exe, Path(td))
        if not wg_mode:
            wanted = [p for p in wanted if p != "wireguard"]

    try:
        texts = await harvest(args)
    except Exception:
        texts = []
    if not texts:
        log("!! nothing downloaded")
        for p in wanted:
            export(p, [], args)
        write_summary([blank(p) for p in wanted], od, countries)
        return

    seen_l, seen_k, nodes = set(), set(), []
    uid = itertools.count(1)

    def add(n):
        if n and n["key"] not in seen_k:
            seen_k.add(n["key"])
            n["uid"] = next(uid)
            nodes.append(n)

    for t in texts:
        for ln in extract_links(t):
            if ln in seen_l:
                continue
            seen_l.add(ln)
            try:
                add(parse_link(ln))
            except Exception:
                pass
        for blk in extract_wg_blocks(t):
            try:
                add(wg_from_conf(blk))
            except Exception:
                pass

    log("\n[parse] %d links -> %d unique nodes" % (len(seen_l), len(nodes)))
    for p in PROTOS:
        a = sum(1 for n in nodes if n["proto"] == p)
        b = sum(1 for n in nodes if n["proto"] == p and gate(n) and host_ok(n))
        log("        %-11s %6d   usable %6d" % (p, a, b))

    rows = []
    for pi, proto in enumerate(wanted):
        try:
            share = max(70.0, (args.deadline - time.time()) / max(1, len(wanted) - pi))
            args.proto_deadline = min(args.deadline, time.time() + share)
            split = proto in SPLIT_PROTOS
            hu_share = 0.65 if proto == "trojan" else 0.5
            pool = unique_servers([n for n in nodes
                                   if n["proto"] == proto and gate(n) and host_ok(n)])
            log("\n[%s] %d unique servers" % (proto, len(pool)))
            if not pool:
                info = export(proto, [], args)
                rows.append({**blank(proto), **info})
                continue

            live = await preflight(pool, args.preflight_timeout, args.preflight_conc)
            log("[%s] reachable: %d" % (proto, len(live)))
            for n in live:
                n["cc"] = geo.cc(n.get("ip"))
            if countries:
                live = [n for n in live if n.get("cc") in countries]
                log("[%s] in requested country: %d" % (proto, len(live)))
            geo_n = len(live)
            if not live:
                info = export(proto, [], args)
                rows.append({**blank(proto, len(pool), 0), **info})
                continue

            budget = args.max_test if split else args.max_test_other
            cand = allocate_quota(live, budget, split, hu_share)
            log("[%s] deep-testing %d (ws=%d hu=%d)" % (
                proto, len(cand), sum(1 for n in cand if n["net"] == "ws"),
                sum(1 for n in cand if n["net"] == "httpupgrade")))

            if proto == "wireguard":
                lat, kbs = await download_pass(exe, cand, args, wg_mode,
                                               "wg", want_lat=True)
                recs = build_records(cand, lat, lat, kbs, args, proto)
                info = export(proto, recs, args)
                rows.append({**blank(proto, len(pool), geo_n),
                             "tested": len(cand), "live": len(recs), **info})
                continue

            screen = await measure_all(exe, cand, args, rounds=args.rounds, label="test")
            scored = [(n, statistics.median(screen[n["uid"]]))
                      for n in cand if n["uid"] in screen
                      and len(screen[n["uid"]]) >= args.min_success]
            scored.sort(key=lambda x: x[1])
            log("[%s] %d passed screening" % (proto, len(scored)))
            fin = allocate_quota([n for n, _ in scored], args.finalists, split, hu_share)
            final, speed = {}, {}
            if fin and budget_left(args) > 40:
                final = await measure_all(exe, fin, args, rounds=args.rounds_final, label="verify")
            if fin and not args.no_speed_test and budget_left(args) > 60:
                try:
                    _, speed = await download_pass(exe, fin, args, None, "speed")
                    log("[%s] bandwidth verified on %d" % (proto, len(speed)))
                except Exception:
                    log("[%s] bandwidth test skipped" % proto)
            recs = build_records([n for n, _ in scored], screen, final, speed, args, proto)
            info = export(proto, recs, args)
            rows.append({**blank(proto, len(pool), geo_n), "tested": len(cand),
                         "live": len(scored), **info})
        except Exception:
            log("[%s] internal problem:" % proto)
            traceback.print_exc()
            try:
                export(proto, [], args)
            except Exception:
                pass
            rows.append(blank(proto))

    write_summary(rows, od, countries)
    log("\nDone. Files in %s" % od)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--protocol", default="all")
    ap.add_argument("--country", default="any")
    ap.add_argument("--top", type=int, default=100)
    ap.add_argument("--ws-quota", type=int, default=50)
    ap.add_argument("--hu-quota-trojan", type=int, default=70)
    ap.add_argument("--out-dir", default="out")
    ap.add_argument("--max-repos", type=int, default=250)
    ap.add_argument("--files-per-repo", type=int, default=6)
    ap.add_argument("--harvest-mb", type=int, default=220)
    ap.add_argument("--harvest-minutes", type=int, default=6)
    ap.add_argument("--max-age-days", type=int, default=60)
    ap.add_argument("--discover", type=int, default=400)
    ap.add_argument("--rounds", type=int, default=1)
    ap.add_argument("--rounds-final", type=int, default=3)
    ap.add_argument("--finalists", type=int, default=280)
    ap.add_argument("--min-success", type=int, default=1)
    ap.add_argument("--timeout", type=int, default=2500)
    ap.add_argument("--concurrency", type=int, default=80)
    ap.add_argument("--batch", type=int, default=100)
    ap.add_argument("--max-test", type=int, default=2000)
    ap.add_argument("--max-test-other", type=int, default=900)
    ap.add_argument("--speed-timeout", type=int, default=8000)
    ap.add_argument("--speed-conc", type=int, default=24)
    ap.add_argument("--min-kbs", type=float, default=60.0)
    ap.add_argument("--no-speed-test", action="store_true")
    ap.add_argument("--wg-batch", type=int, default=25)
    ap.add_argument("--wg-rounds", type=int, default=2)
    ap.add_argument("--max-minutes", type=int, default=46)
    ap.add_argument("--preflight-timeout", type=float, default=1.2)
    ap.add_argument("--preflight-conc", type=int, default=800)
    ap.add_argument("--annotate", action="store_true")
    ap.add_argument("--workdir", default=".nh")
    ap.add_argument("--bindir", default="bin")
    args = ap.parse_args()
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        log("stopped")
    except Exception:
        traceback.print_exc()
        log("Finished with problems - see STATUS.md")
    sys.exit(0)


if __name__ == "__main__":
    main()
