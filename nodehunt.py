#!/usr/bin/env python3
"""
nodehunt - harvest public GitHub proxy pools, keep only LIVE nodes,
measure REAL latency + REAL bandwidth with sing-box, export the best.

RULES
  * VLESS / Trojan  -> transport must be ws or httpupgrade
  * ANY ws/httpupgrade config -> must have a real, non-empty Host header
  * VMess / SS / Hysteria2 -> any transport
  * Output: 50 ws + 50 httpupgrade (auto-backfill if one type is short)
"""
from __future__ import annotations

import argparse
import asyncio
import base64
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
from urllib.parse import parse_qs, unquote, quote

try:
    import httpx
except ImportError:
    print("Missing package. Run: pip install -r requirements.txt")
    sys.exit(0)

try:
    import h2  # noqa: F401
    HTTP2 = True
except Exception:
    HTTP2 = False

UA = {"User-Agent": "nodehunt/1.0"}
SCHEMES = {"vless": "vless", "vmess": "vmess", "trojan": "trojan",
           "ss": "ss", "hysteria2": "hysteria2", "hy2": "hysteria2"}
PROTOS = ["vless", "vmess", "trojan", "ss", "hysteria2"]
VT_ONLY = {"ws", "httpupgrade"}
SPLIT_PROTOS = {"vless", "trojan"}

SPEED_URL = "https://speed.cloudflare.com/__down?bytes=262144"
SPEED_BYTES = 262144
MAXFILE = 5_000_000

LINK_RE = re.compile(r"(?:vless|vmess|trojan|ss|hysteria2|hy2)://[^\s\"'<>`\\]+", re.I)
B64_RE = re.compile(r"[A-Za-z0-9+/=_-]{120,}")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?"
                     r"[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]*$")
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")

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
TREE_KEY = re.compile(r"(\.txt$|/sub|^sub|base64|list|node|prox|config|subscribe|"
                      r"protocols/|Splitted-By-Protocol|Eternity|v2ray|^README\.md$)", re.I)

PORTS = itertools.count(19100)
IN_BASE = itertools.count(31000, 100)
API_OK = False
TIERS = ("GOLD", "SILVER", "BRONZE")


def log(*a):
    print(*a, flush=True)


def b64d(s: str) -> str:
    s = re.sub(r"\s+", "", s).replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8", "replace")


def is_b64ish(s: str) -> bool:
    return len(s) > 24 and re.fullmatch(r"[A-Za-z0-9+/=_\-\s]+", s) is not None


def is_ip(h: str) -> bool:
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def bad_host(h: str) -> bool:
    if not h or " " in h or h.lower() in ("localhost", "0.0.0.0"):
        return True
    if is_ip(h):
        ip = ipaddress.ip_address(h)
        return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast
    return "." not in h


def split_hp(hp: str):
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


def truthy(v) -> bool:
    return str(v).lower() in ("1", "true", "yes", "on")


def gh_headers():
    h = dict(UA)
    tok = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    if tok:
        h["Authorization"] = "Bearer " + tok
    return h


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
            repo, _, fpath = line.partition(":")
            repos.setdefault(repo.strip(), []).append(fpath.strip())
        elif "/" in line:
            repos.setdefault(line, [])
    return repos, urls


async def fetch_repo(client, repo, paths):
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
            got = await asyncio.gather(*(grab(p, branch) for p in paths[1:]))
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
                name = path.rsplit("/", 1)[-1]
                ext = Path(name).suffix.lower()
                if ext not in ("", ".txt", ".yaml", ".yml", ".md"):
                    continue
                if ext == ".md" and name.lower() != "readme.md":
                    continue
                if TREE_KEY.search(path):
                    cand.append(path)
            if cand:
                for br in ("main", "master", "HEAD"):
                    t = await grab(cand[0], br)
                    if t is not None:
                        branch = br
                        texts.append(t)
                        break
                if branch:
                    got = await asyncio.gather(*(grab(p, branch) for p in cand[1:12]))
                    texts += [g for g in got if g]
            break
        except Exception:
            continue
    return texts


async def discover(client, limit):
    qs = ("v2ray+configs", "v2ray+subscription", "free+v2ray+nodes",
          "proxy+collector+vless", "hysteria2+subscription")

    async def one(q):
        try:
            r = await client.get(
                "https://api.github.com/search/repositories?q=%s"
                "&sort=stars&order=desc&per_page=15" % q,
                headers=gh_headers(), timeout=25)
            if r.status_code == 200:
                return r.json().get("items", [])
        except Exception:
            pass
        return []

    found = {}
    for items in await asyncio.gather(*(one(q) for q in qs)):
        for it in items:
            if it.get("archived") or it.get("size", 0) > 300_000:
                continue
            found[it["full_name"]] = it.get("stargazers_count", 0)
    return [k for k, _ in sorted(found.items(), key=lambda x: -x[1])][:limit]


async def harvest(args):
    repos, urls = load_sources()
    texts = []
    limits = httpx.Limits(max_connections=64, max_keepalive_connections=32)
    async with httpx.AsyncClient(headers=UA, timeout=25, http2=HTTP2,
                                 follow_redirects=True, limits=limits) as c:
        if args.discover:
            try:
                for r in await discover(c, args.discover):
                    repos.setdefault(r, [])
            except Exception:
                pass
        log("[sources] %d repos, %d extra URLs (http2=%s)" % (len(repos), len(urls), HTTP2))
        sem = asyncio.Semaphore(14)

        async def one(repo, paths):
            async with sem:
                try:
                    got = await fetch_repo(c, repo, paths)
                except Exception:
                    got = []
                texts.extend(got)
                log("[sources] %-48s %8.1f KiB" % (repo, sum(len(x) for x in got) / 1024))

        await asyncio.gather(*(one(r, p) for r, p in list(repos.items())[:40]))
        if urls:
            async def geturl(u):
                try:
                    r = await c.get(u)
                    if r.status_code == 200 and len(r.text) < MAXFILE:
                        return r.text
                except Exception:
                    pass
                return None
            texts += [t for t in await asyncio.gather(*(geturl(u) for u in urls[:20])) if t]
    return texts


def extract_links(text: str):
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
            if not out:
                for ln in text.splitlines()[:40000]:
                    ln = ln.strip()
                    if "://" not in ln and is_b64ish(ln):
                        try:
                            d = b64d(ln)
                            if "://" in d:
                                scan(d)
                        except Exception:
                            pass
    except Exception:
        pass
    return out


# ------------------------------------------------------------------ parse
def norm_net(v):
    return NET_MAP.get(str(v).strip().lower(), str(v).strip().lower())


def parse_link(link: str):
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
        params = {"sni": str(j.get("sni") or ""), "host": str(j.get("host") or ""),
                  "path": str(j.get("path") or ""), "alpn": str(j.get("alpn") or ""),
                  "fp": str(j.get("fp") or ""),
                  "scy": str(j.get("scy") or "auto").lower(),
                  "aid": str(j.get("aid") or 0),
                  "allowInsecure": str(j.get("allowInsecure") or "")}
        net = norm_net(j.get("net", "tcp"))
        if net == "grpc":
            params["serviceName"] = params["path"]
        return finish(dict(proto=proto, host=host, port=port,
                           secret=str(j.get("id", "")), net=net, security=sec,
                           params=params, remark=str(j.get("ps", "")), link=link))

    frag = ""
    if "#" in rest:
        rest, frag = rest.split("#", 1)
    q = ""
    if "?" in rest:
        rest, q = rest.split("?", 1)
    params = {k: (v[0] if v else "")
              for k, v in parse_qs(q, keep_blank_values=True).items()}
    remark = unquote(frag)

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
        return finish(dict(proto=proto, host=host, port=port,
                           secret=unquote(password), net="tcp", security="none",
                           params=params, remark=remark, link=link))

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

    return finish(dict(proto=proto, host=host, port=port, secret=secret,
                       net=net, security=sec, params=params,
                       remark=remark, link=link))


def finish(n):
    if bad_host(n["host"]) or not (0 < n["port"] < 65536) or not n["secret"]:
        return None
    p = n["params"]
    if p.get("fp") and p["fp"].lower() not in FP_OK:
        p["fp"] = ""
    if n["proto"] != "hysteria2" and n["net"] in BAD_NET:
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
        n["proto"], n["host"].lower(), n["port"], n["secret"], n["net"],
        n["security"], p.get("path", ""), p.get("host", ""), p.get("sni", ""),
        p.get("serviceName", ""), p.get("pbk", ""), p.get("sid", ""),
        p.get("flow", ""), p.get("method", ""), p.get("scy", ""),
        p.get("aid", ""), p.get("obfs-password", ""), p.get("mport", "")])
    return n


# ------------------------------------------------------------------ QUALITY GATES
def effective_host(n):
    """The Host header this config will actually send."""
    h = (n["params"].get("host") or "").strip()
    if not h and not is_ip(n["host"]):
        h = n["host"].strip()
    if h.count(":") == 1:
        h = h.split(":")[0]
    return h.strip().strip(".")


def host_ok(n):
    """NEW RULE: ws / httpupgrade must carry a real hostname in Host."""
    if n["net"] not in ("ws", "httpupgrade"):
        return True
    h = effective_host(n)
    if not h or " " in h or is_ip(h) or "." not in h:
        return False
    return HOST_RE.match(h) is not None


def gate(n):
    """VLESS / Trojan must be ws or httpupgrade."""
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


def allocate_quota(items, budget, split):
    """Guarantee both transports get tested so 50/50 can actually be filled."""
    if budget <= 0 or len(items) <= budget:
        return items
    if not split:
        return spread(items, budget)
    ws = [n for n in items if n["net"] == "ws"]
    hu = [n for n in items if n["net"] == "httpupgrade"]
    half = budget // 2
    na = min(len(ws), half)
    nb = min(len(hu), budget - na)
    na = min(len(ws), budget - nb)
    return spread(ws, na) + spread(hu, nb)


# ------------------------------------------------------------------ preflight
async def preflight(nodes, timeout, conc):
    """DNS cached per hostname, TCP cached per ip:port. Massive dedupe."""
    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(conc)
    ips = {n["host"]: n["host"] for n in nodes if is_ip(n["host"])}
    names = sorted({n["host"] for n in nodes if not is_ip(n["host"])})
    done = 0

    async def res(h):
        nonlocal done
        async with sem:
            try:
                infos = await asyncio.wait_for(
                    loop.getaddrinfo(h, None, type=socket.SOCK_STREAM), timeout)
                v4 = [i for i in infos if i[0] == socket.AF_INET]
                ips[h] = (v4 or infos)[0][4][0]
            except Exception:
                ips[h] = None
            done += 1
            if done % 500 == 0:
                log("      dns %d/%d" % (done, len(names)))

    if names:
        await asyncio.gather(*(res(h) for h in names))
    log("    dns: %d names -> %d resolved" % (len(names), sum(1 for v in ips.values() if v)))

    pairs = sorted({(ips[n["host"]], n["port"]) for n in nodes
                    if ips.get(n["host"]) and n["proto"] != "hysteria2"})
    ok = set()
    done = 0

    async def tcp(ip, port):
        nonlocal done
        async with sem:
            try:
                _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
                w.close()
                try:
                    await asyncio.wait_for(w.wait_closed(), 1)
                except Exception:
                    pass
                ok.add((ip, port))
            except Exception:
                pass
            done += 1
            if done % 500 == 0:
                log("      tcp %d/%d  open %d" % (done, len(pairs), len(ok)))

    if pairs:
        await asyncio.gather(*(tcp(ip, p) for ip, p in pairs))
    log("    tcp: %d endpoints -> %d open" % (len(pairs), len(ok)))

    alive = []
    for n in nodes:
        ip = ips.get(n["host"])
        if not ip:
            continue
        if n["proto"] == "hysteria2" or (ip, n["port"]) in ok:
            n["ip"] = ip
            alive.append(n)
    return alive


# ------------------------------------------------------------------ engine
def ensure_singbox(bindir: Path) -> str:
    exe = shutil.which("sing-box")
    if exe:
        return exe
    local = bindir / ("sing-box.exe" if os.name == "nt" else "sing-box")
    if local.exists():
        return str(local)
    sysname = {"Linux": "linux", "Darwin": "darwin", "Windows": "windows"}.get(platform.system())
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64",
            "arm64": "arm64"}.get(platform.machine().lower())
    if not sysname or not arch:
        raise RuntimeError("Cannot auto-install sing-box here")
    ext = "zip" if sysname == "windows" else "tar.gz"
    pat = re.compile(r"sing-box-[\d.]+-" + sysname + "-" + arch + r"\." +
                     ext.replace(".", r"\.") + "$")
    with httpx.Client(headers=gh_headers(), timeout=90, follow_redirects=True) as c:
        rel = c.get("https://api.github.com/repos/SagerNet/sing-box/releases/latest").json()
        asset = next(a for a in rel.get("assets", []) if pat.search(a["name"]))
        log("[engine] downloading " + asset["name"])
        blob = c.get(asset["browser_download_url"]).content
    bindir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / asset["name"]
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
    t = {"enabled": True,
         "insecure": truthy(p.get("allowInsecure") or p.get("insecure"))}
    if sni and not is_ip(sni):
        t["server_name"] = sni
    else:
        t["insecure"] = True
    if p.get("alpn"):
        t["alpn"] = [x for x in p["alpn"].split(",") if x]
    if p.get("fp"):
        t["utls"] = {"enabled": True, "fingerprint": p["fp"].lower()}
    if n["security"] == "reality":
        t["reality"] = {"enabled": True, "public_key": p["pbk"],
                        "short_id": p.get("sid", "")}
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


def sb_config(nodes, tags, port, use_urltest=False):
    outs = [to_outbound(n, t) for n, t in zip(nodes, tags)]
    if use_urltest and len(outs) >= 2:
        outs.append({"type": "urltest", "tag": "auto", "outbounds": list(tags),
                     "url": TEST_URLS[0], "interval": "1h", "tolerance": 50})
    return {"log": {"level": "error", "timestamp": False},
            "outbounds": outs,
            "experimental": {"clash_api": {"external_controller": "127.0.0.1:%d" % port}}}


def speed_config(nodes, tags, api_port, in_base):
    outs = [to_outbound(n, t) for n, t in zip(nodes, tags)]
    ins, rules = [], []
    for i, t in enumerate(tags):
        it = "in%05d" % i
        ins.append({"type": "mixed", "tag": it, "listen": "127.0.0.1",
                    "listen_port": in_base + i})
        rules.append({"inbound": [it], "outbound": t})
    return {"log": {"level": "error", "timestamp": False},
            "inbounds": ins, "outbounds": outs,
            "route": {"rules": rules, "final": tags[0]},
            "experimental": {"clash_api": {"external_controller": "127.0.0.1:%d" % api_port}}}


def check_one(exe, wd, n, tag, i):
    cfg = wd / ("chk_%d.json" % i)
    try:
        cfg.write_text(json.dumps(sb_config([n], [tag], 19099)))
        r = subprocess.run([exe, "check", "-c", str(cfg)], capture_output=True, timeout=20)
        ok = r.returncode == 0
    except Exception:
        ok = False
    try:
        cfg.unlink()
    except Exception:
        pass
    return ok


async def validate_parallel(exe, wd, nodes, tags):
    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = [loop.run_in_executor(pool, check_one, exe, wd, n, tags[i], i)
                for i, n in enumerate(nodes)]
        oks = await asyncio.gather(*futs)
    keep = [i for i, ok in enumerate(oks) if ok]
    log("    config check: %d ok, %d dropped" % (len(keep), len(nodes) - len(keep)))
    return keep


class Engine:
    def __init__(self, exe, wd, port):
        self.exe, self.wd, self.port = exe, wd, port
        self.proc = None
        self.base = "http://127.0.0.1:%d" % port

    async def start_cfg(self, cfg, client):
        path = self.wd / "sb.json"
        path.write_text(json.dumps(cfg))
        logf = open(self.wd / "sb.log", "ab")
        try:
            self.proc = subprocess.Popen([self.exe, "run", "-c", str(path)],
                                         stdout=logf, stderr=logf)
        except Exception:
            return False
        for _ in range(60):
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
            if done % 40 == 0:
                log("      %s %d/%d probes" % (o["label"], done, total))

    try:
        for rd in range(o["rounds"]):
            url = o["urls"][rd % len(o["urls"])]
            await asyncio.gather(*(probe(i, url) for i in range(len(nodes))))
            log("    %s round %d/%d done" % (o["label"], rd + 1, o["rounds"]))
        if o["allow_history"]:
            missing = [i for i in range(len(nodes)) if not res[i]]
            if missing:
                try:
                    r = await client.get(eng.base + "/proxies", timeout=15)
                    if r.status_code == 200:
                        px = r.json().get("proxies", {})
                        for i in missing:
                            h = px.get(tags[i], {}).get("history") or []
                            if h:
                                d = h[-1].get("delay")
                                if isinstance(d, (int, float)) and d > 0:
                                    res[i].append(float(d))
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
        log("    batch had a bad config - validating individually")
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


async def measure_all(exe, nodes, args, urls=None, timeout=None, rounds=None,
                      conc=None, label="test", allow_history=True):
    out = {}
    if not nodes:
        return out
    o = {"urls": urls or TEST_URLS, "timeout": timeout or args.timeout,
         "rounds": max(1, rounds or args.rounds), "conc": conc or args.concurrency,
         "label": label, "allow_history": allow_history}
    work = Path(args.workdir)
    work.mkdir(parents=True, exist_ok=True)
    batches = [nodes[i:i + args.batch] for i in range(0, len(nodes), args.batch)]
    async with httpx.AsyncClient(timeout=o["timeout"] / 1000 + 10) as client:
        for bi, batch in enumerate(batches, 1):
            if time.time() > args.deadline:
                log("[%s] time budget reached - keeping what we have" % label)
                break
            t0 = time.time()
            log("[%s] batch %d/%d (%d nodes)" % (label, bi, len(batches), len(batch)))
            try:
                with tempfile.TemporaryDirectory(dir=work) as td:
                    res = await measure_batch(exe, Path(td), batch, client, o)
            except Exception:
                res = {}
            for i, s in res.items():
                out[batch[i]["uid"]] = s
            log("[%s] batch %d/%d alive=%d %.1fs"
                % (label, bi, len(batches), len(res), time.time() - t0))
    return out


async def speed_measure(exe, nodes, args):
    """Real 256 KB download through each proxy -> KB/s. This is the gold filter."""
    out = {}
    if not nodes:
        return out
    work = Path(args.workdir)
    work.mkdir(parents=True, exist_ok=True)
    batches = [nodes[i:i + args.batch] for i in range(0, len(nodes), args.batch)]
    sem = asyncio.Semaphore(args.speed_conc)
    async with httpx.AsyncClient(timeout=5) as rc:
        for bi, batch in enumerate(batches, 1):
            if time.time() > args.deadline:
                break
            tags = ["s%05d" % i for i in range(len(batch))]
            base = next(IN_BASE)
            t0 = time.time()
            log("[speed] batch %d/%d (%d nodes)" % (bi, len(batches), len(batch)))
            with tempfile.TemporaryDirectory(dir=work) as td:
                wd = Path(td)
                eng = Engine(exe, wd, next(PORTS))
                try:
                    started = await eng.start_cfg(speed_config(batch, tags, eng.port, base), rc)
                except Exception:
                    started = False
                if not started:
                    eng.stop()
                    log("[speed] engine would not start - skipping bandwidth test")
                    return out
                done = 0

                async def one(i):
                    nonlocal done
                    async with sem:
                        t = time.monotonic()
                        try:
                            async with httpx.AsyncClient(
                                    proxy="http://127.0.0.1:%d" % (base + i),
                                    timeout=args.speed_timeout / 1000 + 2,
                                    follow_redirects=True) as c:
                                r = await c.get(SPEED_URL)
                                dt = time.monotonic() - t
                                nb = len(r.content)
                                if r.status_code == 200 and nb > 2000 and dt > 0.001:
                                    out[batch[i]["uid"]] = (nb / 1024.0) / dt
                        except Exception:
                            pass
                        done += 1
                        if done % 40 == 0:
                            log("      speed %d/%d" % (done, len(batch)))

                try:
                    await asyncio.gather(*(one(i) for i in range(len(batch))))
                finally:
                    eng.stop()
            log("[speed] batch %d/%d ok=%d %.1fs"
                % (bi, len(batches), len(out), time.time() - t0))
    return out


# ------------------------------------------------------------------ ranking
def build_records(pool, screen, final, speed, args):
    recs = []
    need = max(2, (args.rounds_final + 1) // 2)
    for n in pool:
        uid = n["uid"]
        fs = final.get(uid) or []
        ss = screen.get(uid) or []
        samples = fs or ss
        if not samples:
            continue
        lat = statistics.median(samples)
        jit = statistics.pstdev(samples) if len(samples) > 1 else 0.0
        kbs = speed.get(uid)
        stable = len(fs) >= need
        fast = kbs is not None and kbs >= args.min_kbs
        tier = 0 if (fast and stable) else (1 if (fast or stable) else 2)
        recs.append({"n": n, "lat": lat, "jit": jit, "kbs": kbs,
                     "tier": tier, "sort": (tier, lat + jit)})
    recs.sort(key=lambda r: r["sort"])
    return recs


def select(recs, top, ws_quota, split):
    if not split:
        return recs[:top]
    ws = [r for r in recs if r["n"]["net"] == "ws"]
    hu = [r for r in recs if r["n"]["net"] == "httpupgrade"]
    chosen = ws[:ws_quota] + hu[:max(0, top - ws_quota)]
    if len(chosen) < top:
        used = {id(r) for r in chosen}
        rest = [r for r in recs if id(r) not in used]
        chosen += rest[:top - len(chosen)]
    chosen.sort(key=lambda r: r["sort"])
    return chosen[:top]


def export(proto, recs, args):
    od = Path(args.out_dir)
    od.mkdir(parents=True, exist_ok=True)
    split = proto in SPLIT_PROTOS
    chosen = select(recs, args.top, args.ws_quota, split)

    lines, report = [], []
    for i, r in enumerate(chosen, 1):
        n = r["n"]
        tier = TIERS[r["tier"]]
        if args.annotate:
            tag = (n["remark"] or n["host"]).strip()
            lines.append(n["link"].split("#")[0] + "#" +
                         quote("%s | %dms | %s" % (tag, r["lat"], tier)))
        else:
            lines.append(n["link"])
        report.append({"rank": i, "protocol": proto, "tier": tier,
                       "transport": n["net"], "host_header": effective_host(n),
                       "server": n["host"], "port": n["port"],
                       "latency_ms": round(r["lat"], 1),
                       "jitter_ms": round(r["jit"], 1),
                       "download_kbs": round(r["kbs"], 1) if r["kbs"] else None,
                       "remark": n["remark"], "link": n["link"]})

    txt = od / ("%s_top%d.txt" % (proto, args.top))
    txt.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    (od / ("%s_top%d_b64.txt" % (proto, args.top))).write_text(
        base64.b64encode("\n".join(lines).encode()).decode(), encoding="utf-8")
    (od / ("%s_report.json" % proto)).write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    nws = sum(1 for r in chosen if r["n"]["net"] == "ws")
    nhu = sum(1 for r in chosen if r["n"]["net"] == "httpupgrade")
    ngold = sum(1 for r in chosen if r["tier"] == 0)
    rule = " (ws / httpupgrade only, Host required)" if split else ""
    log("\n=== %s : %d configs%s" % (proto.upper(), len(chosen), rule))
    log("    ws=%d  httpupgrade=%d  GOLD=%d" % (nws, nhu, ngold))
    for r in chosen[:10]:
        n = r["n"]
        log("  %7.1f ms  %-11s %-6s %s" %
            (r["lat"], n["net"], TIERS[r["tier"]], effective_host(n)))
    if len(chosen) > 10:
        log("  ... %d more in the file" % (len(chosen) - 10))
    log("  -> %s" % txt)
    if len(chosen) < args.top:
        log("  NOTE: only %d qualified." % len(chosen))
    return {"written": len(chosen), "ws": nws, "hu": nhu, "gold": ngold,
            "best": chosen[0]["lat"] if chosen else None}


def write_summary(rows, out_dir):
    md = ["# Proxy Hunter results", "",
          "| Protocol | Servers | Tested | Live | WS | HTTPUpgrade | Gold | Written | Fastest |",
          "|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        md.append("| %s | %d | %d | %d | %d | %d | %d | %d | %s |" % (
            r["proto"], r["servers"], r["tested"], r["live"], r["ws"], r["hu"],
            r["gold"], r["written"], ("%.0f ms" % r["best"]) if r["best"] else "-"))
    md += ["",
           "**GOLD** = low latency + stable across 3 rounds + real 256 KB download.",
           "VLESS / Trojan are **ws or httpupgrade only**, and every ws/httpupgrade",
           "config has a **real non-empty Host header** (blank/IP-only rejected).",
           "Latency measured from the GitHub runner (usually USA)."]
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
    asyncio.get_running_loop().set_default_executor(ThreadPoolExecutor(max_workers=256))
    od = Path(args.out_dir)
    od.mkdir(parents=True, exist_ok=True)
    wanted = PROTOS if args.protocol.strip().lower() == "all" else [
        x.strip().lower() for x in args.protocol.split(",") if x.strip()]
    wanted = [p for p in wanted if p in PROTOS] or PROTOS

    def blank(p):
        (od / ("%s_top%d.txt" % (p, args.top))).write_text("")
        return {"proto": p, "servers": 0, "tested": 0, "live": 0, "ws": 0,
                "hu": 0, "gold": 0, "written": 0, "best": None}

    try:
        exe = ensure_singbox(Path(args.bindir))
        log("[engine] sing-box ready: %s" % exe)
    except Exception as e:
        log("!! Could not get sing-box: %s" % e)
        write_summary([blank(p) for p in wanted], od)
        return

    try:
        texts = await harvest(args)
    except Exception:
        texts = []
    if not texts:
        log("!! No sources could be downloaded.")
        write_summary([blank(p) for p in wanted], od)
        return

    seen_links, seen_keys, nodes = set(), set(), []
    uid = itertools.count(1)
    for t in texts:
        for ln in extract_links(t):
            if ln in seen_links:
                continue
            seen_links.add(ln)
            try:
                n = parse_link(ln)
            except Exception:
                n = None
            if n and n["key"] not in seen_keys:
                seen_keys.add(n["key"])
                n["uid"] = next(uid)
                nodes.append(n)

    log("\n[parse] %d links -> %d unique usable nodes" % (len(seen_links), len(nodes)))
    for p in PROTOS:
        a = sum(1 for n in nodes if n["proto"] == p)
        b = sum(1 for n in nodes if n["proto"] == p and gate(n))
        c = sum(1 for n in nodes if n["proto"] == p and gate(n) and host_ok(n))
        log("        %-11s %6d  transport-ok %6d  host-ok %6d" % (p, a, b, c))

    rows = []
    for proto in wanted:
        try:
            if time.time() > args.deadline:
                log("[%s] skipped - time budget used up" % proto)
                export(proto, [], args)
                rows.append(blank(proto))
                continue

            split = proto in SPLIT_PROTOS
            raw = [n for n in nodes if n["proto"] == proto]
            ok_t = [n for n in raw if gate(n)]
            ok_h = [n for n in ok_t if host_ok(n)]
            pool = unique_servers(ok_h)
            log("\n[%s] %d -> %d transport -> %d valid Host -> %d unique servers"
                % (proto, len(raw), len(ok_t), len(ok_h), len(pool)))
            if not pool:
                info = export(proto, [], args)
                rows.append({"proto": proto, "servers": 0, "tested": 0, "live": 0, **info})
                continue

            log("[%s] preflight..." % proto)
            if args.no_preflight:
                for n in pool:
                    n["ip"] = n["host"]
                live = pool
            else:
                live = await preflight(pool, args.preflight_timeout, args.preflight_conc)
            log("[%s] reachable: %d" % (proto, len(live)))

            budget = args.max_test if split else args.max_test_other
            cand = allocate_quota(live, budget, split)
            log("[%s] deep-testing %d (ws=%d httpupgrade=%d)" % (
                proto, len(cand),
                sum(1 for n in cand if n["net"] == "ws"),
                sum(1 for n in cand if n["net"] == "httpupgrade")))
            if not cand:
                info = export(proto, [], args)
                rows.append({"proto": proto, "servers": len(pool), "tested": 0,
                             "live": 0, **info})
                continue

            screen = await measure_all(exe, cand, args, rounds=args.rounds, label="test")
            scored = [(n, statistics.median(screen[n["uid"]]))
                      for n in cand if n["uid"] in screen
                      and len(screen[n["uid"]]) >= args.min_success]
            scored.sort(key=lambda x: x[1])
            log("[%s] %d passed screening" % (proto, len(scored)))

            fin_nodes = allocate_quota([n for n, _ in scored], args.finalists, split)
            final, speed = {}, {}
            if fin_nodes and time.time() < args.deadline:
                final = await measure_all(exe, fin_nodes, args,
                                          rounds=args.rounds_final, label="verify")
            if (fin_nodes and not args.no_speed_test
                    and args.deadline - time.time() > 90):
                try:
                    speed = await speed_measure(exe, fin_nodes, args)
                    log("[%s] bandwidth verified on %d nodes" % (proto, len(speed)))
                except Exception:
                    log("[%s] bandwidth test skipped" % proto)

            recs = build_records([n for n, _ in scored], screen, final, speed, args)
            info = export(proto, recs, args)
            rows.append({"proto": proto, "servers": len(pool), "tested": len(cand),
                         "live": len(scored), **info})
        except Exception:
            log("[%s] skipped due to an internal problem:" % proto)
            traceback.print_exc()
            try:
                export(proto, [], args)
            except Exception:
                pass
            rows.append(blank(proto))

    write_summary(rows, od)
    log("\nDone. Files are in: %s" % od)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--protocol", default="all")
    ap.add_argument("--top", type=int, default=100)
    ap.add_argument("--ws-quota", type=int, default=50)
    ap.add_argument("--out-dir", default="out")
    ap.add_argument("--rounds", type=int, default=1)
    ap.add_argument("--rounds-final", type=int, default=3)
    ap.add_argument("--finalists", type=int, default=240)
    ap.add_argument("--min-success", type=int, default=1)
    ap.add_argument("--timeout", type=int, default=2500)
    ap.add_argument("--concurrency", type=int, default=64)
    ap.add_argument("--batch", type=int, default=80)
    ap.add_argument("--max-test", type=int, default=1200)
    ap.add_argument("--max-test-other", type=int, default=600)
    ap.add_argument("--speed-timeout", type=int, default=8000)
    ap.add_argument("--speed-conc", type=int, default=24)
    ap.add_argument("--min-kbs", type=float, default=60.0)
    ap.add_argument("--no-speed-test", action="store_true")
    ap.add_argument("--max-minutes", type=int, default=42)
    ap.add_argument("--preflight-timeout", type=float, default=1.2)
    ap.add_argument("--preflight-conc", type=int, default=600)
    ap.add_argument("--no-preflight", action="store_true")
    ap.add_argument("--discover", type=int, default=10)
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
