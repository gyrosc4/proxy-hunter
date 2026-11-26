#!/usr/bin/env python3
"""
nodehunt - harvest public GitHub proxy pools, keep only LIVE nodes,
measure REAL end-to-end latency with sing-box, export the N fastest.

RULE: VLESS and Trojan are kept ONLY when transport = ws or httpupgrade.
      VMess / Shadowsocks / Hysteria2 = any transport, alive + fast is enough.

Designed to never crash: every risky step is wrapped and skipped on failure.
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
import statistics
import subprocess
import sys
import tarfile
import tempfile
import time
import traceback
import zipfile
from pathlib import Path
from urllib.parse import parse_qs, unquote, quote

try:
    import httpx
except ImportError:
    print("Missing package. Run: pip install -r requirements.txt")
    sys.exit(0)

# ------------------------------------------------------------------ constants
UA = {"User-Agent": "nodehunt/1.0"}
SCHEMES = {"vless": "vless", "vmess": "vmess", "trojan": "trojan",
           "ss": "ss", "hysteria2": "hysteria2", "hy2": "hysteria2"}
PROTOS = ["vless", "vmess", "trojan", "ss", "hysteria2"]
VT_ONLY = {"ws", "httpupgrade"}          # the vless / trojan restriction

LINK_RE = re.compile(r"(?:vless|vmess|trojan|ss|hysteria2|hy2)://[^\s\"'<>`\\]+", re.I)
B64_RE = re.compile(r"[A-Za-z0-9+/=_-]{120,}")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?"
                     r"[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]*$")

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


# ------------------------------------------------------------------ helpers
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


# ------------------------------------------------------------------ 1. harvest
def load_sources(path="sources.txt"):
    repos = {}
    urls = []
    p = Path(path)
    if not p.exists():
        return repos, urls
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("http://") or line.startswith("https://"):
            urls.append(line)
            continue
        if ":" in line and "/" in line:
            repo, _, fpath = line.partition(":")
            repos.setdefault(repo.strip(), []).append(fpath.strip())
        elif "/" in line:
            repos.setdefault(line, [])
    return repos, urls


async def fetch_repo(client, repo, paths):
    """Try listed paths; if the repo gives nothing, scan its file tree."""
    texts = []
    branch = None
    for p in paths:
        tries = [branch] if branch else ["main", "master", "HEAD"]
        for br in tries:
            try:
                r = await client.get(
                    f"https://raw.githubusercontent.com/{repo}/{br}/{p}")
                if r.status_code == 200 and r.text.strip():
                    branch = br
                    if len(r.text) < 12_000_000:
                        texts.append(r.text)
                    break
            except Exception:
                pass
    if texts:
        return texts

    for ref in ("HEAD", "main", "master"):
        try:
            r = await client.get(
                f"https://api.github.com/repos/{repo}/git/trees/{ref}?recursive=1",
                headers=gh_headers(), timeout=25)
            if r.status_code != 200:
                continue
            cand = []
            for e in r.json().get("tree", []):
                if e.get("type") != "blob":
                    continue
                size = e.get("size", 0)
                path = e.get("path", "")
                if not (20 < size < 8_000_000) or TREE_SKIP.search(path):
                    continue
                name = path.rsplit("/", 1)[-1]
                ext = Path(name).suffix.lower()
                if ext not in ("", ".txt", ".yaml", ".yml", ".md"):
                    continue
                if ext == ".md" and name.lower() != "readme.md":
                    continue
                if TREE_KEY.search(path):
                    cand.append(path)
            for path in cand[:15]:
                for br in ([branch] if branch else ["main", "master", "HEAD"]):
                    try:
                        rr = await client.get(
                            f"https://raw.githubusercontent.com/{repo}/{br}/{path}")
                        if rr.status_code == 200 and rr.text.strip():
                            branch = br
                            texts.append(rr.text)
                            break
                    except Exception:
                        pass
            break
        except Exception:
            continue
    return texts


async def discover(client, limit):
    found = {}
    for q in ("v2ray+configs", "v2ray+subscription", "free+v2ray+nodes",
              "proxy+collector+vless", "hysteria2+subscription"):
        try:
            r = await client.get(
                f"https://api.github.com/search/repositories?q={q}"
                f"&sort=stars&order=desc&per_page=15",
                headers=gh_headers(), timeout=25)
            if r.status_code != 200:
                continue
            for it in r.json().get("items", []):
                if it.get("archived") or it.get("size", 0) > 400_000:
                    continue
                found[it["full_name"]] = it.get("stargazers_count", 0)
        except Exception:
            continue
    return [k for k, _ in sorted(found.items(), key=lambda x: -x[1])][:limit]


async def harvest(args):
    repos, urls = load_sources()
    texts = []
    limits = httpx.Limits(max_connections=24, max_keepalive_connections=12)
    async with httpx.AsyncClient(headers=UA, timeout=30,
                                 follow_redirects=True, limits=limits) as c:
        if args.discover:
            try:
                for r in await discover(c, args.discover):
                    repos.setdefault(r, [])
            except Exception:
                pass
        log(f"[sources] {len(repos)} repos, {len(urls)} extra URLs")
        sem = asyncio.Semaphore(6)

        async def one(repo, paths):
            async with sem:
                try:
                    got = await fetch_repo(c, repo, paths)
                except Exception:
                    got = []
                texts.extend(got)
                log(f"[sources] {repo:<50} {sum(len(x) for x in got)/1024:8.1f} KiB")

        await asyncio.gather(*(one(r, p) for r, p in list(repos.items())[:40]))
        for u in urls[:20]:
            try:
                r = await c.get(u)
                if r.status_code == 200:
                    texts.append(r.text)
            except Exception:
                pass
    return texts


def extract_links(text: str):
    out = []

    def scan(t):
        for m in LINK_RE.finditer(t):
            out.append(m.group(0).rstrip(".,;:)]}'\"`<>"))

    try:
        scan(text)
        if not out or B64_RE.search(text):
            if is_b64ish(text):
                try:
                    d = b64d(text)
                    if "://" in d:
                        scan(d)
                except Exception:
                    pass
            for i, m in enumerate(B64_RE.finditer(text)):
                if i > 500:
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


# ------------------------------------------------------------------ 2. parse
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


def gate(n):
    """THE RULE: vless + trojan must be ws or httpupgrade."""
    if n["proto"] in ("vless", "trojan"):
        return n["net"] in VT_ONLY
    return True


# ------------------------------------------------------------------ 3. preflight
async def preflight(nodes, timeout, conc):
    sem = asyncio.Semaphore(conc)
    loop = asyncio.get_running_loop()
    alive = []

    async def resolve(h):
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(h, None, type=socket.SOCK_STREAM), timeout)
            v4 = [i for i in infos if i[0] == socket.AF_INET]
            return (v4 or infos)[0][4][0]
        except Exception:
            return None

    async def one(n):
        async with sem:
            try:
                ip = n["host"] if is_ip(n["host"]) else await resolve(n["host"])
                if not ip:
                    return
                if n["proto"] == "hysteria2":      # QUIC/UDP - no TCP probe
                    n["ip"] = ip
                    alive.append(n)
                    return
                _, w = await asyncio.wait_for(
                    asyncio.open_connection(ip, n["port"]), timeout)
                w.close()
                try:
                    await asyncio.wait_for(w.wait_closed(), 1)
                except Exception:
                    pass
                n["ip"] = ip
                alive.append(n)
            except Exception:
                pass

    await asyncio.gather(*(one(n) for n in nodes))
    return alive


import socket  # noqa: E402  (used above)


# ------------------------------------------------------------------ 4. engine
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
        raise RuntimeError("Cannot auto-install sing-box on this system")
    ext = "zip" if sysname == "windows" else "tar.gz"
    pat = re.compile(r"sing-box-[\d.]+-" + sysname + "-" + arch + r"\." + ext.replace(".", r"\.") + "$")
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
    sni = p.get("sni") or (n["host"] if not is_ip(n["host"]) else "")
    t = {"enabled": True,
         "insecure": truthy(p.get("allowInsecure") or p.get("insecure"))}
    if sni:
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
    hdr = p.get("host") or (n["host"] if not is_ip(n["host"]) else "")
    path = p.get("path") or "/"
    if net == "ws":
        t = {"type": "ws", "path": path}
        if hdr:
            t["headers"] = {"Host": hdr}
        m = re.search(r"[?&]ed=(\d+)", path)
        if m:
            t["path"] = re.split(r"[?&]ed=", path)[0]
            t["max_early_data"] = int(m.group(1))
            t["early_data_header_name"] = "Sec-WebSocket-Protocol"
        return t
    if net == "httpupgrade":
        t = {"type": "httpupgrade", "path": path}
        if hdr:
            t["host"] = hdr
        return t
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


def sb_config(nodes, tags, port):
    outs = [to_outbound(n, t) for n, t in zip(nodes, tags)]
    if len(outs) >= 2:
        outs.append({"type": "urltest", "tag": "auto", "outbounds": list(tags),
                     "url": TEST_URLS[0], "interval": "1h", "tolerance": 50})
    return {"log": {"level": "error", "timestamp": False},
            "outbounds": outs,
            "experimental": {"clash_api": {"external_controller": "127.0.0.1:%d" % port}}}


def check_ok(exe, cfg):
    try:
        r = subprocess.run([exe, "check", "-c", str(cfg)],
                           capture_output=True, timeout=90)
        return r.returncode == 0
    except Exception:
        return False


def prune(exe, wd, nodes, tags):
    """Drop configs sing-box refuses, by bisecting - fast, no network."""
    cfg = wd / "check.json"

    def rec(idx):
        if not idx:
            return []
        try:
            cfg.write_text(json.dumps(
                sb_config([nodes[i] for i in idx], [tags[i] for i in idx], next(PORTS))))
        except Exception:
            return []
        if check_ok(exe, cfg):
            return idx
        if len(idx) == 1:
            return []
        m = len(idx) // 2
        return rec(idx[:m]) + rec(idx[m:])

    try:
        return rec(list(range(len(nodes))))
    except Exception:
        return list(range(len(nodes)))


class Engine:
    def __init__(self, exe, wd, port):
        self.exe, self.wd, self.port = exe, wd, port
        self.proc = None
        self.base = "http://127.0.0.1:%d" % port

    async def start(self, nodes, tags, client):
        cfg = self.wd / "sb.json"
        cfg.write_text(json.dumps(sb_config(nodes, tags, self.port)))
        logf = open(self.wd / "sb.log", "ab")
        try:
            self.proc = subprocess.Popen([self.exe, "run", "-c", str(cfg)],
                                         stdout=logf, stderr=logf)
        except Exception:
            return False
        for _ in range(90):
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
                    self.proc.wait(6)
                except Exception:
                    self.proc.kill()
        except Exception:
            pass
        self.proc = None


async def run_group(exe, wd, nodes, tags, args, client):
    eng = Engine(exe, wd, next(PORTS))
    if not await eng.start(nodes, tags, client):
        eng.stop()
        if len(nodes) == 1:
            return {}
        m = len(nodes) // 2
        a = await run_group(exe, wd, nodes[:m], tags[:m], args, client)
        b = await run_group(exe, wd, nodes[m:], tags[m:], args, client)
        return {**a, **{k + m: v for k, v in b.items()}}

    res = {i: [] for i in range(len(nodes))}
    sem = asyncio.Semaphore(args.concurrency)

    async def probe(i, url):
        async with sem:
            try:
                r = await client.get(eng.base + "/proxies/" + tags[i] + "/delay",
                                     params={"url": url, "timeout": args.timeout},
                                     timeout=args.timeout / 1000 + 5)
                if r.status_code == 200:
                    d = r.json().get("delay", 0)
                    if isinstance(d, (int, float)) and d > 0:
                        res[i].append(float(d))
            except Exception:
                pass

    try:
        await asyncio.sleep(1.5)
        for rd in range(max(1, args.rounds)):
            url = TEST_URLS[rd % len(TEST_URLS)]
            await asyncio.gather(*(probe(i, url) for i in range(len(nodes))))
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


async def measure_batch(exe, wd, nodes, args, client):
    tags = ["n%05d" % i for i in range(len(nodes))]
    keep = prune(exe, wd, nodes, tags)
    if not keep:
        return {}
    sub = [nodes[i] for i in keep]
    stags = [tags[i] for i in keep]
    local = await run_group(exe, wd, sub, stags, args, client)
    return {keep[i]: v for i, v in local.items()}


async def measure_all(exe, nodes, args):
    out = {}
    work = Path(args.workdir)
    work.mkdir(parents=True, exist_ok=True)
    batches = [nodes[i:i + args.batch] for i in range(0, len(nodes), args.batch)]
    async with httpx.AsyncClient(timeout=args.timeout / 1000 + 10) as client:
        for bi, batch in enumerate(batches, 1):
            t0 = time.time()
            try:
                with tempfile.TemporaryDirectory(dir=work) as td:
                    res = await measure_batch(exe, Path(td), batch, args, client)
            except Exception:
                res = {}
            for i, s in res.items():
                out[batch[i]["uid"]] = s
            log("[test] batch %d/%d  tested=%d  alive=%d  %.1fs"
                % (bi, len(batches), len(batch), len(res), time.time() - t0))
    return out


# ------------------------------------------------------------------ 5. export
def export(proto, ranked, args):
    od = Path(args.out_dir)
    od.mkdir(parents=True, exist_ok=True)
    top, used = [], set()
    for n, ms in ranked:
        hp = (n["host"].lower(), n["port"])
        if hp in used:
            continue
        used.add(hp)
        top.append((n, ms))
        if len(top) >= args.top:
            break

    lines = []
    for n, ms in top:
        if args.annotate:
            base = n["link"].split("#")[0]
            tag = (n["remark"] or n["host"]).strip()
            lines.append(base + "#" + quote("%s | %dms" % (tag, ms)))
        else:
            lines.append(n["link"])

    txt = od / ("%s_top%d.txt" % (proto, args.top))
    txt.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    (od / ("%s_top%d_b64.txt" % (proto, args.top))).write_text(
        base64.b64encode("\n".join(lines).encode()).decode(), encoding="utf-8")
    (od / ("%s_report.json" % proto)).write_text(json.dumps(
        [{"rank": i + 1, "protocol": proto, "transport": n["net"],
          "host": n["host"], "port": n["port"], "latency_ms": round(ms, 1),
          "remark": n["remark"], "link": n["link"]}
         for i, (n, ms) in enumerate(top)], indent=2, ensure_ascii=False), encoding="utf-8")

    rule = " (ws / httpupgrade only)" if proto in ("vless", "trojan") else ""
    log("\n=== %s - top %d%s" % (proto.upper(), len(top), rule))
    for i, (n, ms) in enumerate(top, 1):
        log("  %2d. %7.1f ms  %-11s %s:%d" % (i, ms, n["net"], n["host"], n["port"]))
    log("  -> %s" % txt)
    if len(top) < args.top:
        log("  NOTE: only %d live nodes matched." % len(top))
    return len(top), (top[0][1] if top else None)


def write_summary(rows, out_dir):
    md = ["# Proxy Hunter results", "",
          "| Protocol | Tested | Live | Written | Fastest |",
          "|---|---|---|---|---|"]
    for p, tested, live, written, best in rows:
        md.append("| %s | %d | %d | %d | %s |"
                  % (p, tested, live, written, ("%.0f ms" % best) if best else "-"))
    md += ["", "VLESS and Trojan contain **only WebSocket / HTTPUpgrade** servers.",
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
    od = Path(args.out_dir)
    od.mkdir(parents=True, exist_ok=True)
    wanted = PROTOS if args.protocol.strip().lower() == "all" else [
        x.strip().lower() for x in args.protocol.split(",") if x.strip()]
    wanted = [p for p in wanted if p in PROTOS] or PROTOS

    try:
        exe = ensure_singbox(Path(args.bindir))
        log("[engine] sing-box ready: %s" % exe)
    except Exception as e:
        log("!! Could not get sing-box: %s" % e)
        for p in wanted:
            (od / ("%s_top%d.txt" % (p, args.top))).write_text("")
        write_summary([(p, 0, 0, 0, None) for p in wanted], od)
        return

    try:
        texts = await harvest(args)
    except Exception:
        texts = []
    if not texts:
        log("!! No sources could be downloaded.")
        for p in wanted:
            (od / ("%s_top%d.txt" % (p, args.top))).write_text("")
        write_summary([(p, 0, 0, 0, None) for p in wanted], od)
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
        c = sum(1 for n in nodes if n["proto"] == p)
        g = sum(1 for n in nodes if n["proto"] == p and gate(n))
        log("        %-11s %6d   after rule: %6d" % (p, c, g))

    rows = []
    for proto in wanted:
        try:
            pool = [n for n in nodes if n["proto"] == proto and gate(n)]
            if not pool:
                log("\n[%s] nothing to test" % proto)
                export(proto, [], args)
                rows.append((proto, 0, 0, 0, None))
                continue
            log("\n[%s] preflight %d nodes..." % (proto, len(pool)))
            if args.no_preflight:
                for n in pool:
                    n["ip"] = n["host"]
                live = pool
            else:
                live = await preflight(pool, args.preflight_timeout, args.preflight_conc)
            log("[%s] reachable: %d" % (proto, len(live)))
            if args.max_test and len(live) > args.max_test:
                live = live[:args.max_test]
            if not live:
                export(proto, [], args)
                rows.append((proto, len(pool), 0, 0, None))
                continue

            samples = await measure_all(exe, live, args)
            scored = [(n, statistics.median(samples[n["uid"]]))
                      for n in live if n["uid"] in samples
                      and len(samples[n["uid"]]) >= args.min_success]
            scored.sort(key=lambda x: x[1])
            log("[%s] %d passed the real end-to-end test" % (proto, len(scored)))

            finalists = scored[:max(args.top * 3, args.top)]
            if finalists and args.rounds_final > 0:
                saved = args.rounds
                args.rounds = args.rounds_final
                try:
                    again = await measure_all(exe, [n for n, _ in finalists], args)
                finally:
                    args.rounds = saved
                rescored = []
                for n, _old in finalists:
                    s = again.get(n["uid"])
                    if s and len(s) >= max(1, args.rounds_final - 1):
                        rescored.append((n, statistics.median(s)))
                rescored.sort(key=lambda x: x[1])
                if rescored:
                    scored = rescored + scored[len(finalists):]

            written, best = export(proto, scored, args)
            rows.append((proto, len(live), len(scored), written, best))
        except Exception:
            log("[%s] skipped due to an internal problem:" % proto)
            traceback.print_exc()
            try:
                export(proto, [], args)
            except Exception:
                pass
            rows.append((proto, 0, 0, 0, None))

    write_summary(rows, od)
    log("\nDone. Files are in: %s" % od)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--protocol", default="all")
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--out-dir", default="out")
    ap.add_argument("--rounds", type=int, default=2)
    ap.add_argument("--rounds-final", type=int, default=3)
    ap.add_argument("--min-success", type=int, default=1)
    ap.add_argument("--timeout", type=int, default=4000)
    ap.add_argument("--concurrency", type=int, default=32)
    ap.add_argument("--batch", type=int, default=150)
    ap.add_argument("--max-test", type=int, default=900)
    ap.add_argument("--preflight-timeout", type=float, default=1.5)
    ap.add_argument("--preflight-conc", type=int, default=400)
    ap.add_argument("--no-preflight", action="store_true")
    ap.add_argument("--discover", type=int, default=0)
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
