# Proxy Hunter results

| Protocol | Servers | Tested | Live | WS | HTTPUpgrade | Gold | Written | Fastest |
|---|---|---|---|---|---|---|---|---|
| vless | 258 | 216 | 27 | 27 | 0 | 15 | 27 | 95 ms |
| vmess | 1192 | 556 | 78 | 6 | 0 | 76 | 78 | 50 ms |
| trojan | 34 | 26 | 0 | 0 | 0 | 0 | 0 | - |
| ss | 2202 | 389 | 266 | 0 | 0 | 100 | 100 | 44 ms |
| hysteria2 | 145 | 145 | 59 | 0 | 0 | 56 | 59 | 100 ms |

**GOLD** = low latency + stable across 3 rounds + real 256 KB download.
VLESS / Trojan are **ws or httpupgrade only**, and every ws/httpupgrade
config has a **real non-empty Host header** (blank/IP-only rejected).
Latency measured from the GitHub runner (usually USA).
