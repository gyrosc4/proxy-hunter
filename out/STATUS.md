# Proxy Hunter results

| Protocol | Servers | Tested | Live | WS | HTTPUpgrade | Gold | Written | Fastest |
|---|---|---|---|---|---|---|---|---|
| trojan | 35 | 31 | 2 | 2 | 0 | 1 | 2 | 431 ms |

**GOLD** = low latency + stable across 3 rounds + real 256 KB download.
VLESS / Trojan are **ws or httpupgrade only**, and every ws/httpupgrade
config has a **real non-empty Host header** (blank/IP-only rejected).
Latency measured from the GitHub runner (usually USA).
