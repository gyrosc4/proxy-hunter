# Proxy Hunter results

| Protocol | Servers | Tested | Live | WS | HTTPUpgrade | Gold | Written | Fastest |
|---|---|---|---|---|---|---|---|---|
| vless | 365 | 318 | 37 | 37 | 0 | 14 | 37 | 75 ms |

**GOLD** = low latency + stable across 3 rounds + real 256 KB download.
VLESS / Trojan are **ws or httpupgrade only**, and every ws/httpupgrade
config has a **real non-empty Host header** (blank/IP-only rejected).
Latency measured from the GitHub runner (usually USA).
