# Proxy Hunter results

| Protocol | Servers | Tested | Live | WS | HTTPUpgrade | Gold | Written | Fastest |
|---|---|---|---|---|---|---|---|---|
| hysteria2 | 177 | 177 | 53 | 0 | 0 | 48 | 53 | 95 ms |

**GOLD** = low latency + stable across 3 rounds + real 256 KB download.
VLESS / Trojan are **ws or httpupgrade only**, and every ws/httpupgrade
config has a **real non-empty Host header** (blank/IP-only rejected).
Latency measured from the GitHub runner (usually USA).
