# Proxy Hunter results

| Protocol | Servers | Tested | Live | WS | HTTPUpgrade | Gold | Written | Fastest |
|---|---|---|---|---|---|---|---|---|
| vless | 483 | 440 | 142 | 100 | 0 | 41 | 100 | 60 ms |
| vmess | 1172 | 593 | 88 | 12 | 0 | 84 | 88 | 33 ms |
| trojan | 45 | 39 | 9 | 9 | 0 | 4 | 9 | 138 ms |
| ss | 2210 | 402 | 299 | 0 | 0 | 100 | 100 | 34 ms |
| hysteria2 | 155 | 155 | 70 | 0 | 0 | 66 | 70 | 27 ms |

**GOLD** = low latency + stable across 3 rounds + real 256 KB download.
VLESS / Trojan are **ws or httpupgrade only**, and every ws/httpupgrade
config has a **real non-empty Host header** (blank/IP-only rejected).
Latency measured from the GitHub runner (usually USA).
