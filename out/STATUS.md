# Proxy Hunter results

Country filter: **Any**

| Protocol | Servers | In country | Tested | Live | WS | HU | Gold | Written | Fastest |
|---|---|---|---|---|---|---|---|---|---|
| vless | 5083 | 3347 | 2000 | 47 | 47 | 0 | 22 | 47 | 71 ms |
| vmess | 2505 | 746 | 746 | 90 | 6 | 0 | 88 | 90 | 23 ms |
| trojan | 232 | 182 | 182 | 1 | 1 | 0 | 0 | 1 | 47 ms |
| ss | 2816 | 514 | 514 | 299 | 0 | 0 | 100 | 100 | 31 ms |
| hysteria2 | 413 | 359 | 359 | 42 | 0 | 0 | 35 | 42 | 26 ms |
| wireguard | 437 | 436 | 436 | 72 | 0 | 0 | 72 | 72 | 43 ms |

**GOLD** = low latency + stable + real 256 KB download.
Trojan lists HTTPUpgrade first. VLESS/Trojan are ws/httpupgrade only,
and every ws/httpupgrade config has a real non-empty Host header.
WireGuard also ships as `wireguard_configs.zip` (ready-to-import .conf).
Country = geolocation of the server IP (Cloudflare-fronted nodes show the CDN country).
