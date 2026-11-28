# Proxy Hunter results

Country filter: **Any**

| Protocol | Servers | In country | Tested | Live | WS | HU | Gold | Written | Fastest |
|---|---|---|---|---|---|---|---|---|---|
| vless | 5044 | 3340 | 2000 | 205 | 100 | 0 | 88 | 100 | 31 ms |
| vmess | 2514 | 725 | 725 | 103 | 9 | 0 | 96 | 100 | 33 ms |
| trojan | 223 | 173 | 173 | 13 | 13 | 0 | 2 | 13 | 74 ms |
| ss | 2797 | 515 | 515 | 341 | 0 | 0 | 100 | 100 | 32 ms |
| hysteria2 | 435 | 383 | 383 | 68 | 0 | 0 | 63 | 68 | 35 ms |
| wireguard | 436 | 435 | 435 | 65 | 0 | 0 | 62 | 65 | 59 ms |

**GOLD** = low latency + stable + real 256 KB download.
Trojan lists HTTPUpgrade first. VLESS/Trojan are ws/httpupgrade only,
and every ws/httpupgrade config has a real non-empty Host header.
WireGuard also ships as `wireguard_configs.zip` (ready-to-import .conf).
Country = geolocation of the server IP (Cloudflare-fronted nodes show the CDN country).
