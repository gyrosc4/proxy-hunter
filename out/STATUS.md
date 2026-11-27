# Proxy Hunter results

Country filter: **Any**

| Protocol | Servers | In country | Tested | Live | WS | HU | Gold | Written | Fastest |
|---|---|---|---|---|---|---|---|---|---|
| vless | 5158 | 3422 | 2000 | 39 | 39 | 0 | 31 | 39 | 31 ms |
| vmess | 2526 | 718 | 718 | 97 | 12 | 0 | 92 | 97 | 36 ms |
| trojan | 219 | 167 | 167 | 3 | 3 | 0 | 3 | 3 | 462 ms |
| ss | 2810 | 519 | 519 | 251 | 0 | 0 | 100 | 100 | 40 ms |
| hysteria2 | 429 | 378 | 378 | 61 | 0 | 0 | 54 | 61 | 35 ms |
| wireguard | 514 | 513 | 513 | 67 | 0 | 0 | 65 | 67 | 65 ms |

**GOLD** = low latency + stable + real 256 KB download.
Trojan lists HTTPUpgrade first. VLESS/Trojan are ws/httpupgrade only,
and every ws/httpupgrade config has a real non-empty Host header.
WireGuard also ships as `wireguard_configs.zip` (ready-to-import .conf).
Country = geolocation of the server IP (Cloudflare-fronted nodes show the CDN country).
