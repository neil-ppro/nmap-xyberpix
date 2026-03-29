# nxytools — lightweight lab utilities (nmap-xyberpix)

Small **Python 3** CLIs (stdlib only) next to **nfuzz** / **ngit**. Each tool requires **`--authorized`** or **`NXY_AUTHORIZED=1`**. Do not point them at systems you are not permitted to test.

| Tool | Purpose |
|------|---------|
| **nxy-banner** | TCP connect + read first bytes (banner). |
| **nxy-dnsperm** | Subdomain words × base domain → DNS resolution (capped). |
| **nxy-httpfuzz** | Repeated HTTP GET with bounded `User-Agent` mutations + rate limit. |
| **nxy-wsprobe** | Send WebSocket upgrade request; print response headers. |

Install with `make install-nxytools` (see top-level `Makefile`). Man page: **nxytools(1)**.

Common limits: no NUL or shell metacharacters in host/URL/path arguments; connection and iteration caps documented in `--help`.
