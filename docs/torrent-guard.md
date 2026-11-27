# KTO Torrent Guard v3 (Kernel nftables + optional nDPId)

Server-side two-layer BitTorrent blocker for Linux exit nodes (Ubuntu 20.04/22.04/24.04+,
Debian 11/12+, `x86_64` / `arm64`) running host-networked Xray / Remnawave and optional WARP.
Does not modify Xray/Remnawave profiles, SSH, WARP, or existing firewall tables.

## Architecture

### Layer 1 — Fast Kernel `nftables` (`engine: "kernel"`, default)
- Installs in ~2 seconds, uses zero packet-capture RAM, requires no compiler toolchain.
- Inspects outbound traffic in `nftables` **`output` hook (priority 0)** **before** packets
  leave the server (and before WireGuard/WARP encryption or SNAT), preventing the first
  BitTorrent/tracker/DHT packet from reaching external peers or DMCA monitors:
  - **BitTorrent TCP handshake** (`\x13BitTorrent protocol`, `tcp doff` 5..8) → immediate `TCP RST`
  - **HTTP trackers** (`GET /announce?`, `GET /scrape?`) → immediate `TCP RST`
  - **UDP trackers** (BEP 15 connect magic `0x0000041727101980`) → `DROP`
  - **BitTorrent DHT** (BEP 5 KRPC `d1:ad2:id20:` / `d1:rd2:id20:`) → `DROP` (also dropped on ingress)
- Caught remote endpoints (`peer_ip : peer_port : proto`) are added dynamically to
  `@bt_peers{4,6}_{tcp,udp}` for `ttl` seconds (default `600s` / 10 minutes), immediately
  resetting/dropping reconnects and MSE fallback attempts to that peer:port without banning
  unrelated ports on the same IP or any client IP.
- Shared web/DNS destination ports (`53`, `80`, `443`, `853`) are **never** added to peer:port
  bans — only the matched tracker/handshake packet is reset, keeping normal HTTPS/HTTP/DNS intact.
- Automatically protects loopback, RFC1918/CGNAT/link-local/ULA/multicast ranges, all listening
  TCP ports (SSH, Xray, Caddy, Nginx, HAProxy), WireGuard listen ports, known server UDP daemons,
  and non-ephemeral Xray UDP listeners (e.g. Hysteria2 on `443`/`8443`).

### Layer 2 — Optional Deep nDPI (`engine: "hybrid"`)
- Optional layer compiled on demand from pinned `nDPId` + `libnDPI` for nodes that also need
  deep detection of **uTP** and **MSE/PE encrypted BitTorrent** (via nDPI `DPI` and `DPI (cache)`).
- Fixed all v2 bugs:
  - No self-unban on nDPId `idle` events (bans persist for full `ttl`, default `600s`).
  - Batched `nft` updates (`0.2s` / 64-item threshold) instead of per-event fork storms.
  - Resilient main loop (`try/except` around refresh/config/flush/status so transient glitches never wipe rules).
  - Live nftables config reload when `ttl`, `interfaces`, `protected_udp`, or `exempt_ips` change.
  - Monotonic clock freshness checks (immune to NTP/chrony backward clock steps).
  - Per-capture staleness detection (catches silently stalled capture after `warp` restart).
  - Memory-adaptive profiles (`< 4 GiB`, `4–16 GiB`, `>= 16 GiB`) and no 2 GiB free RAM updater wall.
- Can be added (`hybrid`) or removed (`remove-ndpi` → back to zero-RAM `kernel`) at any time.

## Usage

From `kto.sh` menu: **Прокси и фильтры › Торрент-блокер (Kernel + nDPI, выходная нода)**,
or directly via CLI:

```bash
bash kto.sh torrent-guard [setup|install|update|hybrid|kernel|enforce|observe|status|logs|stop|uninstall]
```

After installation, `kto-torrent` CLI is available directly:

```bash
sudo kto-torrent status          # engine, mode, active peer bans, per-category drop counters
sudo kto-torrent status --json   # machine-readable JSON status
sudo kto-torrent enforce         # enable blocking (persists across reboot)
sudo kto-torrent observe         # immediately remove table inet kto_torrent_guard
sudo kto-torrent logs [-f]       # recent logs (or live stream with -f)
sudo kto-torrent remove-ndpi     # switch hybrid -> zero-RAM kernel mode
sudo kto-torrent stop            # disable services and clean up rules
sudo kto-torrent uninstall       # remove only KTO Torrent Guard files/units/rules
```

## Isolated Firewall Self-Test

Both installer, updater, and GitHub Actions (`Torrent Guard` workflow on Ubuntu 24.04) run
real TCP/UDP IPv4/IPv6 + SNAT socket tests inside disposable network namespaces:

```bash
sudo timeout 60 unshare --net python3 scripts/kto-torrent-guard.py check-nft
```
