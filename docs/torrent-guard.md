# Optional Torrent Guard

This is a standalone, experimental userspace nDPI integration for Ubuntu 24.04
x86_64 exit nodes with host-networked Xray. It is not installed by kto.sh, does
not change the Xray profile, and is not the Remnawave Torrent Blocker plugin.

It is a reactive filter, not a guarantee against BitTorrent or copyright abuse.
The first packets pass before classification. Encrypted, obfuscated, unobserved,
or misclassified flows can pass. Legitimate applications that use BitTorrent
(including some game updaters) can be blocked. An encrypted outbound to another
proxy cannot be inspected here; install filtering on the actual final exit.

## Install

Keep the current SSH session open and have provider console access available.
The installation compiles pinned nDPId and its pinned nDPI submodule in userspace,
with two build jobs. It does not install kernel modules or change the kernel.
Allow at least 1.5 GB of disk space for the temporary build.
Upstream `nDPId -v` returns exit status 1 even when it successfully prints its
version. The installer accepts that status only with a valid nDPId/nDPI banner;
a version display alone is not confirmation that the services were installed.

```bash
curl -q -4 -fSL --connect-timeout 10 --max-time 90 \
  https://raw.githubusercontent.com/Alpha012/kto-optimize/main/scripts/install-torrent-guard.sh \
  -o /tmp/install-torrent-guard.sh
bash -n /tmp/install-torrent-guard.sh
sudo bash /tmp/install-torrent-guard.sh --interface eth0 --interface warp
```

Download and syntax checks must succeed before running the installer. It starts
in `observe` mode: **no blocking**. The same Ubuntu image and XanMod kernel as
the target node were not available for local end-to-end verification. The
installer checks nftables rules and set insertions in a temporary network
namespace before enabling services. This does not verify detection quality or
throughput on your traffic.

```bash
sudo kto-torrent status
sudo kto-torrent logs
```

Both `kto-eth0` and `kto-warp` must appear under `captures`, and `events` must
increase. Test with a legally distributed Ubuntu ISO torrent through this node,
not from the server itself. Look for `OBSERVE BitTorrent peer=...`. Keep a normal
HTTPS connection and an SSH session working during the test. A running process
with zero torrent detections is not evidence that torrent blocking works.

## Flow Capacity and Existing Installations

`CAPTURE_ERROR Max flows to track reached` means the capture process cannot track
some new flows. It is not the host's conntrack limit. Older installations used
16,384 flows per reader thread. New installations use two reader threads with
32,768 flows each, or 65,536 each on hosts with at least 16 GiB RAM. The memory
limits per interface are respectively `MemoryHigh=768M` / `MemoryMax=1G` and
`MemoryHigh=1536M` / `MemoryMax=2G`. These are limits, not reserved memory, and
do not guarantee enough capacity at every packet/connection rate.

Tracking garbage collection runs every five seconds. TCP/UDP flows idle for
60/30 seconds can be forgotten; TCP flows with FIN/RST are retained for ten
seconds. These are detector retention settings, not socket timeouts: they do
not close Xray connections. Forgetting an idle flow can reduce recognition of
later packets, so this remains a capacity/coverage tradeoff.

For an existing installation, update without rebuilding nDPId:

```bash
(
set -e
F=$(mktemp /tmp/kto-torrent-tune.XXXXXX.py)
trap 'rm -f "$F"' EXIT
curl -q -4 -fSL --noproxy '*' --connect-timeout 10 --max-time 60 \
  https://raw.githubusercontent.com/Alpha012/kto-optimize/main/scripts/tune-torrent-capture.py \
  -o "$F"
sudo python3 "$F"
)
```

The updater requires `observe` mode and at least 2 GiB available RAM. It backs
up files under `/opt/kto-torrent-guard/capture-backup-*`, downloads a checksum-
pinned observer, and restarts only the observer and its captures. If startup
verification fails, it restores the old files and attempts service recovery.
It does not change Xray, SSH, firewall settings, or the configured mode.
Inspect fresh logs and memory/CPU usage after the node has been under load:

```bash
sudo kto-torrent status
sudo journalctl -u kto-torrent-guard --since '2 minutes ago' --no-pager -n 60
sudo systemctl status 'kto-torrent-capture@*' --no-pager
```

Detection logs include the capture alias, nDPI confidence, and `hash_present`.
The torrent hash itself is not logged. A `DPI` confidence label is not proof
that a classifier cannot be wrong. A missing hash does not disprove BitTorrent
(for example DHT or encrypted traffic); a present hash is not a security
guarantee either. Keep observation enabled while investigating suspicious
game/service detections, and test those applications before enforcement.

## Enable, Verify, Undo

```bash
sudo kto-torrent enforce
sudo nft list table inet kto_torrent_guard
```

This persists across reboot. New DPI-confirmed BitTorrent peer endpoints are
added as `(address, port, transport)` for ten minutes. A subsequent verdict can
block them again after expiration. They are blocked node-wide, not per account:
other clients cannot use the same endpoint either. IP/port-only guesses and
generic FileSharing categories are ignored. No client IP bans are performed.

Retest the legal torrent after enabling enforcement. Logs must show `BLOCKED`,
and the nftables drop counters must increase. Those checks establish that the
detector and firewall are connected, not that every torrent variant is blocked.
Test normal sites, DNS, SSH, and WARP too. At high connection/packet rates, watch
CPU, capture errors, flow-limit events, and systemd memory limits; dropped
capture packets reduce coverage.

```bash
sudo kto-torrent observe    # remove this guard's blocking rules
sudo kto-torrent stop       # disable its services and rules, including at boot
sudo kto-torrent uninstall  # remove its services, config, and program
```

The observer keeps no PCAP files and disables nDPId packet-payload events.
Torrent peer endpoints are logged to journald; its existing storage policy
applies. The observer socket is local and accessible only to root and the
dedicated system group. Capturers drop to a dedicated non-login user after
opening capture handles. No Internet API is exposed.

## Scope and Limitations

The filter only owns `table inet kto_torrent_guard`; it refuses to modify a table
with that name without its ownership marker. It does not flush the firewall or
change marks, routing, SSH settings, passwords, WARP, or Remnawave services.
Listening TCP ports are exempt, including SSH and proxy inbound ports. UDP ports
also served over TCP and WireGuard listen ports are exempt. For a UDP-only
service (for example Hysteria2 on UDP 8443), pass `--protect-udp 8443` at install.
Unconnected UDP egress sockets are not blindly treated as server listeners.
The SSH client's address is also exempt if `SSH_CONNECTION` reaches the installer.

The table uses INPUT/OUTPUT hooks because Xray uses the host network. It is not a
FORWARD filter for bridge-networked containers or a general WireGuard gateway.
Monitoring `warp` is necessary to inspect its inner traffic before encryption.
Matching only the remote endpoint avoids depending on source NAT rewriting the
local source address/port. A systemd restart or observer failure removes this
guard's rules; the design fails open to preserve connectivity. Check status and
logs rather than assuming protection continues after a failure.

No performance or full-detection claim is made. Automatic account suspension
and integration into Remnawave are separate features and are not implemented.

Upstream sources:

- https://github.com/utoni/nDPId
- https://github.com/ntop/nDPI
