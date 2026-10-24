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
