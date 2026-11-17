# Connection-Scoped Torrent Guard

This is an optional, experimental userspace nDPI integration for Ubuntu 24.04
x86_64 exit nodes with host-networked Xray. It is available from kto.sh, does
not change the Xray profile, and is not the Remnawave Torrent Blocker plugin.
Opening the main script or running full optimization does not install it.

It is a reactive filter, not a guarantee against BitTorrent or copyright abuse.
The first packets pass before classification. Encrypted, obfuscated, unobserved,
or misclassified flows can pass. Legitimate applications that use BitTorrent
(including some game updaters) can be blocked. An encrypted outbound to another
proxy cannot be inspected here; install filtering on the actual final exit.

Version 2 drops a classified connection, not a whole client, account, or remote
peer endpoint. The key is `(interface, local address, local port, remote address,
remote port, transport)`. A second connection to the same remote service with
a different local port is not banned. Only nDPI's direct `DPI` verdict is used;
partial, cached, aggressive, and IP/port guesses are ignored. This reduces
coverage and does not eliminate false positives such as game traffic.

## Install

### Main Script Menu

Run the main script normally and select **Торрент-блокер (nDPI, выходная нода)**,
or open that menu directly with one command:

```bash
(F=$(mktemp) && trap 'rm -f "$F"' EXIT && curl -q -4 -fSL --noproxy '*' --connect-timeout 10 --max-time 90 https://raw.githubusercontent.com/Alpha012/kto-optimize/main/kto.sh -o "$F" && bash -n "$F" && bash "$F" torrent-guard)
```

Choose **1** to install/update in observation mode, or **2** to install/update
and then enable blocking after explicit confirmation and successful checks.
The wizard accepts optional egress interface names and protected inbound UDP
ports (for example a UDP-only Hysteria2 listener). Empty interfaces select
default-route devices plus `warp`. Updating preserves the existing interfaces,
protected ports, and other settings and does not rebuild nDPId. It temporarily
switches to observation; a failed update never automatically enables blocking.
Stopped installations are started in observation, not their previous blocking
mode. An old peer-wide installation must be updated before this menu enables it.

The menu also provides status, recent logs, observation, stop, and removal.
It is visible in node and whitelist modes, but encrypted whitelist relays cannot
inspect the traffic inside a tunnel: use it on the final exit instead.
The direct entrypoint `bash kto.sh torrent-guard [install|update|setup|enforce|observe|status|logs|stop|uninstall]`
bypasses unrelated optimization, storage repair, and machine-mode migrations.
`setup` means install/update and enforce, not an unattended silent install.
Removing this guard does not remove Xray, SSH, WARP, or other firewall tables.

### Standalone Installer

Keep the current SSH session open and have provider console access available.
The installation compiles pinned nDPId and its pinned nDPI submodule in userspace,
with two build jobs. It does not install kernel modules or change the kernel.
Allow at least 1.5 GB of disk space for the temporary build.
Without `--interface`, the installer selects the IPv4 default-route interfaces
from the main table and includes `warp` when present. Explicit interfaces are
recommended for unusual policy-routing setups. Add each plaintext egress device;
capturing only the encrypted WireGuard outer interface is not sufficient.
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
installer tests real TCP/UDP sockets between temporary network namespaces
before enabling services. It verifies IPv4, IPv6, ingress/egress drops, source
NAT address/port rewriting, and an unrelated connection to the same remote
service continuing to work. The host routes and test peers on the Internet are
not used. This verifies the firewall, not detection quality or throughput.

```bash
sudo kto-torrent status
sudo kto-torrent logs
```

Both `kto-eth0` and `kto-warp` must appear under `captures`, and `events` must
increase. Test with a legally distributed Ubuntu ISO torrent through this node,
not from the server itself. Look for `OBSERVE BitTorrent local=... peer=...`. Keep a normal
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

First use `sudo kto-torrent observe` if the old filter is enforcing. The updater
requires `observe` mode and at least 2 GiB available RAM. It backs
up files under `/opt/kto-torrent-guard/capture-backup-*`, downloads a checksum-
pinned observer, verifies selective blocking in isolated namespaces, and restarts
only the observer and its captures. It replaces the old peer-wide implementation
with the connection-scoped implementation. If startup
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

This persists across reboot. Classified connections are inserted into IPv4/IPv6
sets with a timeout (60 seconds for new installs; existing configured timeouts
are preserved on update). A subsequent verdict can block a connection again
after expiration. Flow `end`/`idle` events remove its ban early; a new flow
generation clears a stale ban for the reused tuple. No client, account, entire
peer, tracker-IP, port-range, or UDP-wide ban is performed. Other connections
keep their existing firewall policy. Partial/cache/IP/port-only guesses and
generic FileSharing categories are ignored.

This is not per-request isolation inside a single multiplexed connection: if
several application requests share exactly one transport flow, that whole flow
is the smallest blocking unit. A false positive can still break that flow.
The classifier needs packets before it can decide, so detection cannot promise
zero leaked packets or prevent every possible copyright complaint.

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

The table uses PREROUTING at priority -101 (before standard reverse NAT) and
POSTROUTING at priority 101 (after standard source NAT at priority 100). This
matches the capture-visible tuple even when WARP masquerade changes the source
address or port. Nonstandard NAT/mangling priorities, forwarding offload, bridge
containers, or a general VPN gateway require separate validation; the supported
deployment remains a host-networked proxy exit.
Monitoring `warp` is necessary to inspect its inner traffic before encryption.
A systemd restart or observer failure removes this
guard's rules; the design fails open to preserve connectivity. Check status and
logs rather than assuming protection continues after a failure.

No performance or full-detection claim is made. Automatic account suspension
and integration into Remnawave are separate features and are not implemented.

## Developer Checks

The GitHub Actions workflow `Torrent Guard` runs focused unit tests and the same
real-socket firewall test on Ubuntu 24.04. Run the latter locally only in a
disposable network namespace:

```bash
sudo timeout 60 unshare --net python3 scripts/kto-torrent-guard.py check-nft
```

The helper refuses to run this test in PID 1's network namespace. It never
contacts real torrent peers or changes the host's firewall for testing.

Upstream sources:

- https://github.com/utoni/nDPId
- https://github.com/ntop/nDPI
- https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks
