#!/usr/bin/env python3
"""Two-layer BitTorrent blocker (kernel nftables + optional nDPId) for exit nodes."""

from __future__ import annotations

import argparse
from collections import OrderedDict
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import subprocess
import sys
import time


TABLE = "kto_torrent_guard"
OWNER = "kto-torrent-guard-v1"
CONFIG = Path("/etc/kto-torrent-guard.json")
RUNTIME = Path("/run/kto-torrent-guard")
MAX_FLOWS = 32768
MAX_PEER_BANS = 65536
MAX_FRAME = 33792
VERSION = 3
DEFAULT_TTL = 600
FLUSH_INTERVAL_SEC = 0.2
FLUSH_IMMEDIATE_THRESHOLD = 64
CAPTURE_STALE_SEC = 180.0

# Ports where peer-wide IP:port bans could affect shared web/DNS infrastructure.
# Detections on these destination ports fall back to per-connection 5-tuple or packet RST.
SHARED_SERVICE_PORTS = frozenset({53, 80, 443, 853})

# Known server daemons whose non-ephemeral UDP listeners should always be protected.
PROTECTED_UDP_DAEMONS = frozenset({
    "hysteria", "caddy", "nginx", "haproxy", "named", "unbound",
    "systemd-resolve", "chronyd", "ntpd", "openvpn", "sing-box",
})

# Exact BitTorrent protocol signatures for kernel nftables payload matching.
# All chunks use power-of-two bit widths (64/32/16) for universal nftables compatibility.
TCP_DOFF_VALUES = (8, 5, 6, 7)
SIG_BT_HANDSHAKE_CHUNKS = (
    (0, 64, "0x13426974546f7272"),    # \x13BitTorr
    (64, 64, "0x656e742070726f74"),   # ent prot
    (128, 32, "0x6f636f6c"),          # ocol
)
SIG_HTTP_ANNOUNCE_CHUNKS = (
    (0, 64, "0x474554202f616e6e"),    # GET /ann
    (64, 32, "0x6f756e63"),           # ounc
    (96, 16, "0x653f"),               # e?
)
SIG_HTTP_SCRAPE_CHUNKS = (
    (0, 64, "0x474554202f736372"),    # GET /scr
    (64, 32, "0x6170653f"),           # ape?
)
SIG_UDP_DHT_PREFIXES = (
    ("0x64313a6164323a69", "0x6432303a"),  # d1:ad2:id20:
    ("0x64313a7264323a69", "0x6432303a"),  # d1:rd2:id20:
)

COUNTER_KEYS = {
    "kto:sig_bt_tcp": "bt_tcp",
    "kto:sig_http_tracker": "http_tracker",
    "kto:sig_udp_tracker": "udp_tracker",
    "kto:sig_dht": "dht",
    "kto:peer_tcp": "peer_tcp",
    "kto:peer_udp": "peer_udp",
    "kto:ndpi_flow": "ndpi_flows",
}


def command(args, *, input=None, check=True, timeout=10):
    result = subprocess.run(args, input=input, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        detail = (result.stderr or result.stdout).strip()[:3000]
        raise RuntimeError(f"{args[0]} failed (exit={result.returncode}): {detail}")
    return result


def config(path=CONFIG):
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("config must be a JSON object")
    if raw.get("mode") not in ("observe", "enforce"):
        raise ValueError("mode must be observe or enforce")
    engine = raw.get("engine", "kernel")
    if engine not in ("kernel", "hybrid"):
        raise ValueError("engine must be kernel or hybrid")
    raw["engine"] = engine
    ttl = raw.get("ttl", DEFAULT_TTL)
    if type(ttl) is not int or not 60 <= ttl <= 86400:
        raise ValueError("ttl must be 60..86400 seconds")
    raw["ttl"] = ttl
    block_cache = raw.get("block_encrypted_cache", True)
    if type(block_cache) is not bool:
        raise ValueError("block_encrypted_cache must be boolean")
    raw["block_encrypted_cache"] = block_cache
    raw["exempt_ips"] = [str(ipaddress.ip_address(ip)) for ip in raw.get("exempt_ips", [])]
    interfaces = raw.get("interfaces", [])
    if engine == "hybrid":
        if (not isinstance(interfaces, list) or not interfaces or len(interfaces) > 16 or
                not all(isinstance(item, str) and item != "lo" and
                        re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", item) for item in interfaces) or
                len(set(interfaces)) != len(interfaces)):
            raise ValueError("interfaces must contain 1..16 unique non-loopback interface names")
    else:
        if (not isinstance(interfaces, list) or len(interfaces) > 16 or
                not all(isinstance(item, str) and item != "lo" and
                        re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", item) for item in interfaces) or
                len(set(interfaces)) != len(interfaces)):
            raise ValueError("interfaces must contain unique non-loopback interface names")
    raw["interfaces"] = interfaces
    raw["protected_udp"] = raw.get("protected_udp", [])
    if (not isinstance(raw["protected_udp"], list) or
            any(type(port) is not int or not 0 < port < 65536 for port in raw["protected_udp"])):
        raise ValueError("protected_udp must contain valid port numbers")
    return raw


def atomic_json(path, value):
    temporary = path.with_suffix(".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(value, handle)
        handle.write("\n")
    os.replace(temporary, path)


def notify_ready():
    address = os.environ.get("NOTIFY_SOCKET")
    if address:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notifier:
            notifier.connect("\0" + address[1:] if address.startswith("@") else address)
            notifier.sendall(b"READY=1")


class Frames:
    """nDPId's five ASCII length digits precede a JSON frame including newline."""

    def __init__(self):
        self.buffer = bytearray()
        self.alias = None
        self.last_seen = time.monotonic()

    def feed(self, data):
        self.buffer.extend(data)
        messages = []
        while len(self.buffer) >= 5:
            prefix = self.buffer[:5]
            if not all(48 <= byte <= 57 for byte in prefix):
                raise ValueError("invalid nDPId frame prefix")
            length = int(prefix)
            if not 2 <= length <= MAX_FRAME:
                raise ValueError("invalid nDPId frame size")
            if len(self.buffer) < 5 + length:
                break
            payload = self.buffer[5:5 + length]
            del self.buffer[:5 + length]
            message = json.loads(payload)
            if not isinstance(message, dict):
                raise ValueError("nDPId event is not an object")
            messages.append(message)
        if len(self.buffer) > MAX_FRAME + 5:
            raise ValueError("oversized nDPId input")
        return messages


def listening_ports(text):
    ports = {"tcp": set(), "udp": set(), "udp_daemons": set()}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 5 or fields[0] not in ("tcp", "udp"):
            continue
        proto = fields[0]
        try:
            port = int(fields[4].rsplit(":", 1)[1])
        except (IndexError, ValueError):
            continue
        if not 0 < port < 65536:
            continue
        ports[proto].add(port)
        if proto == "udp" and len(fields) >= 7:
            proc_info = " ".join(fields[6:])
            names = set(re.findall(r'\(\("([^"]+)"', proc_info))
            # Protect well-known server daemons on any port, plus non-ephemeral
            # (< 10000) xray listeners (e.g. Hysteria2 on 443/8443 UDP) without
            # exempting Xray's high-port outbound UDP egress sockets.
            if (names & PROTECTED_UDP_DAEMONS) or ("xray" in names and port < 10000):
                ports["udp_daemons"].add(port)
    return ports


def protected_ports(text, extra_udp, wireguard_text=""):
    parsed = listening_ports(text)
    # An unconnected Xray UDP egress socket appears in `ss -lu` too. It must not
    # become an exemption merely because UDP has no TCP-style LISTEN state.
    udp = (parsed["udp"] & parsed["tcp"]) | parsed["udp_daemons"]
    udp.update(extra_udp)
    for line in wireguard_text.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1].isdigit() and 0 < int(fields[1]) < 65536:
            udp.add(int(fields[1]))
    return {"tcp": parsed["tcp"], "udp": udp}


def flow_identity(event):
    values = tuple(event.get(key) for key in ("thread_id", "flow_id", "flow_first_seen"))
    if (all(type(value) is int for value in values) and 0 <= values[0] < 32
            and 0 < values[1] < 2**64 and 0 <= values[2] < 2**64):
        return values
    return None


def connection_tuple(event, addresses, protected, exempt, interfaces):
    interface = next((name for name in interfaces if event.get("alias") == f"kto-{name}"), None)
    if interface is None or flow_identity(event) is None:
        return None
    protocol = event.get("l4_proto")
    if protocol not in ("tcp", "udp"):
        return None
    try:
        src = ipaddress.ip_address(event["src_ip"])
        dst = ipaddress.ip_address(event["dst_ip"])
        sport, dport = event["src_port"], event["dst_port"]
        if any(type(port) is not int or not 0 < port < 65536 for port in (sport, dport)):
            return None
        if src.version != dst.version:
            return None
        if str(src) in addresses and str(dst) not in addresses:
            local, local_port, peer, port = src, sport, dst, dport
        elif str(dst) in addresses and str(src) not in addresses:
            local, local_port, peer, port = dst, dport, src, sport
        else:
            return None
        if (not peer.is_global or str(peer) in exempt or
                local_port in protected[protocol]):
            return None
    except (KeyError, ValueError, TypeError):
        return None
    return peer.version, interface, str(local), local_port, str(peer), port, protocol


def confidence_is_accepted(confidence, *, allow_cache=True):
    """Validate nDPI confidence by label value rather than brittle numeric enum IDs."""
    if not isinstance(confidence, dict) or not confidence:
        return False
    allowed = {"DPI", "DPI (cache)"} if allow_cache else {"DPI"}
    return any(isinstance(value, str) and value in allowed for value in confidence.values())


def torrent_flow(event, addresses, protected, exempt, interfaces, *, allow_cache=True):
    if event.get("flow_event_name") not in ("detected", "detection-update", "update"):
        return None
    ndpi = event.get("ndpi")
    if not isinstance(ndpi, dict):
        return None
    if "bittorrent" not in str(ndpi.get("proto", "")).casefold().split("."):
        return None
    if not confidence_is_accepted(ndpi.get("confidence", {}), allow_cache=allow_cache):
        return None
    return connection_tuple(event, addresses, protected, exempt, interfaces)


def nft_element(flow):
    _version, _interface, local, local_port, remote, remote_port, protocol = flow
    return f"{local} . {local_port} . {remote} . {remote_port} . {protocol}"


def nft_set(version, interface):
    # Hex keeps names collision-free and valid even for interfaces with dots/dashes.
    return f"flows{version}_{interface.encode('ascii').hex()}"


def nft_peer_set(version, protocol):
    return f"bt_peers{version}_{protocol}"


def nft_add(flow, ttl):
    return f"add element inet {TABLE} {nft_set(flow[0], flow[1])} {{ {nft_element(flow)} timeout {ttl}s }}\n"


def nft_add_peer(peer_ban, ttl):
    version, peer_ip, peer_port, protocol = peer_ban
    return f"add element inet {TABLE} {nft_peer_set(version, protocol)} {{ {peer_ip} . {peer_port} timeout {ttl}s }}\n"


def nft_remove(flow):
    # Ubuntu 22.04/24.04 nft may lack `destroy element`. Add-if-missing then delete in
    # one transaction, so expiry cannot race deletion and no temporary ban leaks.
    element = f"inet {TABLE} {nft_set(flow[0], flow[1])} {{ {nft_element(flow)} }}"
    return f"add element {element}\ndelete element {element}\n"


def _tcp_sig_rule(doff, chunks, target_chain):
    base = doff * 32
    parts = [f"meta l4proto tcp @th,96,4 {doff}"]
    for offset, bits, hexval in chunks:
        parts.append(f"@th,{base + offset},{bits} {hexval}")
    parts.append(f"jump {target_chain}")
    return " ".join(parts)


def nft_table(protected, ttl, interfaces, *, exempt_ips=(), engine="kernel"):
    exempt_v4 = sorted({str(ip) for ip in (ipaddress.ip_address(x) for x in exempt_ips) if ip.version == 4})
    exempt_v6 = sorted({str(ip) for ip in (ipaddress.ip_address(x) for x in exempt_ips) if ip.version == 6})

    lines = [f"table inet {TABLE} {{", f'comment "{OWNER}"']

    # Private / link-local / multicast ranges are never inspected or banned.
    lines.extend([
        "set private_v4 {",
        "type ipv4_addr",
        "flags interval",
        "elements = { 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, "
        "172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4 }",
        "}",
        "set private_v6 {",
        "type ipv6_addr",
        "flags interval",
        "elements = { ::1/128, fc00::/7, fe80::/10, ff00::/8 }",
        "}",
    ])
    if exempt_v4:
        lines.extend([
            "set exempt_v4 {", "type ipv4_addr",
            f"elements = {{ {', '.join(exempt_v4)} }}", "}",
        ])
    if exempt_v6:
        lines.extend([
            "set exempt_v6 {", "type ipv6_addr",
            f"elements = {{ {', '.join(exempt_v6)} }}", "}",
        ])

    for protocol in ("tcp", "udp"):
        lines.extend([f"set protect_{protocol} {{", "type inet_service"])
        if protected[protocol]:
            elements = ", ".join(map(str, sorted(protected[protocol])))
            lines.append(f"elements = {{ {elements} }}")
        lines.append("}")

    # Dynamic kernel sets for caught BitTorrent peer endpoints (IP + port + proto).
    # Blocks repeated attempts (including MSE fallback) to the same torrent peer:port
    # without banning unrelated services or the whole client/IP.
    for version in (4, 6):
        for protocol in ("tcp", "udp"):
            lines.extend([
                f"set {nft_peer_set(version, protocol)} {{",
                f"type ipv{version}_addr . inet_service",
                f"flags dynamic,timeout; timeout {ttl}s; size {MAX_PEER_BANS}",
                "}",
            ])

    # Per-interface 5-tuple sets for hybrid nDPI detections on shared ports (53/80/443/853).
    if engine == "hybrid":
        for name in interfaces:
            for version in (4, 6):
                lines.extend([
                    f"set {nft_set(version, name)} {{",
                    f"type ipv{version}_addr . inet_service . ipv{version}_addr . inet_service . inet_proto",
                    f"flags timeout; timeout {ttl}s; size {MAX_FLOWS}",
                    "}",
                ])

    # Verdict helper chains for kernel signature matches in output.
    lines.extend([
        "chain block_bt_tcp {",
        "meta nfproto ipv4 meta l4proto tcp th dport != 80 th dport != 443 add @bt_peers4_tcp { ip daddr . th dport }",
        "meta nfproto ipv6 meta l4proto tcp th dport != 80 th dport != 443 add @bt_peers6_tcp { ip6 daddr . th dport }",
        'meta l4proto tcp counter reject with tcp reset comment "kto:sig_bt_tcp"',
        "}",
        "chain block_http_tracker {",
        "meta nfproto ipv4 meta l4proto tcp th dport != 80 th dport != 443 add @bt_peers4_tcp { ip daddr . th dport }",
        "meta nfproto ipv6 meta l4proto tcp th dport != 80 th dport != 443 add @bt_peers6_tcp { ip6 daddr . th dport }",
        'meta l4proto tcp counter reject with tcp reset comment "kto:sig_http_tracker"',
        "}",
        "chain block_udp_tracker {",
        "meta nfproto ipv4 meta l4proto udp th dport != 53 th dport != 443 th dport != 853 add @bt_peers4_udp { ip daddr . th dport }",
        "meta nfproto ipv6 meta l4proto udp th dport != 53 th dport != 443 th dport != 853 add @bt_peers6_udp { ip6 daddr . th dport }",
        'meta l4proto udp counter drop comment "kto:sig_udp_tracker"',
        "}",
        "chain block_dht {",
        "meta nfproto ipv4 meta l4proto udp th dport != 53 th dport != 443 th dport != 853 add @bt_peers4_udp { ip daddr . th dport }",
        "meta nfproto ipv6 meta l4proto udp th dport != 53 th dport != 443 th dport != 853 add @bt_peers6_udp { ip6 daddr . th dport }",
        'meta l4proto udp counter drop comment "kto:sig_dht"',
        "}",
    ])

    # TCP signature inspection chain (called only on non-SYN/FIN/RST packets).
    lines.append("chain inspect_tcp {")
    for doff in TCP_DOFF_VALUES:
        lines.append(_tcp_sig_rule(doff, SIG_BT_HANDSHAKE_CHUNKS, "block_bt_tcp"))
    for doff in TCP_DOFF_VALUES:
        lines.append(_tcp_sig_rule(doff, SIG_HTTP_ANNOUNCE_CHUNKS, "block_http_tracker"))
    for doff in TCP_DOFF_VALUES:
        lines.append(_tcp_sig_rule(doff, SIG_HTTP_SCRAPE_CHUNKS, "block_http_tracker"))
    lines.append("}")

    # UDP signature inspection chain (BEP 15 UDP trackers + BEP 5 DHT KRPC).
    lines.extend([
        "chain inspect_udp {",
        "udp length 24 @th,64,64 0x0000041727101980 @th,128,32 0x00000000 jump block_udp_tracker",
    ])
    for w1, w2 in SIG_UDP_DHT_PREFIXES:
        lines.append(f"meta l4proto udp @th,64,64 {w1} @th,128,32 {w2} jump block_dht")
    lines.append("}")

    # OUTPUT hook: runs BEFORE packets leave the host (and BEFORE WireGuard/WARP
    # encryption or SNAT), stopping the very first BitTorrent/DHT/tracker packet
    # with immediate TCP RST / UDP drop.
    lines.extend([
        "chain output {",
        "type filter hook output priority 0; policy accept;",
        'oifname "lo" return',
        "tcp sport @protect_tcp return",
        "udp sport @protect_udp return",
        "ip daddr @private_v4 return",
        "ip6 daddr @private_v6 return",
    ])
    if exempt_v4:
        lines.append("ip daddr @exempt_v4 return")
    if exempt_v6:
        lines.append("ip6 daddr @exempt_v6 return")
    lines.extend([
        'meta l4proto tcp ip daddr . th dport @bt_peers4_tcp counter reject with tcp reset comment "kto:peer_tcp"',
        'meta l4proto tcp ip6 daddr . th dport @bt_peers6_tcp counter reject with tcp reset comment "kto:peer_tcp"',
        'meta l4proto udp ip daddr . th dport @bt_peers4_udp counter drop comment "kto:peer_udp"',
        'meta l4proto udp ip6 daddr . th dport @bt_peers6_udp counter drop comment "kto:peer_udp"',
        "tcp flags & (syn | fin | rst) == 0 jump inspect_tcp",
        "meta l4proto udp jump inspect_udp",
        "}",
    ])

    # PREROUTING (-101, before reverse NAT) and POSTROUTING (101, after SNAT/WARP):
    # drop return traffic from banned peers and enforce hybrid nDPI 5-tuple drops.
    for direction, priority in (("prerouting", -101), ("postrouting", 101)):
        inbound = direction == "prerouting"
        local_ip, peer_ip = ("daddr", "saddr") if inbound else ("saddr", "daddr")
        local_port, peer_port = ("dport", "sport") if inbound else ("sport", "dport")
        interface = "iifname" if inbound else "oifname"
        lines.extend([
            f"chain {direction} {{",
            f"type filter hook {direction} priority {priority}; policy accept;",
            f'{interface} "lo" return',
            f"tcp {local_port} @protect_tcp return",
            f"udp {local_port} @protect_udp return",
            f"ip {peer_ip} @private_v4 return",
            f"ip6 {peer_ip} @private_v6 return",
        ])
        if exempt_v4:
            lines.append(f"ip {peer_ip} @exempt_v4 return")
        if exempt_v6:
            lines.append(f"ip6 {peer_ip} @exempt_v6 return")
        if inbound:
            lines.extend([
                f'meta l4proto tcp ip {peer_ip} . th {peer_port} @bt_peers4_tcp counter drop comment "kto:peer_tcp"',
                f'meta l4proto tcp ip6 {peer_ip} . th {peer_port} @bt_peers6_tcp counter drop comment "kto:peer_tcp"',
                f'meta l4proto udp ip {peer_ip} . th {peer_port} @bt_peers4_udp counter drop comment "kto:peer_udp"',
                f'meta l4proto udp ip6 {peer_ip} . th {peer_port} @bt_peers6_udp counter drop comment "kto:peer_udp"',
            ])
            for w1, w2 in SIG_UDP_DHT_PREFIXES:
                lines.append(f'meta l4proto udp @th,64,64 {w1} @th,128,32 {w2} counter drop comment "kto:sig_dht"')
        if engine == "hybrid":
            for name in interfaces:
                for version, family in ((4, "ip"), (6, "ip6")):
                    set_name = nft_set(version, name)
                    lines.append(
                        f"{interface} {json.dumps(name)} meta l4proto {{ tcp, udp }} "
                        f"{family} {local_ip} . th {local_port} . {family} {peer_ip} . th {peer_port} . "
                        f'meta l4proto @{set_name} counter drop comment "kto:ndpi_flow"'
                    )
        lines.append("}")

    lines.append("}")
    return "\n".join(lines) + "\n"


def owns_table():
    result = command(["nft", "-j", "--terse", "list", "table", "inet", TABLE], check=False)
    if result.returncode:
        if "No such file or directory" in result.stderr:
            return False
        raise RuntimeError(result.stderr.strip() or "cannot inspect nftables table")
    objects = json.loads(result.stdout).get("nftables", [])
    tables = [entry["table"] for entry in objects if "table" in entry]
    if not any(table.get("name") == TABLE and table.get("comment") == OWNER for table in tables):
        raise RuntimeError(f"refusing to modify unowned table inet {TABLE}")
    return True


def read_kernel_stats():
    drops = {key: 0 for key in COUNTER_KEYS.values()}
    active_peers = 0
    result = command(["nft", "-j", "list", "table", "inet", TABLE], check=False)
    if result.returncode:
        drops["total"] = 0
        return drops, 0
    try:
        objects = json.loads(result.stdout).get("nftables", [])
    except ValueError:
        drops["total"] = 0
        return drops, 0
    for entry in objects:
        if "rule" in entry:
            rule = entry["rule"]
            key = COUNTER_KEYS.get(rule.get("comment", ""))
            if key:
                packets = sum(
                    expr.get("counter", {}).get("packets", 0)
                    for expr in rule.get("expr", [])
                    if isinstance(expr, dict)
                )
                drops[key] += packets
        elif "set" in entry:
            st = entry["set"]
            if str(st.get("name", "")).startswith("bt_peers"):
                active_peers += len(st.get("elem", []))
    drops["total"] = sum(drops.values())
    return drops, active_peers


def cleanup():
    if owns_table():
        command(["nft", "delete", "table", "inet", TABLE])


def check_nft():
    """Installer runs this in a disposable network namespace, not on the host."""
    if os.stat("/proc/self/ns/net").st_ino == os.stat("/proc/1/ns/net").st_ino:
        raise RuntimeError("self-test requires unshare --net; refusing to touch the host firewall")
    # Validate both kernel-only and hybrid rulesets.
    kernel_rules = nft_table({"tcp": {22, 443}, "udp": {2408}}, 600, [], engine="kernel")
    command(["nft", "--check", "-f", "-"], input=kernel_rules)
    rules = nft_table({"tcp": {22, 443}, "udp": {2408}}, 600, ["eth0", "warp", "ktg-test0"],
                      exempt_ips=["203.0.113.99"], engine="hybrid")
    command(["nft", "--check", "-f", "-"], input=rules)
    command(["nft", "-f", "-"], input=rules)
    try:
        command(["nft", "-f", "-"], input=(
            nft_add((4, "eth0", "5.34.179.103", 55432, "93.184.216.34", 49999, "tcp"), 600) +
            nft_add((6, "warp", "2606:4700:110:8765::2", 55432, "2001:4860:4860::8888", 49999, "udp"), 600) +
            nft_add_peer((4, "93.184.216.34", 51413, "tcp"), 600) +
            nft_add_peer((6, "2001:4860:4860::8888", 6881, "udp"), 600) +
            nft_remove((4, "eth0", "5.34.179.103", 55433, "93.184.216.34", 49999, "tcp"))))
        reused = 4, "eth0", "5.34.179.103", 55432, "93.184.216.34", 49999, "tcp"
        command(["nft", "-f", "-"], input=nft_remove(reused) + nft_add(reused, 600))
        if not owns_table():
            raise RuntimeError("nftables self-test failed")
        check_isolation()
    finally:
        cleanup()
    print("NFT SELF-TEST OK (Kernel signatures, TCP RST, DHT/Trackers, IPv4/IPv6, SNAT, unrelated traffic intact)")


def check_isolation():
    """Exercise real sockets between disposable namespaces, never public peers."""
    program = r'''
import selectors, socket, sys
print("NETNS", flush=True)
sys.stdin.readline()
sel = selectors.DefaultSelector()
for family, address in ((socket.AF_INET, "192.0.2.2"), (socket.AF_INET6, "2001:db8:6b74:6f::2")):
    for port in (80, 49996, 49997, 49998, 49999):
        for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
            sock = socket.socket(family, kind)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind((address, port))
            if kind == socket.SOCK_STREAM:
                sock.listen(16)
            sel.register(sock, selectors.EVENT_READ, "udp" if kind == socket.SOCK_DGRAM else "listen")
print("READY", flush=True)
while True:
    for key, _ in sel.select():
        sock = key.fileobj
        if key.data == "listen":
            client, _ = sock.accept()
            sel.register(client, selectors.EVENT_READ, "tcp")
        elif key.data == "udp":
            data, address = sock.recvfrom(2048)
            if data.startswith(b"push "):
                _, ip, port = data.decode().split()
                sock.sendto(b"probe", (ip, int(port)))
            sock.sendto(data, address)
        else:
            try:
                data = sock.recv(2048)
            except OSError:
                data = b""
            if data:
                try:
                    sock.sendall(data)
                except OSError:
                    sel.unregister(sock)
                    sock.close()
            else:
                sel.unregister(sock)
                sock.close()
'''
    peer = subprocess.Popen(["unshare", "--net", sys.executable, "-u", "-c", program],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    sockets = []

    def ready(expected):
        with selectors.DefaultSelector() as waiter:
            waiter.register(peer.stdout, selectors.EVENT_READ)
            if not waiter.select(8) or peer.stdout.readline().strip() != expected:
                raise RuntimeError("isolated socket test peer did not become ready")

    def socket_for(family, kind, address, port=0):
        sock = socket.socket(family, kind)
        sockets.append(sock)
        sock.settimeout(1)
        sock.bind((address, port))
        return sock

    def echo(sock, remote):
        sock.sendto(b"echo", remote)
        if sock.recv(1024) != b"echo":
            raise RuntimeError("unrelated UDP connection stopped working")

    def dropped(sock):
        sock.settimeout(0.4)
        try:
            data = sock.recv(1024)
            if not data:
                return
        except (socket.timeout, PermissionError, ConnectionResetError, BrokenPipeError):
            return
        raise RuntimeError("a banned connection still received traffic")

    try:
        ready("NETNS")
        command(["ip", "link", "add", "ktg-test0", "type", "veth", "peer", "name", "ktg-test1"])
        command(["ip", "link", "set", "ktg-test1", "netns", str(peer.pid)])
        command(["ip", "address", "add", "192.0.2.1/30", "dev", "ktg-test0"])
        command(["ip", "-6", "address", "add", "2001:db8:6b74:6f::1/64", "dev", "ktg-test0", "nodad"])
        command(["ip", "link", "set", "ktg-test0", "up"])
        command(["ip", "link", "set", "lo", "up"])
        command(["ip", "address", "add", "198.51.100.1/32", "dev", "lo"])
        ns = ["nsenter", "--target", str(peer.pid), "--net", "--"]
        command(ns + ["ip", "address", "add", "192.0.2.2/30", "dev", "ktg-test1"])
        command(ns + ["ip", "-6", "address", "add", "2001:db8:6b74:6f::2/64", "dev", "ktg-test1", "nodad"])
        command(ns + ["ip", "link", "set", "ktg-test1", "up"])
        command(ns + ["ip", "route", "add", "198.51.100.1/32", "via", "192.0.2.1"])
        command(["nft", "-f", "-"], input='''table ip ktg_test_nat {
chain post { type nat hook postrouting priority 100; policy accept;
ip saddr 192.0.2.1 udp sport 40000 snat to 198.51.100.1:45000
}
}
''')
        peer.stdin.write("start\n")
        peer.stdin.flush()
        ready("READY")

        for family, local, remote, captured, captured_port, version in (
            (socket.AF_INET, "192.0.2.1", "192.0.2.2", "198.51.100.1", 45000, 4),
            (socket.AF_INET6, "2001:db8:6b74:6f::1", "2001:db8:6b74:6f::2", "2001:db8:6b74:6f::1", 40000, 6),
        ):
            # 1) Normal TCP & UDP work fine.
            normal_udp = socket_for(family, socket.SOCK_DGRAM, local, 40001)
            echo(normal_udp, (remote, 49997))

            # 2) Kernel BitTorrent TCP handshake -> immediate TCP RST + peer:port ban.
            bt_tcp = socket_for(family, socket.SOCK_STREAM, local)
            bt_tcp.connect((remote, 49998))
            try:
                bt_tcp.sendall(b"\x13BitTorrent protocol" + b"\x00" * 48)
            except (PermissionError, ConnectionResetError, BrokenPipeError):
                pass
            dropped(bt_tcp)
            # Reconnecting to the SAME banned peer:49998 fails immediately even with plain text.
            bt_retry = socket_for(family, socket.SOCK_STREAM, local)
            bt_retry.settimeout(0.5)
            try:
                bt_retry.connect((remote, 49998))
                bt_retry.sendall(b"plain")
                if bt_retry.recv(64):
                    raise RuntimeError("banned torrent peer:port accepted a new connection")
            except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError, PermissionError, socket.timeout):
                pass
            # Another port (49997) on the SAME peer IP still works!
            ok_tcp = socket_for(family, socket.SOCK_STREAM, local)
            ok_tcp.connect((remote, 49997))
            ok_tcp.sendall(b"normal-https")
            if ok_tcp.recv(64) != b"normal-https":
                raise RuntimeError("unrelated TCP port on same IP was affected")

            # 3) HTTP tracker on port 80 is reset, but normal HTTP on port 80 keeps working!
            http_tr = socket_for(family, socket.SOCK_STREAM, local)
            http_tr.connect((remote, 80))
            try:
                http_tr.sendall(b"GET /announce?info_hash=123456 HTTP/1.1\r\nHost: x\r\n\r\n")
            except (PermissionError, ConnectionResetError, BrokenPipeError):
                pass
            dropped(http_tr)
            http_ok = socket_for(family, socket.SOCK_STREAM, local)
            http_ok.connect((remote, 80))
            http_ok.sendall(b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n")
            if not http_ok.recv(64).startswith(b"GET /index.html"):
                raise RuntimeError("normal HTTP on port 80 was blocked after tracker reset")

            # 4) Kernel UDP tracker (BEP 15) and DHT (BEP 5) are dropped immediately on distinct ports.
            udp_tr = socket_for(family, socket.SOCK_DGRAM, local)
            try:
                udp_tr.sendto(b"\x00\x00\x04\x17\x27\x10\x19\x80\x00\x00\x00\x00\x11\x22\x33\x44", (remote, 49998))
            except PermissionError:
                pass
            dropped(udp_tr)
            # Re-sending ordinary UDP to the newly banned peer:49998 hits bt_peers*_udp directly.
            try:
                udp_tr.sendto(b"plain-after-ban", (remote, 49998))
            except PermissionError:
                pass
            dropped(udp_tr)

            udp_dht = socket_for(family, socket.SOCK_DGRAM, local)
            try:
                udp_dht.sendto(b"d1:ad2:id20:01234567890123456789e1:q4:ping1:t2:aa1:y1:qe", (remote, 49996))
            except PermissionError:
                pass
            dropped(udp_dht)
            # Unrelated UDP port 49997 still echoes normally.
            echo(normal_udp, (remote, 49997))

            # 5) Hybrid nDPI per-connection 5-tuple drop with SNAT (e.g. WARP masquerade).
            blocked = socket_for(family, socket.SOCK_DGRAM, local, 40000)
            target = (remote, 49999)
            echo(blocked, target)
            echo(normal_udp, target)
            flow = version, "ktg-test0", captured, captured_port, remote, 49999, "udp"
            command(["nft", "-f", "-"], input=nft_add(flow, 600))
            try:
                blocked.sendto(b"blocked", target)
            except PermissionError:
                pass
            dropped(blocked)
            echo(normal_udp, target)
            request = f"push {captured} {captured_port}".encode()
            normal_udp.sendto(request, target)
            if normal_udp.recv(1024) != request:
                raise RuntimeError("control UDP connection failed")
            dropped(blocked)
            command(["nft", "-f", "-"], input=nft_remove(flow))
            blocked.settimeout(1)
            echo(blocked, target)

        drops, _ = read_kernel_stats()
        for key in ("bt_tcp", "http_tracker", "udp_tracker", "dht", "peer_tcp", "peer_udp", "ndpi_flows"):
            if drops.get(key, 0) < 1:
                raise RuntimeError(f"socket self-test did not confirm drop counter for {key}: {drops}")
    finally:
        for sock in sockets:
            sock.close()
        peer.terminate()
        try:
            peer.wait(timeout=3)
        except subprocess.TimeoutExpired:
            peer.kill()
            peer.wait(timeout=3)
        peer.stdin.close()
        peer.stdout.close()
        command(["ip", "link", "delete", "ktg-test0"], check=False)
        command(["nft", "delete", "table", "ip", "ktg_test_nat"], check=False)


class Guard:
    def __init__(self):
        self.settings = config()
        self.addresses = set()
        self.protected = {"tcp": set(), "udp": set()}
        self.local_updated = 0.0
        self.active_mode = None
        self.applied_signature = None
        self.seen = OrderedDict()
        self.identities = {}
        self.pending = set()
        self.pending_peers = set()
        self.removals = set()
        self.blocked = OrderedDict()
        self.blocked_peers = OrderedDict()
        self.events = self.detections = self.added = self.peer_bans_added = self.errors = 0
        self.running = True
        self.started = time.time()
        self.started_mono = time.monotonic()
        self.saturated_at = 0.0
        self.last_flush = 0.0

    def _table_signature(self, settings):
        return (
            settings["mode"],
            settings["engine"],
            settings["ttl"],
            tuple(settings["interfaces"]),
            tuple(settings["exempt_ips"]),
            tuple(sorted(settings["protected_udp"])),
        )

    def refresh_local(self):
        addresses = json.loads(command(["ip", "-j", "address", "show"]).stdout)
        local = {str(ipaddress.ip_address(addr["local"])) for interface in addresses
                 for addr in interface.get("addr_info", []) if "local" in addr}
        try:
            wg = command(["wg", "show", "all", "listen-port"], check=False).stdout
        except FileNotFoundError:
            wg = ""
        ss_res = command(["ss", "-Hlnutp"], check=False)
        ss_text = ss_res.stdout if ss_res.returncode == 0 and ss_res.stdout.strip() else command(["ss", "-Hlnut"]).stdout
        ports = protected_ports(ss_text, self.settings["protected_udp"], wg)
        if not local or not any(ports.values()):
            raise RuntimeError("cannot obtain local addresses/listeners; refusing enforcement")
        self.addresses = local
        # Preserve a port once seen, so restarting sshd/xray cannot expose it to this filter.
        for protocol in ports:
            new = ports[protocol] - self.protected[protocol]
            if new and self.active_mode == "enforce":
                values = ", ".join(map(str, sorted(new)))
                command(["nft", "-f", "-"], input=(
                    f"add element inet {TABLE} protect_{protocol} {{ {values} }}\n"))
            self.protected[protocol].update(ports[protocol])
        self.local_updated = time.monotonic()

    def set_mode(self, *, force_reload=False):
        settings = config()
        sig = self._table_signature(settings)
        self.settings = settings
        mode = self.settings["mode"]
        if not force_reload and mode == self.active_mode and sig == self.applied_signature:
            return False
        now = time.monotonic()
        retained_flows = {flow for flow, exp in self.blocked.items() if exp > now}
        retained_peers = {peer for peer, exp in self.blocked_peers.items() if exp > now}
        if mode == "enforce":
            present = owns_table()
            rules = nft_table(
                self.protected,
                self.settings["ttl"],
                self.settings["interfaces"],
                exempt_ips=self.settings["exempt_ips"],
                engine=self.settings["engine"],
            )
            if present:
                rules = f"delete table inet {TABLE}\n" + rules
            command(["nft", "--check", "-f", "-"], input=rules)
            command(["nft", "-f", "-"], input=rules)
        else:
            cleanup()
        self.pending.clear()
        self.pending_peers.clear()
        self.removals.clear()
        self.blocked.clear()
        self.blocked_peers.clear()
        if mode == "enforce" and force_reload:
            valid_ifaces = set(self.settings["interfaces"])
            if self.settings["engine"] == "hybrid":
                self.pending.update(f for f in retained_flows if f[1] in valid_ifaces)
            self.pending_peers.update(retained_peers)
        self.identities = {flow: identity for flow, identity in self.identities.items() if flow in self.seen}
        self.active_mode = mode
        self.applied_signature = sig
        print(
            f"MODE {mode}; engine={self.settings['engine']}; ttl={self.settings['ttl']}s; "
            f"kernel output RST+drop + peer:port bans",
            flush=True,
        )
        return True

    def retire_flow(self, flow):
        """Clear a stale 5-tuple ban only when a NEW flow reuses the same local port."""
        self.pending.discard(flow)
        if flow in self.blocked:
            self.removals.add(flow)
        self.seen.pop(flow, None)
        self.identities.pop(flow, None)

    def handle(self, event):
        self.events += 1
        if isinstance(event.get("error_event_name"), str):
            self.errors += 1
            name = event["error_event_name"].replace("\n", " ").replace("\r", " ")[:80]
            details = " ".join(f"{key}={event[key]}" for key in
                               ("current_active", "max_active", "current_idle", "max_idle")
                               if type(event.get(key)) is int)
            print(f"CAPTURE_ERROR {name} {details}".rstrip(), flush=True)
        if self.local_updated <= 0 or time.monotonic() - self.local_updated > 60:
            return
        exempt = set(self.settings["exempt_ips"])
        # Only retire a 5-tuple ban when a NEW flow reuses the exact local port.
        # Do NOT retire on `idle`/`end`: our own nft drop silences packets, which
        # previously caused nDPId's idle timeout to unban still-living torrent sockets!
        if event.get("flow_event_name") == "new":
            flow = connection_tuple(event, self.addresses, self.protected, exempt,
                                    self.settings["interfaces"])
            if flow is not None:
                identity = flow_identity(event)
                if flow in self.identities and self.identities.get(flow) != identity:
                    self.retire_flow(flow)
            return
        flow = torrent_flow(
            event,
            self.addresses,
            self.protected,
            exempt,
            self.settings["interfaces"],
            allow_cache=self.settings["block_encrypted_cache"],
        )
        if flow is None:
            return
        self.detections += 1
        now = time.monotonic()
        identity = flow_identity(event)
        if flow in self.identities and self.identities[flow] != identity:
            self.retire_flow(flow)
        first = flow not in self.seen or now - self.seen[flow] > self.settings["ttl"]
        self.seen[flow] = now
        self.identities[flow] = identity
        self.seen.move_to_end(flow)
        while len(self.seen) > MAX_FLOWS:
            old, _ = self.seen.popitem(last=False)
            if old not in self.blocked and old not in self.pending:
                self.identities.pop(old, None)
        if first:
            ndpi = event["ndpi"]
            confidence = json.dumps(ndpi["confidence"], ensure_ascii=True, separators=(",", ":"))[:160]
            capture = json.dumps(event.get("alias", "unknown"), ensure_ascii=True)[:80]
            metadata = ndpi.get("bittorrent", {})
            has_hash = isinstance(metadata, dict) and bool(metadata.get("hash"))
            print(f"{(self.active_mode or 'init').upper()} BitTorrent local={flow[2]}:{flow[3]} "
                  f"peer={flow[4]}:{flow[5]} protocol={flow[6]} capture={capture} "
                  f"confidence={confidence} hash_present={has_hash}", flush=True)
        if self.active_mode != "enforce":
            return
        version, _iface, _local, _lport, peer_ip, peer_port, protocol = flow
        # Non-shared ports get a strict peer:port ban (stops reconnects & MSE fallback);
        # shared web/DNS ports (53/80/443/853) fall back to strict 5-tuple connection drop.
        if peer_port not in SHARED_SERVICE_PORTS:
            peer_key = (version, peer_ip, peer_port, protocol)
            if self.blocked_peers.get(peer_key, now + 1) <= now:
                del self.blocked_peers[peer_key]
            if peer_key not in self.blocked_peers:
                if len(self.blocked_peers) + len(self.pending_peers) < MAX_PEER_BANS:
                    self.pending_peers.add(peer_key)
                elif now - self.saturated_at > 10:
                    self.errors += 1
                    self.saturated_at = now
                    print("CAPACITY_ERROR peer ban set full; new detections are not blocked", flush=True)
        else:
            if self.blocked.get(flow, now + 1) <= now:
                del self.blocked[flow]
            if flow not in self.blocked or flow in self.removals:
                if len(self.blocked) + len(self.pending) < MAX_FLOWS:
                    self.pending.add(flow)
                elif now - self.saturated_at > 10:
                    self.errors += 1
                    self.saturated_at = now
                    print("CAPACITY_ERROR connection ban set full; new detections are not blocked", flush=True)

    def flush(self, *, force=False):
        now = time.monotonic()
        while self.blocked and next(iter(self.blocked.values())) <= now:
            expired, _ = self.blocked.popitem(last=False)
            if expired not in self.seen:
                self.identities.pop(expired, None)
        while self.blocked_peers and next(iter(self.blocked_peers.values())) <= now:
            self.blocked_peers.popitem(last=False)
        if self.active_mode != "enforce":
            return
        queued = len(self.removals) + len(self.pending) + len(self.pending_peers)
        if queued == 0:
            return
        if not force and queued < FLUSH_IMMEDIATE_THRESHOLD and now - self.last_flush < FLUSH_INTERVAL_SEC:
            return
        removals = sorted(self.removals)[:256]
        # Remove an old generation before reusing its 5-tuple for a new flow.
        flows = sorted(self.pending - (self.removals - set(removals)))[:256]
        peers = sorted(self.pending_peers)[:256]
        lines = [nft_remove(flow).rstrip() for flow in removals]
        lines.extend(nft_add(flow, self.settings["ttl"]).rstrip() for flow in flows)
        lines.extend(nft_add_peer(peer, self.settings["ttl"]).rstrip() for peer in peers)
        if not lines:
            return
        command(["nft", "-f", "-"], input="\n".join(lines) + "\n")
        self.last_flush = now
        for flow in removals:
            self.removals.discard(flow)
            self.blocked.pop(flow, None)
        for flow in flows:
            self.pending.discard(flow)
            self.blocked[flow] = now + self.settings["ttl"] + 2
            self.blocked.move_to_end(flow)
        for peer in peers:
            self.pending_peers.discard(peer)
            self.blocked_peers[peer] = now + self.settings["ttl"] + 2
            self.blocked_peers.move_to_end(peer)
        self.added += len(flows)
        self.peer_bans_added += len(peers)
        if flows or peers:
            print(
                f"BLOCKED peers={len(peers)} connections={len(flows)} ttl={self.settings['ttl']}s",
                flush=True,
            )

    def status(self, connections, captures, stale_captures):
        kernel_drops, active_kernel_peers = (
            read_kernel_stats() if self.active_mode == "enforce" else ({k: 0 for k in COUNTER_KEYS.values()} | {"total": 0}, 0)
        )
        expected = sorted(f"kto-{name}" for name in self.settings["interfaces"]) if self.settings["engine"] == "hybrid" else []
        atomic_json(RUNTIME / "status.json", {
            "version": VERSION,
            "engine": self.settings["engine"],
            "block_scope": "peer_port+kernel",
            "mode": self.active_mode,
            "ttl": self.settings["ttl"],
            "started": self.started,
            "started_mono": self.started_mono,
            "updated": time.time(),
            "updated_mono": time.monotonic(),
            "collector_connections": connections,
            "events": self.events,
            "torrent_events": self.detections,
            "connections_added": self.added,
            "peer_bans_added": self.peer_bans_added,
            "tracked_bans": len(self.blocked) + len(self.blocked_peers),
            "active_kernel_peers": active_kernel_peers,
            "kernel_drops": kernel_drops,
            "protected_tcp": sorted(self.protected["tcp"]),
            "protected_udp": sorted(self.protected["udp"]),
            "errors": self.errors,
            "captures": sorted(captures),
            "expected_captures": expected,
            "stale_captures": sorted(stale_captures),
        })

    def run(self):
        self.refresh_local()
        self.set_mode()
        selector = selectors.DefaultSelector()
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        path = RUNTIME / "collector.sock"
        path.unlink(missing_ok=True)
        server.bind(str(path))
        os.chmod(path, 0o660)
        server.listen(16)
        server.setblocking(False)
        selector.register(server, selectors.EVENT_READ, None)
        notify_ready()
        refresh = status_at = mode_at = 0.0
        try:
            while self.running:
                for key, _ in selector.select(0.2):
                    if key.data is None:
                        client, _ = server.accept()
                        if len(selector.get_map()) >= 17:
                            client.close()
                            continue
                        client.setblocking(False)
                        selector.register(client, selectors.EVENT_READ, Frames())
                    else:
                        try:
                            data = key.fileobj.recv(MAX_FRAME)
                            if not data:
                                raise ConnectionError("collector disconnected")
                            key.data.last_seen = time.monotonic()
                            valid_aliases = {f"kto-{name}" for name in self.settings["interfaces"]}
                            for event in key.data.feed(data):
                                alias = event.get("alias")
                                if isinstance(alias, str) and alias in valid_aliases:
                                    key.data.alias = alias
                                self.handle(event)
                        except (ValueError, ConnectionError, OSError):
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                now = time.monotonic()
                if now >= refresh:
                    try:
                        self.refresh_local()
                        if self.active_mode == "enforce" and not owns_table():
                            self.set_mode(force_reload=True)
                            self.errors += 1
                            print("RULES RESTORED: owned table had disappeared", flush=True)
                    except Exception as exc:
                        self.errors += 1
                        print(f"REFRESH_ERROR {exc}", flush=True)
                    refresh = now + 15
                if now >= mode_at:
                    try:
                        if self.set_mode():
                            status_at = 0.0
                    except Exception as exc:
                        self.errors += 1
                        print(f"CONFIG_ERROR {exc}", flush=True)
                    mode_at = now + 1
                try:
                    self.flush()
                except Exception as exc:
                    self.errors += 1
                    self.last_flush = now + 2.0
                    print(f"FLUSH_ERROR {exc}", flush=True)
                if now >= status_at:
                    try:
                        captures = set()
                        stale = set()
                        for key in selector.get_map().values():
                            if key.data is not None and key.data.alias is not None:
                                captures.add(key.data.alias)
                                if now - key.data.last_seen > CAPTURE_STALE_SEC:
                                    stale.add(key.data.alias)
                        self.status(len(selector.get_map()) - 1, captures, stale)
                    except Exception as exc:
                        self.errors += 1
                        print(f"STATUS_ERROR {exc}", flush=True)
                    status_at = now + 5
        finally:
            for key in list(selector.get_map().values()):
                key.fileobj.close()
            selector.close()
            path.unlink(missing_ok=True)
            try:
                cleanup()
            except Exception as exc:
                print(f"CLEANUP_ERROR {exc}", flush=True)


def status_is_fresh(raw, *, now_wall=None, now_mono=None):
    now_wall = time.time() if now_wall is None else now_wall
    now_mono = time.monotonic() if now_mono is None else now_mono
    if isinstance(raw.get("updated_mono"), (int, float)):
        age = now_mono - raw["updated_mono"]
        if 0 <= age <= 15:
            return True
    if isinstance(raw.get("updated"), (int, float)):
        age = now_wall - raw["updated"]
        return -5 <= age <= 15
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("daemon", "observe", "enforce", "status", "cleanup", "check-nft"))
    args = parser.parse_args()
    if args.action == "check-nft":
        check_nft()
    elif args.action == "status":
        status_path = RUNTIME / "status.json"
        if not status_path.exists():
            raise RuntimeError("GUARD STOPPED: status file not found; service is not running")
        raw = json.loads(status_path.read_text(encoding="utf-8"))
        print(json.dumps(raw, indent=2))
        if not status_is_fresh(raw) or raw.get("version") != VERSION:
            raise RuntimeError("STALE/OUTDATED GUARD: inspect systemctl and journal; not protected")
        if raw.get("engine") == "hybrid":
            if (not raw.get("collector_connections") or
                    set(raw.get("captures", [])) != set(raw.get("expected_captures", [])) or
                    raw.get("stale_captures")):
                raise RuntimeError("STALE/NO CAPTURE: inspect systemctl and journal; nDPI capture unhealthy")
    elif args.action in ("observe", "enforce"):
        raw = config()
        raw["mode"] = args.action
        requested_mono = time.monotonic()
        requested_wall = time.time()
        atomic_json(CONFIG, raw)
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            try:
                status = json.loads((RUNTIME / "status.json").read_text(encoding="utf-8"))
                updated_ok = (
                    (isinstance(status.get("updated_mono"), (int, float)) and status["updated_mono"] >= requested_mono) or
                    (isinstance(status.get("updated"), (int, float)) and status["updated"] >= requested_wall - 1)
                )
                if status.get("mode") == args.action and updated_ok:
                    print(f"APPLIED {args.action} (engine={status.get('engine', raw['engine'])})")
                    break
            except (OSError, ValueError, KeyError):
                pass
            time.sleep(0.5)
        else:
            raise RuntimeError("mode not acknowledged; check journal or use kto-torrent stop")
    elif args.action == "cleanup":
        cleanup()
    else:
        guard = Guard()
        for signum in (signal.SIGTERM, signal.SIGINT):
            signal.signal(signum, lambda *_: setattr(guard, "running", False))
        guard.run()


if __name__ == "__main__":
    main()
