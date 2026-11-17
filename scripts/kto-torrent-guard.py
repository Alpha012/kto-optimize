#!/usr/bin/env python3
"""Reactive, connection-scoped BitTorrent filter for host-networked exit nodes."""

from __future__ import annotations

import argparse
from collections import OrderedDict
import ipaddress
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import re
import sys
import time


TABLE = "kto_torrent_guard"
OWNER = "kto-torrent-guard-v1"
CONFIG = Path("/etc/kto-torrent-guard.json")
RUNTIME = Path("/run/kto-torrent-guard")
MAX_FLOWS = 32768
MAX_FRAME = 33792
VERSION = 2


def command(args, *, input=None, check=True):
    result = subprocess.run(args, input=input, text=True, capture_output=True, timeout=5)
    if check and result.returncode:
        detail = (result.stderr or result.stdout).strip()[:3000]
        raise RuntimeError(f"{args[0]} failed (exit={result.returncode}): {detail}")
    return result


def config(path=CONFIG):
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("mode") not in ("observe", "enforce"):
        raise ValueError("mode must be observe or enforce")
    ttl = raw.get("ttl", 60)
    if type(ttl) is not int or not 60 <= ttl <= 3600:
        raise ValueError("ttl must be 60..3600 seconds")
    raw["ttl"] = ttl
    raw["exempt_ips"] = [str(ipaddress.ip_address(ip)) for ip in raw.get("exempt_ips", [])]
    interfaces = raw.get("interfaces", [])
    if (not isinstance(interfaces, list) or not interfaces or len(interfaces) > 16 or
            not all(isinstance(item, str) and item != "lo" and
                    re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", item) for item in interfaces) or
            len(set(interfaces)) != len(interfaces)):
        raise ValueError("interfaces must contain 1..16 unique non-loopback interface names")
    raw["protected_udp"] = raw.get("protected_udp", [])
    if any(type(port) is not int or not 0 < port < 65536 for port in raw["protected_udp"]):
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
    ports = {"tcp": set(), "udp": set()}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 5 or fields[0] not in ports:
            continue
        try:
            port = int(fields[4].rsplit(":", 1)[1])
        except (IndexError, ValueError):
            continue
        if 0 < port < 65536:
            ports[fields[0]].add(port)
    return ports


def protected_ports(text, extra_udp, wireguard_text=""):
    ports = listening_ports(text)
    # An unconnected Xray UDP egress socket appears in `ss -lu` too. It must not
    # become an exemption merely because UDP has no TCP-style LISTEN state.
    ports["udp"] &= ports["tcp"]
    ports["udp"].update(extra_udp)
    for line in wireguard_text.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1].isdigit() and 0 < int(fields[1]) < 65536:
            ports["udp"].add(int(fields[1]))
    return ports


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


def torrent_flow(event, addresses, protected, exempt, interfaces):
    if event.get("flow_event_name") not in ("detected", "detection-update", "update"):
        return None
    ndpi = event.get("ndpi")
    if not isinstance(ndpi, dict):
        return None
    if "bittorrent" not in str(ndpi.get("proto", "")).casefold().split("."):
        return None
    # Cached/partial/IP/port classifications cannot ban a new connection.
    confidence = ndpi.get("confidence", {})
    if not isinstance(confidence, dict) or confidence.get("6") != "DPI":
        return None
    return connection_tuple(event, addresses, protected, exempt, interfaces)


def nft_element(flow):
    _version, _interface, local, local_port, remote, remote_port, protocol = flow
    return f'{local} . {local_port} . {remote} . {remote_port} . {protocol}'


def nft_set(version, interface):
    # Hex keeps names collision-free and valid even for interfaces with dots/dashes.
    return f"flows{version}_{interface.encode('ascii').hex()}"


def nft_add(flow, ttl):
    return f"add element inet {TABLE} {nft_set(flow[0], flow[1])} {{ {nft_element(flow)} timeout {ttl}s }}\n"


def nft_remove(flow):
    # Ubuntu 24.04 nft lacks `destroy element`. Add-if-missing then delete in
    # one transaction, so expiry cannot race deletion and no temporary ban leaks.
    element = f"inet {TABLE} {nft_set(flow[0], flow[1])} {{ {nft_element(flow)} }}"
    return f"add element {element}\ndelete element {element}\n"


def nft_table(protected, ttl, interfaces):
    lines = [f"table inet {TABLE} {{", f'comment "{OWNER}"']
    # Five concatenated types fit Ubuntu 24.04's datatype encoding. Keep the
    # interface in the set name/rule, not as a sixth concatenated datatype.
    for name in interfaces:
        for version in (4, 6):
            lines.extend([
                f"set {nft_set(version, name)} {{",
                f"type ipv{version}_addr . inet_service . ipv{version}_addr . inet_service . inet_proto",
                f"flags timeout; timeout {ttl}s; size {MAX_FLOWS}", "}",
            ])
    for protocol in ("tcp", "udp"):
        lines.extend([f"set protect_{protocol} {{", "type inet_service"])
        if protected[protocol]:
            elements = ", ".join(map(str, sorted(protected[protocol])))
            lines.append(f"elements = {{ {elements} }}")
        lines.append("}")
    # Match the capture-side tuple: before standard reverse NAT on ingress,
    # after standard SNAT/masquerade on egress (including WARP source rewriting).
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
        ])
        for name in interfaces:
            for version, family in ((4, "ip"), (6, "ip6")):
                set_name = nft_set(version, name)
                lines.append(
                    f"{interface} {json.dumps(name)} meta l4proto {{ tcp, udp }} "
                    f"{family} {local_ip} . th {local_port} . {family} {peer_ip} . th {peer_port} . "
                    f"meta l4proto @{set_name} counter drop"
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


def cleanup():
    if owns_table():
        command(["nft", "delete", "table", "inet", TABLE])


def check_nft():
    """Installer runs this in a disposable network namespace, not on the host."""
    if os.stat("/proc/self/ns/net").st_ino == os.stat("/proc/1/ns/net").st_ino:
        raise RuntimeError("self-test requires unshare --net; refusing to touch the host firewall")
    rules = nft_table({"tcp": {22, 443}, "udp": {2408}}, 600, ["eth0", "warp", "ktg-test0"])
    command(["nft", "--check", "-f", "-"], input=rules)
    command(["nft", "-f", "-"], input=rules)
    try:
        command(["nft", "-f", "-"], input=(
            nft_add((4, "eth0", "5.34.179.103", 55432, "93.184.216.34", 49999, "tcp"), 600) +
            nft_add((6, "warp", "2606:4700:110:8765::2", 55432, "2001:4860:4860::8888", 49999, "udp"), 600) +
            nft_remove((4, "eth0", "5.34.179.103", 55433, "93.184.216.34", 49999, "tcp"))))
        reused = 4, "eth0", "5.34.179.103", 55432, "93.184.216.34", 49999, "tcp"
        command(["nft", "-f", "-"], input=nft_remove(reused) + nft_add(reused, 600))
        if not owns_table():
            raise RuntimeError("nftables self-test failed")
        check_isolation()
    finally:
        cleanup()
    print("NFT SELF-TEST OK (TCP/UDP, IPv4/IPv6, SNAT, unrelated connections stay usable)")


def check_isolation():
    """Exercise real sockets between disposable namespaces, never public peers."""
    program = r'''
import selectors, socket, sys
print("NETNS", flush=True)
sys.stdin.readline()
sel = selectors.DefaultSelector()
for family, address in ((socket.AF_INET, "192.0.2.2"), (socket.AF_INET6, "fd42:6b74:6f::2")):
    for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
        sock = socket.socket(family, kind)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((address, 49999))
        if kind == socket.SOCK_STREAM:
            sock.listen(8)
        sel.register(sock, selectors.EVENT_READ, "udp" if kind == socket.SOCK_DGRAM else "listen")
print("READY", flush=True)
while True:
    for key, _ in sel.select():
        sock = key.fileobj
        if key.data == "listen":
            client, _ = sock.accept()
            sel.register(client, selectors.EVENT_READ, "tcp")
        elif key.data == "udp":
            data, address = sock.recvfrom(1024)
            if data.startswith(b"push "):
                _, ip, port = data.decode().split()
                sock.sendto(b"probe", (ip, int(port)))
            sock.sendto(data, address)
        else:
            data = sock.recv(1024)
            if data:
                sock.sendall(data)
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

    def socket_for(family, kind, address, port):
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
            sock.recv(1024)
        except (socket.timeout, PermissionError):
            return
        raise RuntimeError("a banned connection still received traffic")

    try:
        ready("NETNS")
        command(["ip", "link", "add", "ktg-test0", "type", "veth", "peer", "name", "ktg-test1"])
        command(["ip", "link", "set", "ktg-test1", "netns", str(peer.pid)])
        command(["ip", "address", "add", "192.0.2.1/30", "dev", "ktg-test0"])
        command(["ip", "-6", "address", "add", "fd42:6b74:6f::1/64", "dev", "ktg-test0", "nodad"])
        command(["ip", "link", "set", "ktg-test0", "up"])
        command(["ip", "link", "set", "lo", "up"])
        command(["ip", "address", "add", "198.51.100.1/32", "dev", "lo"])
        ns = ["nsenter", "--target", str(peer.pid), "--net", "--"]
        command(ns + ["ip", "address", "add", "192.0.2.2/30", "dev", "ktg-test1"])
        command(ns + ["ip", "-6", "address", "add", "fd42:6b74:6f::2/64", "dev", "ktg-test1", "nodad"])
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
            (socket.AF_INET6, "fd42:6b74:6f::1", "fd42:6b74:6f::2", "fd42:6b74:6f::1", 40000, 6),
        ):
            blocked = socket_for(family, socket.SOCK_DGRAM, local, 40000)
            normal = socket_for(family, socket.SOCK_DGRAM, local, 40001)
            target = (remote, 49999)
            echo(blocked, target)
            echo(normal, target)
            flow = version, "ktg-test0", captured, captured_port, remote, 49999, "udp"
            command(["nft", "-f", "-"], input=nft_add(flow, 600))
            try:
                blocked.sendto(b"blocked", target)
            except PermissionError:
                pass  # A local POSTROUTING drop can synchronously return EPERM.
            dropped(blocked)
            echo(normal, target)
            request = f"push {captured} {captured_port}".encode()
            normal.sendto(request, target)
            if normal.recv(1024) != request:
                raise RuntimeError("control UDP connection failed")
            dropped(blocked)
            # Same remote port over TCP must still be reachable.
            tcp = socket_for(family, socket.SOCK_STREAM, local, 40010)
            tcp.connect(target)
            tcp.sendall(b"tcp-ok")
            if tcp.recv(1024) != b"tcp-ok":
                raise RuntimeError("TCP was affected by the UDP ban")
            tcp_flow = version, "ktg-test0", local, 40010, remote, 49999, "tcp"
            command(["nft", "-f", "-"], input=nft_add(tcp_flow, 600))
            try:
                tcp.sendall(b"blocked")
            except PermissionError:
                pass
            dropped(tcp)
            other = socket_for(family, socket.SOCK_STREAM, local, 40011)
            other.connect(target)
            other.sendall(b"other")
            if other.recv(1024) != b"other":
                raise RuntimeError("another TCP connection was blocked")
            command(["nft", "-f", "-"], input=nft_remove(flow))
            blocked.settimeout(1)
            echo(blocked, target)
        report = json.loads(command(["nft", "-j", "list", "table", "inet", TABLE]).stdout)
        drops = {"prerouting": 0, "postrouting": 0}
        for entry in report["nftables"]:
            rule = entry.get("rule", {})
            if rule.get("chain") in drops:
                drops[rule["chain"]] += sum(expr.get("counter", {}).get("packets", 0)
                                            for expr in rule.get("expr", []))
        if not all(drops.values()):
            raise RuntimeError("socket test did not confirm both ingress and egress drop counters")
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
        self.seen = OrderedDict()
        self.identities = {}
        self.pending = set()
        self.removals = set()
        self.blocked = OrderedDict()
        self.events = self.detections = self.added = self.errors = 0
        self.running = True
        self.started = time.time()
        self.saturated_at = 0

    def refresh_local(self):
        addresses = json.loads(command(["ip", "-j", "address", "show"]).stdout)
        local = {str(ipaddress.ip_address(addr["local"])) for interface in addresses
                 for addr in interface.get("addr_info", []) if "local" in addr}
        try:
            wg = command(["wg", "show", "all", "listen-port"], check=False).stdout
        except FileNotFoundError:
            wg = ""
        ports = protected_ports(command(["ss", "-Hlnut"]).stdout,
                                self.settings["protected_udp"], wg)
        if not local or not any(ports.values()):
            raise RuntimeError("cannot obtain local addresses/listeners; refusing enforcement")
        self.addresses = local
        # Preserve a port once seen, so restarting sshd cannot expose it to this filter.
        for protocol in ports:
            new = ports[protocol] - self.protected[protocol]
            if new and self.active_mode == "enforce":
                values = ", ".join(map(str, sorted(new)))
                command(["nft", "-f", "-"], input=(
                    f"add element inet {TABLE} protect_{protocol} {{ {values} }}\n"))
            self.protected[protocol].update(ports[protocol])
        self.local_updated = time.monotonic()

    def set_mode(self):
        settings = config()
        if settings != self.settings:
            self.settings = settings
        mode = self.settings["mode"]
        if mode == self.active_mode:
            return
        if mode == "enforce":
            present = owns_table()
            rules = nft_table(self.protected, self.settings["ttl"], self.settings["interfaces"])
            if present:
                rules = f"delete table inet {TABLE}\n" + rules
            command(["nft", "--check", "-f", "-"], input=rules)
            command(["nft", "-f", "-"], input=rules)
        else:
            cleanup()
        self.pending.clear()
        self.removals.clear()
        self.blocked.clear()
        self.identities = {flow: identity for flow, identity in self.identities.items() if flow in self.seen}
        self.active_mode = mode
        print(f"MODE {mode}; IPv4+IPv6; connection-only drops, no client/peer IP bans", flush=True)

    def retire(self, flow):
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
        if event.get("flow_event_name") in ("new", "end", "idle"):
            flow = connection_tuple(event, self.addresses, self.protected, exempt,
                                    self.settings["interfaces"])
            if flow is not None:
                identity = flow_identity(event)
                if ((event["flow_event_name"] == "new" and self.identities.get(flow) != identity) or
                        (event["flow_event_name"] != "new" and self.identities.get(flow) == identity)):
                    self.retire(flow)
            return
        flow = torrent_flow(event, self.addresses, self.protected, exempt, self.settings["interfaces"])
        if flow is None:
            return
        self.detections += 1
        now = time.monotonic()
        identity = flow_identity(event)
        if flow in self.identities and self.identities[flow] != identity:
            self.retire(flow)
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
            print(f"{self.active_mode.upper()} BitTorrent local={flow[2]}:{flow[3]} peer={flow[4]}:{flow[5]} "
                  f"protocol={flow[6]} capture={capture} confidence={confidence} "
                  f"hash_present={has_hash}", flush=True)
        if self.blocked.get(flow, now + 1) <= now:
            del self.blocked[flow]
        if self.active_mode == "enforce" and (flow not in self.blocked or flow in self.removals):
            if len(self.blocked) + len(self.pending) < MAX_FLOWS:
                self.pending.add(flow)
            elif now - self.saturated_at > 10:
                self.errors += 1
                self.saturated_at = now
                print("CAPACITY_ERROR connection ban set full; new detections are not blocked", flush=True)

    def flush(self):
        now = time.monotonic()
        while self.blocked and next(iter(self.blocked.values())) <= now:
            expired, _ = self.blocked.popitem(last=False)
            if expired not in self.seen:
                self.identities.pop(expired, None)
        if self.active_mode != "enforce":
            return
        removals = sorted(self.removals)[:256]
        # Remove an old generation before reusing its 5-tuple for a new flow.
        flows = sorted(self.pending - (self.removals - set(removals)))[:256]
        lines = [nft_remove(flow).rstrip() for flow in removals]
        lines.extend(nft_add(flow, self.settings["ttl"]).rstrip() for flow in flows)
        if not lines:
            return
        command(["nft", "-f", "-"], input="\n".join(lines) + "\n")
        for flow in removals:
            self.removals.discard(flow)
            self.blocked.pop(flow, None)
        for flow in flows:
            self.pending.discard(flow)
            self.blocked[flow] = now + self.settings["ttl"] + 2
            self.blocked.move_to_end(flow)
        self.added += len(flows)
        if flows:
            print(f"BLOCKED connections={len(flows)} ttl={self.settings['ttl']}s", flush=True)

    def status(self, connections, captures):
        atomic_json(RUNTIME / "status.json", {
            "version": VERSION, "block_scope": "connection",
            "mode": self.active_mode, "started": self.started, "updated": time.time(),
            "collector_connections": connections, "events": self.events,
            "torrent_events": self.detections, "connections_added": self.added,
            "tracked_bans": len(self.blocked), "errors": self.errors,
            "captures": sorted(captures),
            "expected_captures": sorted(f"kto-{name}" for name in self.settings["interfaces"]),
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
                for key, _ in selector.select(0.25):
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
                            for event in key.data.feed(data):
                                alias = event.get("alias")
                                if isinstance(alias, str) and alias in {
                                    f"kto-{name}" for name in self.settings["interfaces"]
                                }:
                                    key.data.alias = alias
                                self.handle(event)
                        except (ValueError, ConnectionError, OSError):
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                now = time.monotonic()
                if now >= refresh:
                    self.refresh_local()
                    if self.active_mode == "enforce" and not owns_table():
                        retained = {peer for peer, expires in self.blocked.items() if expires > now}
                        self.active_mode = None
                        self.set_mode()
                        self.pending.update(retained)
                        self.errors += 1
                        print("RULES RESTORED: owned table had disappeared", flush=True)
                    refresh = now + 15
                if now >= mode_at:
                    self.set_mode()
                    mode_at = now + 1
                self.flush()
                if now >= status_at:
                    captures = {key.data.alias for key in selector.get_map().values()
                                if key.data is not None and key.data.alias is not None}
                    self.status(len(selector.get_map()) - 1, captures)
                    status_at = now + 5
        finally:
            for key in list(selector.get_map().values()):
                key.fileobj.close()
            selector.close()
            path.unlink(missing_ok=True)
            cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("daemon", "observe", "enforce", "status", "cleanup", "check-nft"))
    args = parser.parse_args()
    if args.action == "check-nft":
        check_nft()
    elif args.action == "status":
        raw = json.loads((RUNTIME / "status.json").read_text(encoding="utf-8"))
        age = time.time() - raw["updated"]
        print(json.dumps(raw, indent=2))
        if (age > 15 or age < 0 or raw.get("version") != VERSION or
                raw.get("block_scope") != "connection" or not raw["collector_connections"] or
                set(raw["captures"]) != set(raw["expected_captures"])):
            raise RuntimeError("STALE/NO CAPTURE: inspect systemctl and journal; not protected")
    elif args.action in ("observe", "enforce"):
        raw = config()
        raw["mode"] = args.action
        requested_at = time.time()
        atomic_json(CONFIG, raw)
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            try:
                status = json.loads((RUNTIME / "status.json").read_text(encoding="utf-8"))
                if status["mode"] == args.action and status["updated"] >= requested_at:
                    print(f"APPLIED {args.action}")
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
