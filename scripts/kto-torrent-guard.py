#!/usr/bin/env python3
"""Optional, reactive BitTorrent peer filter for host-networked proxy nodes."""

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
import time


TABLE = "kto_torrent_guard"
OWNER = "kto-torrent-guard-v1"
CONFIG = Path("/etc/kto-torrent-guard.json")
RUNTIME = Path("/run/kto-torrent-guard")
MAX_PEERS = 32768
MAX_FRAME = 33792


def command(args, *, input=None, check=True):
    return subprocess.run(args, input=input, text=True, capture_output=True,
                          check=check, timeout=5)


def config(path=CONFIG):
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("mode") not in ("observe", "enforce"):
        raise ValueError("mode must be observe or enforce")
    ttl = raw.get("ttl", 600)
    if type(ttl) is not int or not 60 <= ttl <= 3600:
        raise ValueError("ttl must be 60..3600 seconds")
    raw["ttl"] = ttl
    raw["exempt_ips"] = [str(ipaddress.ip_address(ip)) for ip in raw.get("exempt_ips", [])]
    interfaces = raw.get("interfaces", [])
    if not interfaces or not all(isinstance(item, str) and item for item in interfaces):
        raise ValueError("interfaces must be a nonempty list")
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


def torrent_peer(event, addresses, protected, exempt):
    if event.get("flow_event_name") not in ("detected", "detection-update", "update"):
        return None
    ndpi = event.get("ndpi")
    if not isinstance(ndpi, dict):
        return None
    # Port/IP guesses and a generic FileSharing category are not a torrent verdict.
    if "bittorrent" not in str(ndpi.get("proto", "")).casefold().split("."):
        return None
    confidence = ndpi.get("confidence", {})
    if not isinstance(confidence, dict) or not any(
        confidence.get(key) == label for key, label in (
            ("3", "DPI (partial)"), ("4", "DPI (partial cache)"),
            ("5", "DPI (cache)"), ("6", "DPI"),
        )
    ):
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
            peer, port, local_port = dst, dport, sport
        elif str(dst) in addresses and str(src) not in addresses:
            peer, port, local_port = src, sport, dport
        else:
            return None
        if (not peer.is_global or str(peer) in exempt or
                local_port in protected[protocol]):
            return None
    except (KeyError, ValueError, TypeError):
        return None
    return peer.version, str(peer), port, protocol


def nft_table(protected, ttl):
    lines = [f"table inet {TABLE} {{", f'comment "{OWNER}"']
    for version in (4, 6):
        lines.extend([
            f"set peers{version} {{",
            f"type ipv{version}_addr . inet_service . inet_proto",
            f"flags timeout; timeout {ttl}s; size {MAX_PEERS}", "}",
        ])
    for protocol in ("tcp", "udp"):
        lines.extend([f"set protect_{protocol} {{", "type inet_service"])
        if protected[protocol]:
            elements = ", ".join(map(str, sorted(protected[protocol])))
            lines.append(f"elements = {{ {elements} }}")
        lines.append("}")
    for direction in ("input", "output"):
        local_port = "dport" if direction == "input" else "sport"
        peer_ip = "saddr" if direction == "input" else "daddr"
        peer_port = "sport" if direction == "input" else "dport"
        lines.extend([
            f"chain {direction} {{",
            f"type filter hook {direction} priority -20; policy accept;",
            'iifname "lo" return' if direction == "input" else 'oifname "lo" return',
            f"tcp {local_port} @protect_tcp return",
            f"udp {local_port} @protect_udp return",
        ])
        for version, family in ((4, "ip"), (6, "ip6")):
            lines.append(
                f"meta l4proto {{ tcp, udp }} {family} {peer_ip} . th {peer_port} . "
                f"meta l4proto @peers{version} counter drop"
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
    rules = nft_table({"tcp": {22, 443}, "udp": {2408}}, 600)
    command(["nft", "--check", "-f", "-"], input=rules)
    command(["nft", "-f", "-"], input=rules)
    try:
        command(["nft", "-f", "-"], input=(
            f"add element inet {TABLE} peers4 {{ 93.184.216.34 . 49999 . tcp timeout 600s }}\n"
            f"add element inet {TABLE} peers6 {{ 2001:4860:4860::8888 . 49999 . udp timeout 600s }}\n"))
        if not owns_table():
            raise RuntimeError("nftables self-test failed")
    finally:
        cleanup()
    print("NFT SELF-TEST OK (isolated namespace, IPv4+IPv6, timed peer sets)")


class Guard:
    def __init__(self):
        self.settings = config()
        self.addresses = set()
        self.protected = {"tcp": set(), "udp": set()}
        self.local_updated = 0.0
        self.active_mode = None
        self.seen = OrderedDict()
        self.pending = set()
        self.blocked = OrderedDict()
        self.events = self.detections = self.added = self.errors = 0
        self.running = True
        self.started = time.time()

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
            rules = nft_table(self.protected, self.settings["ttl"])
            if present:
                rules = f"delete table inet {TABLE}\n" + rules
            command(["nft", "--check", "-f", "-"], input=rules)
            command(["nft", "-f", "-"], input=rules)
        else:
            cleanup()
        self.pending.clear()
        self.blocked.clear()
        self.active_mode = mode
        print(f"MODE {mode}; IPv4+IPv6; peer endpoint bans, not client IP bans", flush=True)

    def handle(self, event):
        self.events += 1
        if isinstance(event.get("error_event_name"), str):
            self.errors += 1
            name = event["error_event_name"].replace("\n", " ").replace("\r", " ")[:80]
            print(f"CAPTURE_ERROR {name}", flush=True)
        if time.monotonic() - self.local_updated > 60:
            return
        peer = torrent_peer(event, self.addresses, self.protected,
                            set(self.settings["exempt_ips"]))
        if peer is None:
            return
        self.detections += 1
        now = time.monotonic()
        first = peer not in self.seen or now - self.seen[peer] > self.settings["ttl"]
        self.seen[peer] = now
        self.seen.move_to_end(peer)
        while len(self.seen) > MAX_PEERS:
            self.seen.popitem(last=False)
        if first:
            print(f"{self.active_mode.upper()} BitTorrent peer={peer[1]}:{peer[2]} "
                  f"protocol={peer[3]}", flush=True)
        if self.blocked.get(peer, now + 1) <= now:
            del self.blocked[peer]
        if self.active_mode == "enforce" and peer not in self.blocked and len(self.pending) < MAX_PEERS:
            self.pending.add(peer)

    def flush(self):
        now = time.monotonic()
        while self.blocked and next(iter(self.blocked.values())) <= now:
            self.blocked.popitem(last=False)
        if not self.pending or self.active_mode != "enforce":
            return
        peers = sorted(self.pending)[:256]
        lines = [f"add element inet {TABLE} peers{version} "
                 f"{{ {ip} . {port} . {proto} timeout {self.settings['ttl']}s }}"
                 for version, ip, port, proto in peers]
        command(["nft", "-f", "-"], input="\n".join(lines) + "\n")
        for peer in peers:
            self.pending.discard(peer)
            self.blocked[peer] = now + self.settings["ttl"] + 2
        self.added += len(peers)
        print(f"BLOCKED endpoints={len(peers)} ttl={self.settings['ttl']}s", flush=True)

    def status(self, connections, captures):
        atomic_json(RUNTIME / "status.json", {
            "mode": self.active_mode, "started": self.started, "updated": time.time(),
            "collector_connections": connections, "events": self.events,
            "torrent_events": self.detections, "endpoints_added": self.added,
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
        if (age > 15 or not raw["collector_connections"] or
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
