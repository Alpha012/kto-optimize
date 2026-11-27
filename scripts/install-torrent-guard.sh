#!/usr/bin/env bash
# Two-layer BitTorrent blocker installer (fast Kernel nftables + optional nDPId).
# Does not alter Xray, WARP, SSH, or existing firewall tables.
set -Eeuo pipefail
export LC_ALL=C DEBIAN_FRONTEND=noninteractive GIT_TERMINAL_PROMPT=0

PREFIX=/opt/kto-torrent-guard
CONFIG=/etc/kto-torrent-guard.json
NDPID_REF=b1ef7a62e57b6902098053809bbeb69eb6017c99
NDPI_REF=c8443f9747efa204fe8673f1fae99f462267d1f5
GUARD_SHA256=03ecb6d92892fd23b08f1802120128b407eae799af08acecb2eec949e5b86c5f
RAW_BASE="${KTO_RAW_BASE:-https://raw.githubusercontent.com/Alpha012/kto-optimize/main}"
SOURCE="${RAW_BASE%/}/scripts"
ENGINE=kernel
MODE=observe
TTL=600
ADD_NDPI=0
LOCAL_GUARD=""
INTERFACES=()
PROTECTED_UDP=()
BUILD=""
INSTALLED=0
CURRENT_STEP=preflight

die() { printf '[STOP] %s\n' "$*" >&2; exit 1; }
step() { CURRENT_STEP=$*; printf '\n[..] %s\n' "$*"; }

probe_ndpid_version() {
    local binary=$1 output rc=0
    # Upstream returns 1 for a successful -v; verify the banner as well as status.
    output=$("$binary" -v 2>&1) || rc=$?
    printf '%s\n' "$output"
    if (( rc != 0 && rc != 1 )); then
        die "nDPId version probe failed (exit=$rc)."
    fi
    [[ "$output" == *'nDPId version '* && "$output" == *'nDPI version...: '* ]] ||
        die 'nDPId version probe did not return a valid version banner.'
}

on_exit() {
    local rc=$?
    trap - EXIT
    if (( rc != 0 )); then
        printf '[ERROR] Setup stopped (exit=%s). Step: %s\n' "$rc" "$CURRENT_STEP" >&2
    fi
    if (( rc != 0 && INSTALLED == 1 && ADD_NDPI == 0 )); then
        printf '[ERROR] Setup failed; stopping only torrent-guard services.\n' >&2
        for interface in "${INTERFACES[@]+"${INTERFACES[@]}"}"; do
            systemctl disable --now "kto-torrent-capture@$interface.service" >/dev/null 2>&1 || true
        done
        systemctl disable --now kto-torrent-guard.service >/dev/null 2>&1 || true
        python3 "$PREFIX/guard.py" cleanup >/dev/null 2>&1 || true
        printf 'Diagnostic: journalctl -u kto-torrent-guard -u "kto-torrent-capture@*" -n 80 --no-pager\n' >&2
    fi
    if [[ -n "$BUILD" && "$BUILD" == /var/tmp/kto-torrent-build.* && -d "$BUILD" ]]; then
        rm -rf -- "$BUILD"
    fi
    exit "$rc"
}
trap on_exit EXIT

while (( $# )); do
    case "$1" in
        --engine) (( $# >= 2 )) || die '--engine needs kernel or hybrid'; ENGINE=$2; shift 2 ;;
        --interface) (( $# >= 2 )) || die '--interface needs a name'; INTERFACES+=("$2"); shift 2 ;;
        --mode) (( $# >= 2 )) || die '--mode needs observe or enforce'; MODE=$2; shift 2 ;;
        --ttl) (( $# >= 2 )) || die '--ttl needs seconds (60..86400)'; TTL=$2; shift 2 ;;
        --protect-udp) (( $# >= 2 )) || die '--protect-udp needs a port'; PROTECTED_UDP+=("$2"); shift 2 ;;
        --local-guard) (( $# >= 2 )) || die '--local-guard needs a path'; LOCAL_GUARD=$2; shift 2 ;;
        --add-ndpi) ADD_NDPI=1; ENGINE=hybrid; shift ;;
        *) die "Unknown option: $1" ;;
    esac
done

[[ $EUID == 0 ]] || die 'Run this installer with sudo bash.'
[[ "$ENGINE" == kernel || "$ENGINE" == hybrid ]] || die 'Engine must be kernel or hybrid.'
[[ "$MODE" == observe || "$MODE" == enforce ]] || die 'Mode must be observe or enforce.'
[[ "$TTL" =~ ^[0-9]+$ ]] && (( 10#$TTL >= 60 && 10#$TTL <= 86400 )) || die "Invalid TTL: $TTL"
[[ -f /etc/os-release ]] || die 'Linux /etc/os-release is required.'
. /etc/os-release
case "${ID:-}" in
    ubuntu|debian) ;;
    *) die "Unsupported OS (${ID:-unknown}). Ubuntu or Debian is required." ;;
esac
case "$(uname -m)" in
    x86_64|aarch64|arm64) ;;
    *) die "Unsupported architecture: $(uname -m). x86_64 or arm64 is required." ;;
esac
command -v systemctl >/dev/null || die 'systemd is required.'

if (( ADD_NDPI == 1 )); then
    [[ -f "$PREFIX/.owner" && "$(cat "$PREFIX/.owner")" == kto-torrent-guard-v1 && -s "$CONFIG" ]] ||
        die 'Existing KTO torrent guard installation not found for --add-ndpi.'
else
    [[ ! -e "$PREFIX" && ! -e "$CONFIG" && ! -e /usr/local/bin/kto-torrent ]] ||
        die 'Torrent guard already exists. Use kto-torrent status/observe/enforce/stop/uninstall.'
    [[ ! -e /etc/systemd/system/kto-torrent-guard.service &&
       ! -e /etc/systemd/system/kto-torrent-capture@.service ]] ||
        die 'Torrent guard unit names are already occupied.'
fi

detect_default_interfaces() {
    mapfile -t INTERFACES < <(ip -j -4 route show table main default 2>/dev/null | python3 -c '
import json, sys
seen = set()
try:
    routes = json.load(sys.stdin)
except Exception:
    routes = []
for route in routes:
    name = route.get("dev", "")
    if name and name != "lo" and name not in seen:
        seen.add(name)
        print(name)
')
    if ip link show warp >/dev/null 2>&1 && [[ " ${INTERFACES[*]+"${INTERFACES[*]}"} " != *' warp '* ]]; then
        INTERFACES+=(warp)
    fi
}

if (( ${#INTERFACES[@]} == 0 )); then
    detect_default_interfaces
    if [[ "$ENGINE" == hybrid ]] && (( ${#INTERFACES[@]} == 0 )); then
        die 'No IPv4 default interface found. Pass --interface NAME explicitly.'
    fi
fi

declare -A SEEN=()
for port in "${PROTECTED_UDP[@]+"${PROTECTED_UDP[@]}"}"; do
    [[ "$port" =~ ^[0-9]{1,5}$ ]] && (( 10#$port > 0 && 10#$port < 65536 )) || die "Invalid UDP port: $port"
done
for interface in "${INTERFACES[@]+"${INTERFACES[@]}"}"; do
    [[ "$interface" =~ ^[a-zA-Z0-9_.-]{1,15}$ && "$interface" != lo ]] || die "Invalid interface: $interface"
    [[ -z "${SEEN[$interface]:-}" ]] || die "Duplicate interface: $interface"
    SEEN[$interface]=1
    ip link show dev "$interface" >/dev/null || die "Interface not found: $interface"
done

ensure_packages() {
    local missing=() pkg
    for pkg in "$@"; do
        dpkg -s "$pkg" >/dev/null 2>&1 || missing+=("$pkg")
    done
    if (( ${#missing[@]} > 0 )); then
        [[ -z "$(dpkg --audit)" ]] || die 'APT/dpkg has unfinished packages. Repair them before installing.'
        timeout 180 apt-get update
        timeout 600 apt-get install -y --no-install-recommends "${missing[@]}"
    fi
}

step 'Checking runtime dependencies (nftables, python3, iproute2)'
ensure_packages ca-certificates curl python3 nftables iproute2 util-linux

BUILD=$(mktemp -d /var/tmp/kto-torrent-build.XXXXXX)

step 'Preparing hash-verified torrent guard engine'
if [[ -n "$LOCAL_GUARD" ]]; then
    [[ -f "$LOCAL_GUARD" ]] || die "Local guard file not found: $LOCAL_GUARD"
    cp "$LOCAL_GUARD" "$BUILD/guard.py"
else
    curl -q -4 --noproxy '*' -fSL --retry 2 --connect-timeout 10 --max-time 60 \
        "$SOURCE/kto-torrent-guard.py" -o "$BUILD/guard.py"
fi
printf '%s  %s\n' "$GUARD_SHA256" "$BUILD/guard.py" | sha256sum -c -
python3 - "$BUILD/guard.py" <<'PY'
import sys
from pathlib import Path
p = Path(sys.argv[1])
compile(p.read_text(encoding="utf-8"), str(p), "exec")
PY

if (( ADD_NDPI == 0 )); then
    python3 "$BUILD/guard.py" cleanup
fi

step 'Testing kernel signatures, TCP RST, DHT/tracker drops, and NAT isolation'
timeout 60 unshare --net python3 "$BUILD/guard.py" check-nft

if [[ "$ENGINE" == hybrid ]]; then
    (( $(df -Pk /var/tmp | awk 'NR==2 {print $4}') >= 1500000 )) ||
        die 'At least 1.5 GB free in /var/tmp is required to compile optional nDPId.'
    step 'Installing userspace nDPId build dependencies (no kernel packages)'
    ensure_packages build-essential cmake git wget unzip pkg-config \
        autoconf automake libtool libpcap-dev flex bison gettext

    step 'Fetching pinned nDPId and its pinned nDPI submodule'
    git init -q "$BUILD/source"
    git -C "$BUILD/source" remote add origin https://github.com/utoni/nDPId.git
    timeout 180 git -C "$BUILD/source" -c http.lowSpeedLimit=1024 -c http.lowSpeedTime=30 \
        fetch --depth 1 origin "$NDPID_REF"
    git -C "$BUILD/source" checkout -q --detach FETCH_HEAD
    timeout 300 git -C "$BUILD/source" -c http.lowSpeedLimit=1024 -c http.lowSpeedTime=30 \
        submodule update --init --depth 1 -- libnDPI
    [[ "$(git -C "$BUILD/source" rev-parse HEAD)" == "$NDPID_REF" ]] || die 'nDPId revision mismatch.'
    [[ "$(git -C "$BUILD/source/libnDPI" rev-parse HEAD)" == "$NDPI_REF" ]] || die 'nDPI revision mismatch.'

    step 'Compiling nDPId in userspace (limited to two build jobs)'
    cmake -S "$BUILD/source" -B "$BUILD/build" \
        -DCMAKE_BUILD_TYPE=Release -DBUILD_NDPI=ON -DBUILD_EXAMPLES=OFF \
        -DENABLE_ZLIB=OFF -DENABLE_CRYPTO=OFF -DENABLE_SYSTEMD=OFF
    timeout 1800 env MAKEFLAGS=j2 cmake --build "$BUILD/build" --target nDPId --parallel 2
    probe_ndpid_version "$BUILD/build/nDPId"
fi

step 'Installing services and CLI; existing proxy services stay running'
getent group kto-torrent >/dev/null || groupadd --system kto-torrent
id kto-torrent >/dev/null 2>&1 || useradd --system --gid kto-torrent \
    --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin kto-torrent
install -d -m 755 "$PREFIX" "$PREFIX/capture"
install -m 755 "$BUILD/guard.py" "$PREFIX/guard.py"
printf '%s\n' 'kto-torrent-guard-v1' > "$PREFIX/.owner"

if [[ "$ENGINE" == hybrid ]]; then
    install -m 755 "$BUILD/build/nDPId" "$PREFIX/nDPId"
    MEM_KIB=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
    if (( MEM_KIB >= 16777216 )); then
        FLOW_LIMIT=65536
        CAPTURE_MEMORY_HIGH=1536M
        CAPTURE_MEMORY_MAX=2G
    elif (( MEM_KIB >= 4194304 )); then
        FLOW_LIMIT=32768
        CAPTURE_MEMORY_HIGH=768M
        CAPTURE_MEMORY_MAX=1G
    else
        FLOW_LIMIT=16384
        CAPTURE_MEMORY_HIGH=384M
        CAPTURE_MEMORY_MAX=512M
    fi
    rm -f "$PREFIX"/capture/*.conf
    for interface in "${INTERFACES[@]}"; do
        cat > "$PREFIX/capture/$interface.conf" <<EOF
[general]
netif = $interface
collector = /run/kto-torrent-guard/collector.sock
user = kto-torrent
group = kto-torrent
alias = kto-$interface
bpf = (tcp or udp) and not net 127.0.0.0/8 and not host ::1
[tuning]
max-reader-threads = 2
max-flows-per-thread = $FLOW_LIMIT
max-idle-flows-per-thread = 1024
max-packets-per-flow-to-send = 0
max-packets-per-flow-to-process = 32
daemon-status-interval = 60000000
flow-scan-interval = 5000000
tcp-max-idle-time = 60000000
udp-max-idle-time = 30000000
tcp-max-post-end-flow-time = 10000000
[ndpi]
fpc = disable
dpi.guess_on_giveup = 0
EOF
    done
fi

UDP_PORTS=$(IFS=,; printf '%s' "${PROTECTED_UDP[*]+"${PROTECTED_UDP[*]}"}")
python3 - "$ADD_NDPI" "$ENGINE" "$MODE" "$TTL" "${SSH_CONNECTION:-}" "$UDP_PORTS" "${INTERFACES[@]+"${INTERFACES[@]}"}" <<'PY'
import ipaddress
import json
import os
from pathlib import Path
import sys

add_ndpi = sys.argv[1] == "1"
engine = sys.argv[2]
mode = sys.argv[3]
ttl = int(sys.argv[4])
ssh_conn = sys.argv[5]
udp_ports = [int(p) for p in sys.argv[6].split(",") if p]
interfaces = sys.argv[7:]
path = Path("/etc/kto-torrent-guard.json")

if add_ndpi and path.exists():
    cfg = json.loads(path.read_text(encoding="utf-8"))
    cfg["engine"] = "hybrid"
    cfg["interfaces"] = interfaces
    cfg.setdefault("ttl", ttl)
    cfg.setdefault("block_encrypted_cache", True)
    if udp_ports:
        cfg["protected_udp"] = sorted(set(cfg.get("protected_udp", [])) | set(udp_ports))
else:
    ips = []
    if ssh_conn.split():
        try:
            ips.append(str(ipaddress.ip_address(ssh_conn.split()[0])))
        except ValueError:
            pass
    cfg = {
        "engine": engine,
        "mode": mode,
        "ttl": ttl,
        "exempt_ips": ips,
        "interfaces": interfaces,
        "protected_udp": udp_ports,
        "block_encrypted_cache": True,
    }

tmp = path.with_suffix(".tmp")
fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as handle:
    json.dump(cfg, handle)
    handle.write("\n")
os.replace(tmp, path)
PY

CAPTURE_UNITS=()
if [[ "$ENGINE" == hybrid ]]; then
    for interface in "${INTERFACES[@]}"; do
        CAPTURE_UNITS+=("kto-torrent-capture@$interface.service")
    done
fi
WANTS_LINE="Wants=network-online.target"
if (( ${#CAPTURE_UNITS[@]} > 0 )); then
    WANTS_LINE="Wants=network-online.target ${CAPTURE_UNITS[*]}"
fi

cat > /etc/systemd/system/kto-torrent-guard.service <<EOF
[Unit]
Description=KTO BitTorrent blocker (Kernel nftables + optional nDPI)
After=network-online.target
${WANTS_LINE}
[Service]
Type=notify
NotifyAccess=main
TimeoutStartSec=30
Group=kto-torrent
RuntimeDirectory=kto-torrent-guard
RuntimeDirectoryMode=0750
ExecStart=/usr/bin/python3 /opt/kto-torrent-guard/guard.py daemon
ExecStopPost=/usr/bin/python3 /opt/kto-torrent-guard/guard.py cleanup
Restart=on-failure
RestartSec=5
TimeoutStopSec=15
UMask=0077
Environment=LC_ALL=C
Environment=PYTHONDONTWRITEBYTECODE=1
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/run/kto-torrent-guard
CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_READ_SEARCH CAP_SYS_PTRACE
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
MemoryMax=192M
LogRateLimitIntervalSec=30s
LogRateLimitBurst=100
[Install]
WantedBy=multi-user.target
EOF

if [[ "$ENGINE" == hybrid ]]; then
    cat > /etc/systemd/system/kto-torrent-capture@.service <<EOF
[Unit]
Description=KTO nDPId capture on %i
After=network-online.target kto-torrent-guard.service
Wants=kto-torrent-guard.service
PartOf=kto-torrent-guard.service
[Service]
Type=simple
Group=kto-torrent
Environment=NDPID_STARTED_BY_SYSTEMD=1
ExecStart=/opt/kto-torrent-guard/nDPId -l -f /opt/kto-torrent-guard/capture/%i.conf
Restart=on-failure
RestartSec=5
TimeoutStopSec=15
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/run/kto-torrent-guard
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_SETUID CAP_SETGID
RestrictAddressFamilies=AF_UNIX AF_PACKET AF_NETLINK AF_INET AF_INET6
MemoryHigh=$CAPTURE_MEMORY_HIGH
MemoryMax=$CAPTURE_MEMORY_MAX
Nice=5
LogRateLimitIntervalSec=30s
LogRateLimitBurst=60
[Install]
WantedBy=multi-user.target
EOF
fi

cat > /usr/local/bin/kto-torrent <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C
PREFIX=/opt/kto-torrent-guard
CONFIG=/etc/kto-torrent-guard.json
[[ $EUID == 0 ]] || { echo 'Use sudo kto-torrent ...' >&2; exit 1; }

print_status_summary() {
    local json_out rc=0
    json_out="$(python3 "$PREFIX/guard.py" status 2>&1)" || rc=$?
    if [[ "${1:-}" == "--json" ]]; then
        printf '%s\n' "$json_out"
        return "$rc"
    fi
    if ! printf '%s\n' "$json_out" | python3 -c '
import json, sys
text = sys.stdin.read()
start = text.find("{")
end = text.rfind("}")
if start == -1 or end == -1:
    sys.exit(1)
raw = json.loads(text[start:end + 1])
drops = raw.get("kernel_drops", {})
print(f"Engine:          {raw.get(\"engine\", \"unknown\")} (v{raw.get(\"version\", \"?\")})")
print(f"Mode:            {raw.get(\"mode\", \"unknown\")} (TTL={raw.get(\"ttl\", \"?\")}s)")
print(f"Active peer ban: {raw.get(\"active_kernel_peers\", 0)} endpoints")
print(f"Blocked packets: total={drops.get(\"total\", 0)} "
      f"(bt_tcp={drops.get(\"bt_tcp\", 0)}, http_tracker={drops.get(\"http_tracker\", 0)}, "
      f"udp_tracker={drops.get(\"udp_tracker\", 0)}, dht={drops.get(\"dht\", 0)}, "
      f"peer_tcp={drops.get(\"peer_tcp\", 0)}, peer_udp={drops.get(\"peer_udp\", 0)}, "
      f"ndpi={drops.get(\"ndpi_flows\", 0)})")
if raw.get("engine") == "hybrid":
    print(f"nDPI captures:   {raw.get(\"captures\", [])} / expected={raw.get(\"expected_captures\", [])} "
          f"(events={raw.get(\"events\", 0)}, detections={raw.get(\"torrent_events\", 0)})")
    if raw.get("stale_captures"):
        print(f"Stale captures:  {raw.get(\"stale_captures\")}")
print(f"Protected ports: tcp={len(raw.get(\"protected_tcp\", []))} udp={raw.get(\"protected_udp\", [])}")
print(f"Errors:          {raw.get(\"errors\", 0)}")
'; then
        printf '%s\n' "$json_out"
    elif (( rc != 0 )); then
        printf '%s\n' "$json_out" | tail -n 5 >&2
    fi
    return "$rc"
}

case "${1:-status}" in
    status)
        systemctl is-active kto-torrent-guard.service >/dev/null 2>&1 \
            && echo "Service:         kto-torrent-guard.service (active)" \
            || echo "Service:         kto-torrent-guard.service (inactive)"
        print_status_summary "${2:-}"
        ;;
    observe|enforce)
        systemctl is-active --quiet kto-torrent-guard.service
        if [[ "$1" == enforce ]]; then
            python3 "$PREFIX/guard.py" status >/dev/null
        fi
        python3 "$PREFIX/guard.py" "$1"
        print_status_summary
        ;;
    logs)
        if [[ "${2:-}" == "-f" || "${2:-}" == "--follow" ]]; then
            journalctl -u kto-torrent-guard -u 'kto-torrent-capture@*' -n 80 -f
        else
            journalctl -u kto-torrent-guard -u 'kto-torrent-capture@*' -n 80 --no-pager
        fi
        ;;
    remove-ndpi)
        for file in "$PREFIX"/capture/*.conf; do
            [[ -f "$file" ]] || continue
            name=${file##*/}; name=${name%.conf}
            systemctl disable --now "kto-torrent-capture@$name.service" >/dev/null 2>&1 || true
            rm -f -- "$file"
        done
        rm -f /etc/systemd/system/kto-torrent-capture@.service "$PREFIX/nDPId"
        python3 - "$CONFIG" <<'PY'
import json, os, sys
from pathlib import Path
path = Path(sys.argv[1])
cfg = json.loads(path.read_text(encoding="utf-8"))
cfg["engine"] = "kernel"
tmp = path.with_suffix(".tmp")
fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as handle:
    json.dump(cfg, handle)
    handle.write("\n")
os.replace(tmp, path)
PY
        sed -i '/^Wants=network-online\.target /c\Wants=network-online.target' \
            /etc/systemd/system/kto-torrent-guard.service 2>/dev/null || true
        systemctl daemon-reload
        systemctl restart kto-torrent-guard.service
        sleep 2
        print_status_summary
        ;;
    stop|uninstall)
        for file in "$PREFIX"/capture/*.conf; do
            [[ -f "$file" ]] || continue
            name=${file##*/}; name=${name%.conf}
            systemctl disable --now "kto-torrent-capture@$name.service" >/dev/null 2>&1 || true
        done
        systemctl disable --now kto-torrent-guard.service >/dev/null 2>&1 || true
        python3 "$PREFIX/guard.py" cleanup
        if [[ "$1" == uninstall ]]; then
            [[ "$(cat "$PREFIX/.owner")" == kto-torrent-guard-v1 ]]
            rm -f /etc/systemd/system/kto-torrent-guard.service \
                /etc/systemd/system/kto-torrent-capture@.service /etc/kto-torrent-guard.json
            rm -rf -- /opt/kto-torrent-guard
            rm -f /usr/local/bin/kto-torrent
            systemctl daemon-reload
        fi
        ;;
    *)
        echo 'Usage: kto-torrent status [--json]|logs [-f]|observe|enforce|remove-ndpi|stop|uninstall' >&2
        exit 2
        ;;
esac
EOF

chmod 755 /usr/local/bin/kto-torrent
chmod 644 /etc/systemd/system/kto-torrent-*.service
if compgen -G "$PREFIX/capture/*.conf" >/dev/null; then
    chmod 644 "$PREFIX"/capture/*.conf
fi
INSTALLED=1
systemctl daemon-reload
if (( ADD_NDPI == 1 )); then
    systemctl restart kto-torrent-guard.service
else
    systemctl enable --now kto-torrent-guard.service
fi
if [[ "$ENGINE" == hybrid ]]; then
    for interface in "${INTERFACES[@]}"; do
        systemctl enable --now "kto-torrent-capture@$interface.service"
    done
fi

step 'Waiting for torrent guard daemon to report healthy status'
READY=0
for (( attempt=0; attempt<20; attempt++ )); do
    if python3 "$PREFIX/guard.py" status >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 1
done
(( READY == 1 )) || die 'Guard did not report healthy status; setup was not successful.'
if [[ "$ENGINE" == hybrid ]]; then
    for interface in "${INTERFACES[@]}"; do
        systemctl is-active --quiet "kto-torrent-capture@$interface.service" || die "Capture failed on $interface."
    done
fi
INSTALLED=0
printf '\n[OK] Installed KTO Torrent Guard v3. Engine=%s. Mode=%s. TTL=%ss.\n' "$ENGINE" "$MODE" "$TTL"
printf '%s\n' \
    'sudo kto-torrent status      # engine, mode, and kernel/nDPI drop counters' \
    'sudo kto-torrent enforce     # enable blocking (persists across reboot)' \
    'sudo kto-torrent observe     # remove blocking rules immediately' \
    'sudo kto-torrent logs        # inspect recent logs' \
    'sudo kto-torrent remove-ndpi # drop nDPI and keep zero-RAM kernel mode' \
    'sudo kto-torrent uninstall   # remove only this guard'
