#!/usr/bin/env bash
# Optional standalone installer. Does not alter Xray, WARP, SSH, or existing tables.
set -Eeuo pipefail
export LC_ALL=C DEBIAN_FRONTEND=noninteractive GIT_TERMINAL_PROMPT=0

PREFIX=/opt/kto-torrent-guard
CONFIG=/etc/kto-torrent-guard.json
NDPID_REF=b1ef7a62e57b6902098053809bbeb69eb6017c99
NDPI_REF=c8443f9747efa204fe8673f1fae99f462267d1f5
GUARD_SHA256=965f78cf725d537f0d66dbb2b30c30f54426ad9803264247ea14b29efbc4e03e
SOURCE=https://raw.githubusercontent.com/Alpha012/kto-optimize/main/scripts
MODE=observe
INTERFACES=()
PROTECTED_UDP=()
BUILD=
INSTALLED=0

die() { printf '[STOP] %s\n' "$*" >&2; exit 1; }
step() { printf '\n[..] %s\n' "$*"; }

on_exit() {
    local rc=$?
    trap - EXIT
    if (( rc != 0 && INSTALLED == 1 )); then
        printf '[ERROR] Setup failed; stopping only torrent-guard services.\n' >&2
        for interface in "${INTERFACES[@]}"; do
            systemctl disable --now "kto-torrent-capture@$interface.service" >/dev/null 2>&1 || true
        done
        systemctl disable --now kto-torrent-guard.service >/dev/null 2>&1 || true
        python3 "$PREFIX/guard.py" cleanup || true
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
        --interface) (( $# >= 2 )) || die '--interface needs a name'; INTERFACES+=("$2"); shift 2 ;;
        --mode) (( $# >= 2 )) || die '--mode needs observe or enforce'; MODE=$2; shift 2 ;;
        --protect-udp) (( $# >= 2 )) || die '--protect-udp needs a port'; PROTECTED_UDP+=("$2"); shift 2 ;;
        *) die "Unknown option: $1" ;;
    esac
done
[[ $EUID == 0 ]] || die 'Run this installer with sudo bash.'
[[ "$MODE" == observe || "$MODE" == enforce ]] || die 'Mode must be observe or enforce.'
[[ -f /etc/os-release ]] || die 'Linux /etc/os-release is required.'
. /etc/os-release
[[ "$ID" == ubuntu && "$VERSION_ID" == 24.04 ]] || die 'This installer targets Ubuntu 24.04 only.'
[[ "$(uname -m)" == x86_64 ]] || die 'This installer has been prepared for x86_64.'
command -v systemctl >/dev/null || die 'systemd is required.'
[[ ! -e "$PREFIX" && ! -e "$CONFIG" && ! -e /usr/local/bin/kto-torrent ]] ||
    die 'Torrent guard already exists. Use kto-torrent status/observe/enforce/stop/uninstall.'
[[ ! -e /etc/systemd/system/kto-torrent-guard.service &&
   ! -e /etc/systemd/system/kto-torrent-capture@.service ]] || die 'Torrent guard unit names are already occupied.'
[[ -z "$(dpkg --audit)" ]] || die 'APT/dpkg has unfinished packages. Repair them before installing.'
(( $(df -Pk /var/tmp | awk 'NR==2 {print $4}') >= 1500000 )) ||
    die 'At least 1.5 GB free in /var/tmp is required for the source build.'
if (( ${#INTERFACES[@]} == 0 )); then
    INTERFACES=(eth0)
    ip link show warp >/dev/null 2>&1 && INTERFACES+=(warp)
fi
declare -A SEEN=()
for port in "${PROTECTED_UDP[@]}"; do
    [[ "$port" =~ ^[0-9]{1,5}$ ]] && (( 10#$port > 0 && 10#$port < 65536 )) || die "Invalid UDP port: $port"
done
for interface in "${INTERFACES[@]}"; do
    [[ "$interface" =~ ^[a-zA-Z0-9_.-]{1,15}$ && "$interface" != lo ]] || die "Invalid interface: $interface"
    [[ -z "${SEEN[$interface]:-}" ]] || die "Duplicate interface: $interface"
    SEEN[$interface]=1
    ip link show dev "$interface" >/dev/null || die "Interface not found: $interface"
done

step 'Installing userspace build dependencies (no kernel or header packages)'
timeout 180 apt-get update
timeout 600 apt-get install -y --no-install-recommends \
    build-essential cmake git ca-certificates curl wget unzip pkg-config \
    autoconf automake libtool libpcap-dev flex bison gettext python3 nftables iproute2 util-linux

step 'Checking nftables access and downloading the reviewed helper'
BUILD=$(mktemp -d /var/tmp/kto-torrent-build.XXXXXX)
curl -q -4 --noproxy '*' -fSL --retry 2 --connect-timeout 10 --max-time 60 \
    "$SOURCE/kto-torrent-guard.py" -o "$BUILD/guard.py"
printf '%s  %s\n' "$GUARD_SHA256" "$BUILD/guard.py" | sha256sum -c -
python3 - "$BUILD/guard.py" <<'PY'
import sys
from pathlib import Path
p = Path(sys.argv[1])
compile(p.read_text(encoding="utf-8"), str(p), "exec")
PY
python3 "$BUILD/guard.py" cleanup
step 'Testing nftables syntax and IPv4/IPv6 sets in an isolated network namespace'
unshare --net python3 "$BUILD/guard.py" check-nft

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
"$BUILD/build/nDPId" -v

step 'Installing isolated services; existing proxy services stay running'
getent group kto-torrent >/dev/null || groupadd --system kto-torrent
id kto-torrent >/dev/null 2>&1 || useradd --system --gid kto-torrent \
    --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin kto-torrent
install -d -m 755 "$PREFIX" "$PREFIX/capture"
install -m 755 "$BUILD/build/nDPId" "$PREFIX/nDPId"
install -m 755 "$BUILD/guard.py" "$PREFIX/guard.py"
printf '%s\n' 'kto-torrent-guard-v1' > "$PREFIX/.owner"
UDP_PORTS=$(IFS=,; printf '%s' "${PROTECTED_UDP[*]}")
python3 - "$MODE" "${SSH_CONNECTION:-}" "$UDP_PORTS" "${INTERFACES[@]}" <<'PY'
import ipaddress
import json
import os
import sys
ips = []
if sys.argv[2].split():
    ips.append(str(ipaddress.ip_address(sys.argv[2].split()[0])))
fd = os.open('/etc/kto-torrent-guard.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as f:
    json.dump({'mode': sys.argv[1], 'ttl': 600, 'exempt_ips': ips,
               'interfaces': sys.argv[4:],
               'protected_udp': [int(p) for p in sys.argv[3].split(',') if p]}, f)
    f.write('\n')
PY
for interface in "${INTERFACES[@]}"; do
    cat > "$PREFIX/capture/$interface.conf" <<EOF
[general]
netif = $interface
collector = /run/kto-torrent-guard/collector.sock
user = kto-torrent
group = kto-torrent
alias = kto-$interface
pidfile = /tmp/kto-torrent-capture-$interface.pid
bpf = (tcp or udp) and not net 127.0.0.0/8 and not host ::1
[tuning]
max-reader-threads = 2
max-flows-per-thread = 16384
max-idle-flows-per-thread = 256
max-packets-per-flow-to-send = 0
max-packets-per-flow-to-process = 32
daemon-status-interval = 60000000
tcp-max-idle-time = 180000000
udp-max-idle-time = 120000000
[ndpi]
fpc = disable
dpi.guess_on_giveup = 0
EOF
done
CAPTURE_UNITS=()
for interface in "${INTERFACES[@]}"; do CAPTURE_UNITS+=("kto-torrent-capture@$interface.service"); done
cat > /etc/systemd/system/kto-torrent-guard.service <<EOF
[Unit]
Description=KTO BitTorrent peer guard (userspace nDPI events)
After=network-online.target
Wants=network-online.target ${CAPTURE_UNITS[*]}
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
CapabilityBoundingSet=CAP_NET_ADMIN
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
MemoryMax=192M
LogRateLimitIntervalSec=30s
LogRateLimitBurst=100
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/kto-torrent-capture@.service <<'EOF'
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
MemoryHigh=768M
MemoryMax=1G
Nice=5
LogRateLimitIntervalSec=30s
LogRateLimitBurst=60
[Install]
WantedBy=multi-user.target
EOF
cat > /usr/local/bin/kto-torrent <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C
PREFIX=/opt/kto-torrent-guard
[[ $EUID == 0 ]] || { echo 'Use sudo kto-torrent ...' >&2; exit 1; }
case "${1:-status}" in
    status)
        systemctl --no-pager --full status kto-torrent-guard.service || true
        python3 "$PREFIX/guard.py" status
        ;;
    observe|enforce)
        systemctl is-active --quiet kto-torrent-guard.service
        if [[ "$1" == enforce ]]; then python3 "$PREFIX/guard.py" status >/dev/null; fi
        python3 "$PREFIX/guard.py" "$1"
        python3 "$PREFIX/guard.py" status
        ;;
    logs) journalctl -u kto-torrent-guard -u 'kto-torrent-capture@*' -n 60 -f ;;
    stop|uninstall)
        for file in "$PREFIX"/capture/*.conf; do
            [[ -f "$file" ]] || continue
            name=${file##*/}; name=${name%.conf}
            systemctl disable --now "kto-torrent-capture@$name.service"
        done
        systemctl disable --now kto-torrent-guard.service
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
    *) echo 'Usage: kto-torrent status|logs|observe|enforce|stop|uninstall' >&2; exit 2 ;;
esac
EOF
chmod 755 /usr/local/bin/kto-torrent
chmod 644 "$PREFIX"/capture/*.conf /etc/systemd/system/kto-torrent-*.service
INSTALLED=1
systemctl daemon-reload
systemctl enable --now kto-torrent-guard.service
for interface in "${INTERFACES[@]}"; do
    systemctl enable --now "kto-torrent-capture@$interface.service"
done
step 'Waiting for capture processes to connect to the collector'
READY=0
for (( attempt=0; attempt<20; attempt++ )); do
    if python3 "$PREFIX/guard.py" status >/dev/null 2>&1; then READY=1; break; fi
    sleep 1
done
(( READY == 1 )) || die 'No healthy capture connection; setup was not successful.'
for interface in "${INTERFACES[@]}"; do
    systemctl is-active --quiet "kto-torrent-capture@$interface.service" || die "Capture failed on $interface."
done
INSTALLED=0
printf '\n[OK] Installed. Mode=%s. Interfaces=%s\n' "$MODE" "${INTERFACES[*]}"
printf '%s\n' \
    'Observe is NOT blocking. Enforce is reactive, not a 100% BitTorrent guarantee.' \
    'sudo kto-torrent status' \
    'sudo kto-torrent logs' \
    'sudo kto-torrent enforce    # enable packet drops, persists across reboot' \
    'sudo kto-torrent observe    # immediately remove our drops' \
    'sudo kto-torrent uninstall  # remove only this guard'
