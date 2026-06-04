#!/usr/bin/env bash
# shellcheck shell=bash

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_VERSION="3.1.0"
NODE_PORT="${KTO_NODE_PORT:-1488}"
REMNA_DIR="/opt/remnanode"
REMNA_CONTAINER="remnanode"
CERT_DIR="/opt/remnawave"
LOG_FILE="${KTO_LOG_FILE:-/var/log/kto-vpn-tune.log}"
ANTISCANNER_SCRIPT="/usr/local/bin/update-antiscanner.sh"
ANTISCANNER_URL="https://gist.githubusercontent.com/sngvy/07cee7ac810c9d222fbebddff8c1d1b8/raw/blacklist.txt"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
PURPLE='\033[38;5;93m'
RED='\033[0;31m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

SUDO=()
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    SUDO=(sudo)
fi

on_error() {
    local rc=$?
    echo -e "\n${RED}[ОШИБКА]${NC} Строка ${1:-?}: ${2:-unknown}" >&2
    echo -e "${DIM}Лог: ${LOG_FILE}${NC}" >&2
    exit "$rc"
}
trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR

init_log() {
    local log_dir
    log_dir="$(dirname "$LOG_FILE")"
    "${SUDO[@]}" mkdir -p "$log_dir" >/dev/null 2>&1 || true
    "${SUDO[@]}" touch "$LOG_FILE" >/dev/null 2>&1 || LOG_FILE="/tmp/kto-vpn-tune.log"
    echo "===== kto VPN v${SCRIPT_VERSION} $(date -Is) =====" >> "$LOG_FILE" 2>/dev/null || true
}

header() {
    printf '\033c'
    echo -e "${PURPLE}==========================================${NC}"
    echo -e "${BOLD}${GREEN}                 kto VPN                  ${NC}"
    echo -e "${DIM}                  v${SCRIPT_VERSION}${NC}"
    echo -e "${PURPLE}==========================================${NC}"
}

stage() { echo -e "${PURPLE}[..]${NC} $*"; }
ok() { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*" >&2; }
fail() { echo -e "${RED}[ОШИБКА]${NC} $*" >&2; }

need_root() {
    if [[ ${#SUDO[@]} -gt 0 ]] && ! command -v sudo >/dev/null 2>&1; then
        fail "Запусти от root или установи sudo."
        exit 1
    fi
    "${SUDO[@]}" -v >/dev/null 2>&1 || true
}

cmd() {
    "$@" >> "$LOG_FILE" 2>&1
}

must() {
    local title="$1"
    shift
    if ! "$@" >> "$LOG_FILE" 2>&1; then
        fail "$title"
        tail -n 25 "$LOG_FILE" >&2 || true
        return 1
    fi
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

write_root_file() {
    local path="$1"
    local tmp
    tmp="$(mktemp)"
    cat > "$tmp"
    "${SUDO[@]}" install -m 0644 "$tmp" "$path" >> "$LOG_FILE" 2>&1
    rm -f "$tmp"
}

apt_update_quiet() {
    "${SUDO[@]}" apt-get -o DPkg::Lock::Timeout=600 update >> "$LOG_FILE" 2>&1
}

apt_install_quiet() {
    "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive \
        apt-get -o DPkg::Lock::Timeout=600 install -y \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" \
        "$@" >> "$LOG_FILE" 2>&1
}

detect_ssh_port() {
    local port=""
    if command_exists sshd; then
        port="$(sshd -T 2>/dev/null | awk '/^port / {print $2; exit}' || true)"
    fi
    if [[ -z "$port" && -r /etc/ssh/sshd_config ]]; then
        port="$(awk 'tolower($1)=="port" && $1 !~ /^#/ {print $2; exit}' /etc/ssh/sshd_config 2>/dev/null || true)"
    fi
    echo "${port:-22}"
}

validate_domain() {
    local domain="$1"
    [[ "$domain" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]]
}

ask_domain() {
    local prompt="${1:-Введите домен}"
    local domain
    while true; do
        read -r -p "$(echo -e "${PURPLE}>${NC} ${BOLD}${prompt}:${NC} ")" domain
        if validate_domain "$domain"; then
            echo "$domain"
            return 0
        fi
        fail "Некорректный домен. Пример: vpn.domain.com"
    done
}

escape_yaml_secret() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    echo "$value"
}

ensure_docker() {
    if command_exists docker && "${SUDO[@]}" docker compose version >/dev/null 2>&1; then
        return 0
    fi

    stage "Установка Docker"
    if ! command_exists curl; then
        apt_update_quiet
        apt_install_quiet ca-certificates curl
    fi

    if ! command_exists docker; then
        local installer
        installer="$(mktemp)"
        must "Скачивание Docker" curl -fsSL https://get.docker.com -o "$installer"
        must "Установка Docker" "${SUDO[@]}" sh "$installer"
        rm -f "$installer"
    fi

    if ! "${SUDO[@]}" docker compose version >/dev/null 2>&1; then
        apt_update_quiet
        apt_install_quiet docker-compose-plugin
    fi

    cmd "${SUDO[@]}" systemctl enable --now docker || true
}

install_antiscanner() {
    stage "AntiScanner"

    apt_install_quiet curl ufw cron || true
    cmd "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive apt-get purge -y iptables-persistent || true
    cmd "${SUDO[@]}" systemctl enable --now cron || true

    write_root_file "$ANTISCANNER_SCRIPT" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail

URL="${ANTISCANNER_URL}"
TEMP_FILE="\$(mktemp)"
LOG="/var/log/antiscanner_update.log"

cleanup() {
    rm -f "\$TEMP_FILE"
}
trap cleanup EXIT

if ! command -v ufw >/dev/null 2>&1; then
    echo "\$(date '+%Y-%m-%d %H:%M:%S') [ERROR] ufw not found" >> "\$LOG"
    exit 1
fi

if curl -fsSL "\$URL" -o "\$TEMP_FILE" && [[ -s "\$TEMP_FILE" ]]; then
    for rules_file in /etc/ufw/user.rules /etc/ufw/user6.rules; do
        [[ -f "\$rules_file" ]] && sed -i '/AntiScanner-Block/d' "\$rules_file"
    done

    while IFS= read -r subnet; do
        subnet="\$(echo "\$subnet" | xargs)"
        [[ -z "\$subnet" || "\$subnet" == "#"* ]] && continue

        if [[ "\$subnet" =~ \. || "\$subnet" =~ : ]]; then
            ufw insert 1 deny from "\$subnet" comment 'AntiScanner-Block' >/dev/null 2>&1 || true
        fi
    done < "\$TEMP_FILE"

    ufw reload >/dev/null 2>&1 || true
    echo "\$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] AntiScanner updated via ufw" >> "\$LOG"
else
    echo "\$(date '+%Y-%m-%d %H:%M:%S') [ERROR] failed to download blacklist" >> "\$LOG"
    exit 1
fi
EOF
    cmd "${SUDO[@]}" chmod +x "$ANTISCANNER_SCRIPT"

    cmd "${SUDO[@]}" bash -c "(crontab -l 2>/dev/null | grep -v '$ANTISCANNER_SCRIPT' ; echo '20 3 * * * $ANTISCANNER_SCRIPT >> /var/log/antiscanner_update.log 2>&1') | crontab -"

    write_root_file /etc/systemd/system/antiscanner-update.service <<EOF
[Unit]
Description=Update AntiScanner Blocklist on Boot
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${ANTISCANNER_SCRIPT}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    cmd "${SUDO[@]}" systemctl daemon-reload
    cmd "${SUDO[@]}" systemctl enable antiscanner-update.service
    cmd "${SUDO[@]}" "$ANTISCANNER_SCRIPT" || true
}

optimize_system() {
    header
    need_root
    local ssh_port
    ssh_port="$(detect_ssh_port)"

    stage "Подготовка системы"
    cmd "${SUDO[@]}" systemctl stop unattended-upgrades || true
    cmd "${SUDO[@]}" dpkg --configure -a || true
    cmd "${SUDO[@]}" rm -f /etc/apt/sources.list.d/ookla_speedtest-cli.list || true
    cmd "${SUDO[@]}" systemctl disable --now snapd.socket snapd.service || true
    cmd "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive apt-get purge -y snapd || true

    export NEEDRESTART_MODE=a
    export NEEDRESTART_SUSPEND=1

    stage "Пакеты"
    must "apt update" apt_update_quiet
    must "Установка пакетов" apt_install_quiet \
        ca-certificates curl wget gnupg2 chrony ufw cpufrequtils irqbalance \
        software-properties-common logrotate openssl tar xz-utils dnsutils

    stage "Liquorix kernel"
    if [[ "$(uname -m)" == "x86_64" ]] && grep -qi '^ID=ubuntu' /etc/os-release 2>/dev/null; then
        cmd "${SUDO[@]}" add-apt-repository ppa:damentz/liquorix -y
        cmd apt_update_quiet
        for _ in 1 2 3; do
            if apt_install_quiet linux-image-liquorix-amd64 linux-headers-liquorix-amd64; then
                break
            fi
            sleep 2
        done
    else
        echo "Liquorix skipped: non-Ubuntu or non-amd64" >> "$LOG_FILE"
    fi

    stage "Сеть и лимиты"
    cmd "${SUDO[@]}" modprobe tcp_bbr || true
    write_root_file /etc/sysctl.d/99-vpn-tuning.conf <<'EOF'
fs.file-max = 2097152
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65536
net.ipv4.tcp_max_syn_backlog = 262144
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
net.core.rmem_default = 1048576
net.core.rmem_max = 67108864
net.core.wmem_default = 1048576
net.core.wmem_max = 67108864
net.core.optmem_max = 1048576
net.ipv4.tcp_rmem = 4096 1048576 33554432
net.ipv4.tcp_wmem = 4096 1048576 33554432
vm.swappiness = 1
EOF
    cmd "${SUDO[@]}" sysctl --system || true

    write_root_file /etc/security/limits.d/99-vpn-limits.conf <<'EOF'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF
    cmd "${SUDO[@]}" mkdir -p /etc/systemd/system.conf.d /etc/systemd/user.conf.d
    write_root_file /etc/systemd/system.conf.d/99-vpn-limits.conf <<'EOF'
[Manager]
DefaultLimitNOFILE=1048576
EOF
    write_root_file /etc/systemd/user.conf.d/99-vpn-limits.conf <<'EOF'
[Manager]
DefaultLimitNOFILE=1048576
EOF
    echo 'GOVERNOR="performance"' | "${SUDO[@]}" tee /etc/default/cpufrequtils >> "$LOG_FILE" 2>&1 || true
    cmd "${SUDO[@]}" systemctl daemon-reload || true
    cmd "${SUDO[@]}" systemctl enable --now irqbalance chrony || true
    cmd "${SUDO[@]}" systemctl restart cpufrequtils || true

    stage "Firewall"
    cmd "${SUDO[@]}" ufw --force reset
    cmd "${SUDO[@]}" ufw default deny incoming
    cmd "${SUDO[@]}" ufw default allow outgoing
    cmd "${SUDO[@]}" ufw allow "${ssh_port}/tcp"
    cmd "${SUDO[@]}" ufw allow 443/tcp
    cmd "${SUDO[@]}" ufw allow 443/udp
    cmd "${SUDO[@]}" ufw allow "${NODE_PORT}/tcp"
    cmd "${SUDO[@]}" ufw --force enable

    install_antiscanner

    stage "Fail2ban"
    apt_install_quiet fail2ban || true
    write_root_file /etc/fail2ban/jail.d/99-kto-sshd.conf <<'EOF'
[sshd]
enabled = true
bantime = 1h
findtime = 10m
maxretry = 5
EOF
    cmd "${SUDO[@]}" systemctl enable --now fail2ban || true

    echo
    ok "Оптимизация завершена. Рекомендуется: sudo reboot"
}

install_remnawave_node() {
    header
    need_root
    local secret escaped
    read -r -s -p "$(echo -e "${PURPLE}>${NC} ${BOLD}Введите SECRET_KEY для ноды:${NC} ")" secret
    echo
    if [[ -z "$secret" ]]; then
        fail "SECRET_KEY не может быть пустым"
        exit 1
    fi
    escaped="$(escape_yaml_secret "$secret")"

    ensure_docker

    stage "Remnawave Node"
    cmd "${SUDO[@]}" mkdir -p "$REMNA_DIR"
    write_root_file "$REMNA_DIR/docker-compose.yml" <<EOF
services:
  remnanode:
    container_name: remnanode
    hostname: remnanode
    image: remnawave/node:latest
    network_mode: host
    restart: always
    cap_add:
      - NET_ADMIN
    ulimits:
      nofile:
        soft: 1048576
        hard: 1048576
    environment:
      - NODE_PORT=1488
      - SECRET_KEY="${escaped}"
EOF

    stage "docker compose up -d"
    if ! (cd "$REMNA_DIR" && "${SUDO[@]}" docker compose pull) >> "$LOG_FILE" 2>&1; then
        fail "Docker compose pull"
        tail -n 25 "$LOG_FILE" >&2 || true
        exit 1
    fi
    if ! (cd "$REMNA_DIR" && "${SUDO[@]}" docker compose up -d) >> "$LOG_FILE" 2>&1; then
        fail "Docker compose up -d"
        tail -n 25 "$LOG_FILE" >&2 || true
        exit 1
    fi

    echo
    ok "Нода запущена"
    echo -e "Логи: ${BOLD}sudo docker logs -f remnanode${NC}"
}

install_selfsteal() {
    header
    need_root
    local domain
    domain="$(ask_domain "Введите домен для SelfSteal")"

    stage "SelfSteal"
    must "SelfSteal install" \
        "${SUDO[@]}" bash -c \
        'bash <(curl -Ls "https://github.com/DigneZzZ/remnawave-scripts/raw/main/selfsteal.sh") --force --domain "$1" install' \
        _ "$domain"

    echo
    ok "SelfSteal установлен"
}

install_warp_native() {
    header
    need_root
    stage "WARP Native"
    local script
    script="$(mktemp)"
    must "Скачивание WARP" curl -fsSL https://raw.githubusercontent.com/distillium/warp-native/main/install.sh -o "$script"
    printf '2\n1\n' | "${SUDO[@]}" bash "$script" >> "$LOG_FILE" 2>&1
    rm -f "$script"
    echo
    ok "WARP установлен"
}

install_speedtest() {
    header
    need_root
    stage "Speedtest"
    cmd "${SUDO[@]}" apt-get remove -y speedtest-cli || true
    cmd "${SUDO[@]}" rm -f /usr/bin/speedtest /usr/local/bin/speedtest || true
    if [[ "$(uname -m)" == "aarch64" || "$(uname -m)" == "arm64" ]]; then
        curl -fsSL https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-aarch64.tgz | "${SUDO[@]}" tar xz -C /usr/local/bin speedtest >> "$LOG_FILE" 2>&1
    else
        curl -fsSL https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-x86_64.tgz | "${SUDO[@]}" tar xz -C /usr/local/bin speedtest >> "$LOG_FILE" 2>&1
    fi
    echo
    /usr/local/bin/speedtest --accept-license --accept-gdpr
}

ipcheck_place() {
    header
    echo -e "${YELLOW}[INFO]${NC} IP.Check.Place\n"
    bash <(curl -Ls https://IP.Check.Place) -l en
}

ipcheck_region() {
    header
    echo -e "${YELLOW}[INFO]${NC} IP Region Check\n"
    bash <(wget -qO- https://github.com/Davoyan/ipregion/raw/main/ipregion.sh)
}

container_running() {
    local name="$1"
    command_exists docker && "${SUDO[@]}" docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$name"
}

issue_ssl_certificate() {
    header
    need_root
    local domain email had_80=0 stopped=()
    domain="$(ask_domain "Введите домен для SSL")"
    email="admin@${domain}"

    stage "SSL"
    apt_update_quiet
    apt_install_quiet cron socat curl openssl
    cmd "${SUDO[@]}" systemctl enable --now cron || true
    cmd "${SUDO[@]}" mkdir -p "$CERT_DIR"

    if ! "${SUDO[@]}" test -x /root/.acme.sh/acme.sh; then
        curl -fsSL https://get.acme.sh | "${SUDO[@]}" env HOME=/root sh -s "email=${email}" --force >> "$LOG_FILE" 2>&1
    fi

    cmd "${SUDO[@]}" env HOME=/root /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt

    if command_exists ufw && "${SUDO[@]}" ufw status 2>/dev/null | grep -q "Status: active"; then
        if "${SUDO[@]}" ufw status 2>/dev/null | grep -Eq '^80/tcp[[:space:]]+ALLOW|^80[[:space:]]+ALLOW'; then
            had_80=1
        else
            cmd "${SUDO[@]}" ufw allow 80/tcp
        fi
    fi

    for c in remnanode caddy-selfsteal nginx-selfsteal; do
        if container_running "$c"; then
            stopped+=("$c")
            cmd "${SUDO[@]}" docker stop "$c"
        fi
    done

    if "${SUDO[@]}" env HOME=/root /root/.acme.sh/acme.sh \
        --issue --standalone -d "$domain" \
        --key-file "${CERT_DIR}/privkey.key" \
        --fullchain-file "${CERT_DIR}/fullchain.pem" \
        --force >> "$LOG_FILE" 2>&1; then
        ok "Сертификат выпущен"
    else
        fail "Не удалось выпустить сертификат. Проверь DNS и порт 80."
        tail -n 25 "$LOG_FILE" >&2 || true
    fi

    for c in "${stopped[@]:-}"; do
        cmd "${SUDO[@]}" docker start "$c" || true
    done

    if [[ "$had_80" == "0" ]] && command_exists ufw && "${SUDO[@]}" ufw status 2>/dev/null | grep -q "Status: active"; then
        cmd "${SUDO[@]}" ufw delete allow 80/tcp || true
    fi

    echo
    echo -e "Ключ:      ${BOLD}${CERT_DIR}/privkey.key${NC}"
    echo -e "Fullchain: ${BOLD}${CERT_DIR}/fullchain.pem${NC}"
}

badge() {
    local ok_flag="$1"
    if [[ "$ok_flag" == "1" ]]; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAIL${NC}"
    fi
}

service_ok() {
    local svc="$1"
    systemctl is-active --quiet "$svc" 2>/dev/null && echo 1 || echo 0
}

tcp_listen() {
    local port="$1"
    command_exists ss && ss -lnt 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${port}$" && echo 1 || echo 0
}

udp_listen() {
    local port="$1"
    command_exists ss && ss -lnu 2>/dev/null | awk '{print $5}' | grep -Eq "[:.]${port}$" && echo 1 || echo 0
}

file_ok() {
    local file="$1"
    [[ -s "$file" ]] && echo 1 || echo 0
}

antiscanner_rules_count() {
    if command_exists ufw; then
        "${SUDO[@]}" ufw status 2>/dev/null | grep -c 'AntiScanner-Block' || true
    else
        echo 0
    fi
}

print_row() {
    local name="$1"
    local value="$2"
    local ok_flag="${3:-}"
    if [[ -n "$ok_flag" ]]; then
        printf " %-18s %b\n" "$name" "$value $(badge "$ok_flag")"
    else
        printf " %-18s %b\n" "$name" "$value"
    fi
}

show_status() {
    header
    local ssh_port cc qdisc kernel node_status docker_status cert_days cert_expiry
    ssh_port="$(detect_ssh_port)"
    cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "-")"
    qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "-")"
    kernel="$(uname -r)"

    echo -e "${BOLD}${PURPLE}[ СЕТЬ ]${NC}"
    print_row "BBR + FQ" "${cc} + ${qdisc}" "$([[ "$cc" == "bbr" && "$qdisc" == "fq" ]] && echo 1 || echo 0)"
    print_row "SSH ${ssh_port}/tcp" "listen" "$(tcp_listen "$ssh_port")"
    print_row "TLS 443/tcp" "listen" "$(tcp_listen 443)"
    print_row "Hysteria 443/udp" "listen" "$(udp_listen 443)"
    print_row "Node ${NODE_PORT}/tcp" "listen" "$(tcp_listen "$NODE_PORT")"

    echo
    echo -e "${BOLD}${PURPLE}[ СЛУЖБЫ ]${NC}"
    print_row "ufw" "firewall" "$(service_ok ufw)"
    print_row "antiscanner" "$(antiscanner_rules_count) rules" "$(file_ok "$ANTISCANNER_SCRIPT")"
    print_row "chrony" "time sync" "$(service_ok chrony)"
    print_row "irqbalance" "irq" "$(service_ok irqbalance)"
    print_row "fail2ban" "ssh guard" "$(service_ok fail2ban)"

    echo
    echo -e "${BOLD}${PURPLE}[ REMNAWAVE ]${NC}"
    docker_status="not installed"
    if command_exists docker; then
        docker_status="$(service_ok docker)"
        print_row "docker" "engine" "$docker_status"
        node_status="$("${SUDO[@]}" docker inspect -f '{{.State.Status}}' "$REMNA_CONTAINER" 2>/dev/null || echo "not found")"
        if [[ "$node_status" == "running" ]]; then
            print_row "remnanode" "$node_status" 1
        else
            print_row "remnanode" "$node_status" 0
        fi
    else
        print_row "docker" "$docker_status" 0
        print_row "remnanode" "not found" 0
    fi

    echo
    echo -e "${BOLD}${PURPLE}[ SSL ]${NC}"
    print_row "privkey.key" "$CERT_DIR/privkey.key" "$(file_ok "$CERT_DIR/privkey.key")"
    print_row "fullchain.pem" "$CERT_DIR/fullchain.pem" "$(file_ok "$CERT_DIR/fullchain.pem")"
    if [[ -s "$CERT_DIR/fullchain.pem" ]]; then
        cert_expiry="$(openssl x509 -enddate -noout -in "$CERT_DIR/fullchain.pem" 2>/dev/null | sed 's/notAfter=//' || true)"
        cert_days="$(openssl x509 -checkend 1209600 -noout -in "$CERT_DIR/fullchain.pem" >/dev/null 2>&1 && echo 1 || echo 0)"
        print_row "expires" "${cert_expiry:-unknown}" "$cert_days"
    fi

    echo
    echo -e "${BOLD}${PURPLE}[ ЯДРО ]${NC}"
    if [[ "$kernel" == *liquorix* ]]; then
        print_row "kernel" "$kernel" 1
    else
        print_row "kernel" "$kernel" 0
    fi
}

menu() {
    header
    echo -e "1) Полная оптимизация"
    echo -e "2) Установка ноды Remnawave"
    echo -e "3) Установка SelfSteal"
    echo -e "4) Установка WARP Native"
    echo -e "5) Панель состояния"
    echo -e "6) Speedtest"
    echo -e "7) Проверка IP (IP.Check.Place)"
    echo -e "8) Проверка IP (Region Check)"
    echo -e "9) Сгенерировать SSL-сертификат"
    echo -e "0) Выход"
    echo -e "${PURPLE}==========================================${NC}"
    echo -ne "${PURPLE}>${NC} ${BOLD}Выберите действие (0-9):${NC} "

    local choice
    read -r choice
    case "$choice" in
        1) optimize_system ;;
        2) install_remnawave_node ;;
        3) install_selfsteal ;;
        4) install_warp_native ;;
        5) show_status ;;
        6) install_speedtest ;;
        7) ipcheck_place ;;
        8) ipcheck_region ;;
        9) issue_ssl_certificate ;;
        0) echo -e "${PURPLE}Выход.${NC}" ;;
        *) fail "Неверный выбор" ;;
    esac
}

main() {
    init_log
    case "${1:-menu}" in
        menu) menu ;;
        optimize) optimize_system ;;
        node|install-node) install_remnawave_node ;;
        selfsteal) install_selfsteal ;;
        warp) install_warp_native ;;
        status) show_status ;;
        speedtest) install_speedtest ;;
        ipcheck-place) ipcheck_place ;;
        ipcheck-region) ipcheck_region ;;
        ssl) issue_ssl_certificate ;;
        *) menu ;;
    esac
}

main "$@"
