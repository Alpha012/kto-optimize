#!/usr/bin/env bash
# shellcheck shell=bash

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_NAME="kto VPN"
SCRIPT_VERSION="2.0.0"

DRY_RUN=0
ASSUME_YES=0
NO_COLOR="${NO_COLOR:-0}"
ACTION=""
PROFILE="balanced"

SYSCTL_FILE="/etc/sysctl.d/99-kto-vpn.conf"
LIMITS_FILE="/etc/security/limits.d/99-kto-vpn-limits.conf"
SYSTEMD_SYSTEM_DROPIN="/etc/systemd/system.conf.d/99-kto-vpn.conf"
SYSTEMD_USER_DROPIN="/etc/systemd/user.conf.d/99-kto-vpn.conf"
JOURNALD_DROPIN="/etc/systemd/journald.conf.d/99-kto-vpn.conf"
BACKUP_ROOT="/var/backups/kto-vpn"
REMNA_DIR="/opt/remnanode"
REMNA_CONTAINER="remnanode"

if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
    LOG_FILE="${KTO_LOG_FILE:-/var/log/kto-vpn-tune.log}"
else
    LOG_FILE="${KTO_LOG_FILE:-/tmp/kto-vpn-tune.log}"
fi

SUDO=()
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    SUDO=(sudo)
fi

if [[ -t 1 && "$NO_COLOR" != "1" ]]; then
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    PURPLE='\033[38;5;93m'
    RED='\033[0;31m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    DIM='\033[2m'
    NC='\033[0m'
else
    GREEN=''
    YELLOW=''
    PURPLE=''
    RED=''
    BLUE=''
    BOLD=''
    DIM=''
    NC=''
fi

cleanup_files=()

cleanup() {
    local file
    for file in "${cleanup_files[@]:-}"; do
        [[ -z "$file" ]] && continue
        if [[ -d "$file" ]]; then
            rm -rf "$file"
        elif [[ -f "$file" ]]; then
            rm -f "$file"
        fi
    done
}

on_error() {
    local exit_code=$?
    local line_no=${1:-unknown}
    local cmd=${2:-unknown}
    echo -e "\n${RED}[ERROR]${NC} Команда упала на строке ${line_no}: ${cmd}" >&2
    echo -e "${YELLOW}[LOG]${NC} ${LOG_FILE}" >&2
    exit "$exit_code"
}

trap cleanup EXIT
trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR

print_header() {
    printf '\033c'
    echo -e "${PURPLE}==========================================${NC}"
    echo -e "${BOLD}${GREEN}                 ${SCRIPT_NAME}                  ${NC}"
    echo -e "${DIM}                  v${SCRIPT_VERSION}${NC}"
    echo -e "${PURPLE}==========================================${NC}"
}

info() { echo -e "${YELLOW}[INFO]${NC} $*"; }
step() { echo -e "${PURPLE}[..]${NC} $*"; }
ok() { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
fail() { echo -e "${RED}[FAIL]${NC} $*" >&2; }

pause() {
    [[ -t 0 ]] || return 0
    echo
    read -r -p "Нажми Enter, чтобы продолжить..." _
}

usage() {
    cat <<EOF
${SCRIPT_NAME} v${SCRIPT_VERSION}

Использование:
  ./tune.sh                         Интерактивное меню
  ./tune.sh optimize                Полная оптимизация
  ./tune.sh install-node            Установка Remnawave Node
  ./tune.sh status                  Панель состояния
  ./tune.sh ssl                     Выпуск SSL-сертификата
  ./tune.sh speedtest               Speedtest
  ./tune.sh ipcheck-place           Проверка IP.Check.Place
  ./tune.sh ipcheck-region          Проверка региона IP
  ./tune.sh selfsteal               Установка SelfSteal
  ./tune.sh warp                    Установка WARP Native
  ./tune.sh rollback                Откат последнего бэкапа

Опции:
  --profile balanced|throughput|low-memory
  --yes                             Автоответ "да" на подтверждения
  --dry-run                         Показать действия без изменений
  --no-color                        Без цветов
  --log PATH                        Путь к лог-файлу
  -h, --help                        Помощь

Примеры:
  ./tune.sh optimize --profile throughput
  ./tune.sh install-node --yes
  ./tune.sh status --no-color
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            optimize|install-node|status|ssl|speedtest|ipcheck-place|ipcheck-region|selfsteal|warp|rollback)
                ACTION="$1"
                shift
                ;;
            --profile)
                PROFILE="${2:-}"
                shift 2
                ;;
            --profile=*)
                PROFILE="${1#*=}"
                shift
                ;;
            --yes|-y)
                ASSUME_YES=1
                shift
                ;;
            --dry-run)
                DRY_RUN=1
                shift
                ;;
            --no-color)
                NO_COLOR=1
                shift
                ;;
            --log)
                LOG_FILE="${2:-}"
                shift 2
                ;;
            --log=*)
                LOG_FILE="${1#*=}"
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                fail "Неизвестный аргумент: $1"
                usage
                exit 2
                ;;
        esac
    done

    case "$PROFILE" in
        balanced|throughput|low-memory) ;;
        *)
            fail "Неизвестный профиль: $PROFILE"
            exit 2
            ;;
    esac
}

init_logging() {
    local log_dir
    log_dir="$(dirname "$LOG_FILE")"

    if [[ "$DRY_RUN" == "1" ]]; then
        mkdir -p "$log_dir" 2>/dev/null || true
        : > "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/kto-vpn-tune.log"
        return 0
    fi

    if [[ ${#SUDO[@]} -gt 0 && "$LOG_FILE" == /var/log/* ]]; then
        "${SUDO[@]}" mkdir -p "$log_dir"
        "${SUDO[@]}" touch "$LOG_FILE"
        "${SUDO[@]}" chmod 0644 "$LOG_FILE"
    else
        mkdir -p "$log_dir"
        touch "$LOG_FILE"
        chmod 0644 "$LOG_FILE" 2>/dev/null || true
    fi

    {
        echo
        echo "===== ${SCRIPT_NAME} v${SCRIPT_VERSION} started at $(date -Is) ====="
        echo "Action=${ACTION:-menu} Profile=${PROFILE} DryRun=${DRY_RUN} Yes=${ASSUME_YES}"
    } >> "$LOG_FILE"
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

require_sudo() {
    if [[ ${#SUDO[@]} -eq 0 ]]; then
        return 0
    fi

    if ! command_exists sudo; then
        fail "Нужны root-права, но sudo не установлен. Запусти скрипт от root."
        exit 1
    fi

    step "Проверяю sudo-доступ"
    "${SUDO[@]}" -v
    ok "sudo доступен"
}

run() {
    local title="$1"
    shift

    step "$title"

    {
        echo
        echo "[$(date -Is)] $title"
        printf '+'
        printf ' %q' "$@"
        echo
    } >> "$LOG_FILE"

    if [[ "$DRY_RUN" == "1" ]]; then
        echo -e "${BLUE}[DRY]${NC} $*"
        return 0
    fi

    if "$@" >> "$LOG_FILE" 2>&1; then
        ok "$title"
    else
        local rc=$?
        fail "$title"
        echo -e "${YELLOW}Последние строки лога:${NC}" >&2
        tail -n 35 "$LOG_FILE" >&2 || true
        return "$rc"
    fi
}

run_optional() {
    local title="$1"
    shift

    if run "$title" "$@"; then
        return 0
    fi

    warn "$title: пропускаю, это не критично"
    return 0
}

write_root_file() {
    local path="$1"
    local mode="${2:-0644}"
    local tmp
    tmp="$(mktemp)"
    cleanup_files+=("$tmp")

    cat > "$tmp"

    if [[ "$DRY_RUN" == "1" ]]; then
        step "DRY-RUN запись файла $path"
        sed 's/^/  | /' "$tmp"
        return 0
    fi

    run "Запись $path" "${SUDO[@]}" install -m "$mode" "$tmp" "$path"
}

append_log_separator() {
    echo "-----" >> "$LOG_FILE"
}

confirm() {
    local prompt="$1"
    local default="${2:-n}"
    local answer
    local suffix

    if [[ "$ASSUME_YES" == "1" ]]; then
        return 0
    fi

    if [[ "$default" == "y" ]]; then
        suffix="[Y/n]"
    else
        suffix="[y/N]"
    fi

    if [[ ! -t 0 ]]; then
        [[ "$default" == "y" ]]
        return $?
    fi

    while true; do
        read -r -p "$(echo -e "${PURPLE}[?]${NC} ${prompt} ${suffix} ")" answer
        answer="${answer:-$default}"
        case "$answer" in
            y|Y|yes|YES|д|Д|да|ДА) return 0 ;;
            n|N|no|NO|н|Н|нет|НЕТ) return 1 ;;
            *) echo "Ответь y/n." ;;
        esac
    done
}

ask_default() {
    local prompt="$1"
    local default="$2"
    local answer

    if [[ ! -t 0 ]]; then
        printf '%s\n' "$default"
        return 0
    fi

    read -r -p "$(echo -e "${PURPLE}[?]${NC} ${prompt} ${DIM}[$default]${NC}: ")" answer
    printf '%s\n' "${answer:-$default}"
}

ask_required() {
    local prompt="$1"
    local answer

    while true; do
        read -r -p "$(echo -e "${PURPLE}[?]${NC} ${prompt}: ")" answer
        if [[ -n "$answer" ]]; then
            printf '%s\n' "$answer"
            return 0
        fi
        echo "Значение не может быть пустым."
    done
}

ask_secret() {
    local prompt="$1"
    local answer

    while true; do
        read -r -s -p "$(echo -e "${PURPLE}[?]${NC} ${prompt}: ")" answer
        echo
        if [[ -n "$answer" ]]; then
            printf '%s\n' "$answer"
            return 0
        fi
        echo "Секрет не может быть пустым."
    done
}

validate_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 ))
}

ask_port() {
    local prompt="$1"
    local default="$2"
    local port

    while true; do
        port="$(ask_default "$prompt" "$default")"
        if validate_port "$port"; then
            printf '%s\n' "$port"
            return 0
        fi
        echo "Порт должен быть числом 1-65535."
    done
}

validate_domain() {
    local domain="$1"
    [[ "$domain" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]]
}

ask_domain() {
    local domain

    while true; do
        domain="$(ask_required "Введите домен, например vpn.domain.com")"
        if validate_domain "$domain"; then
            printf '%s\n' "$domain"
            return 0
        fi
        echo "Похоже, это не домен. Пример: vpn.domain.com"
    done
}

valid_ip_or_cidrish() {
    local value="$1"
    [[ "$value" =~ ^[0-9a-fA-F:.]+(/[0-9]{1,3})?$ ]]
}

download_file() {
    local url="$1"
    local output="$2"

    if command_exists curl; then
        run "Скачивание $(basename "$output")" curl -fsSL --retry 3 --connect-timeout 15 "$url" -o "$output"
    elif command_exists wget; then
        run "Скачивание $(basename "$output")" wget -q --tries=3 --timeout=20 "$url" -O "$output"
    else
        fail "Нужен curl или wget для скачивания: $url"
        return 1
    fi
}

detect_os() {
    if [[ ! -r /etc/os-release ]]; then
        fail "Не могу определить ОС: /etc/os-release не найден."
        exit 1
    fi

    # shellcheck disable=SC1091
    source /etc/os-release

    case "${ID:-}" in
        ubuntu|debian)
            ok "ОС: ${PRETTY_NAME:-$ID}"
            ;;
        *)
            warn "ОС ${PRETTY_NAME:-${ID:-unknown}} не проверялась. Скрипт рассчитан на Ubuntu/Debian."
            if ! confirm "Продолжить на свой риск?" "n"; then
                exit 1
            fi
            ;;
    esac
}

apt_update() {
    run "apt update с ожиданием lock" \
        "${SUDO[@]}" apt-get -o DPkg::Lock::Timeout=600 update
}

apt_install() {
    local title="$1"
    shift
    run "$title" \
        "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive \
        apt-get -o DPkg::Lock::Timeout=600 install -y \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" \
        "$@"
}

apt_purge() {
    local title="$1"
    shift
    run "$title" \
        "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive \
        apt-get -o DPkg::Lock::Timeout=600 purge -y "$@"
}

backup_configs() {
    local backup_dir
    backup_dir="${BACKUP_ROOT}/$(date +%F-%H%M%S)"

    run "Создание каталога бэкапа" "${SUDO[@]}" mkdir -p "$backup_dir"

    if [[ "$DRY_RUN" == "1" ]]; then
        ok "Бэкап: $backup_dir"
        return 0
    fi

    backup_one() {
        local source_path="$1"
        local backup_name="$2"

        if "${SUDO[@]}" test -e "$source_path"; then
            "${SUDO[@]}" cp -a "$source_path" "$backup_dir/$backup_name" >> "$LOG_FILE" 2>&1 || true
        fi
    }

    backup_one "$SYSCTL_FILE" "sysctl.conf"
    backup_one "$LIMITS_FILE" "limits.conf"
    backup_one "$SYSTEMD_SYSTEM_DROPIN" "systemd-system.conf"
    backup_one "$SYSTEMD_USER_DROPIN" "systemd-user.conf"
    backup_one "$JOURNALD_DROPIN" "journald.conf"
    backup_one "/etc/ufw" "ufw"
    backup_one "$REMNA_DIR/docker-compose.yml" "remnanode-docker-compose.yml"
    backup_one "$REMNA_DIR/.env" "remnanode.env"
    backup_one "/etc/logrotate.d/remnanode" "logrotate-remnanode"

    ok "Бэкап сохранен: $backup_dir"
}

install_base_packages() {
    apt_update
    apt_install "Установка базовых утилит" \
        ca-certificates curl wget gnupg lsb-release apt-transport-https \
        chrony ufw irqbalance logrotate openssl tar xz-utils dnsutils \
        software-properties-common

    run_optional "Установка cpufrequtils" \
        "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive \
        apt-get -o DPkg::Lock::Timeout=600 install -y cpufrequtils
}

maybe_remove_snapd() {
    if ! command_exists snap && ! systemctl list-unit-files snapd.service >/dev/null 2>&1; then
        ok "snapd не найден"
        return 0
    fi

    if ! confirm "Удалить snapd? Это может удалить snap-пакеты." "n"; then
        warn "snapd оставлен"
        return 0
    fi

    run_optional "Остановка snapd" "${SUDO[@]}" systemctl disable --now snapd.socket snapd.service
    apt_purge "Удаление snapd" snapd
}

install_liquorix_kernel() {
    # shellcheck disable=SC1091
    source /etc/os-release

    case "$(uname -m)" in
        x86_64|amd64) ;;
        *)
            warn "Liquorix amd64 пакет не подходит для архитектуры $(uname -m). Пропускаю установку ядра."
            return 0
            ;;
    esac

    if [[ "${ID:-}" != "ubuntu" ]]; then
        warn "Liquorix через PPA ставлю только на Ubuntu. На Debian лучше оставить штатное ядро или ставить вручную."
        return 0
    fi

    if ! confirm "Установить ядро Liquorix? Нужен reboot после установки." "y"; then
        warn "Установка Liquorix пропущена"
        return 0
    fi

    run "Добавление PPA Liquorix" "${SUDO[@]}" add-apt-repository ppa:damentz/liquorix -y
    apt_update

    local attempt
    for attempt in 1 2 3; do
        if apt_install "Установка Liquorix kernel, попытка ${attempt}/3" \
            linux-image-liquorix-amd64 linux-headers-liquorix-amd64; then
            ok "Liquorix установлен. Перезагрузка нужна для загрузки нового ядра."
            return 0
        fi
        sleep 2
    done

    fail "Liquorix не установился после 3 попыток"
    return 1
}

build_sysctl_profile() {
    local profile="$1"

    cat <<'EOF'
# kto VPN tuning
# Safe baseline for VPN/proxy nodes. Reapply with: sudo sysctl --system

fs.file-max = 2097152

net.core.default_qdisc = fq

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

vm.swappiness = 1
EOF

    case "$profile" in
        balanced)
            cat <<'EOF'

net.core.rmem_default = 1048576
net.core.rmem_max = 16777216
net.core.wmem_default = 1048576
net.core.wmem_max = 16777216
net.core.optmem_max = 262144

net.ipv4.tcp_rmem = 4096 1048576 16777216
net.ipv4.tcp_wmem = 4096 1048576 16777216
EOF
            ;;
        throughput)
            cat <<'EOF'

net.core.rmem_default = 1048576
net.core.rmem_max = 67108864
net.core.wmem_default = 1048576
net.core.wmem_max = 67108864
net.core.optmem_max = 1048576

net.ipv4.tcp_rmem = 4096 1048576 33554432
net.ipv4.tcp_wmem = 4096 1048576 33554432
EOF
            ;;
        low-memory)
            cat <<'EOF'

net.core.rmem_default = 262144
net.core.rmem_max = 4194304
net.core.wmem_default = 262144
net.core.wmem_max = 4194304
net.core.optmem_max = 65536

net.ipv4.tcp_rmem = 4096 262144 4194304
net.ipv4.tcp_wmem = 4096 262144 4194304
EOF
            ;;
    esac
}

apply_sysctl_profile() {
    local profile="$1"
    local tmp
    tmp="$(mktemp)"
    cleanup_files+=("$tmp")

    run_optional "Загрузка модуля tcp_bbr" "${SUDO[@]}" modprobe tcp_bbr
    build_sysctl_profile "$profile" > "$tmp"

    local available_cc current_cc
    available_cc="$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)"
    if [[ "$available_cc" == *"bbr"* ]]; then
        echo "net.ipv4.tcp_congestion_control = bbr" >> "$tmp"
    else
        warn "BBR не найден в доступных congestion control: ${available_cc:-unknown}. Остальные sysctl будут применены."
    fi

    if [[ "$DRY_RUN" == "1" ]]; then
        step "DRY-RUN sysctl профиль $profile"
        sed 's/^/  | /' "$tmp"
    else
        run "Запись sysctl профиля $profile" "${SUDO[@]}" install -m 0644 "$tmp" "$SYSCTL_FILE"
        run_optional "Применение sysctl" "${SUDO[@]}" sysctl --system
    fi

    current_cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)"

    if [[ "$current_cc" == "bbr" ]]; then
        ok "BBR активен"
    elif [[ "$available_cc" == *"bbr"* ]]; then
        warn "BBR доступен, но не активен сейчас: ${current_cc:-unknown}"
    else
        warn "BBR не найден в доступных congestion control: ${available_cc:-unknown}"
    fi
}

apply_limits() {
    write_root_file "$LIMITS_FILE" 0644 <<'EOF'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
* soft nproc 65535
* hard nproc 65535
root soft nproc 65535
root hard nproc 65535
EOF

    run "Создание systemd drop-in каталогов" \
        "${SUDO[@]}" mkdir -p /etc/systemd/system.conf.d /etc/systemd/user.conf.d

    write_root_file "$SYSTEMD_SYSTEM_DROPIN" 0644 <<'EOF'
[Manager]
DefaultLimitNOFILE=1048576
DefaultLimitNPROC=65535
EOF

    write_root_file "$SYSTEMD_USER_DROPIN" 0644 <<'EOF'
[Manager]
DefaultLimitNOFILE=1048576
DefaultLimitNPROC=65535
EOF

    run "systemd daemon-reload" "${SUDO[@]}" systemctl daemon-reload
}

configure_journald_limits() {
    if ! confirm "Ограничить размер journald логов, чтобы диск не забивался?" "y"; then
        return 0
    fi

    run "Создание journald drop-in каталога" "${SUDO[@]}" mkdir -p /etc/systemd/journald.conf.d

    write_root_file "$JOURNALD_DROPIN" 0644 <<'EOF'
[Journal]
SystemMaxUse=512M
RuntimeMaxUse=128M
MaxRetentionSec=30day
EOF

    run_optional "Перезапуск systemd-journald" "${SUDO[@]}" systemctl restart systemd-journald
}

configure_cpu_and_services() {
    if command_exists cpufreq-info || [[ -d /sys/devices/system/cpu/cpu0/cpufreq ]]; then
        write_root_file "/etc/default/cpufrequtils" 0644 <<'EOF'
GOVERNOR="performance"
EOF
        run_optional "Включение cpufrequtils" "${SUDO[@]}" systemctl enable --now cpufrequtils
        run_optional "Перезапуск cpufrequtils" "${SUDO[@]}" systemctl restart cpufrequtils
    else
        warn "CPU governor не настраиваю: cpufreq недоступен на этой системе/VPS"
    fi

    run_optional "Включение irqbalance" "${SUDO[@]}" systemctl enable --now irqbalance
    run_optional "Включение chrony" "${SUDO[@]}" systemctl enable --now chrony
}

detect_ssh_port() {
    local port=""

    if command_exists sshd; then
        port="$(sshd -T 2>/dev/null | awk '/^port / {print $2; exit}' || true)"
    fi

    if [[ -z "$port" && -r /etc/ssh/sshd_config ]]; then
        port="$(awk 'tolower($1)=="port" && $1 !~ /^#/ {print $2; exit}' /etc/ssh/sshd_config 2>/dev/null || true)"
    fi

    printf '%s\n' "${port:-22}"
}

ufw_rule_exists() {
    local pattern="$1"
    "${SUDO[@]}" ufw status 2>/dev/null | grep -Eq "$pattern"
}

configure_firewall() {
    local ssh_port node_port panel_ip open_node_global reset_ufw
    ssh_port="$(detect_ssh_port)"

    info "SSH порт определен как ${ssh_port}. Его правило будет добавлено до включения UFW."

    reset_ufw=0
    if confirm "Пересобрать UFW с нуля? Существующие правила будут сброшены." "n"; then
        reset_ufw=1
    fi

    if [[ "$reset_ufw" == "1" ]]; then
        run "UFW reset" "${SUDO[@]}" ufw --force reset
    fi

    run "UFW default deny incoming" "${SUDO[@]}" ufw default deny incoming
    run "UFW default allow outgoing" "${SUDO[@]}" ufw default allow outgoing
    run "UFW allow SSH ${ssh_port}/tcp" "${SUDO[@]}" ufw allow "${ssh_port}/tcp"

    if confirm "Открыть 443/tcp для TLS/Reality/HTTPS?" "y"; then
        run "UFW allow 443/tcp" "${SUDO[@]}" ufw allow 443/tcp
    fi

    if confirm "Настроить порт Remnawave Node в UFW сейчас?" "y"; then
        node_port="$(ask_port "Порт Remnawave Node" "2222")"
        panel_ip="$(ask_default "IP/CIDR панели, которой разрешить доступ к порту ноды. Оставь пустым, если неизвестно" "")"
        if [[ -n "$panel_ip" ]]; then
            if valid_ip_or_cidrish "$panel_ip"; then
                run "UFW allow node port ${node_port} from ${panel_ip}" \
                    "${SUDO[@]}" ufw allow from "$panel_ip" to any port "$node_port" proto tcp
            else
                warn "IP/CIDR выглядит странно: $panel_ip. Правило не добавлено."
            fi
        else
            open_node_global=0
            if confirm "Открыть порт ${node_port}/tcp для всего интернета? Лучше так не делать." "n"; then
                open_node_global=1
            fi
            if [[ "$open_node_global" == "1" ]]; then
                run "UFW allow node port ${node_port}/tcp globally" "${SUDO[@]}" ufw allow "${node_port}/tcp"
            else
                warn "Порт ноды не открыт. Добавь IP панели позже через статус/ручную команду."
            fi
        fi
    fi

    run "UFW enable" "${SUDO[@]}" ufw --force enable
}

install_fail2ban_optional() {
    if ! confirm "Установить fail2ban для защиты SSH от перебора?" "y"; then
        return 0
    fi

    apt_install "Установка fail2ban" fail2ban

    write_root_file "/etc/fail2ban/jail.d/99-kto-sshd.conf" 0644 <<'EOF'
[sshd]
enabled = true
bantime = 1h
findtime = 10m
maxretry = 5
EOF

    run_optional "Включение fail2ban" "${SUDO[@]}" systemctl enable --now fail2ban
    run_optional "Перезапуск fail2ban" "${SUDO[@]}" systemctl restart fail2ban
}

optimize_system() {
    print_header
    info "Запуск полной оптимизации. Профиль: ${PROFILE}"
    require_sudo
    detect_os
    backup_configs

    export NEEDRESTART_MODE=a
    export NEEDRESTART_SUSPEND=1

    install_base_packages
    maybe_remove_snapd
    install_liquorix_kernel
    apply_sysctl_profile "$PROFILE"
    apply_limits
    configure_journald_limits
    configure_cpu_and_services
    configure_firewall
    install_fail2ban_optional

    echo
    ok "Оптимизация завершена."
    warn "Если ставился Liquorix или менялись лимиты systemd, сделай reboot."
    echo -e "${YELLOW}Лог:${NC} ${LOG_FILE}"
}

ensure_docker() {
    if command_exists docker && "${SUDO[@]}" docker compose version >/dev/null 2>&1; then
        ok "Docker и Docker Compose plugin уже установлены"
        return 0
    fi

    if ! command_exists docker; then
        if ! confirm "Docker не найден. Установить через официальный get.docker.com script?" "y"; then
            fail "Docker нужен для Remnawave Node"
            return 1
        fi

        local installer
        installer="$(mktemp)"
        cleanup_files+=("$installer")
        download_file "https://get.docker.com" "$installer"
        run "Установка Docker" "${SUDO[@]}" sh "$installer"
    fi

    if ! "${SUDO[@]}" docker compose version >/dev/null 2>&1; then
        apt_update
        apt_install "Установка Docker Compose plugin" docker-compose-plugin
    fi

    run_optional "Включение Docker" "${SUDO[@]}" systemctl enable --now docker

    if ! "${SUDO[@]}" docker compose version >/dev/null 2>&1; then
        fail "Docker Compose plugin не найден после установки"
        return 1
    fi

    ok "Docker Compose готов"
}

remna_env_mode_prompt() {
    local mode

    echo
    echo -e "${BOLD}Формат Remnawave Node:${NC}"
    echo "  1) modern: APP_PORT + SSL_CERT (актуальная схема из документации)"
    echo "  2) legacy: NODE_PORT + SECRET_KEY (старые/сгенерированные compose)"
    mode="$(ask_default "Выбери режим 1/2" "1")"

    case "$mode" in
        1|modern) printf '%s\n' "modern" ;;
        2|legacy) printf '%s\n' "legacy" ;;
        *)
            warn "Неизвестный режим, использую modern"
            printf '%s\n' "modern"
            ;;
    esac
}

write_remnawave_node_files() {
    local mode="$1"
    local node_port="$2"
    local secret_value="$3"
    local image_tag="$4"
    local env_tmp compose_tmp

    run "Создание каталога Remnawave Node" "${SUDO[@]}" mkdir -p "$REMNA_DIR"

    env_tmp="$(mktemp)"
    compose_tmp="$(mktemp)"
    cleanup_files+=("$env_tmp" "$compose_tmp")

    if [[ "$mode" == "modern" ]]; then
        secret_value="${secret_value#SSL_CERT=}"
        cat > "$env_tmp" <<EOF
APP_PORT=${node_port}
SSL_CERT=${secret_value}
EOF
    else
        secret_value="${secret_value#SECRET_KEY=}"
        cat > "$env_tmp" <<EOF
NODE_PORT=${node_port}
SECRET_KEY=${secret_value}
EOF
    fi

    cat > "$compose_tmp" <<EOF
services:
  remnanode:
    container_name: ${REMNA_CONTAINER}
    hostname: ${REMNA_CONTAINER}
    image: remnawave/node:${image_tag}
    restart: always
    network_mode: host
    env_file:
      - .env
    ulimits:
      nofile:
        soft: 1048576
        hard: 1048576
    logging:
      driver: json-file
      options:
        max-size: "50m"
        max-file: "5"
EOF

    if [[ "$DRY_RUN" == "1" ]]; then
        step "DRY-RUN Remnawave .env"
        sed 's/^/  | /' "$env_tmp"
        step "DRY-RUN Remnawave docker-compose.yml"
        sed 's/^/  | /' "$compose_tmp"
        return 0
    fi

    run "Запись Remnawave .env" "${SUDO[@]}" install -m 0600 "$env_tmp" "$REMNA_DIR/.env"
    run "Запись Remnawave docker-compose.yml" "${SUDO[@]}" install -m 0644 "$compose_tmp" "$REMNA_DIR/docker-compose.yml"
}

configure_remna_firewall() {
    local node_port="$1"
    local panel_ip

    if ! command_exists ufw; then
        warn "ufw не найден, firewall правило для Remnawave Node не добавлено"
        return 0
    fi

    if ! "${SUDO[@]}" ufw status >/dev/null 2>&1; then
        warn "ufw недоступен, пропускаю firewall правило"
        return 0
    fi

    panel_ip="$(ask_default "IP/CIDR панели Remnawave для доступа к порту ${node_port}. Оставь пустым, чтобы не открывать" "")"
    if [[ -n "$panel_ip" ]]; then
        if valid_ip_or_cidrish "$panel_ip"; then
            run "UFW allow Remnawave Node ${node_port} from ${panel_ip}" \
                "${SUDO[@]}" ufw allow from "$panel_ip" to any port "$node_port" proto tcp
        else
            warn "IP/CIDR выглядит странно: $panel_ip. Правило не добавлено."
        fi
    elif confirm "Открыть ${node_port}/tcp для всех? Это хуже по безопасности." "n"; then
        run "UFW allow Remnawave Node ${node_port}/tcp globally" "${SUDO[@]}" ufw allow "${node_port}/tcp"
    else
        warn "Порт ${node_port} не открыт. Панель не достучится до ноды, пока не добавишь правило."
    fi
}

install_remnawave_node() {
    print_header
    info "Установка Remnawave Node"
    require_sudo
    detect_os
    backup_configs
    install_base_packages
    ensure_docker

    local mode node_port secret_value image_tag
    mode="$(remna_env_mode_prompt)"
    node_port="$(ask_port "Порт Remnawave Node" "2222")"
    image_tag="$(ask_default "Docker image tag remnawave/node" "latest")"

    if [[ "$mode" == "modern" ]]; then
        secret_value="$(ask_secret "Вставь SSL_CERT из панели Remnawave")"
    else
        secret_value="$(ask_secret "Вставь SECRET_KEY из панели Remnawave")"
    fi

    write_remnawave_node_files "$mode" "$node_port" "$secret_value" "$image_tag"
    configure_remna_firewall "$node_port"

    run "Docker compose pull Remnawave Node" "${SUDO[@]}" docker compose -f "$REMNA_DIR/docker-compose.yml" --env-file "$REMNA_DIR/.env" pull
    run "Docker compose up Remnawave Node" "${SUDO[@]}" docker compose -f "$REMNA_DIR/docker-compose.yml" --env-file "$REMNA_DIR/.env" up -d

    echo
    ok "Remnawave Node запущена"
    echo -e "Логи: ${BOLD}${PURPLE}sudo docker logs -f ${REMNA_CONTAINER}${NC}"
}

install_selfsteal() {
    print_header
    info "Установка SelfSteal"
    require_sudo

    warn "Скрипт будет скачан и выполнен с GitHub. Используй только если доверяешь источнику."
    if ! confirm "Продолжить?" "n"; then
        exit 0
    fi

    local script
    script="$(mktemp)"
    cleanup_files+=("$script")
    download_file "https://github.com/DigneZzZ/remnawave-scripts/raw/main/selfsteal.sh" "$script"
    run "Запуск SelfSteal installer" "${SUDO[@]}" bash "$script" @ install
    ok "SelfSteal установлен"
}

install_warp_native() {
    print_header
    info "Установка WARP Native"
    require_sudo

    warn "Скрипт будет скачан и выполнен с GitHub. Используй только если доверяешь источнику."
    if ! confirm "Продолжить?" "n"; then
        exit 0
    fi

    local script
    script="$(mktemp)"
    cleanup_files+=("$script")
    download_file "https://raw.githubusercontent.com/distillium/warp-native/main/install.sh" "$script"

    if [[ "$DRY_RUN" == "1" ]]; then
        step "DRY-RUN WARP installer"
        return 0
    fi

    step "Запуск WARP installer"
    printf '2\n1\n' | "${SUDO[@]}" bash "$script" >> "$LOG_FILE" 2>&1
    ok "WARP Native установлен"
}

install_speedtest() {
    print_header
    info "Speedtest"
    require_sudo

    local arch tar_url tmpdir archive
    arch="$(uname -m)"
    tmpdir="$(mktemp -d)"
    cleanup_files+=("$tmpdir")
    archive="$tmpdir/speedtest.tgz"

    case "$arch" in
        x86_64|amd64)
            tar_url="https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-x86_64.tgz"
            ;;
        aarch64|arm64)
            tar_url="https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-aarch64.tgz"
            ;;
        *)
            fail "Неизвестная архитектура для Ookla tarball: $arch"
            return 1
            ;;
    esac

    run_optional "Удаление старого speedtest-cli" "${SUDO[@]}" apt-get remove -y speedtest-cli
    download_file "$tar_url" "$archive"
    run "Распаковка speedtest" "${SUDO[@]}" tar xzf "$archive" -C /usr/local/bin speedtest

    echo
    /usr/local/bin/speedtest --accept-license --accept-gdpr
    ok "Speedtest завершен"
}

ipcheck_place() {
    print_header
    info "IP.Check.Place"

    local script
    script="$(mktemp)"
    cleanup_files+=("$script")
    download_file "https://IP.Check.Place" "$script"

    if [[ "$DRY_RUN" == "1" ]]; then
        return 0
    fi

    bash "$script" -l en
    ok "Проверка завершена"
}

ipcheck_region() {
    print_header
    info "IP Region Check"

    local script
    script="$(mktemp)"
    cleanup_files+=("$script")
    download_file "https://github.com/Davoyan/ipregion/raw/main/ipregion.sh" "$script"

    if [[ "$DRY_RUN" == "1" ]]; then
        return 0
    fi

    bash "$script"
    ok "Проверка завершена"
}

public_ipv4() {
    local ip=""
    if command_exists curl; then
        ip="$(curl -fsS --max-time 8 https://api.ipify.org 2>/dev/null || true)"
    fi
    if [[ -z "$ip" && command_exists wget ]]; then
        ip="$(wget -qO- --timeout=8 https://api.ipify.org 2>/dev/null || true)"
    fi
    printf '%s\n' "$ip"
}

domain_ipv4s() {
    local domain="$1"
    if command_exists dig; then
        dig +short A "$domain" 2>/dev/null || true
    else
        getent ahostsv4 "$domain" 2>/dev/null | awk '{print $1}' | sort -u || true
    fi
}

ensure_acme_sh() {
    local email="$1"

    if "${SUDO[@]}" test -x /root/.acme.sh/acme.sh; then
        ok "acme.sh уже установлен"
        return 0
    fi

    local installer
    installer="$(mktemp)"
    cleanup_files+=("$installer")
    download_file "https://get.acme.sh" "$installer"
    run "Установка acme.sh" "${SUDO[@]}" env HOME=/root sh "$installer" "email=$email" --force
}

acme_sh() {
    "${SUDO[@]}" env HOME=/root /root/.acme.sh/acme.sh "$@"
}

issue_ssl_certificate() {
    print_header
    info "Генерация SSL-сертификата Let's Encrypt через acme.sh"
    require_sudo
    detect_os
    install_base_packages

    local domain email cert_dir public_ip domain_ips had_ufw_80=0 stop_remna=0 acme_rc=0
    domain="$(ask_domain)"
    email="$(ask_default "Email для acme.sh/Let's Encrypt" "admin@${domain}")"
    cert_dir="$(ask_default "Куда сохранить privkey.key и fullchain.pem" "/opt/remnawave/nginx")"

    public_ip="$(public_ipv4)"
    domain_ips="$(domain_ipv4s "$domain" | xargs 2>/dev/null || true)"

    if [[ -n "$public_ip" && -n "$domain_ips" && "$domain_ips" != *"$public_ip"* ]]; then
        warn "Домен ${domain} сейчас указывает на: ${domain_ips}"
        warn "Публичный IPv4 сервера похож на: ${public_ip}"
        if ! confirm "Продолжить выпуск сертификата?" "n"; then
            exit 1
        fi
    fi

    ensure_acme_sh "$email"
    run "Создание каталога сертификатов" "${SUDO[@]}" mkdir -p "$cert_dir"

    if command_exists ufw && "${SUDO[@]}" ufw status 2>/dev/null | grep -q "Status: active"; then
        if ufw_rule_exists '^80/tcp[[:space:]]+ALLOW|^80[[:space:]]+ALLOW'; then
            had_ufw_80=1
        else
            run "Временное открытие 80/tcp для ACME" "${SUDO[@]}" ufw allow 80/tcp
        fi
    fi

    if "${SUDO[@]}" docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$REMNA_CONTAINER"; then
        if confirm "Остановить ${REMNA_CONTAINER} на время выпуска сертификата?" "n"; then
            stop_remna=1
            run "Остановка ${REMNA_CONTAINER}" "${SUDO[@]}" docker stop "$REMNA_CONTAINER"
        fi
    fi

    run "acme.sh set default CA letsencrypt" \
        "${SUDO[@]}" env HOME=/root /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt

    set +e
    run "Выпуск сертификата для ${domain}" \
        "${SUDO[@]}" env HOME=/root /root/.acme.sh/acme.sh \
        --issue --standalone -d "$domain" \
        --key-file "${cert_dir}/privkey.key" \
        --fullchain-file "${cert_dir}/fullchain.pem" \
        --force
    acme_rc=$?
    set -e

    if [[ "$stop_remna" == "1" ]]; then
        run_optional "Запуск ${REMNA_CONTAINER}" "${SUDO[@]}" docker start "$REMNA_CONTAINER"
    fi

    if [[ "$had_ufw_80" == "0" ]] && command_exists ufw && "${SUDO[@]}" ufw status 2>/dev/null | grep -q "Status: active"; then
        run_optional "Закрытие временного 80/tcp" "${SUDO[@]}" ufw delete allow 80/tcp
    fi

    if [[ "$acme_rc" -ne 0 ]]; then
        fail "Сертификат не выпущен. Проверь DNS домена, занятость 80/tcp и лог: ${LOG_FILE}"
        return "$acme_rc"
    fi

    ok "Сертификат выпущен"
    echo -e "Ключ:      ${BOLD}${cert_dir}/privkey.key${NC}"
    echo -e "Fullchain: ${BOLD}${cert_dir}/fullchain.pem${NC}"
}

print_stat() {
    local name="$1"
    local value="$2"
    local expected="$3"

    printf ' %-24s ' "$name"
    if [[ "$value" == *"$expected"* ]]; then
        echo -e "${GREEN}[ OK ]${NC}"
    else
        echo -e "${RED}[ FAIL ]${NC} (${value:-empty})"
    fi
}

service_stat_line() {
    local svc="$1"
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        echo -ne "${BOLD}${svc}:${NC} ${GREEN}OK${NC}    "
    else
        echo -ne "${BOLD}${svc}:${NC} ${RED}FAIL${NC}  "
    fi
}

show_status() {
    print_header

    local kernel_ver net_cc net_qdisc tfo keepalive filemax docker_status remna_status ports cert_file cert_expiry

    echo -e "${BOLD}${PURPLE}[ СИСТЕМА ]${NC}"
    echo " OS:       $(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}" || echo unknown)"
    echo " Kernel:   $(uname -r)"
    echo " Uptime:   $(uptime -p 2>/dev/null || true)"
    echo " Load:     $(uptime 2>/dev/null | awk -F'load average:' '{print $2}' | sed 's/^ //')"
    echo

    kernel_ver="$(uname -r)"
    print_stat "Ядро Liquorix" "$kernel_ver" "liquorix"

    net_cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)"
    net_qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || true)"
    print_stat "BBR + FQ" "${net_cc}+${net_qdisc}" "bbr+fq"

    tfo="$(sysctl -n net.ipv4.tcp_fastopen 2>/dev/null || true)"
    print_stat "TCP Fast Open" "$tfo" "3"

    keepalive="$(sysctl -n net.ipv4.tcp_keepalive_time 2>/dev/null || true)"
    print_stat "Keepalive 600s" "$keepalive" "600"

    filemax="$(sysctl -n fs.file-max 2>/dev/null || true)"
    print_stat "fs.file-max" "$filemax" "2097152"

    echo
    echo -e "${BOLD}${PURPLE}[ СЛУЖБЫ ]${NC}"
    service_stat_line chrony
    service_stat_line ufw
    service_stat_line irqbalance
    service_stat_line fail2ban
    service_stat_line docker
    echo

    echo
    echo -e "${BOLD}${PURPLE}[ DOCKER / REMNAWAVE ]${NC}"
    if command_exists docker; then
        docker_status="$("${SUDO[@]}" docker version --format '{{.Server.Version}}' 2>/dev/null || echo "not available")"
        echo " Docker:   $docker_status"
        remna_status="$("${SUDO[@]}" docker ps -a --filter "name=^/${REMNA_CONTAINER}$" --format '{{.Status}}' 2>/dev/null || true)"
        echo " Node:     ${remna_status:-not found}"
    else
        echo " Docker:   not installed"
        echo " Node:     not found"
    fi

    echo
    echo -e "${BOLD}${PURPLE}[ ПОРТЫ ]${NC}"
    if command_exists ufw; then
        ports="$("${SUDO[@]}" ufw status 2>/dev/null | awk '/ALLOW/ {print $1}' | sed 's/(v6)//g' | sort -u | xargs 2>/dev/null || true)"
        echo " UFW:      ${ports:-нет правил или ufw выключен}"
    fi
    if command_exists ss; then
        ss -lnt 2>/dev/null | awk 'NR==1 || /:(22|80|443|1488|2222)[[:space:]]/' || true
    fi

    echo
    echo -e "${BOLD}${PURPLE}[ SSL ]${NC}"
    cert_file="/opt/remnawave/nginx/fullchain.pem"
    if [[ -f "$cert_file" ]]; then
        cert_expiry="$(openssl x509 -enddate -noout -in "$cert_file" 2>/dev/null | sed 's/notAfter=//' || true)"
        echo " ${cert_file}: ${cert_expiry:-unknown}"
    else
        echo " ${cert_file}: not found"
    fi

    echo
    echo -e "${YELLOW}Лог:${NC} ${LOG_FILE}"
}

latest_backup_dir() {
    "${SUDO[@]}" find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | tail -n 1
}

rollback_latest_backup() {
    print_header
    info "Откат последнего бэкапа"
    require_sudo

    local backup_dir
    backup_dir="$(latest_backup_dir || true)"
    if [[ -z "$backup_dir" ]]; then
        fail "Бэкапы не найдены в $BACKUP_ROOT"
        exit 1
    fi

    echo "Последний бэкап: $backup_dir"
    if ! confirm "Восстановить конфиги из этого бэкапа?" "n"; then
        exit 0
    fi

    if [[ "$DRY_RUN" == "1" ]]; then
        step "DRY-RUN rollback $backup_dir"
        return 0
    fi

    restore_one() {
        local backup_name="$1"
        local target_path="$2"
        local mode="${3:-0644}"

        if "${SUDO[@]}" test -f "$backup_dir/$backup_name"; then
            run "Восстановление $target_path" "${SUDO[@]}" install -m "$mode" "$backup_dir/$backup_name" "$target_path"
        fi
    }

    restore_one "sysctl.conf" "$SYSCTL_FILE" 0644
    restore_one "limits.conf" "$LIMITS_FILE" 0644
    restore_one "systemd-system.conf" "$SYSTEMD_SYSTEM_DROPIN" 0644
    restore_one "systemd-user.conf" "$SYSTEMD_USER_DROPIN" 0644
    restore_one "journald.conf" "$JOURNALD_DROPIN" 0644
    restore_one "logrotate-remnanode" "/etc/logrotate.d/remnanode" 0644
    restore_one "remnanode-docker-compose.yml" "$REMNA_DIR/docker-compose.yml" 0644
    restore_one "remnanode.env" "$REMNA_DIR/.env" 0600

    run_optional "Применение sysctl после rollback" "${SUDO[@]}" sysctl --system
    run_optional "systemd daemon-reload после rollback" "${SUDO[@]}" systemctl daemon-reload

    ok "Откат завершен"
}

show_menu() {
    print_header
    echo -e "1) Полная оптимизация"
    echo -e "2) Установка Remnawave Node"
    echo -e "3) Установка SelfSteal"
    echo -e "4) Установка WARP Native"
    echo -e "5) Панель состояния"
    echo -e "6) Speedtest"
    echo -e "7) Проверка IP (IP.Check.Place)"
    echo -e "8) Проверка IP (Region Check)"
    echo -e "9) Сгенерировать SSL-сертификат"
    echo -e "10) Откат последнего бэкапа"
    echo -e "0) Выход"
    echo -e "${PURPLE}==========================================${NC}"

    local choice
    read -r -p "$(echo -e "${PURPLE}>${NC} ${BOLD}Выберите действие:${NC} ")" choice

    case "$choice" in
        1)
            echo
            echo "Профили: balanced, throughput, low-memory"
            PROFILE="$(ask_default "Профиль оптимизации" "$PROFILE")"
            case "$PROFILE" in
                balanced|throughput|low-memory) ;;
                *)
                    warn "Неизвестный профиль '${PROFILE}', использую balanced"
                    PROFILE="balanced"
                    ;;
            esac
            optimize_system
            ;;
        2) install_remnawave_node ;;
        3) install_selfsteal ;;
        4) install_warp_native ;;
        5) show_status ;;
        6) install_speedtest ;;
        7) ipcheck_place ;;
        8) ipcheck_region ;;
        9) issue_ssl_certificate ;;
        10) rollback_latest_backup ;;
        0)
            echo -e "${PURPLE}Выход.${NC}"
            exit 0
            ;;
        *)
            fail "Неверный выбор"
            exit 2
            ;;
    esac
}

main() {
    parse_args "$@"
    init_logging

    case "$ACTION" in
        optimize) optimize_system ;;
        install-node) install_remnawave_node ;;
        status) show_status ;;
        ssl) issue_ssl_certificate ;;
        speedtest) install_speedtest ;;
        ipcheck-place) ipcheck_place ;;
        ipcheck-region) ipcheck_region ;;
        selfsteal) install_selfsteal ;;
        warp) install_warp_native ;;
        rollback) rollback_latest_backup ;;
        "") show_menu ;;
        *)
            fail "Неизвестное действие: $ACTION"
            exit 2
            ;;
    esac
}

main "$@"
