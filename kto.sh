#!/usr/bin/env bash
# shellcheck shell=bash

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_VERSION="1.4.8.8"
SCRIPT_BUILD="v140"
NODE_PORT="${KTO_NODE_PORT:-1488}"
REMNA_DIR="/opt/remnawave"
REMNA_CONTAINER="remnanode"
CERT_DIR="/opt/remnawave"
CONFIG_FILE="/etc/kto-cfg.conf"
LEGACY_CONFIG_FILE="/etc/kto-vpn.conf"
CONFIG_SOURCE_FILE=""
MACHINE_MODE="${KTO_MACHINE_MODE:-}"
NODE_PROFILE="${KTO_NODE_PROFILE:-}"
REMNA_API_URL="${KTO_REMNA_API_URL:-https://admin.ktoygaday.xyz}"
REMNA_API_TOKEN="${KTO_REMNA_API_TOKEN:-}"
if [[ -n "${KTO_LOG_FILE:-}" ]]; then
    LOG_FILE="$KTO_LOG_FILE"
elif [[ ${EUID:-$(id -u)} -eq 0 ]]; then
    LOG_FILE="/var/log/kto-vpn-tune.log"
else
    LOG_FILE="/tmp/kto-vpn-tune.log"
fi
ANTISCANNER_SCRIPT="/usr/local/bin/update-antiscanner.sh"
ANTISCANNER_URL="https://gist.githubusercontent.com/sngvy/07cee7ac810c9d222fbebddff8c1d1b8/raw/blacklist.txt"
ZRAM_SETUP_SCRIPT="/usr/local/sbin/kto-zram-setup"
ZRAM_SERVICE="kto-zram.service"
ZRAM_PERCENT="${KTO_ZRAM_PERCENT:-50}"
ZRAM_MAX_MB="${KTO_ZRAM_MAX_MB:-2048}"
STORAGE_GUARD_JOURNAL_CONF="/etc/systemd/journald.conf.d/99-kto-storage.conf"
KTO_LOGROTATE_CONF="/etc/logrotate.d/kto-vpn"
DOCKER_DAEMON_JSON="/etc/docker/daemon.json"
MEMORY_GUARD_SYSCTL_CONF="/etc/sysctl.d/zz-kto-memory.conf"
DNS_GUARD_RESOLVED_CONF="/etc/systemd/resolved.conf.d/99-kto-dns.conf"
IPV6_WHITELIST_SYSCTL_CONF="/etc/sysctl.d/98-kto-whitelist-ipv6.conf"
STATS_COLLECTOR_CONFIG="/etc/kto-stats-collector.conf"
STATS_COLLECTOR_SCRIPT="/usr/local/bin/kto-stats-collector"
STATS_COLLECTOR_SERVICE="kto-stats-collector.service"
STATS_COLLECTOR_STATE_DIR="/var/lib/kto-stats-collector"
STATS_PUSH_CONFIG="/etc/kto-stats-push.conf"
STATS_PUSH_SCRIPT="/usr/local/bin/kto-stats-push"
STATS_PUSH_SERVICE="kto-stats-push.service"
STATS_PUSH_TIMER="kto-stats-push.timer"
STATS_COLLECTOR_PORT_DEFAULT="9788"
STATS_PUSH_INTERVAL_DEFAULT="15"
STATS_COLLECTOR_STALE_SEC_DEFAULT="60"
STATS_COLLECTOR_TZ_DEFAULT="Europe/Moscow"
STATS_ALLOWED_USER_ID_DEFAULT="646296998"
STATS_EXPECTED_NODES_DEFAULT="10"
SPEEDTEST_TIMEOUT="${KTO_SPEEDTEST_TIMEOUT:-240}"
SPEEDTEST_DOWNLOAD_TIMEOUT="${KTO_SPEEDTEST_DOWNLOAD_TIMEOUT:-180}"
APT_UPDATED=0

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
PURPLE='\033[38;5;93m'
RED='\033[0;31m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

SUDO=()
if command -v sudo >/dev/null 2>&1; then
    SUDO=(sudo -n)
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

    if [[ "$LOG_FILE" == /tmp/* ]]; then
        mkdir -p "$log_dir" >/dev/null 2>&1 || true
        touch "$LOG_FILE" >/dev/null 2>&1 || LOG_FILE="/tmp/kto-vpn-tune.log"
    else
        "${SUDO[@]}" mkdir -p "$log_dir" >/dev/null 2>&1 || true
        "${SUDO[@]}" touch "$LOG_FILE" >/dev/null 2>&1 || LOG_FILE="/tmp/kto-vpn-tune.log"
        if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
            "${SUDO[@]}" chmod 0666 "$LOG_FILE" >/dev/null 2>&1 || true
        fi
    fi

    echo "===== kto VPN v${SCRIPT_VERSION} ${SCRIPT_BUILD} $(date -Is) =====" >> "$LOG_FILE" 2>/dev/null || true
}

header_line() {
    local text="$1"
    local style="${2:-}"
    local width=42
    local indent=$(( (width - ${#text}) / 2 ))
    (( indent < 0 )) && indent=0
    printf '%b%*s%s%b\n' "$style" "$indent" "" "$text" "$NC"
}

header() {
    printf '\033c'
    echo -e "${PURPLE}==========================================${NC}"
    header_line "kto  VPN" "${BOLD}${GREEN}"
    header_line "v${SCRIPT_VERSION}" "$DIM"
    header_line "$SCRIPT_BUILD" "$DIM"
    echo -e "${PURPLE}==========================================${NC}"
}

stage() { echo -e "${PURPLE}[..]${NC} $*"; }
ok() { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*" >&2; }
fail() { echo -e "${RED}[ОШИБКА]${NC} $*" >&2; }

format_duration() {
    local total="$1"
    local hours minutes seconds
    hours=$(( total / 3600 ))
    minutes=$(( (total % 3600) / 60 ))
    seconds=$(( total % 60 ))

    if (( hours > 0 )); then
        printf '%dh %dm %ds' "$hours" "$minutes" "$seconds"
    elif (( minutes > 0 )); then
        printf '%dm %ds' "$minutes" "$seconds"
    else
        printf '%ds' "$seconds"
    fi
}

need_root() {
    if [[ ${#SUDO[@]} -eq 0 && ${EUID:-$(id -u)} -ne 0 ]]; then
        fail "Запусти от root или установи sudo."
        exit 1
    fi
    if [[ ${EUID:-$(id -u)} -ne 0 ]] && ! "${SUDO[@]}" true >/dev/null 2>&1; then
        fail "sudo требует пароль. Запусти от root или включи NOPASSWD для пользователя."
        exit 1
    fi
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

run_live_capture_timeout() {
    local timeout_sec="$1"
    local output_file="$2"
    shift 2

    : > "$output_file"
    if command_exists timeout; then
        timeout --foreground "${timeout_sec}s" "$@" 2>&1 | tee -a "$LOG_FILE" "$output_file"
        return "${PIPESTATUS[0]}"
    fi

    "$@" 2>&1 | tee -a "$LOG_FILE" "$output_file"
    return "${PIPESTATUS[0]}"
}

PROGRESS_TOTAL=1
PROGRESS_CURRENT=0
PROGRESS_WIDTH=26
PROGRESS_CLEAR=""
PROGRESS_GREEN=""
PROGRESS_PURPLE=""
PROGRESS_RED=""
PROGRESS_DIM=""
PROGRESS_NC=""

init_progress_style() {
    [[ -t 1 ]] || return 0
    command -v tput >/dev/null 2>&1 || return 0
    [[ "${TERM:-}" != "dumb" ]] || return 0

    PROGRESS_CLEAR="$(tput el 2>/dev/null || true)"
    PROGRESS_GREEN="$(tput setaf 2 2>/dev/null || true)"
    PROGRESS_PURPLE="$(tput setaf 5 2>/dev/null || true)"
    PROGRESS_RED="$(tput setaf 1 2>/dev/null || true)"
    PROGRESS_DIM="$(tput dim 2>/dev/null || true)"
    PROGRESS_NC="$(tput sgr0 2>/dev/null || true)"
}

progress_bar() {
    local percent="$1"
    local filled empty bar gap
    filled=$(( percent * PROGRESS_WIDTH / 100 ))
    empty=$(( PROGRESS_WIDTH - filled ))
    printf -v bar '%*s' "$filled" ''
    printf -v gap '%*s' "$empty" ''
    bar="${bar// /#}"
    gap="${gap// /-}"
    printf '%s%s' "$bar" "$gap"
}

progress_line() {
    local percent="$1"
    local title="$2"
    local frame="$3"
    local frame_color="$PROGRESS_PURPLE"
    local bar_color="$PROGRESS_GREEN"

    if [[ "$frame" == "OK" ]]; then
        frame_color="$PROGRESS_GREEN"
    elif [[ "$frame" == "!" ]]; then
        frame_color="$PROGRESS_RED"
    fi

    printf '\r%s%s%s%s %3d%% [%s%s%s] %s%s%s' \
        "$PROGRESS_CLEAR" \
        "$frame_color" "$frame" "$PROGRESS_NC" \
        "$percent" \
        "$bar_color" "$(progress_bar "$percent")" "$PROGRESS_NC" \
        "$PROGRESS_DIM" "$title" "$PROGRESS_NC"
}

progress_start() {
    PROGRESS_TOTAL="$1"
    PROGRESS_CURRENT=0
    init_progress_style
    echo
}

progress_step() {
    local title="$1"
    shift

    local from to shown pid rc frame_idx frame
    local frames=('|' '/' '-' '\')
    from=$(( PROGRESS_CURRENT * 100 / PROGRESS_TOTAL ))
    to=$(( (PROGRESS_CURRENT + 1) * 100 / PROGRESS_TOTAL ))
    shown="$from"
    frame_idx=0

    if [[ ! -t 1 ]]; then
        printf '[..] %3d%% [%s] %s\n' "$to" "$(progress_bar "$to")" "$title"
        if "$@" >> "$LOG_FILE" 2>&1; then
            PROGRESS_CURRENT=$(( PROGRESS_CURRENT + 1 ))
            printf '[OK] %s\n' "$title"
            return 0
        fi
        fail "$title"
        tail -n 25 "$LOG_FILE" >&2 || true
        return 1
    fi

    ("$@") >> "$LOG_FILE" 2>&1 &
    pid=$!

    while jobs -pr | grep -qx "$pid"; do
        frame="${frames[$frame_idx]}"
        progress_line "$shown" "$title" "$frame"
        sleep 0.12
        frame_idx=$(( (frame_idx + 1) % 4 ))
        if (( shown < to - 1 )); then
            shown=$(( shown + 1 ))
        fi
    done

    if wait "$pid"; then
        rc=0
    else
        rc=$?
    fi

    if (( rc != 0 )); then
        progress_line "$shown" "$title" '!'
        echo
        fail "$title"
        tail -n 25 "$LOG_FILE" >&2 || true
        return "$rc"
    fi

    PROGRESS_CURRENT=$(( PROGRESS_CURRENT + 1 ))
    progress_line "$to" "$title" 'OK'
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

write_root_file_mode() {
    local mode="$1"
    local path="$2"
    local tmp
    tmp="$(mktemp)"
    cat > "$tmp"
    "${SUDO[@]}" install -m "$mode" "$tmp" "$path" >> "$LOG_FILE" 2>&1
    rm -f "$tmp"
}

write_root_file() {
    local path="$1"
    write_root_file_mode 0644 "$path"
}

valid_machine_mode() {
    [[ "$1" == "node" || "$1" == "whitelist" || "$1" == "panel" ]]
}

valid_node_profile() {
    [[ "$1" == "reality" || "$1" == "hysteria2" ]]
}

node_profile_label() {
    case "${NODE_PROFILE:-}" in
        reality) echo "Reality" ;;
        hysteria2) echo "Hysteria2" ;;
        *) echo "-" ;;
    esac
}

config_label() {
    if [[ "$MACHINE_MODE" == "node" ]]; then
        echo "node / $(node_profile_label)"
    else
        echo "$MACHINE_MODE"
    fi
}

config_get() {
    local key="$1"
    local file="${2:-$CONFIG_FILE}"
    "${SUDO[@]}" awk -v key="$key" -F= '
        $1 == key {
            value = $0
            sub(/^[^=]*=/, "", value)
            gsub(/^"/, "", value)
            gsub(/"$/, "", value)
            gsub(/\\"/, "\"", value)
            gsub(/\\\\/, "\\", value)
            print value
            exit
        }
    ' "$file" 2>/dev/null || true
}

escape_config_value() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    echo "$value"
}

load_machine_mode() {
    local saved_mode="" saved_profile="" saved_api_url="" saved_api_token="" source_file="$CONFIG_FILE"
    CONFIG_SOURCE_FILE=""

    if [[ -n "$MACHINE_MODE" ]]; then
        if ! valid_machine_mode "$MACHINE_MODE"; then
            warn "KTO_MACHINE_MODE должен быть node, whitelist или panel. Игнорирую."
            MACHINE_MODE=""
        fi
    fi

    if [[ -n "$NODE_PROFILE" ]]; then
        if ! valid_node_profile "$NODE_PROFILE"; then
            warn "KTO_NODE_PROFILE должен быть reality или hysteria2. Игнорирую."
            NODE_PROFILE=""
        fi
    fi

    if ! "${SUDO[@]}" test -f "$source_file" 2>/dev/null && "${SUDO[@]}" test -f "$LEGACY_CONFIG_FILE" 2>/dev/null; then
        source_file="$LEGACY_CONFIG_FILE"
    fi
    CONFIG_SOURCE_FILE="$source_file"

    saved_mode="$("${SUDO[@]}" awk -F= '$1=="MACHINE_MODE"{gsub(/"/,"",$2); print $2; exit}' "$source_file" 2>/dev/null || true)"
    if [[ -z "$MACHINE_MODE" ]] && valid_machine_mode "$saved_mode"; then
        MACHINE_MODE="$saved_mode"
    fi

    saved_profile="$("${SUDO[@]}" awk -F= '$1=="NODE_PROFILE"{gsub(/"/,"",$2); print $2; exit}' "$source_file" 2>/dev/null || true)"
    if [[ -z "$NODE_PROFILE" ]] && valid_node_profile "$saved_profile"; then
        NODE_PROFILE="$saved_profile"
    fi

    saved_api_url="$(config_get REMNA_API_URL "$source_file")"
    if [[ -z "${KTO_REMNA_API_URL:-}" && -n "$saved_api_url" ]]; then
        REMNA_API_URL="$saved_api_url"
    fi

    saved_api_token="$(config_get REMNA_API_TOKEN "$source_file")"
    if [[ -z "${KTO_REMNA_API_TOKEN:-}" && -n "$saved_api_token" ]]; then
        REMNA_API_TOKEN="$saved_api_token"
    fi

    if [[ "$MACHINE_MODE" != "node" ]]; then
        NODE_PROFILE=""
    fi
}

save_machine_mode() {
    local safe_mode safe_profile safe_url safe_token
    safe_mode="$(escape_config_value "$MACHINE_MODE")"
    safe_profile="$(escape_config_value "$NODE_PROFILE")"
    safe_url="$(escape_config_value "$REMNA_API_URL")"
    safe_token="$(escape_config_value "$REMNA_API_TOKEN")"

    write_root_file_mode 0600 "$CONFIG_FILE" <<EOF
MACHINE_MODE="$safe_mode"
NODE_PROFILE="$safe_profile"
REMNA_API_URL="$safe_url"
REMNA_API_TOKEN="$safe_token"
EOF
}

compose_down_dir() {
    local dir="$1"
    if command_exists docker && "${SUDO[@]}" test -f "$dir/docker-compose.yml" 2>/dev/null; then
        (cd "$dir" && "${SUDO[@]}" docker compose down -v --remove-orphans) >> "$LOG_FILE" 2>&1 || true
    fi
}

clear_runtime_dir() {
    local dir="$1"
    case "$dir" in
        "$REMNA_DIR"|/opt/caddy|/opt/nginx-selfsteal)
            cmd "${SUDO[@]}" mkdir -p -- "$dir" || true
            cmd "${SUDO[@]}" find "$dir" -mindepth 1 -exec rm -rf -- {} + || true
            ;;
        *)
            warn "Пропускаю небезопасный путь очистки: $dir"
            ;;
    esac
}

cleanup_runtime_state() {
    need_root
    stage "Очищаю старую установку"

    compose_down_dir "$REMNA_DIR"
    compose_down_dir /opt/caddy
    compose_down_dir /opt/nginx-selfsteal

    if command_exists docker; then
        for container in "$REMNA_CONTAINER" caddy-selfsteal nginx-selfsteal; do
            cmd "${SUDO[@]}" docker rm -f "$container" || true
        done
    fi

    clear_runtime_dir "$REMNA_DIR"
    clear_runtime_dir /opt/caddy
    clear_runtime_dir /opt/nginx-selfsteal

    cmd "${SUDO[@]}" find /opt -maxdepth 1 -type d -name 'selfsteal-backup-*' -exec rm -rf -- {} + || true
    cmd "${SUDO[@]}" rm -f /dev/shm/nginx.sock "$LEGACY_CONFIG_FILE" || true
    cmd "${SUDO[@]}" systemctl disable --now haproxy || true

    if command_exists ufw; then
        cmd "${SUDO[@]}" ufw allow 443/tcp || true
        if [[ "$MACHINE_MODE" == "node" ]]; then
            cmd "${SUDO[@]}" ufw allow 443/udp || true
            cmd "${SUDO[@]}" ufw allow "${NODE_PORT}/tcp" || true
        else
            cmd "${SUDO[@]}" ufw --force delete allow 443/udp || true
            cmd "${SUDO[@]}" ufw --force delete allow "${NODE_PORT}/tcp" || true
        fi
        cmd "${SUDO[@]}" ufw --force delete allow 80/tcp || true
    fi
}

select_node_profile() {
    local choice

    while true; do
        header
        echo -e "${BOLD}${PURPLE}[ ПРОФИЛЬ НОДЫ ]${NC}"
        echo -e "1) Reality"
        echo -e "2) Hysteria2"
        echo -e "${PURPLE}==========================================${NC}"
        echo -ne "${PURPLE}>${NC} ${BOLD}Выберите профиль (1-2):${NC} "
        read -r choice
        case "$choice" in
            1|reality|Reality)
                NODE_PROFILE="reality"
                break
                ;;
            2|hysteria2|Hysteria2|hysteria|Hysteria)
                NODE_PROFILE="hysteria2"
                break
                ;;
            *)
                fail "Неверный выбор"
                sleep 1
                ;;
        esac
    done
}

select_machine_mode() {
    local choice

    while true; do
        header
        echo -e "${BOLD}${PURPLE}[ РЕЖИМ МАШИНЫ ]${NC}"
        echo -e "1) node"
        echo -e "2) whitelist"
        echo -e "3) panel"
        echo -e "${PURPLE}==========================================${NC}"
        echo -ne "${PURPLE}>${NC} ${BOLD}Выберите режим (1-3):${NC} "
        read -r choice
        case "$choice" in
            1|node)
                MACHINE_MODE="node"
                break
                ;;
            2|whitelist)
                MACHINE_MODE="whitelist"
                NODE_PROFILE=""
                break
                ;;
            3|panel)
                MACHINE_MODE="panel"
                NODE_PROFILE=""
                break
                ;;
            *)
                fail "Неверный выбор"
                sleep 1
                ;;
        esac
    done

    if [[ "$MACHINE_MODE" == "node" ]]; then
        select_node_profile
    fi

    need_root
    save_machine_mode
}

reconfigure_machine_mode() {
    local old_mode="$MACHINE_MODE"
    local old_profile="$NODE_PROFILE"

    select_machine_mode

    if [[ "$old_mode" != "$MACHINE_MODE" || "$old_profile" != "$NODE_PROFILE" ]]; then
        header
        stage "Применяю новый конфиг"
        if [[ "$MACHINE_MODE" == "panel" || "$old_mode" == "panel" ]]; then
            warn "Автоочистка рантайма пропущена для режима panel."
        else
            cleanup_runtime_state
        fi
        save_machine_mode
        echo
        ok "Конфиг обновлён: $(config_label)"
        if [[ "$MACHINE_MODE" != "panel" && "$old_mode" != "panel" ]]; then
            ok "Старая нода/SelfSteal очищены"
        fi
    else
        echo
        ok "Настройки не изменились"
    fi
}

settings_menu() {
    local choice

    while true; do
        header
        echo -e "${BOLD}${PURPLE}[ НАСТРОЙКИ ]${NC}"
        echo -e "1) Изменение режима"
        echo -e "2) Проверка системы"
        echo -e "3) Очистка диска"
        if [[ "$MACHINE_MODE" == "whitelist" ]]; then
            echo -e "4) Обновить HAProxy IP/SNI"
        fi
        echo -e "0) Выйти"
        echo -e "${PURPLE}==========================================${NC}"
        echo -ne "${PURPLE}>${NC} ${BOLD}Выберите действие:${NC} "
        read -r choice

        case "$choice" in
            1)
                reconfigure_machine_mode
                ;;
            2)
                system_check
                ;;
            3)
                clean_disk_now
                system_check_pause
                ;;
            4)
                if [[ "$MACHINE_MODE" == "whitelist" ]]; then
                    configure_haproxy_backend
                else
                    fail "Этот пункт доступен только для режима whitelist."
                    sleep 1
                fi
                ;;
            0)
                return 0
                ;;
            *)
                fail "Неверный выбор"
                sleep 1
                ;;
        esac
    done
}

ensure_machine_mode() {
    load_machine_mode
    if ! valid_machine_mode "$MACHINE_MODE"; then
        select_machine_mode
    elif [[ "$MACHINE_MODE" == "node" ]] && ! valid_node_profile "$NODE_PROFILE"; then
        select_node_profile
        need_root
        save_machine_mode
    elif [[ "$CONFIG_SOURCE_FILE" == "$LEGACY_CONFIG_FILE" ]]; then
        need_root
        save_machine_mode
    fi
}

require_node_mode() {
    if [[ "$MACHINE_MODE" != "node" ]]; then
        fail "Этот пункт доступен только для режима node."
        exit 1
    fi
}

require_hysteria2_profile() {
    require_node_mode
    if [[ "$NODE_PROFILE" != "hysteria2" ]]; then
        fail "SSL доступен только для профиля Hysteria2."
        exit 1
    fi
}

require_reality_profile() {
    require_node_mode
    if [[ "$NODE_PROFILE" != "reality" ]]; then
        fail "SelfSteal доступен только для профиля Reality."
        exit 1
    fi
}

require_whitelist_mode() {
    if [[ "$MACHINE_MODE" != "whitelist" ]]; then
        fail "Этот пункт доступен только для режима whitelist."
        exit 1
    fi
}

require_panel_mode() {
    if [[ "$MACHINE_MODE" != "panel" ]]; then
        fail "Этот пункт доступен только для режима panel."
        exit 1
    fi
}

apt_update_quiet() {
    if [[ "$APT_UPDATED" == "1" ]]; then
        echo "apt update skipped: cache already refreshed" >> "$LOG_FILE"
        return 0
    fi
    apt_update_force
}

apt_update_force() {
    wait_for_apt_locks || true
    "${SUDO[@]}" apt-get -o DPkg::Lock::Timeout=600 update >> "$LOG_FILE" 2>&1
    APT_UPDATED=1
}

package_installed() {
    local pkg="$1"
    dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"
}

wait_for_apt_locks() {
    local waited=0
    local lock_info
    local locks=(
        /var/lib/apt/lists/lock
        /var/cache/apt/archives/lock
        /var/lib/dpkg/lock
        /var/lib/dpkg/lock-frontend
    )

    command_exists fuser || return 0
    while "${SUDO[@]}" fuser "${locks[@]}" >/dev/null 2>&1; do
        if (( waited == 0 )); then
            warn "apt занят другим процессом, жду освобождения lock."
        elif (( waited % 30 == 0 )); then
            lock_info="$("${SUDO[@]}" fuser "${locks[@]}" 2>/dev/null | tr '\n' ' ' | tr -s ' ' || true)"
            warn "apt всё ещё занят (${waited}s). ${lock_info}"
        fi
        if (( waited >= 600 )); then
            echo "apt lock wait timeout" >> "$LOG_FILE"
            return 1
        fi
        sleep 2
        waited=$(( waited + 2 ))
    done
}

apt_install_quiet() {
    local missing=() pkg
    for pkg in "$@"; do
        if ! package_installed "$pkg"; then
            missing+=("$pkg")
        fi
    done

    if [[ ${#missing[@]} -eq 0 ]]; then
        echo "apt install skipped: already installed: $*" >> "$LOG_FILE"
        return 0
    fi

    wait_for_apt_locks || true
    "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive \
        apt-get -o DPkg::Lock::Timeout=600 install -y \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" \
        "${missing[@]}" >> "$LOG_FILE" 2>&1
}

apt_install_with_update_if_missing() {
    local missing=() pkg
    for pkg in "$@"; do
        if ! package_installed "$pkg"; then
            missing+=("$pkg")
        fi
    done

    if [[ ${#missing[@]} -eq 0 ]]; then
        echo "apt install skipped: already installed: $*" >> "$LOG_FILE"
        return 0
    fi

    if ! apt_update_quiet; then
        warn "apt update не прошёл, пробую ставить пакеты по текущему кешу apt."
    fi
    apt_install_quiet "${missing[@]}"
}

liquorix_installed() {
    package_installed linux-image-liquorix-amd64 && package_installed linux-headers-liquorix-amd64
}

liquorix_source_configured() {
    grep -RqsE 'damentz.*liquorix|liquorix' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null
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
        printf '%s: ' "$prompt" >&2
        read -r domain
        if validate_domain "$domain"; then
            echo "$domain"
            return 0
        fi
        fail "Некорректный домен. Пример: vpn.domain.com"
    done
}

ask_text() {
    local prompt="$1"
    local default="${2:-}"
    local value
    while true; do
        if [[ -n "$default" ]]; then
            printf '%s [%s]: ' "$prompt" "$default" >&2
        else
            printf '%s: ' "$prompt" >&2
        fi
        read -r value
        value="${value:-$default}"
        if [[ -n "$value" ]]; then
            echo "$value"
            return 0
        fi
        fail "Значение не может быть пустым"
    done
}

ask_optional_text() {
    local prompt="$1"
    local default="${2:-}"
    local value
    if [[ -n "$default" ]]; then
        printf '%s [%s]: ' "$prompt" "$default" >&2
    else
        printf '%s: ' "$prompt" >&2
    fi
    read -r value
    echo "${value:-$default}"
}

ask_int() {
    local prompt="$1"
    local default="$2"
    local min="${3:-1}"
    local max="${4:-2147483647}"
    local value
    while true; do
        value="$(ask_text "$prompt" "$default")"
        if [[ "$value" =~ ^[0-9]+$ ]] && (( value >= min && value <= max )); then
            echo "$value"
            return 0
        fi
        fail "Некорректное число. Диапазон: ${min}-${max}"
    done
}

generate_secret() {
    if command_exists openssl; then
        openssl rand -hex 32 2>/dev/null && return 0
    fi
    if command_exists od; then
        od -An -N32 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n' && echo && return 0
    fi
    date +%s%N
}

ask_secret_value() {
    local prompt="$1"
    local value
    while true; do
        printf '%s: ' "$prompt" >&2
        read -r -s value
        printf '\n' >&2
        if [[ -n "$value" ]]; then
            echo "$value"
            return 0
        fi
        fail "Значение не может быть пустым"
    done
}

validate_time_hm() {
    [[ "$1" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]]
}

normalize_time_hm() {
    local value="$1"
    value="${value//;/:}"
    value="${value//./:}"
    value="${value//,/:}"
    echo "$value"
}

ask_time_hm() {
    local prompt="$1"
    local default="${2-}"
    local value
    while true; do
        value="$(ask_text "$prompt" "$default")"
        value="$(normalize_time_hm "$value")"
        if validate_time_hm "$value"; then
            echo "$value"
            return 0
        fi
        fail "Некорректное время. Пример: 00:05 или 23;59"
    done
}

ask_optional_time_hm() {
    local prompt="$1"
    local default="${2-}"
    local value
    while true; do
        value="$(ask_optional_text "$prompt" "$default")"
        value="$(normalize_time_hm "$value")"
        if [[ -z "$value" ]] || validate_time_hm "$value"; then
            echo "$value"
            return 0
        fi
        fail "Некорректное время. Пример: 00:05 или 23;59"
    done
}

ask_secret_key() {
    local secret
    while true; do
        printf 'Введите SECRET_KEY: ' >&2
        read -r -s secret
        printf '\n' >&2
        if [[ -n "$secret" ]]; then
            echo "$secret"
            return 0
        fi
        fail "SECRET_KEY не может быть пустым"
    done
}

ask_api_token() {
    local token
    while true; do
        printf 'Введите Remnawave API token: ' >&2
        read -r -s token
        printf '\n' >&2
        if [[ -n "$token" ]]; then
            echo "$token"
            return 0
        fi
        fail "API token не может быть пустым"
    done
}

validate_ipv4() {
    local ip="$1" octet
    local octets=()
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS=. read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
        (( 10#$octet >= 0 && 10#$octet <= 255 )) || return 1
    done
}

ask_ipv4() {
    local prompt="${1:-Введите IP}"
    local ip
    while true; do
        printf '%s: ' "$prompt" >&2
        read -r ip
        if validate_ipv4 "$ip"; then
            echo "$ip"
            return 0
        fi
        fail "Некорректный IPv4. Пример: 1.2.3.4"
    done
}

default_network_interface() {
    ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="dev") {print $(i+1); exit}}'
}

network_interface_exists() {
    local iface="$1"
    ip link show dev "$iface" >/dev/null 2>&1
}

hosts_file_has_hostname() {
    local host="$1"
    "${SUDO[@]}" awk -v host="$host" '
        /^[[:space:]]*#/ { next }
        {
            for (i = 2; i <= NF; i++) {
                if ($i == host) {
                    found = 1
                }
            }
        }
        END { exit found ? 0 : 1 }
    ' /etc/hosts 2>/dev/null
}

hostname_hosts_configured() {
    local host
    host="$(hostname 2>/dev/null || true)"
    [[ -n "$host" ]] || return 0
    hosts_file_has_hostname "$host" || getent hosts "$host" >/dev/null 2>&1
}

ensure_hostname_hosts_entry() {
    local host short tmp
    host="$(hostname 2>/dev/null || true)"
    [[ -n "$host" ]] || return 0
    hostname_hosts_configured && return 0

    short="${host%%.*}"
    tmp="$(mktemp)"
    {
        printf '\n127.0.1.1\t%s' "$host"
        if [[ -n "$short" && "$short" != "$host" ]]; then
            printf ' %s' "$short"
        fi
        printf '\n'
    } > "$tmp"
    "${SUDO[@]}" tee -a /etc/hosts < "$tmp" >> "$LOG_FILE" 2>&1 || true
    rm -f "$tmp"
}

systemd_resolved_available() {
    command_exists systemctl && systemctl cat systemd-resolved.service >/dev/null 2>&1
}

resolv_conf_uses_resolved() {
    local target
    "${SUDO[@]}" test -L /etc/resolv.conf 2>/dev/null || return 1
    target="$("${SUDO[@]}" readlink -f /etc/resolv.conf 2>/dev/null || true)"
    [[ "$target" == "/run/systemd/resolve/stub-resolv.conf" || "$target" == "/run/systemd/resolve/resolv.conf" ]]
}

static_resolv_conf_configured() {
    root_file_has_line /etc/resolv.conf "nameserver 1.1.1.1" &&
        root_file_has_line /etc/resolv.conf "nameserver 1.0.0.1" &&
        root_file_has_line /etc/resolv.conf "nameserver 8.8.8.8"
}

resolved_dns_guard_configured() {
    root_file_has_line "$DNS_GUARD_RESOLVED_CONF" "[Resolve]" &&
        root_file_has_line "$DNS_GUARD_RESOLVED_CONF" "DNS=1.1.1.1 1.0.0.1 8.8.8.8" &&
        root_file_has_line "$DNS_GUARD_RESOLVED_CONF" "FallbackDNS=9.9.9.9 8.8.4.4" &&
        root_file_has_line "$DNS_GUARD_RESOLVED_CONF" "Domains=~." &&
        root_file_has_line "$DNS_GUARD_RESOLVED_CONF" "Cache=yes"
}

dns_guard_configured() {
    if systemd_resolved_available; then
        { resolved_dns_guard_configured && resolv_conf_uses_resolved; } || static_resolv_conf_configured
    else
        static_resolv_conf_configured
    fi
}

dns_resolution_ok() {
    getent hosts api.telegram.org >/dev/null 2>&1 ||
        getent hosts raw.githubusercontent.com >/dev/null 2>&1
}

wait_for_dns_resolution() {
    local waited=0
    while (( waited < 10 )); do
        dns_resolution_ok && return 0
        sleep 1
        waited=$(( waited + 1 ))
    done
    return 1
}

ipv6_sysctl_available() {
    sysctl -n net.ipv6.conf.all.disable_ipv6 >/dev/null 2>&1
}

whitelist_ipv6_disabled() {
    local all default lo
    if ! ipv6_sysctl_available; then
        return 0
    fi

    all="$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 0)"
    default="$(sysctl -n net.ipv6.conf.default.disable_ipv6 2>/dev/null || echo 0)"
    lo="$(sysctl -n net.ipv6.conf.lo.disable_ipv6 2>/dev/null || echo 0)"
    [[ "$all" == "1" && "$default" == "1" && "$lo" == "1" ]]
}

escape_yaml_secret() {
    local value="$1"
    value="${value//$'\r'/}"
    value="${value//$'\n'/}"
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

ensure_remna_api_config() {
    if [[ -z "$REMNA_API_URL" ]]; then
        fail "REMNA_API_URL пустой"
        exit 1
    fi

    if [[ -z "$REMNA_API_TOKEN" ]]; then
        REMNA_API_TOKEN="$(ask_api_token)"
        save_machine_mode
    fi
}

remna_api() {
    local method="$1"
    local path="$2"
    local payload_file="${3:-}"
    local tmp code url
    tmp="$(mktemp)"
    url="${REMNA_API_URL%/}${path}"

    if [[ -n "$payload_file" ]]; then
        code="$(curl -k -sS -L -X "$method" \
            -H "Authorization: Bearer ${REMNA_API_TOKEN}" \
            -H "Accept: application/json" \
            -H "Content-Type: application/json" \
            --data-binary "@${payload_file}" \
            -o "$tmp" -w '%{http_code}' "$url" 2>> "$LOG_FILE" || true)"
    else
        code="$(curl -k -sS -L -X "$method" \
            -H "Authorization: Bearer ${REMNA_API_TOKEN}" \
            -H "Accept: application/json" \
            -o "$tmp" -w '%{http_code}' "$url" 2>> "$LOG_FILE" || true)"
    fi

    if [[ "$code" =~ ^2[0-9][0-9]$ ]]; then
        cat "$tmp"
        rm -f "$tmp"
        return 0
    fi

    fail "Remnawave API ${method} ${path} (${code:-curl})"
    head -c 700 "$tmp" >&2 || true
    echo >&2
    rm -f "$tmp"
    return 1
}

external_ipv4() {
    local ip
    ip="$(curl -4 -fsSL --max-time 8 https://api.ipify.org 2>/dev/null || true)"
    if ! validate_ipv4 "$ip"; then
        ip="$(curl -4 -fsSL --max-time 8 https://ifconfig.me/ip 2>/dev/null || true)"
    fi
    if ! validate_ipv4 "$ip"; then
        ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
    fi
    if validate_ipv4 "$ip"; then
        echo "$ip"
        return 0
    fi
    fail "Не смог определить внешний IPv4"
    return 1
}

remna_profile_uuid_by_name() {
    local name="$1"
    remna_api GET /api/config-profiles \
        | jq -r --arg name "$name" '.response.configProfiles[]? | select(.name == $name) | .uuid' \
        | head -n 1
}

remna_node_uuid_by_name() {
    local name="$1"
    remna_api GET /api/nodes \
        | jq -r --arg name "$name" '.response[]? | select(.name == $name) | .uuid' \
        | head -n 1
}

remna_node_uuid_by_address() {
    local address="$1"
    remna_api GET /api/nodes \
        | jq -r --arg address "$address" '.response[]? | select(.address == $address) | .uuid' \
        | head -n 1
}

remna_host_uuid_by_remark() {
    local remark="$1"
    remna_api GET /api/hosts \
        | jq -r --arg remark "$remark" '.response[]? | select(.remark == $remark) | .uuid' \
        | head -n 1
}

remna_host_uuid_by_address() {
    local address="$1"
    remna_api GET /api/hosts \
        | jq -r --arg address "$address" '.response[]? | select(.address == $address) | .uuid' \
        | head -n 1
}

remna_enable_node() {
    local uuid="$1"
    remna_api POST "/api/nodes/${uuid}/actions/enable" >/dev/null || true
}

install_antiscanner() {
    stage "AntiScanner"
    local existing_rules=0
    existing_rules="$(antiscanner_rules_count)"

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
    if [[ "$existing_rules" =~ ^[0-9]+$ && "$existing_rules" -gt 0 ]]; then
        echo "AntiScanner update skipped: rules already present ($existing_rules)" >> "$LOG_FILE"
    else
        cmd "${SUDO[@]}" "$ANTISCANNER_SCRIPT" || true
    fi
}

opt_prepare_system() {
    cmd "${SUDO[@]}" systemctl stop unattended-upgrades || true
    cmd "${SUDO[@]}" dpkg --configure -a || true
    cmd "${SUDO[@]}" apt-get clean || true
    cmd "${SUDO[@]}" apt-get autoclean || true
    cmd "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive apt-get autoremove --purge -y || true
    if command_exists journalctl; then
        cmd "${SUDO[@]}" journalctl --vacuum-size=256M --vacuum-time=7d || true
    fi
    cmd "${SUDO[@]}" rm -f /etc/apt/sources.list.d/ookla_speedtest-cli.list || true
    if package_installed snapd; then
        cmd "${SUDO[@]}" systemctl disable --now snapd.socket snapd.service || true
        cmd "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive apt-get purge -y snapd || true
    else
        echo "snapd purge skipped: not installed" >> "$LOG_FILE"
    fi
}

optimization_packages() {
    local packages cpus
    packages=(ca-certificates curl wget gnupg2 software-properties-common ufw openssl dnsutils jq logrotate)
    if [[ "$MACHINE_MODE" == "node" ]]; then
        packages+=(chrony cpufrequtils tar xz-utils)
        cpus="$(cpu_count)"
        if (( cpus > 1 )); then
            packages+=(irqbalance)
        fi
    fi
    printf '%s\n' "${packages[@]}"
}

opt_install_packages() {
    local packages
    mapfile -t packages < <(optimization_packages)
    apt_update_quiet
    apt_install_quiet "${packages[@]}"
}

backup_resolv_conf() {
    if "${SUDO[@]}" test -e /etc/resolv.conf 2>/dev/null && ! "${SUDO[@]}" test -e /etc/resolv.conf.kto-backup 2>/dev/null; then
        cmd "${SUDO[@]}" cp -a /etc/resolv.conf /etc/resolv.conf.kto-backup || true
    fi
}

write_static_resolv_conf() {
    backup_resolv_conf
    cmd "${SUDO[@]}" rm -f /etc/resolv.conf || true
    write_root_file /etc/resolv.conf <<'EOF'
nameserver 1.1.1.1
nameserver 1.0.0.1
nameserver 8.8.8.8
options timeout:2 attempts:3 rotate
EOF
}

opt_dns_guard() {
    ensure_hostname_hosts_entry

    if systemd_resolved_available; then
        cmd "${SUDO[@]}" mkdir -p /etc/systemd/resolved.conf.d
        write_root_file "$DNS_GUARD_RESOLVED_CONF" <<'EOF'
[Resolve]
DNS=1.1.1.1 1.0.0.1 8.8.8.8
FallbackDNS=9.9.9.9 8.8.4.4
Domains=~.
DNSSEC=no
DNSOverTLS=no
DNSStubListener=yes
Cache=yes
EOF
        cmd "${SUDO[@]}" systemctl enable --now systemd-resolved || true
        cmd "${SUDO[@]}" systemctl restart systemd-resolved || true
        if "${SUDO[@]}" test -e /run/systemd/resolve/stub-resolv.conf 2>/dev/null; then
            backup_resolv_conf
            cmd "${SUDO[@]}" ln -sfn /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf || true
        elif "${SUDO[@]}" test -e /run/systemd/resolve/resolv.conf 2>/dev/null; then
            backup_resolv_conf
            cmd "${SUDO[@]}" ln -sfn /run/systemd/resolve/resolv.conf /etc/resolv.conf || true
        fi
        if command_exists resolvectl; then
            cmd "${SUDO[@]}" resolvectl flush-caches || true
        fi
    else
        write_static_resolv_conf
    fi

    if ! wait_for_dns_resolution; then
        echo "DNS guard fallback: static /etc/resolv.conf" >> "$LOG_FILE"
        write_static_resolv_conf
    fi

    if ! dns_resolution_ok; then
        warn "DNS всё ещё не резолвит api.telegram.org/raw.githubusercontent.com. Проверь /etc/resolv.conf, провайдера или IPv6."
    fi
}

opt_ipv6_mode_guard() {
    if [[ "$MACHINE_MODE" == "whitelist" ]]; then
        write_root_file "$IPV6_WHITELIST_SYSCTL_CONF" <<'EOF'
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
        cmd "${SUDO[@]}" sysctl -w net.ipv6.conf.all.disable_ipv6=1 || true
        cmd "${SUDO[@]}" sysctl -w net.ipv6.conf.default.disable_ipv6=1 || true
        cmd "${SUDO[@]}" sysctl -w net.ipv6.conf.lo.disable_ipv6=1 || true
    elif "${SUDO[@]}" test -f "$IPV6_WHITELIST_SYSCTL_CONF" 2>/dev/null; then
        cmd "${SUDO[@]}" rm -f "$IPV6_WHITELIST_SYSCTL_CONF"
        cmd "${SUDO[@]}" sysctl -w net.ipv6.conf.all.disable_ipv6=0 || true
        cmd "${SUDO[@]}" sysctl -w net.ipv6.conf.default.disable_ipv6=0 || true
        cmd "${SUDO[@]}" sysctl -w net.ipv6.conf.lo.disable_ipv6=0 || true
    fi
}

configure_docker_log_rotation() {
    command_exists docker || return 0

    local tmp backup
    tmp="$(mktemp)"
    cmd "${SUDO[@]}" mkdir -p /etc/docker

    if "${SUDO[@]}" test -s "$DOCKER_DAEMON_JSON" 2>/dev/null && command_exists jq && "${SUDO[@]}" jq -e . "$DOCKER_DAEMON_JSON" >/dev/null 2>&1; then
        if ! "${SUDO[@]}" jq '. + {"log-driver":"json-file"} | ."log-opts" = ((."log-opts" // {}) + {"max-size":"20m","max-file":"3"})' "$DOCKER_DAEMON_JSON" > "$tmp" 2>> "$LOG_FILE"; then
            rm -f "$tmp"
            echo "Docker log rotation skipped: jq merge failed" >> "$LOG_FILE"
            return 0
        fi
    elif "${SUDO[@]}" test -f "$DOCKER_DAEMON_JSON" 2>/dev/null && ! command_exists jq; then
        rm -f "$tmp"
        echo "Docker log rotation skipped: jq not installed and daemon.json exists" >> "$LOG_FILE"
        return 0
    else
        cat > "$tmp" <<'EOF'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "20m",
    "max-file": "3"
  }
}
EOF
    fi

    if "${SUDO[@]}" test -f "$DOCKER_DAEMON_JSON" 2>/dev/null; then
        backup="${DOCKER_DAEMON_JSON}.kto-backup-$(date +%Y%m%d%H%M%S)"
        cmd "${SUDO[@]}" cp -a "$DOCKER_DAEMON_JSON" "$backup" || true
    fi
    cmd "${SUDO[@]}" install -m 0644 "$tmp" "$DOCKER_DAEMON_JSON"
    rm -f "$tmp"

    cmd "${SUDO[@]}" find /var/lib/docker/containers -type f -name '*-json.log' -size +100M -exec truncate -s 0 {} + || true
    cmd "${SUDO[@]}" docker image prune -af || true
    cmd "${SUDO[@]}" docker builder prune -af || true
    cmd "${SUDO[@]}" systemctl reload docker || true
}

truncate_large_var_logs() {
    cmd "${SUDO[@]}" find /var/log -xdev -type f -size +256M \
        ! -path '/var/log/journal/*' \
        -printf 'truncate large log: %s %p\n' || true
    cmd "${SUDO[@]}" find /var/log -xdev -type f -size +256M \
        ! -path '/var/log/journal/*' \
        -exec truncate -s 0 {} + || true
}

opt_storage_guard() {
    cmd "${SUDO[@]}" apt-get clean || true
    cmd "${SUDO[@]}" apt-get autoclean || true
    cmd "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive apt-get autoremove --purge -y || true

    cmd "${SUDO[@]}" mkdir -p /etc/systemd/journald.conf.d /etc/logrotate.d
    write_root_file "$STORAGE_GUARD_JOURNAL_CONF" <<'EOF'
[Journal]
SystemMaxUse=256M
RuntimeMaxUse=64M
MaxRetentionSec=7day
MaxFileSec=1day
EOF

    if command_exists journalctl; then
        cmd "${SUDO[@]}" journalctl --vacuum-size=256M --vacuum-time=7d || true
    fi
    cmd "${SUDO[@]}" systemctl restart systemd-journald || true

    write_root_file "$KTO_LOGROTATE_CONF" <<EOF
$LOG_FILE {
    size 10M
    rotate 5
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
EOF
    if command_exists logrotate; then
        cmd "${SUDO[@]}" logrotate "$KTO_LOGROTATE_CONF" || true
    fi

    cmd "${SUDO[@]}" find /tmp -xdev -mindepth 1 -mtime +2 -exec rm -rf -- {} + || true
    cmd "${SUDO[@]}" find /var/tmp -xdev -mindepth 1 -mtime +7 -exec rm -rf -- {} + || true
    cmd "${SUDO[@]}" find /var/crash -type f -delete || true
    cmd "${SUDO[@]}" find /var/lib/systemd/coredump -type f -mtime +1 -delete || true
    cmd "${SUDO[@]}" find /var/log -xdev -type f \( -name '*.gz' -o -name '*.old' -o -name '*.1' \) -mtime +14 -delete || true
    truncate_large_var_logs

    configure_docker_log_rotation
}

print_disk_usage_top() {
    echo
    echo -e "${BOLD}${PURPLE}[ КРУПНЕЙШЕЕ НА ДИСКЕ ]${NC}"
    if command_exists timeout; then
        "${SUDO[@]}" timeout 30s du -xhd1 / 2>/dev/null | sort -hr | head -n 12 || true
    else
        "${SUDO[@]}" du -xhd1 / 2>/dev/null | sort -hr | head -n 12 || true
    fi

    echo
    echo -e "${BOLD}${PURPLE}[ КРУПНЕЙШЕЕ В /VAR ]${NC}"
    if command_exists timeout; then
        "${SUDO[@]}" timeout 30s du -xhd1 /var 2>/dev/null | sort -hr | head -n 12 || true
    else
        "${SUDO[@]}" du -xhd1 /var 2>/dev/null | sort -hr | head -n 12 || true
    fi

    echo
    echo -e "${BOLD}${PURPLE}[ КРУПНЫЕ ЛОГИ ]${NC}"
    if command_exists timeout; then
        "${SUDO[@]}" timeout 30s du -ahx /var/log 2>/dev/null | sort -hr | head -n 20 || true
    else
        "${SUDO[@]}" du -ahx /var/log 2>/dev/null | sort -hr | head -n 20 || true
    fi

    if command_exists docker; then
        echo
        echo -e "${BOLD}${PURPLE}[ DOCKER DISK ]${NC}"
        "${SUDO[@]}" docker system df 2>/dev/null || true
    fi
}

clean_disk_now() {
    header
    need_root
    local used

    stage "Очищаю диск"
    opt_storage_guard

    used="$(root_disk_used_percent)"
    ok "Очистка диска завершена"
    print_row "root disk" "${used}% used"
    print_row "apt archives" "$(format_mb "$(apt_cache_usage_mb)")"
    print_row "apt lists" "$(format_mb "$(apt_lists_usage_mb)")"
    if [[ "$used" =~ ^[0-9]+$ && "$used" -ge 90 ]]; then
        warn "Диск всё ещё забит. Авточистка уже сделала безопасное; дальше надо смотреть крупнейшие директории."
        print_disk_usage_top
    fi
}

opt_memory_guard() {
    local swappiness=10

    if zram_recommended; then
        opt_zram
    fi
    if zram_active; then
        swappiness=100
    fi

    write_root_file "$MEMORY_GUARD_SYSCTL_CONF" <<EOF
vm.swappiness = $swappiness
vm.vfs_cache_pressure = 150
vm.dirty_background_ratio = 5
vm.dirty_ratio = 20
vm.page-cluster = 0
EOF
    cmd "${SUDO[@]}" sysctl --system || true
}

opt_liquorix_kernel() {
    if [[ "$(uname -m)" == "x86_64" ]] && grep -qi '^ID=ubuntu' /etc/os-release 2>/dev/null; then
        if liquorix_installed; then
            echo "Liquorix skipped: packages already installed" >> "$LOG_FILE"
            return 0
        fi
        if liquorix_source_configured; then
            apt_update_quiet
        else
            cmd "${SUDO[@]}" add-apt-repository ppa:damentz/liquorix -y
            apt_update_force
        fi
        for _ in 1 2 3; do
            if apt_install_quiet linux-image-liquorix-amd64 linux-headers-liquorix-amd64; then
                break
            fi
            sleep 2
        done
    else
        echo "Liquorix skipped: non-Ubuntu or non-amd64" >> "$LOG_FILE"
    fi
}

opt_network_limits() {
    opt_dns_guard
    opt_ipv6_mode_guard

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
    cmd "${SUDO[@]}" systemctl daemon-reload || true
    if [[ "$MACHINE_MODE" == "node" ]]; then
        echo 'GOVERNOR="performance"' | "${SUDO[@]}" tee /etc/default/cpufrequtils >> "$LOG_FILE" 2>&1 || true
        cmd "${SUDO[@]}" systemctl enable --now chrony || true
        if (( $(cpu_count) > 1 )); then
            cmd "${SUDO[@]}" systemctl enable --now irqbalance || true
        else
            echo "irqbalance skipped: single CPU" >> "$LOG_FILE"
        fi
        cmd "${SUDO[@]}" systemctl restart cpufrequtils || true
    fi
}

opt_firewall() {
    local ssh_port="$1"
    local anti_rules
    anti_rules="$(antiscanner_rules_count)"

    if [[ "$anti_rules" =~ ^[0-9]+$ && "$anti_rules" -gt 0 ]]; then
        echo "ufw reset skipped: AntiScanner rules already present ($anti_rules)" >> "$LOG_FILE"
    else
        cmd "${SUDO[@]}" ufw --force reset
    fi
    cmd "${SUDO[@]}" ufw default deny incoming
    cmd "${SUDO[@]}" ufw default allow outgoing
    cmd "${SUDO[@]}" ufw allow "${ssh_port}/tcp"
    cmd "${SUDO[@]}" ufw allow 443/tcp
    if [[ "$MACHINE_MODE" == "node" ]]; then
        cmd "${SUDO[@]}" ufw allow 443/udp
        cmd "${SUDO[@]}" ufw allow "${NODE_PORT}/tcp"
    else
        cmd "${SUDO[@]}" ufw --force delete allow 443/udp || true
        cmd "${SUDO[@]}" ufw --force delete allow "${NODE_PORT}/tcp" || true
    fi
    cmd "${SUDO[@]}" ufw --force enable
}

opt_antiscanner() {
    install_antiscanner
}

opt_fail2ban() {
    apt_install_quiet fail2ban || true
    write_root_file /etc/fail2ban/jail.d/99-kto-sshd.conf <<'EOF'
[sshd]
enabled = true
bantime = 1h
findtime = 10m
maxretry = 5
EOF
    cmd "${SUDO[@]}" systemctl enable --now fail2ban || true
}

opt_zram() {
    need_root
    local size

    if zram_active; then
        ok "ZRAM уже активен: $(zram_swap_summary)"
        return 0
    fi

    if ! command_exists zramctl; then
        apt_update_quiet
        apt_install_quiet util-linux
    fi
    if ! command_exists zramctl; then
        fail "zramctl не найден"
        return 1
    fi

    size="$(recommended_zram_mb)"
    stage "Настраиваю ZRAM ($(format_mb "$size"))"

    write_root_file_mode 0755 "$ZRAM_SETUP_SCRIPT" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail

SIZE_MB="\${KTO_ZRAM_SIZE_MB:-$size}"
PREFERRED_ALGO="\${KTO_ZRAM_ALGO:-zstd}"

if awk '\$1 ~ /^\\/dev\\/zram/ {found=1} END{exit found ? 0 : 1}' /proc/swaps 2>/dev/null; then
    exit 0
fi

modprobe zram

dev=""
for algo in "\$PREFERRED_ALGO" lz4 lzo-rle lzo; do
    if dev="\$(zramctl --find --size "\${SIZE_MB}M" --algorithm "\$algo" 2>/dev/null)"; then
        break
    fi
done

if [[ -z "\$dev" ]]; then
    dev="\$(zramctl --find --size "\${SIZE_MB}M")"
fi

mkswap -f "\$dev" >/dev/null
swapon -p 100 "\$dev"
EOF

    write_root_file "/etc/systemd/system/${ZRAM_SERVICE}" <<EOF
[Unit]
Description=kto ZRAM swap
Documentation=man:zramctl(8) man:swapon(8)
After=local-fs.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${ZRAM_SETUP_SCRIPT}
ExecStop=/bin/sh -c 'for dev in /dev/zram*; do [ -b "\$dev" ] || continue; swapoff "\$dev" 2>/dev/null || true; zramctl --reset "\$dev" 2>/dev/null || true; done'

[Install]
WantedBy=multi-user.target
EOF

    cmd "${SUDO[@]}" systemctl daemon-reload
    must "Включение ZRAM" "${SUDO[@]}" systemctl enable --now "$ZRAM_SERVICE"

    if zram_active; then
        ok "ZRAM включен: $(zram_swap_summary)"
    else
        fail "ZRAM service запустился, но swap не активен"
        return 1
    fi
}

SYSTEM_CHECK_MISSING=0
SYSTEM_CHECK_WARNINGS=0
SYSTEM_CHECK_NEEDS_PREPARE=0
SYSTEM_CHECK_NEEDS_PACKAGES=0
SYSTEM_CHECK_NEEDS_KERNEL=0
SYSTEM_CHECK_NEEDS_NETWORK=0
SYSTEM_CHECK_NEEDS_FIREWALL=0
SYSTEM_CHECK_NEEDS_ANTISCANNER=0
SYSTEM_CHECK_NEEDS_FAIL2BAN=0
SYSTEM_CHECK_NEEDS_ZRAM=0
SYSTEM_CHECK_NEEDS_STORAGE=0
SYSTEM_CHECK_NEEDS_MEMORY_GUARD=0

system_check_reset() {
    SYSTEM_CHECK_MISSING=0
    SYSTEM_CHECK_WARNINGS=0
    SYSTEM_CHECK_NEEDS_PREPARE=0
    SYSTEM_CHECK_NEEDS_PACKAGES=0
    SYSTEM_CHECK_NEEDS_KERNEL=0
    SYSTEM_CHECK_NEEDS_NETWORK=0
    SYSTEM_CHECK_NEEDS_FIREWALL=0
    SYSTEM_CHECK_NEEDS_ANTISCANNER=0
    SYSTEM_CHECK_NEEDS_FAIL2BAN=0
    SYSTEM_CHECK_NEEDS_ZRAM=0
    SYSTEM_CHECK_NEEDS_STORAGE=0
    SYSTEM_CHECK_NEEDS_MEMORY_GUARD=0
}

system_check_badge() {
    local status="$1"
    case "$status" in
        ok) echo -e "${GREEN}OK${NC}" ;;
        miss) echo -e "${RED}TODO${NC}" ;;
        warn) echo -e "${YELLOW}WARN${NC}" ;;
        skip) echo -e "${DIM}SKIP${NC}" ;;
        *) echo -e "${RED}?${NC}" ;;
    esac
}

system_check_row() {
    local status="$1"
    local name="$2"
    local value="$3"

    case "$status" in
        miss) SYSTEM_CHECK_MISSING=$(( SYSTEM_CHECK_MISSING + 1 )) ;;
        warn) SYSTEM_CHECK_WARNINGS=$(( SYSTEM_CHECK_WARNINGS + 1 )) ;;
    esac

    printf " %-22s %b %b\n" "$name" "$value" "$(system_check_badge "$status")"
}

system_check_join() {
    local IFS=", "
    echo "$*"
}

root_file_has_line() {
    local file="$1"
    local line="$2"
    "${SUDO[@]}" test -f "$file" 2>/dev/null || return 1
    "${SUDO[@]}" grep -Fqx "$line" "$file" 2>/dev/null
}

root_file_contains() {
    local file="$1"
    local pattern="$2"
    "${SUDO[@]}" test -f "$file" 2>/dev/null || return 1
    "${SUDO[@]}" grep -Eq "$pattern" "$file" 2>/dev/null
}

cpu_count() {
    local count
    count="$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"
    [[ "$count" =~ ^[0-9]+$ && "$count" -gt 0 ]] || count=1
    echo "$count"
}

meminfo_mb() {
    local key="$1"
    awk -v key="${key}:" '$1 == key {printf "%d\n", $2 / 1024; found=1; exit} END{if (!found) print 0}' /proc/meminfo 2>/dev/null
}

memory_total_mb() {
    meminfo_mb MemTotal
}

memory_available_mb() {
    meminfo_mb MemAvailable
}

swap_total_mb() {
    meminfo_mb SwapTotal
}

format_mb() {
    local mb="$1"
    if (( mb >= 1024 )); then
        awk -v mb="$mb" 'BEGIN{printf "%.1fG", mb / 1024}'
    else
        printf '%dM' "$mb"
    fi
}

zram_active() {
    awk '$1 ~ /^\/dev\/zram/ {found=1} END{exit found ? 0 : 1}' /proc/swaps 2>/dev/null
}

zram_swap_summary() {
    local summary
    summary="$(awk '$1 ~ /^\/dev\/zram/ {printf "%s %dM ", $1, int($3 / 1024)}' /proc/swaps 2>/dev/null | xargs 2>/dev/null || true)"
    echo "${summary:-active}"
}

zram_percent() {
    local percent="${ZRAM_PERCENT:-50}"
    [[ "$percent" =~ ^[0-9]+$ && "$percent" -ge 10 && "$percent" -le 200 ]] || percent=50
    echo "$percent"
}

zram_max_mb() {
    local max_mb="${ZRAM_MAX_MB:-2048}"
    [[ "$max_mb" =~ ^[0-9]+$ && "$max_mb" -ge 128 ]] || max_mb=2048
    echo "$max_mb"
}

recommended_zram_mb() {
    local total percent max_mb size
    total="$(memory_total_mb)"
    percent="$(zram_percent)"
    max_mb="$(zram_max_mb)"
    size=$(( total * percent / 100 ))
    (( size < 128 )) && size=128
    (( size > max_mb )) && size="$max_mb"
    echo "$size"
}

zram_recommended() {
    local total swap
    total="$(memory_total_mb)"
    swap="$(swap_total_mb)"
    (( total > 0 && total < 4096 && swap == 0 )) || return 1
    ! zram_active
}

memory_oom_count() {
    local tmp rc count
    tmp="$(mktemp)"

    if command_exists timeout && command_exists journalctl; then
        if "${SUDO[@]}" timeout 4s journalctl -k -b --no-pager -n 3000 > "$tmp" 2>/dev/null; then
            count="$(grep -Eci 'out of memory|oom-killer|killed process' "$tmp" || true)"
            rm -f "$tmp"
            echo "${count:-0}"
            return 0
        fi
        rc=$?
        echo "OOM journalctl skipped: rc=${rc}" >> "$LOG_FILE" 2>/dev/null || true
    fi

    if command_exists timeout && command_exists dmesg; then
        if "${SUDO[@]}" timeout 4s dmesg > "$tmp" 2>/dev/null; then
            count="$(tail -n 3000 "$tmp" | grep -Eci 'out of memory|oom-killer|killed process' || true)"
            rm -f "$tmp"
            echo "${count:-0}"
            return 0
        fi
        rc=$?
        echo "OOM dmesg skipped: rc=${rc}" >> "$LOG_FILE" 2>/dev/null || true
    fi

    rm -f "$tmp"
    echo "timeout"
}

root_disk_used_percent() {
    df -P / 2>/dev/null | awk 'NR == 2 {gsub(/%/, "", $5); print $5; found=1} END{if (!found) print 0}'
}

apt_cache_usage_mb() {
    "${SUDO[@]}" du -sm /var/cache/apt/archives 2>/dev/null | awk '{sum += $1} END{print sum + 0}'
}

apt_lists_usage_mb() {
    "${SUDO[@]}" du -sm /var/lib/apt/lists 2>/dev/null | awk '{sum += $1} END{print sum + 0}'
}

journald_storage_guard_configured() {
    root_file_has_line "$STORAGE_GUARD_JOURNAL_CONF" "SystemMaxUse=256M" &&
        root_file_has_line "$STORAGE_GUARD_JOURNAL_CONF" "RuntimeMaxUse=64M" &&
        root_file_has_line "$STORAGE_GUARD_JOURNAL_CONF" "MaxRetentionSec=7day"
}

kto_logrotate_configured() {
    root_file_contains "$KTO_LOGROTATE_CONF" 'size[[:space:]]+10M' &&
        root_file_contains "$KTO_LOGROTATE_CONF" 'rotate[[:space:]]+5' &&
        root_file_contains "$KTO_LOGROTATE_CONF" 'copytruncate'
}

docker_log_rotation_configured() {
    root_file_contains "$DOCKER_DAEMON_JSON" '"log-driver"[[:space:]]*:[[:space:]]*"json-file"' &&
        root_file_contains "$DOCKER_DAEMON_JSON" '"max-size"[[:space:]]*:' &&
        root_file_contains "$DOCKER_DAEMON_JSON" '"max-file"[[:space:]]*:'
}

memory_guard_configured() {
    root_file_has_line "$MEMORY_GUARD_SYSCTL_CONF" "vm.vfs_cache_pressure = 150" &&
        root_file_has_line "$MEMORY_GUARD_SYSCTL_CONF" "vm.dirty_background_ratio = 5" &&
        root_file_has_line "$MEMORY_GUARD_SYSCTL_CONF" "vm.dirty_ratio = 20" &&
        root_file_has_line "$MEMORY_GUARD_SYSCTL_CONF" "vm.page-cluster = 0"
}

ufw_active() {
    command_exists ufw && "${SUDO[@]}" ufw status 2>/dev/null | grep -q "Status: active"
}

ufw_rule_allowed() {
    local rule="$1"
    command_exists ufw || return 1
    "${SUDO[@]}" ufw status 2>/dev/null \
        | awk -v rule="$rule" '$0 ~ /ALLOW/ && $1 == rule {found=1} END{exit found ? 0 : 1}'
}

system_check_prepare_state() {
    local issues=() dpkg_audit

    if package_installed snapd; then
        issues+=("snapd установлен")
    fi
    if "${SUDO[@]}" test -e /etc/apt/sources.list.d/ookla_speedtest-cli.list 2>/dev/null; then
        issues+=("старый Ookla apt source")
    fi
    if command_exists dpkg; then
        dpkg_audit="$(dpkg --audit 2>/dev/null || true)"
        if [[ -n "$dpkg_audit" ]]; then
            issues+=("dpkg требует configure")
        fi
    fi

    if (( ${#issues[@]} == 0 )); then
        system_check_row ok "prepare" "очистка не требуется"
    else
        SYSTEM_CHECK_NEEDS_PREPARE=1
        system_check_row miss "prepare" "$(system_check_join "${issues[@]}")"
    fi
}

system_check_packages() {
    local packages=() missing=() pkg
    mapfile -t packages < <(optimization_packages)
    for pkg in "${packages[@]}"; do
        if ! package_installed "$pkg"; then
            missing+=("$pkg")
        fi
    done

    if (( ${#missing[@]} == 0 )); then
        system_check_row ok "packages" "базовый набор установлен"
    else
        SYSTEM_CHECK_NEEDS_PACKAGES=1
        system_check_row miss "packages" "нет: $(system_check_join "${missing[@]}")"
    fi
}

system_check_kernel() {
    local kernel
    kernel="$(uname -r)"

    if [[ "$(uname -m)" != "x86_64" ]] || ! grep -qi '^ID=ubuntu' /etc/os-release 2>/dev/null; then
        system_check_row skip "liquorix" "не Ubuntu amd64"
        return 0
    fi

    if liquorix_installed; then
        if [[ "$kernel" == *liquorix* ]]; then
            system_check_row ok "liquorix" "$kernel"
        else
            system_check_row warn "liquorix" "пакеты стоят, текущее ядро: $kernel; нужен reboot"
        fi
        return 0
    fi

    SYSTEM_CHECK_NEEDS_KERNEL=1
    if liquorix_source_configured; then
        system_check_row miss "liquorix" "repo есть, пакеты не установлены"
    else
        system_check_row miss "liquorix" "repo и пакеты не установлены"
    fi
}

system_check_memory() {
    local total available swap zram_size oom_count swappiness
    total="$(memory_total_mb)"
    available="$(memory_available_mb)"
    swap="$(swap_total_mb)"
    zram_size="$(recommended_zram_mb)"

    if (( total > 0 )); then
        system_check_row ok "RAM" "$(format_mb "$available") available / $(format_mb "$total") total"
    else
        system_check_row warn "RAM" "не смог прочитать /proc/meminfo"
    fi

    if zram_active; then
        system_check_row ok "zram" "$(zram_swap_summary)"
    elif (( swap > 0 )); then
        system_check_row ok "swap" "$(format_mb "$swap") active"
    elif zram_recommended; then
        SYSTEM_CHECK_NEEDS_ZRAM=1
        system_check_row warn "swap/zram" "нет; рекомендую ZRAM $(format_mb "$zram_size")"
    else
        system_check_row skip "swap/zram" "нет; RAM $(format_mb "$total"), опционально"
    fi

    oom_count="$(memory_oom_count)"
    if [[ "$oom_count" =~ ^[0-9]+$ && "$oom_count" -gt 0 ]]; then
        system_check_row warn "OOM" "${oom_count} events в текущей загрузке"
    elif [[ "$oom_count" =~ ^[0-9]+$ ]]; then
        system_check_row ok "OOM" "не найдено в последних kernel logs"
    else
        system_check_row skip "OOM" "проверка пропущена (${oom_count})"
    fi

    swappiness="$(sysctl -n vm.swappiness 2>/dev/null || echo "-")"
    if memory_guard_configured; then
        system_check_row ok "memory guard" "swappiness=${swappiness}"
    else
        SYSTEM_CHECK_NEEDS_MEMORY_GUARD=1
        system_check_row miss "memory guard" "нет $MEMORY_GUARD_SYSCTL_CONF"
    fi
}

system_check_storage() {
    local used cache lists
    used="$(root_disk_used_percent)"
    cache="$(apt_cache_usage_mb)"
    lists="$(apt_lists_usage_mb)"

    if [[ "$used" =~ ^[0-9]+$ && "$used" -ge 95 ]]; then
        SYSTEM_CHECK_NEEDS_STORAGE=1
        system_check_row miss "root disk" "${used}% used, критично: автоочистка + ручной аудит"
    elif [[ "$used" =~ ^[0-9]+$ && "$used" -ge 90 ]]; then
        system_check_row warn "root disk" "${used}% used, мало места; запусти очистку/аудит"
    elif [[ "$used" =~ ^[0-9]+$ && "$used" -ge 80 ]]; then
        system_check_row warn "root disk" "${used}% used"
    elif [[ "$used" =~ ^[0-9]+$ ]]; then
        system_check_row ok "root disk" "${used}% used"
    else
        system_check_row warn "root disk" "не смог прочитать df"
    fi

    if [[ "$cache" =~ ^[0-9]+$ && "$cache" -ge 512 ]]; then
        SYSTEM_CHECK_NEEDS_STORAGE=1
        system_check_row miss "apt archives" "$(format_mb "$cache"), можно чистить"
    elif [[ "$cache" =~ ^[0-9]+$ && "$cache" -ge 128 ]]; then
        system_check_row warn "apt archives" "$(format_mb "$cache"), не критично"
    else
        system_check_row ok "apt archives" "$(format_mb "${cache:-0}")"
    fi

    if [[ "$lists" =~ ^[0-9]+$ && "$lists" -ge 512 ]]; then
        system_check_row skip "apt lists" "$(format_mb "$lists"), индекс пакетов после apt update"
    elif [[ "$lists" =~ ^[0-9]+$ ]]; then
        system_check_row ok "apt lists" "$(format_mb "$lists")"
    else
        system_check_row skip "apt lists" "не смог прочитать"
    fi

    if journald_storage_guard_configured; then
        system_check_row ok "journald" "limit 256M / 7d"
    else
        SYSTEM_CHECK_NEEDS_STORAGE=1
        system_check_row miss "journald" "лимит логов не настроен"
    fi

    if kto_logrotate_configured; then
        system_check_row ok "kto logrotate" "size 10M, rotate 5"
    else
        SYSTEM_CHECK_NEEDS_STORAGE=1
        system_check_row miss "kto logrotate" "нет ротации $LOG_FILE"
    fi

    if command_exists docker; then
        if docker_log_rotation_configured; then
            system_check_row ok "docker logs" "json-file max-size/max-file"
        else
            SYSTEM_CHECK_NEEDS_STORAGE=1
            system_check_row miss "docker logs" "нет log rotation"
        fi
    else
        system_check_row skip "docker logs" "docker не установлен"
    fi
}

system_check_network_limits() {
    local cc qdisc limits_ok=1 sysctl_file_ok=1 service_issues=() cpus
    cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "-")"
    qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "-")"

    if hostname_hosts_configured; then
        system_check_row ok "hostname" "$(hostname 2>/dev/null || echo "-")"
    else
        SYSTEM_CHECK_NEEDS_NETWORK=1
        system_check_row miss "hostname" "нет записи в /etc/hosts"
    fi

    if dns_guard_configured; then
        if systemd_resolved_available && resolved_dns_guard_configured && resolv_conf_uses_resolved; then
            system_check_row ok "dns guard" "forced через systemd-resolved"
        elif static_resolv_conf_configured; then
            system_check_row ok "dns guard" "static /etc/resolv.conf"
        else
            system_check_row ok "dns guard" "настроен"
        fi
    else
        SYSTEM_CHECK_NEEDS_NETWORK=1
        system_check_row miss "dns guard" "принудительный DNS не настроен"
    fi

    if dns_resolution_ok; then
        system_check_row ok "dns resolve" "api.telegram.org/raw.githubusercontent.com"
    else
        SYSTEM_CHECK_NEEDS_NETWORK=1
        system_check_row miss "dns resolve" "внешние домены не резолвятся"
    fi

    if [[ "$MACHINE_MODE" == "whitelist" ]]; then
        if whitelist_ipv6_disabled; then
            system_check_row ok "ipv6" "disabled для whitelist"
        else
            SYSTEM_CHECK_NEEDS_NETWORK=1
            system_check_row miss "ipv6" "на whitelist должен быть выключен"
        fi
    elif "${SUDO[@]}" test -f "$IPV6_WHITELIST_SYSCTL_CONF" 2>/dev/null; then
        SYSTEM_CHECK_NEEDS_NETWORK=1
        system_check_row miss "ipv6" "найден whitelist-disable, уберу"
    else
        system_check_row skip "ipv6" "node: не отключаю"
    fi

    if [[ "$cc" == "bbr" && "$qdisc" == "fq" ]]; then
        system_check_row ok "BBR + FQ" "${cc} + ${qdisc}"
    else
        SYSTEM_CHECK_NEEDS_NETWORK=1
        system_check_row miss "BBR + FQ" "${cc} + ${qdisc}"
    fi

    root_file_has_line /etc/sysctl.d/99-vpn-tuning.conf "net.ipv4.tcp_congestion_control = bbr" || sysctl_file_ok=0
    root_file_has_line /etc/sysctl.d/99-vpn-tuning.conf "net.core.default_qdisc = fq" || sysctl_file_ok=0
    root_file_has_line /etc/sysctl.d/99-vpn-tuning.conf "fs.file-max = 2097152" || sysctl_file_ok=0
    root_file_has_line /etc/sysctl.d/99-vpn-tuning.conf "vm.swappiness = 1" || sysctl_file_ok=0
    if [[ "$sysctl_file_ok" == "1" ]]; then
        system_check_row ok "sysctl file" "/etc/sysctl.d/99-vpn-tuning.conf"
    else
        SYSTEM_CHECK_NEEDS_NETWORK=1
        system_check_row miss "sysctl file" "нет или неполный /etc/sysctl.d/99-vpn-tuning.conf"
    fi

    root_file_has_line /etc/security/limits.d/99-vpn-limits.conf "* soft nofile 1048576" || limits_ok=0
    root_file_has_line /etc/security/limits.d/99-vpn-limits.conf "* hard nofile 1048576" || limits_ok=0
    root_file_has_line /etc/systemd/system.conf.d/99-vpn-limits.conf "DefaultLimitNOFILE=1048576" || limits_ok=0
    root_file_has_line /etc/systemd/user.conf.d/99-vpn-limits.conf "DefaultLimitNOFILE=1048576" || limits_ok=0
    if [[ "$limits_ok" == "1" ]]; then
        system_check_row ok "limits" "nofile 1048576"
    else
        SYSTEM_CHECK_NEEDS_NETWORK=1
        system_check_row miss "limits" "nofile/systemd limits не настроены"
    fi

    if [[ "$MACHINE_MODE" == "node" ]]; then
        [[ "$(service_ok chrony)" == "1" ]] || service_issues+=("chrony")
        root_file_has_line /etc/default/cpufrequtils 'GOVERNOR="performance"' || service_issues+=("cpufrequtils")
        if (( ${#service_issues[@]} == 0 )); then
            system_check_row ok "node services" "chrony, performance"
        else
            SYSTEM_CHECK_NEEDS_NETWORK=1
            system_check_row miss "node services" "нет: $(system_check_join "${service_issues[@]}")"
        fi

        cpus="$(cpu_count)"
        if (( cpus <= 1 )); then
            system_check_row skip "irqbalance" "${cpus} CPU, балансировать нечего"
        elif [[ "$(service_ok irqbalance)" == "1" ]]; then
            system_check_row ok "irqbalance" "${cpus} CPU"
        else
            SYSTEM_CHECK_NEEDS_NETWORK=1
            system_check_row miss "irqbalance" "не active, CPU: ${cpus}"
        fi
    fi
}

system_check_firewall() {
    local ssh_port="$1"
    local missing=() extra=()

    if ! command_exists ufw; then
        SYSTEM_CHECK_NEEDS_FIREWALL=1
        system_check_row miss "ufw" "не установлен"
        return 0
    fi

    if ufw_active; then
        system_check_row ok "ufw" "active"
    else
        SYSTEM_CHECK_NEEDS_FIREWALL=1
        system_check_row miss "ufw" "не active"
    fi

    ufw_rule_allowed "${ssh_port}/tcp" || missing+=("${ssh_port}/tcp")
    ufw_rule_allowed "443/tcp" || missing+=("443/tcp")
    if [[ "$MACHINE_MODE" == "node" ]]; then
        ufw_rule_allowed "443/udp" || missing+=("443/udp")
        ufw_rule_allowed "${NODE_PORT}/tcp" || missing+=("${NODE_PORT}/tcp")
    else
        ufw_rule_allowed "443/udp" && extra+=("443/udp")
        ufw_rule_allowed "${NODE_PORT}/tcp" && extra+=("${NODE_PORT}/tcp")
    fi

    if (( ${#missing[@]} == 0 && ${#extra[@]} == 0 )); then
        system_check_row ok "ufw rules" "$(ufw_allowed_ports)"
    else
        SYSTEM_CHECK_NEEDS_FIREWALL=1
        if (( ${#missing[@]} > 0 && ${#extra[@]} > 0 )); then
            system_check_row miss "ufw rules" "нет: $(system_check_join "${missing[@]}"); лишние: $(system_check_join "${extra[@]}")"
        elif (( ${#missing[@]} > 0 )); then
            system_check_row miss "ufw rules" "нет: $(system_check_join "${missing[@]}")"
        else
            system_check_row miss "ufw rules" "лишние: $(system_check_join "${extra[@]}")"
        fi
    fi
}

system_check_antiscanner() {
    local rules enabled=0 details=()
    rules="$(antiscanner_rules_count)"
    "${SUDO[@]}" systemctl is-enabled --quiet antiscanner-update.service 2>/dev/null && enabled=1 || true

    [[ -x "$ANTISCANNER_SCRIPT" ]] || details+=("скрипт")
    [[ "$rules" =~ ^[0-9]+$ && "$rules" -gt 0 ]] || details+=("rules=${rules}")
    [[ "$enabled" == "1" ]] || details+=("systemd")

    if (( ${#details[@]} == 0 )); then
        system_check_row ok "antiscanner" "${rules} rules"
    else
        SYSTEM_CHECK_NEEDS_ANTISCANNER=1
        system_check_row miss "antiscanner" "нет: $(system_check_join "${details[@]}")"
    fi
}

system_check_fail2ban() {
    local missing=()

    package_installed fail2ban || missing+=("package")
    [[ "$(service_ok fail2ban)" == "1" ]] || missing+=("service")
    [[ "$(file_ok /etc/fail2ban/jail.d/99-kto-sshd.conf)" == "1" ]] || missing+=("jail")

    if (( ${#missing[@]} == 0 )); then
        system_check_row ok "fail2ban" "ssh guard"
    else
        SYSTEM_CHECK_NEEDS_FAIL2BAN=1
        system_check_row miss "fail2ban" "нет: $(system_check_join "${missing[@]}")"
    fi
}

system_check_apply_missing() {
    local ssh_port="$1"
    local steps=0 started_at duration

    (( SYSTEM_CHECK_NEEDS_PREPARE == 1 )) && steps=$(( steps + 1 ))
    (( SYSTEM_CHECK_NEEDS_PACKAGES == 1 )) && steps=$(( steps + 1 ))
    (( SYSTEM_CHECK_NEEDS_KERNEL == 1 )) && steps=$(( steps + 1 ))
    (( SYSTEM_CHECK_NEEDS_NETWORK == 1 )) && steps=$(( steps + 1 ))
    (( SYSTEM_CHECK_NEEDS_FIREWALL == 1 )) && steps=$(( steps + 1 ))
    (( SYSTEM_CHECK_NEEDS_ANTISCANNER == 1 )) && steps=$(( steps + 1 ))
    (( SYSTEM_CHECK_NEEDS_FAIL2BAN == 1 )) && steps=$(( steps + 1 ))
    (( SYSTEM_CHECK_NEEDS_STORAGE == 1 )) && steps=$(( steps + 1 ))
    (( SYSTEM_CHECK_NEEDS_MEMORY_GUARD == 1 )) && steps=$(( steps + 1 ))

    if (( steps == 0 )); then
        ok "Недостающих действий нет."
        return 0
    fi

    export NEEDRESTART_MODE=a
    export NEEDRESTART_SUSPEND=1

    started_at="$(date +%s)"
    progress_start "$steps"
    (( SYSTEM_CHECK_NEEDS_PREPARE == 1 )) && progress_step "Готовлю систему" opt_prepare_system
    (( SYSTEM_CHECK_NEEDS_PACKAGES == 1 )) && progress_step "Ставлю пакеты" opt_install_packages
    (( SYSTEM_CHECK_NEEDS_KERNEL == 1 )) && progress_step "Обновляю kernel" opt_liquorix_kernel
    (( SYSTEM_CHECK_NEEDS_NETWORK == 1 )) && progress_step "Настраиваю сеть" opt_network_limits
    (( SYSTEM_CHECK_NEEDS_STORAGE == 1 )) && progress_step "Настраиваю хранение" opt_storage_guard
    (( SYSTEM_CHECK_NEEDS_MEMORY_GUARD == 1 )) && progress_step "Настраиваю память" opt_memory_guard
    (( SYSTEM_CHECK_NEEDS_FIREWALL == 1 )) && progress_step "Настраиваю firewall" opt_firewall "$ssh_port"
    (( SYSTEM_CHECK_NEEDS_ANTISCANNER == 1 )) && progress_step "Подключаю AntiScanner" opt_antiscanner
    (( SYSTEM_CHECK_NEEDS_FAIL2BAN == 1 )) && progress_step "Настраиваю Fail2ban" opt_fail2ban

    echo
    duration=$(( $(date +%s) - started_at ))
    ok "Недостающие блоки применены"
    ok "Время: $(format_duration "$duration")"
}

system_check_pause() {
    local answer
    echo
    echo -ne "${PURPLE}>${NC} ${BOLD}Нажмите Enter, чтобы вернуться:${NC} "
    read -r answer
}

system_check() {
    header
    need_root
    system_check_reset

    local ssh_port choice
    ssh_port="$(detect_ssh_port)"

    echo -e "${BOLD}${PURPLE}[ ПРОВЕРКА СИСТЕМЫ ]${NC}"
    print_row "mode" "$MACHINE_MODE"
    if [[ "$MACHINE_MODE" == "node" ]]; then
        print_row "profile" "$(node_profile_label)"
    fi
    print_row "ssh port" "$ssh_port"

    echo
    echo -e "${BOLD}${PURPLE}[ ПАМЯТЬ ]${NC}"
    system_check_memory

    echo
    echo -e "${BOLD}${PURPLE}[ ДИСК ]${NC}"
    system_check_storage

    echo
    echo -e "${BOLD}${PURPLE}[ OPTIMIZATION AUDIT ]${NC}"
    system_check_prepare_state
    system_check_packages
    system_check_kernel
    system_check_network_limits
    system_check_firewall "$ssh_port"
    system_check_antiscanner
    system_check_fail2ban

    echo
    echo -e "${BOLD}${PURPLE}[ ВЫВОД ]${NC}"
    if (( SYSTEM_CHECK_MISSING == 0 && SYSTEM_CHECK_NEEDS_ZRAM == 0 )); then
        ok "Критичных недостающих блоков не найдено."
        if (( SYSTEM_CHECK_WARNINGS > 0 )); then
            warn "Есть предупреждения, но автоматического исправления не требуется."
        fi
        system_check_pause
        return 0
    fi

    if (( SYSTEM_CHECK_MISSING > 0 )); then
        warn "Найдено блоков к исправлению: ${SYSTEM_CHECK_MISSING}"
    elif (( SYSTEM_CHECK_NEEDS_ZRAM == 1 )); then
        warn "Критичных недостающих блоков нет, но для маленькой VPS рекомендую ZRAM."
    fi
    if (( SYSTEM_CHECK_WARNINGS > 0 )); then
        warn "Предупреждений: ${SYSTEM_CHECK_WARNINGS}"
    fi
    echo
    if (( SYSTEM_CHECK_MISSING > 0 )); then
        echo -e "1) Исправить только недостающее"
        echo -e "2) Запустить полную оптимизацию"
    fi
    if (( SYSTEM_CHECK_NEEDS_ZRAM == 1 )); then
        echo -e "3) Включить ZRAM ($(format_mb "$(recommended_zram_mb)"))"
    fi
    echo -e "0) Ничего не делать"
    echo -e "${PURPLE}==========================================${NC}"
    echo -ne "${PURPLE}>${NC} ${BOLD}Выберите действие:${NC} "
    read -r choice

    case "$choice" in
        1)
            if (( SYSTEM_CHECK_MISSING > 0 )); then
                system_check_apply_missing "$ssh_port"
            else
                fail "Неверный выбор"
            fi
            ;;
        2)
            if (( SYSTEM_CHECK_MISSING > 0 )); then
                optimize_system
            else
                fail "Неверный выбор"
            fi
            ;;
        3)
            if (( SYSTEM_CHECK_NEEDS_ZRAM == 1 )); then
                opt_zram
            else
                fail "Неверный выбор"
            fi
            ;;
        0)
            ok "Оставил систему без изменений."
            ;;
        *)
            fail "Неверный выбор"
            ;;
    esac

    system_check_pause
}

optimize_system() {
    header
    need_root
    local ssh_port started_at duration
    started_at="$(date +%s)"
    ssh_port="$(detect_ssh_port)"

    export NEEDRESTART_MODE=a
    export NEEDRESTART_SUSPEND=1

    progress_start 9
    progress_step "Готовлю систему" opt_prepare_system
    progress_step "Ставлю пакеты" opt_install_packages
    progress_step "Настраиваю хранение" opt_storage_guard
    progress_step "Обновляю kernel" opt_liquorix_kernel
    progress_step "Настраиваю сеть" opt_network_limits
    progress_step "Настраиваю память" opt_memory_guard
    progress_step "Настраиваю firewall" opt_firewall "$ssh_port"
    progress_step "Подключаю AntiScanner" opt_antiscanner
    progress_step "Настраиваю Fail2ban" opt_fail2ban

    echo
    duration=$(( $(date +%s) - started_at ))
    ok "Оптимизация завершена. Рекомендуется: sudo reboot"
    ok "Время: $(format_duration "$duration")"
}

do_install_remnawave_node() {
    local secret escaped
    secret="$1"
    if [[ -z "$secret" ]]; then
        fail "SECRET_KEY не может быть пустым"
        exit 1
    fi
    escaped="$(escape_yaml_secret "$secret")"

    ensure_docker

    stage "Готовлю Remnawave Node ($(node_profile_label))"
    cmd "${SUDO[@]}" mkdir -p "$REMNA_DIR"
    if [[ "$NODE_PROFILE" == "hysteria2" ]]; then
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
    volumes:
      - /opt/remnawave:/opt/remnawave:ro
    environment:
      - NODE_PORT=1488
      - SECRET_KEY="${escaped}"
EOF
    else
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
    fi

    stage "Запускаю контейнер"
    if ! (cd "$REMNA_DIR" && "${SUDO[@]}" docker compose config >/dev/null) >> "$LOG_FILE" 2>&1; then
        fail "docker-compose.yml"
        tail -n 25 "$LOG_FILE" >&2 || true
        exit 1
    fi
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

install_remnawave_node() {
    header
    require_node_mode
    need_root
    local secret
    secret="$(ask_secret_key)"
    do_install_remnawave_node "$secret"
}

do_install_selfsteal() {
    local domain="$1"
    if ! validate_domain "$domain"; then
        fail "Некорректный домен для SelfSteal"
        exit 1
    fi
    stage "Устанавливаю SelfSteal"
    must "SelfSteal install" \
        "${SUDO[@]}" bash -c \
        'bash <(curl -Ls "https://github.com/DigneZzZ/remnawave-scripts/raw/main/selfsteal.sh") --force --domain "$1" install' \
        _ "$domain"

    echo
    ok "SelfSteal установлен"
}

install_selfsteal() {
    header
    require_reality_profile
    need_root
    local domain
    domain="$(ask_domain "Введите домен")"
    do_install_selfsteal "$domain"
}

do_install_warp_native() {
    stage "Устанавливаю WARP Native"
    local script
    script="$(mktemp)"
    must "Скачивание WARP" curl -fsSL https://raw.githubusercontent.com/distillium/warp-native/main/install.sh -o "$script"
    if ! printf '2\n1\n' | "${SUDO[@]}" bash "$script" >> "$LOG_FILE" 2>&1; then
        rm -f "$script"
        fail "WARP не установился"
        tail -n 25 "$LOG_FILE" >&2 || true
        exit 1
    fi
    rm -f "$script"
    echo
    ok "WARP установлен"
}

install_warp_native() {
    header
    require_node_mode
    need_root
    do_install_warp_native
}

speedtest_row() {
    local label="$1"
    local value="$2"
    [[ -n "$value" ]] || return 0
    printf " %-11s %b\n" "$label" "$value"
}

speedtest_clean_output() {
    local output="$1"
    output="${output//$'\r'/$'\n'}"
    output="$(sed -r 's/\x1B\[[0-9;?]*[ -/]*[@-~]//g' <<< "$output")"
    sed -E '/^[[:space:]]*(Download|Upload):.*\[[^]]*\][[:space:]]*[0-9]+%/d' <<< "$output"
}

speedtest_live_status() {
    local output_file="$1"
    local elapsed="$2"
    local output server latency download upload

    output="$(cat "$output_file" 2>/dev/null || true)"
    output="${output//$'\r'/$'\n'}"
    output="$(sed -r 's/\x1B\[[0-9;?]*[ -/]*[@-~]//g' <<< "$output")"

    server="$(awk '/^[[:space:]]*Server:/ {sub(/^[[:space:]]*Server:[[:space:]]*/, ""); print; exit}' <<< "$output")"
    latency="$(awk '/^[[:space:]]*Idle Latency:/ {sub(/^[[:space:]]*Idle Latency:[[:space:]]*/, ""); sub(/[[:space:]]+\(.*/, ""); print; exit}' <<< "$output")"
    download="$(awk '
        /^[[:space:]]*Download:.*\(data used:/ {line=$0}
        END {sub(/^[[:space:]]*Download:[[:space:]]*/, "", line); sub(/[[:space:]]+\(data used:.*/, "", line); print line}
    ' <<< "$output")"
    upload="$(awk '
        /^[[:space:]]*Upload:.*\(data used:/ {line=$0}
        END {sub(/^[[:space:]]*Upload:[[:space:]]*/, "", line); sub(/[[:space:]]+\(data used:.*/, "", line); print line}
    ' <<< "$output")"

    if [[ -z "$download" ]] && grep -Eq '^[[:space:]]*Download:' <<< "$output"; then
        download="идёт"
    fi
    if [[ -z "$upload" ]] && grep -Eq '^[[:space:]]*Upload:' <<< "$output"; then
        upload="идёт"
    fi

    printf '[..] Speedtest %ss' "$elapsed"
    [[ -n "$server" ]] && printf ' | server: %.36s' "$server"
    [[ -n "$latency" ]] && printf ' | ping: %s' "$latency"
    [[ -n "$download" ]] && printf ' | down: %s' "$download"
    [[ -n "$upload" ]] && printf ' | up: %s' "$upload"
}

run_speedtest_live() {
    local output_file="$1"
    shift
    local pid rc start now elapsed

    : > "$output_file"
    if command_exists timeout; then
        timeout --foreground "${SPEEDTEST_TIMEOUT}s" "$@" > "$output_file" 2>&1 &
    else
        "$@" > "$output_file" 2>&1 &
    fi
    pid=$!
    start="$(date +%s)"

    while kill -0 "$pid" 2>/dev/null; do
        now="$(date +%s)"
        elapsed=$(( now - start ))
        printf '\r\033[K%s' "$(speedtest_live_status "$output_file" "$elapsed")"
        sleep 1
    done

    if wait "$pid"; then
        rc=0
    else
        rc=$?
    fi
    printf '\r\033[K'
    cat "$output_file" >> "$LOG_FILE" 2>/dev/null || true
    return "$rc"
}

print_speedtest_result() {
    local output="$1"
    local filtered server isp latency download download_detail upload upload_detail loss url

    output="$(speedtest_clean_output "$output")"
    filtered="$(sed -n '/Speedtest by Ookla/,/Result URL:/p' <<< "$output")"
    [[ -n "$filtered" ]] || return 1

    server="$(awk '/^[[:space:]]*Server:/ {sub(/^[[:space:]]*Server:[[:space:]]*/, ""); print; exit}' <<< "$filtered")"
    isp="$(awk '/^[[:space:]]*ISP:/ {sub(/^[[:space:]]*ISP:[[:space:]]*/, ""); print; exit}' <<< "$filtered")"
    latency="$(awk '/^[[:space:]]*Idle Latency:/ {sub(/^[[:space:]]*Idle Latency:[[:space:]]*/, ""); print; exit}' <<< "$filtered")"
    download="$(awk '/^[[:space:]]*Download:/ {line=$0} END {sub(/^[[:space:]]*Download:[[:space:]]*/, "", line); print line}' <<< "$filtered")"
    download_detail="$(awk '
        /^[[:space:]]*Download:/ {seen=1; detail=""; next}
        seen && /^[[:space:]]+[0-9.]+[[:space:]]+ms/ {sub(/^[[:space:]]+/,""); detail=$0; seen=0}
        END {print detail}
    ' <<< "$filtered")"
    upload="$(awk '/^[[:space:]]*Upload:/ {line=$0} END {sub(/^[[:space:]]*Upload:[[:space:]]*/, "", line); print line}' <<< "$filtered")"
    upload_detail="$(awk '
        /^[[:space:]]*Upload:/ {seen=1; detail=""; next}
        seen && /^[[:space:]]+[0-9.]+[[:space:]]+ms/ {sub(/^[[:space:]]+/,""); detail=$0; seen=0}
        END {print detail}
    ' <<< "$filtered")"
    loss="$(awk '/^[[:space:]]*Packet Loss:/ {sub(/^[[:space:]]*Packet Loss:[[:space:]]*/, ""); print; exit}' <<< "$filtered")"
    url="$(awk '/^[[:space:]]*Result URL:/ {sub(/^[[:space:]]*Result URL:[[:space:]]*/, ""); print; exit}' <<< "$filtered")"

    [[ -n "$download" || -n "$upload" || -n "$latency" ]] || return 1

    echo -e "${BOLD}${PURPLE}[ SPEEDTEST BY OOKLA ]${NC}"
    speedtest_row "Server" "$server"
    speedtest_row "ISP" "$isp"
    speedtest_row "Latency" "$latency"
    speedtest_row "Download" "${GREEN}${download}${NC}"
    speedtest_row "" "$download_detail"
    speedtest_row "Upload" "${GREEN}${upload}${NC}"
    speedtest_row "" "$upload_detail"
    speedtest_row "Loss" "$loss"
    speedtest_row "Result" "$url"
}

install_speedtest() {
    header
    need_root
    local output filtered output_file archive arch url rc
    stage "Готовлю Speedtest"
    if [[ -x /usr/local/bin/speedtest ]] && command_exists timeout; then
        if ! timeout --foreground 10s /usr/local/bin/speedtest --version >> "$LOG_FILE" 2>&1; then
            warn "Speedtest binary не отвечает, переустановлю."
            cmd "${SUDO[@]}" rm -f /usr/local/bin/speedtest || true
        fi
    fi
    if ! [[ -x /usr/local/bin/speedtest ]]; then
        cmd "${SUDO[@]}" apt-get remove -y speedtest-cli || true
        cmd "${SUDO[@]}" rm -f /usr/bin/speedtest /usr/local/bin/speedtest || true
        arch="$(uname -m)"
        if [[ "$arch" == "aarch64" || "$arch" == "arm64" ]]; then
            url="https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-aarch64.tgz"
        else
            url="https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-x86_64.tgz"
        fi
        archive="$(mktemp)"
        output_file="$(mktemp)"
        stage "Скачиваю Ookla CLI"
        if run_live_capture_timeout "$SPEEDTEST_DOWNLOAD_TIMEOUT" "$output_file" \
            curl -fL --progress-bar --connect-timeout 10 --retry 2 --retry-delay 2 --max-time "$SPEEDTEST_DOWNLOAD_TIMEOUT" \
            -o "$archive" "$url"; then
            rc=0
        else
            rc=$?
        fi
        if (( rc != 0 )); then
            rm -f "$archive" "$output_file"
            fail "Скачивание Speedtest"
            if (( rc == 124 )); then
                warn "Скачивание зависло дольше ${SPEEDTEST_DOWNLOAD_TIMEOUT}s."
            fi
            return 1
        fi
        rm -f "$output_file"
        must "Распаковка Speedtest" "${SUDO[@]}" tar xzf "$archive" -C /usr/local/bin speedtest
        rm -f "$archive"
    else
        echo "Speedtest binary skipped: already installed" >> "$LOG_FILE"
    fi
    echo
    stage "Запускаю Speedtest"
    output_file="$(mktemp)"
    if run_speedtest_live "$output_file" \
        /usr/local/bin/speedtest --accept-license --accept-gdpr --progress=yes; then
        rc=0
    else
        rc=$?
    fi
    echo
    output="$(cat "$output_file" 2>/dev/null || true)"
    if print_speedtest_result "$output"; then
        rm -f "$output_file"
        return 0
    fi
    if (( rc != 0 )); then
        if (( rc == 124 )); then
            rm -f "$output_file"
            fail "Speedtest завис дольше ${SPEEDTEST_TIMEOUT}s"
            return 1
        fi
        warn "Ookla завершился с кодом ${rc}, пробую повтор без progress."
        : > "$output_file"
        if run_speedtest_live "$output_file" \
            /usr/local/bin/speedtest --accept-license --accept-gdpr --progress=no; then
            rc=0
        else
            rc=$?
        fi
        echo
        output="$(cat "$output_file" 2>/dev/null || true)"
        if print_speedtest_result "$output"; then
            rm -f "$output_file"
            return 0
        fi
        if (( rc != 0 )); then
            rm -f "$output_file"
            fail "Speedtest"
            printf '%s\n' "$(speedtest_clean_output "$output")" >&2
            return "$rc"
        fi
    fi
    rm -f "$output_file"

    warn "Не смог красиво распарсить результат, оставляю сырой вывод."
    output="$(speedtest_clean_output "$output")"
    filtered="$(sed -n '/Speedtest by Ookla/,/Result URL:/p' <<< "$output")"
    if [[ -n "$filtered" ]]; then
        printf '%s\n' "$filtered"
    else
        printf '%s\n' "$output"
    fi
}

ipcheck_place() {
    header
    stage "Проверяю IP.Check.Place"
    if ! bash <(curl -Ls https://IP.Check.Place) -l en; then
        warn "IP.Check.Place завершился с нестандартным кодом, вывод выше оставил как есть."
    fi
}

ipcheck_region() {
    header
    stage "Проверяю регион IP"
    if ! bash <(wget -qO- https://github.com/Davoyan/ipregion/raw/main/ipregion.sh); then
        warn "Region Check завершился с нестандартным кодом, вывод выше оставил как есть."
    fi
}

container_running() {
    local name="$1"
    command_exists docker && "${SUDO[@]}" docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$name"
}

do_issue_ssl_certificate() {
    local domain="$1"
    local email had_80=0 stopped=()
    if ! validate_domain "$domain"; then
        fail "Некорректный домен для SSL"
        exit 1
    fi
    email="admin@${domain}"

    stage "Генерация SSL"
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
        return 1
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

issue_ssl_certificate() {
    header
    require_hysteria2_profile
    need_root
    local domain
    domain="$(ask_domain "Введите домен")"
    do_issue_ssl_certificate "$domain"
}

install_common_stack() {
    header
    require_node_mode
    need_root
    local secret domain started_at duration

    secret="$(ask_secret_key)"
    domain="$(ask_domain "Введите домен")"

    started_at="$(date +%s)"
    echo

    if [[ "$NODE_PROFILE" == "reality" ]]; then
        stage "Общее поднятие Reality"
        do_install_remnawave_node "$secret"
        do_install_selfsteal "$domain"
        do_install_warp_native
    elif [[ "$NODE_PROFILE" == "hysteria2" ]]; then
        stage "Общее поднятие Hysteria2"
        do_issue_ssl_certificate "$domain"
        do_install_remnawave_node "$secret"
        do_install_warp_native
    else
        fail "Неизвестный профиль node"
        exit 1
    fi

    duration=$(( $(date +%s) - started_at ))
    echo
    ok "Общее поднятие завершено"
    ok "Время: $(format_duration "$duration")"
}

apply_haproxy_config() {
    local backend_ip="$1"
    local allowed_sni="$2"

    stage "Настраиваю HAProxy"
    write_root_file /etc/haproxy/haproxy.cfg <<EOF
global
    maxconn 200000
    nbthread 32
    tune.ssl.default-dh-param 2048
    tune.maxaccept 10000
    tune.bufsize 65536

defaults
    log global
    mode tcp
    option tcplog
    option dontlognull

    option clitcpka
    option srvtcpka
    option tcp-smart-accept
    option tcp-smart-connect
    option splice-auto
    option splice-request
    option splice-response

    timeout connect 5s
    timeout client 2h
    timeout server 2h
    timeout tunnel 2h

    default-server inter 30s fall 8 rise 3


# -------------------------
# FRONTEND : 443
# -------------------------
frontend vless_in
    bind *:443
    tcp-request inspect-delay 5s
    acl clienthello req.ssl_hello_type 1
    acl allowed_sni req.ssl_sni -i ${allowed_sni}
    tcp-request content accept if clienthello allowed_sni
    tcp-request content reject if clienthello !allowed_sni
    tcp-request content reject if WAIT_END
    default_backend vless_pool

backend vless_pool
    mode tcp
    balance leastconn

    server xray1 ${backend_ip}:443 weight 10
EOF

    if ! "${SUDO[@]}" haproxy -c -f /etc/haproxy/haproxy.cfg >> "$LOG_FILE" 2>&1; then
        fail "Проверка HAProxy config"
        tail -n 25 "$LOG_FILE" >&2 || true
        return 1
    fi

    cmd "${SUDO[@]}" systemctl enable haproxy || true
    must "Перезапуск HAProxy" "${SUDO[@]}" systemctl restart haproxy

    ok "HAProxy установлен: 443 -> ${backend_ip}:443"
    ok "Разрешенный SNI: ${allowed_sni}"
}

ensure_haproxy_package() {
    if command_exists haproxy; then
        return 0
    fi
    stage "Устанавливаю HAProxy"
    must "apt update" apt_update_quiet
    must "Установка HAProxy" apt_install_quiet haproxy
}

harden_whitelist_haproxy_firewall() {
    command_exists ufw || return 0
    ufw_active || return 0

    cmd "${SUDO[@]}" ufw allow 443/tcp || true
    cmd "${SUDO[@]}" ufw --force delete allow 443/udp || true
    cmd "${SUDO[@]}" ufw --force delete allow "${NODE_PORT}/tcp" || true
}

configure_haproxy_backend() {
    header
    require_whitelist_mode
    need_root
    local backend_ip allowed_sni
    backend_ip="$(ask_ipv4 "Введите выходной IP")"
    allowed_sni="$(ask_domain "Введите разрешенный SNI")"

    ensure_haproxy_package
    apply_haproxy_config "$backend_ip" "$allowed_sni"
    harden_whitelist_haproxy_firewall
}

install_haproxy() {
    configure_haproxy_backend
}

write_stats_collector_script() {
    write_root_file_mode 0755 "$STATS_COLLECTOR_SCRIPT" <<'EOF'
#!/usr/bin/env python3
import html
import json
import os
import re
import socket
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

COLLECTOR_BUILD = "v140"
CONFIG = os.environ.get("KTO_STATS_COLLECTOR_CONFIG", "/etc/kto-stats-collector.conf")


def load_config(path):
    data = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                value = value.strip()
                if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
                    value = value[1:-1].replace('\\"', '"').replace("\\\\", "\\")
                data[key.strip()] = value
    except FileNotFoundError:
        pass
    return data


cfg = load_config(CONFIG)
LISTEN_HOST = cfg.get("KTO_COLLECTOR_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(cfg.get("KTO_COLLECTOR_LISTEN_PORT", "9788"))
SECRET = cfg.get("KTO_COLLECTOR_SECRET", "")
BOT_TOKEN = cfg.get("KTO_COLLECTOR_BOT_TOKEN", "")
CHAT_ID = cfg.get("KTO_COLLECTOR_CHAT_ID", "")
ALLOWED_USER_ID = str(cfg.get("KTO_COLLECTOR_ALLOWED_USER_ID", "646296998"))
STATE_DIR = cfg.get("KTO_COLLECTOR_STATE_DIR", "/var/lib/kto-stats-collector")
STALE_SEC = int(cfg.get("KTO_COLLECTOR_STALE_SEC", "60"))
CHECK_INTERVAL = int(cfg.get("KTO_COLLECTOR_CHECK_INTERVAL", "30"))
TZ_NAME = cfg.get("KTO_COLLECTOR_TZ", "Europe/Moscow")
DAILY_REPORT_TIME = cfg.get("KTO_COLLECTOR_DAILY_REPORT_TIME", "").strip()
try:
    EXPECTED_NODES = int(cfg.get("KTO_COLLECTOR_EXPECTED_NODES", "10") or "10")
except Exception:
    EXPECTED_NODES = 10
if EXPECTED_NODES < 1:
    EXPECTED_NODES = 10

NODES_FILE = os.path.join(STATE_DIR, "nodes.json")
FALLS_FILE = os.path.join(STATE_DIR, "falls.json")
OFFSET_FILE = os.path.join(STATE_DIR, "telegram_offset")
DAILY_FILE = os.path.join(STATE_DIR, "daily_report_date")
LOCK = threading.RLock()
NODES = {}
FALLS = {}

if TZ_NAME:
    os.environ["TZ"] = TZ_NAME
    try:
        time.tzset()
    except AttributeError:
        pass

_getaddrinfo = socket.getaddrinfo


def getaddrinfo_ipv4(host, port, family=0, socktype=0, proto=0, flags=0):
    return _getaddrinfo(host, port, socket.AF_INET, socktype, proto, flags)


socket.getaddrinfo = getaddrinfo_ipv4


def log(message):
    print(f"collector {COLLECTOR_BUILD}: {message}", flush=True)


def now_ts():
    return int(time.time())


def atomic_write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=os.path.dirname(path))
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(content)
    os.replace(tmp, path)


def load_nodes():
    global NODES
    os.makedirs(STATE_DIR, exist_ok=True)
    try:
        with open(NODES_FILE, "r", encoding="utf-8") as fh:
            loaded = json.load(fh)
            if isinstance(loaded, dict):
                NODES = loaded
    except Exception:
        NODES = {}


def save_nodes():
    atomic_write(NODES_FILE, json.dumps(NODES, ensure_ascii=False, indent=2, sort_keys=True))


def load_falls():
    global FALLS
    os.makedirs(STATE_DIR, exist_ok=True)
    try:
        with open(FALLS_FILE, "r", encoding="utf-8") as fh:
            loaded = json.load(fh)
            if isinstance(loaded, dict):
                FALLS = loaded
    except Exception:
        FALLS = {}


def save_falls():
    atomic_write(FALLS_FILE, json.dumps(FALLS, ensure_ascii=False, indent=2, sort_keys=True))


def today_key():
    return datetime.fromtimestamp(now_ts()).strftime("%Y-%m-%d")


def ensure_today_falls():
    day = today_key()
    if FALLS.get("date") != day:
        FALLS.clear()
        FALLS.update({"date": day, "total": 0, "downtime_sec": 0, "downtime_revoke_sec": 0, "nodes": {}})
    elif not isinstance(FALLS.get("nodes"), dict):
        FALLS["nodes"] = {}
    if "downtime_sec" not in FALLS:
        FALLS["downtime_sec"] = 0
    if "downtime_revoke_sec" not in FALLS:
        FALLS["downtime_revoke_sec"] = 0
    return FALLS


def record_fall(node):
    falls = ensure_today_falls()
    name = str(node.get("name") or node.get("id") or "unknown")
    falls["total"] = int(falls.get("total", 0) or 0) + 1
    nodes = falls.setdefault("nodes", {})
    nodes[name] = int(nodes.get(name, 0) or 0) + 1
    try:
        save_falls()
    except Exception as exc:
        log(f"save falls failed: {exc}")


def record_downtime(seconds):
    seconds = max(0, int(seconds or 0))
    if seconds <= 0:
        return
    falls = ensure_today_falls()
    falls["downtime_sec"] = int(falls.get("downtime_sec", 0) or 0) + seconds
    try:
        save_falls()
    except Exception as exc:
        log(f"save downtime failed: {exc}")


def revoke_downtime(seconds):
    seconds = max(0, int(seconds or 0))
    if seconds <= 0:
        return
    falls = ensure_today_falls()
    falls["downtime_revoke_sec"] = int(falls.get("downtime_revoke_sec", 0) or 0) + seconds
    try:
        save_falls()
    except Exception as exc:
        log(f"save downtime revoke failed: {exc}")


def reset_daily_falls(nodes, ts):
    active_downtime = 0
    for node in nodes:
        last_seen = int(node.get("last_seen", 0) or 0)
        age = ts - last_seen
        if age > STALE_SEC:
            offline_since = int(node.get("offline_since") or last_seen or ts)
            active_downtime += max(0, ts - offline_since)
    falls = ensure_today_falls()
    falls["total"] = 0
    falls["nodes"] = {}
    falls["downtime_sec"] = 0
    falls["downtime_revoke_sec"] = active_downtime
    try:
        save_falls()
    except Exception as exc:
        log(f"save full revoke failed: {exc}")


def format_bytes(value):
    try:
        value = float(value)
    except Exception:
        value = 0.0
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    idx = 0
    while value >= 1024 and idx < len(units) - 1:
        value /= 1024.0
        idx += 1
    if idx == 0:
        return f"{value:.0f} {units[idx]}"
    return f"{value:.1f} {units[idx]}"


def format_percent(value):
    try:
        value = float(value)
    except Exception:
        value = 0.0
    if value <= 0:
        return "0%"
    if value < 0.1:
        return "<0.1%"
    if value >= 10:
        return f"{value:.0f}%"
    return f"{value:.1f}%"


def format_age(seconds):
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m"
    hours = minutes // 60
    return f"{hours}h {minutes % 60}m"


def plural_ru(value, one, few, many):
    value = abs(int(value))
    last_two = value % 100
    last = value % 10
    if 11 <= last_two <= 14:
        return many
    if last == 1:
        return one
    if 2 <= last <= 4:
        return few
    return many


def format_duration_ru(seconds):
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds} {plural_ru(seconds, 'секунда', 'секунды', 'секунд')}"
    minutes = seconds // 60
    rest_seconds = seconds % 60
    if minutes < 60:
        result = f"{minutes} {plural_ru(minutes, 'минута', 'минуты', 'минут')}"
        if rest_seconds:
            result += f" {rest_seconds} {plural_ru(rest_seconds, 'секунда', 'секунды', 'секунд')}"
        return result
    hours = minutes // 60
    rest_minutes = minutes % 60
    result = f"{hours} {plural_ru(hours, 'час', 'часа', 'часов')}"
    if rest_minutes:
        result += f" {rest_minutes} {plural_ru(rest_minutes, 'минута', 'минуты', 'минут')}"
    return result


def fmt_time(ts):
    try:
        return datetime.fromtimestamp(int(ts)).strftime("%d.%m.%Y %H:%M")
    except Exception:
        return "-"


def natural_sort_key(value):
    text = str(value or "").casefold()
    key = []
    for part in re.split(r"(\d+)", text):
        if not part:
            continue
        if part.isdigit():
            key.append((1, int(part)))
        else:
            key.append((0, part))
    return key


def canonical_node_key(value):
    text = re.sub(r"[^\w]+", "", str(value or "").casefold(), flags=re.UNICODE)
    parts = []
    for part in re.split(r"(\d+)", text):
        if not part:
            continue
        if part.isdigit():
            parts.append(str(int(part)))
        else:
            parts.append(part)
    return "".join(parts)


def node_canonical_key(node):
    return canonical_node_key(node.get("name") or node.get("id") or "")


def tg_call(method, data=None, timeout=25):
    if not BOT_TOKEN:
        raise RuntimeError("telegram bot token is empty")
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/{method}"
    encoded = urllib.parse.urlencode(data or {}).encode("utf-8")
    req = urllib.request.Request(url, data=encoded, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", errors="replace")
    parsed = json.loads(body)
    if not parsed.get("ok"):
        raise RuntimeError(body[:700])
    return parsed


def send_message(text):
    if not CHAT_ID:
        log("telegram chat id is empty")
        return False
    try:
        result = tg_call("sendMessage", {
            "chat_id": CHAT_ID,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": "true",
        })
        msg = result.get("result", {})
        log(f"telegram sent message_id={msg.get('message_id')} chat_id={msg.get('chat', {}).get('id')}")
        return True
    except Exception as exc:
        log(f"telegram send failed: {exc}")
        return False


def node_message(node, status=None):
    name = html.escape(str(node.get("name") or node.get("id") or "unknown"))
    ip = html.escape(str(node.get("ip") or "-"))
    uptime_sec = int(node.get("uptime_sec") or 0)
    uptime_text = format_duration_ru(uptime_sec) if uptime_sec > 0 else "-"
    error = str(node.get("error") or "")
    updated = node.get("updated_at") or node.get("last_seen") or 0
    metrics_ok = bool(node.get("metrics_ok"))
    status_text = html.escape(str(status or "OK"))
    footer = f"<i>Обновлено: {fmt_time(updated)} | Статус: {status_text}</i>"
    ram_line = "Забитость ОЗУ: ?% | ? / ?"
    cpu_line = "Нагруженность процессора: ?%"
    if metrics_ok:
        ram_line = f"Забитость ОЗУ: {int(node.get('ram_percent', 0) or 0)}% | {format_bytes(node.get('ram_used', 0))} / {format_bytes(node.get('ram_total', 0))}"
        cpu_line = f"Нагруженность процессора: {format_percent(node.get('cpu_percent', 0))}"
    lines = [f"<blockquote><b>{name}</b>\nIP: {ip}\nАптайм: {uptime_text}</blockquote>", ""]
    if error:
        lines += [
            "I/O: - | -",
            "<b>Сегодня: ошибка | Вчера: - | Месяц: ошибка</b>",
            "",
            f"<b><i>{ram_line}",
            f"{cpu_line}</i></b>",
            "",
            f"Ошибка: {html.escape(error)[:800]}",
            "",
            footer,
        ]
        return "\n".join(lines)
    lines += [
        f"<b>I/O: {format_bytes(node.get('day_rx', 0))} | {format_bytes(node.get('day_tx', 0))}</b>",
        f"<b>Сегодня: {format_bytes(node.get('day_total', 0))} | Вчера: {format_bytes(node.get('yesterday_total', 0))} | Месяц: {format_bytes(node.get('month_total', 0))}</b>",
        "",
        f"<b><i>{ram_line}",
        f"{cpu_line}</i></b>",
        "",
        footer,
    ]
    return "\n".join(lines)


def downtime_totals(nodes, ts):
    dead_items = []
    active_downtime = 0
    for node in nodes:
        last_seen = int(node.get("last_seen", 0) or 0)
        age = ts - last_seen
        if age > STALE_SEC:
            dead_items.append((node, age))
            offline_since = int(node.get("offline_since") or last_seen or ts)
            active_downtime += max(0, ts - offline_since)
    with LOCK:
        falls = dict(ensure_today_falls())
        falls_nodes = dict(falls.get("nodes") or {})
    completed_downtime = int(falls.get("downtime_sec", 0) or 0)
    revoked_downtime = int(falls.get("downtime_revoke_sec", 0) or 0)
    total_downtime = max(0, completed_downtime + active_downtime - revoked_downtime)
    return dead_items, falls, falls_nodes, total_downtime


def dedupe_nodes(values):
    deduped = {}
    for node in values:
        key = node_canonical_key(node)
        current = deduped.get(key)
        if current is None or int(node.get("last_seen", 0) or 0) > int(current.get("last_seen", 0) or 0):
            deduped[key] = node
    return list(deduped.values())


def status_summary(nodes, ts):
    expected_total = max(EXPECTED_NODES, len(nodes), 1)
    live_count = 0
    for node in nodes:
        last_seen = int(node.get("last_seen", 0) or 0)
        age = ts - last_seen
        if age <= STALE_SEC:
            live_count += 1
    dead_items, falls, falls_nodes, total_downtime = downtime_totals(nodes, ts)

    lines = [
        "",
        "<blockquote>На данный момент:</blockquote>",
        f"<b>Живо: {live_count}/{expected_total}</b>",
        "<b>Мертво:</b>",
    ]
    if dead_items:
        dead_items.sort(key=lambda item: natural_sort_key(item[0].get("name") or item[0].get("id") or ""))
        for node, age in dead_items:
            name = html.escape(str(node.get("name") or node.get("id") or "unknown"))
            ip = html.escape(str(node.get("ip") or "-"))
            uptime_sec = int(node.get("uptime_sec") or 0)
            uptime_text = format_duration_ru(uptime_sec) if uptime_sec > 0 else "-"
            last_seen = int(node.get("last_seen", 0) or 0)
            lines += [
                f"<blockquote><b>{name}</b>",
                f"IP: {ip}",
                f"Аптайм: {uptime_text}",
                f"Последнее удачное обновление: {fmt_time(last_seen)}",
                f"В даунтайме: {format_duration_ru(age)}</blockquote>",
            ]
    else:
        lines.append("нет")

    total_falls = int(falls.get("total", 0) or 0)
    lines += [
        "",
        f"<b>Общее кол-во падений за сегодня: {total_falls}</b>",
        f"<b>Общее время даунтайма за сегодня: {format_duration_ru(total_downtime)}</b>",
    ]
    if falls_nodes:
        lines.append("<b>Топ лист машин которые падали:</b>")
        top_lines = []
        for name, count in sorted(falls_nodes.items(), key=lambda item: (-int(item[1]), natural_sort_key(item[0]))):
            top_lines.append(f"{html.escape(str(name))}: {int(count)} раз")
        lines.append(f"<blockquote>{chr(10).join(top_lines)}</blockquote>")
    else:
        lines.append("<b>Топ лист машин которые падали:</b> нет")
    return "\n".join(lines)


def aggregate_message():
    with LOCK:
        nodes = dedupe_nodes(NODES.values())
    ts = now_ts()
    if not nodes:
        return "<b>Статистика обходов</b>\n\nНет данных от машин."
    nodes.sort(key=lambda item: natural_sort_key(item.get("name") or item.get("id") or ""))
    parts = ["<b>Статистика обходов</b>"]
    for node in nodes:
        age = ts - int(node.get("last_seen", 0) or 0)
        status = "OK" if age <= STALE_SEC else f"OFFLINE {format_age(age)}"
        parts.append("")
        parts.append(node_message(node, status))
    parts.append(status_summary(nodes, ts))
    return "\n".join(parts)


def alert_offline(node_id, node, age):
    name = html.escape(str(node.get("name") or node_id))
    return send_message(f"<b>{name}</b>\n\nНе присылал стату: {format_age(age)}")


def alert_online(node_id, node):
    name = html.escape(str(node.get("name") or node_id))
    return send_message(f"<b>{name}</b>\n\nСнова онлайн")


def update_node(payload, remote_ip=""):
    node_id = str(payload.get("id") or payload.get("name") or payload.get("hostname") or "").strip()
    if not node_id:
        raise ValueError("id/name is required")
    current = now_ts()
    record = {
        "id": node_id,
        "name": str(payload.get("name") or node_id),
        "ip": str(remote_ip or payload.get("ip") or ""),
        "uptime_sec": int(payload.get("uptime_sec") or 0),
        "iface": str(payload.get("iface") or ""),
        "hostname": str(payload.get("hostname") or ""),
        "day_total": int(payload.get("day_total") or 0),
        "day_rx": int(payload.get("day_rx") or 0),
        "day_tx": int(payload.get("day_tx") or 0),
        "yesterday_total": int(payload.get("yesterday_total") or 0),
        "yesterday_rx": int(payload.get("yesterday_rx") or 0),
        "yesterday_tx": int(payload.get("yesterday_tx") or 0),
        "month_total": int(payload.get("month_total") or 0),
        "month_rx": int(payload.get("month_rx") or 0),
        "month_tx": int(payload.get("month_tx") or 0),
        "ram_total": int(payload.get("ram_total") or 0),
        "ram_used": int(payload.get("ram_used") or 0),
        "ram_percent": int(payload.get("ram_percent") or 0),
        "cpu_percent": float(payload.get("cpu_percent") or 0),
        "metrics_ok": bool(payload.get("metrics_ok")),
        "error": str(payload.get("error") or ""),
        "updated_at": int(payload.get("updated_at") or current),
        "last_seen": current,
        "offline_alerted": False,
    }
    with LOCK:
        old = NODES.get(node_id, {})
        was_offline = bool(old.get("offline_alerted"))
        if was_offline:
            offline_since = int(old.get("offline_since") or old.get("last_seen") or current)
            record_downtime(current - offline_since)
        canonical = node_canonical_key(record)
        removed = []
        for existing_id, existing_node in list(NODES.items()):
            if existing_id != node_id and node_canonical_key(existing_node) == canonical:
                del NODES[existing_id]
                removed.append(existing_id)
        NODES[node_id] = record
        save_nodes()
    if removed:
        log(f"removed duplicate node records for {node_id}: {', '.join(removed)}")
    if was_offline:
        log(f"node online: {node_id}")
        alert_online(node_id, record)
    return record


def authorized(headers):
    if not SECRET:
        return False
    value = headers.get("Authorization", "")
    return value == f"Bearer {SECRET}" or value == SECRET


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log(fmt % args)

    def send_json(self, code, data):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/health":
            self.send_json(200, {"ok": True, "build": COLLECTOR_BUILD})
            return
        if path == "/nodes":
            if not authorized(self.headers):
                self.send_json(401, {"ok": False, "error": "unauthorized"})
                return
            with LOCK:
                self.send_json(200, {"ok": True, "nodes": NODES})
            return
        self.send_json(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        if path != "/push":
            self.send_json(404, {"ok": False, "error": "not found"})
            return
        if not authorized(self.headers):
            self.send_json(401, {"ok": False, "error": "unauthorized"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 65536:
                raise ValueError("bad content length")
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            remote_ip = self.client_address[0] if self.client_address else ""
            node = update_node(payload, remote_ip)
            self.send_json(200, {"ok": True, "id": node["id"], "last_seen": node["last_seen"]})
        except Exception as exc:
            self.send_json(400, {"ok": False, "error": str(exc)})


def offline_loop():
    while True:
        try:
            time.sleep(CHECK_INTERVAL)
            current = now_ts()
            changed = False
            alerts = []
            with LOCK:
                for node_id, node in NODES.items():
                    age = current - int(node.get("last_seen", 0) or 0)
                    if age > STALE_SEC and not node.get("offline_alerted"):
                        node["offline_alerted"] = True
                        node["offline_since"] = current
                        record_fall(node)
                        alerts.append((node_id, dict(node), age))
                        changed = True
                if changed:
                    save_nodes()
            for node_id, node, age in alerts:
                log(f"node offline: {node_id} age={age}s")
                alert_offline(node_id, node, age)
        except Exception as exc:
            log(f"offline loop failed: {exc}")
            time.sleep(5)


def load_offset():
    try:
        with open(OFFSET_FILE, "r", encoding="utf-8") as fh:
            return int(fh.read().strip())
    except Exception:
        return None


def save_offset(offset):
    atomic_write(OFFSET_FILE, str(offset))


def load_daily_date():
    try:
        with open(DAILY_FILE, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except Exception:
        return ""


def save_daily_date(value):
    atomic_write(DAILY_FILE, value)


def daily_report_loop():
    last_sent = load_daily_date()
    log(f"daily report time={DAILY_REPORT_TIME} tz={TZ_NAME}")
    while True:
        try:
            current = datetime.now()
            today = current.strftime("%Y-%m-%d")
            if current.strftime("%H:%M") == DAILY_REPORT_TIME and last_sent != today:
                if send_message(aggregate_message()):
                    last_sent = today
                    save_daily_date(today)
                time.sleep(70)
            else:
                time.sleep(20)
        except Exception as exc:
            log(f"daily report failed: {exc}")
            time.sleep(20)


def parse_duration_arg(value):
    text = re.sub(r"\s+", "", str(value or "").lower())
    if not text:
        raise ValueError("empty duration")
    units = {
        "d": 86400, "day": 86400, "days": 86400, "д": 86400, "день": 86400, "дня": 86400, "дней": 86400,
        "h": 3600, "hr": 3600, "hrs": 3600, "hour": 3600, "hours": 3600, "ч": 3600, "час": 3600, "часа": 3600, "часов": 3600,
        "m": 60, "min": 60, "mins": 60, "minute": 60, "minutes": 60, "м": 60, "мин": 60, "минута": 60, "минуты": 60, "минут": 60,
        "s": 1, "sec": 1, "secs": 1, "second": 1, "seconds": 1, "с": 1, "сек": 1, "секунда": 1, "секунды": 1, "секунд": 1,
    }
    total = 0
    pos = 0
    for match in re.finditer(r"(\d+)([a-zа-я]+)", text):
        if match.start() != pos:
            raise ValueError("bad duration")
        amount = int(match.group(1))
        unit = match.group(2)
        if unit not in units:
            raise ValueError("bad unit")
        total += amount * units[unit]
        pos = match.end()
    if pos != len(text) or total <= 0:
        raise ValueError("bad duration")
    return total


def handle_statsrevoke(text):
    parts = text.split(maxsplit=1)
    if len(parts) < 2:
        send_message("<b>Пример:</b> /statsrevoke 50h\nМожно: 90m, 30s, 1h30m, 2ч, full")
        return
    arg = parts[1].strip().lower()
    if arg == "full":
        ts = now_ts()
        with LOCK:
            nodes = dedupe_nodes(NODES.values())
            reset_daily_falls(nodes, ts)
        send_message(
            "<b>Стата за сегодня сброшена</b>\n\n"
            "Downtime: 0 секунд\n"
            "Падений: 0\n"
            "Топ машин: пусто"
        )
        return
    try:
        seconds = parse_duration_arg(arg)
    except Exception:
        send_message("<b>Не понял время.</b>\nПример: /statsrevoke 50h\nМожно: 90m, 30s, 1h30m, 2ч, full")
        return
    with LOCK:
        revoke_downtime(seconds)
        nodes = dedupe_nodes(NODES.values())
    _, _, _, total_downtime = downtime_totals(nodes, now_ts())
    send_message(
        "<b>Downtime скорректирован</b>\n\n"
        f"Вычел: {format_duration_ru(seconds)}\n"
        f"Теперь за сегодня: {format_duration_ru(total_downtime)}"
    )


def bot_loop():
    offset = load_offset()
    try:
        info = tg_call("getWebhookInfo")
        webhook_url = info.get("result", {}).get("url") or ""
        if webhook_url:
            log(f"deleteWebhook: {webhook_url}")
            tg_call("deleteWebhook", {"drop_pending_updates": "false"})
    except Exception as exc:
        log(f"webhook check failed: {exc}")
    if offset is None:
        try:
            recent = tg_call("getUpdates", {"timeout": 0, "limit": 1, "offset": -1})
            result = recent.get("result") or []
            if result:
                offset = int(result[-1]["update_id"]) + 1
                save_offset(offset)
        except Exception as exc:
            log(f"initial getUpdates failed: {exc}")
    while True:
        try:
            params = {"timeout": 25, "limit": 20, "allowed_updates": json.dumps(["message"])}
            if offset is not None:
                params["offset"] = offset
            updates = tg_call("getUpdates", params, timeout=35).get("result") or []
            for item in updates:
                update_id = int(item.get("update_id", 0))
                offset = update_id + 1
                save_offset(offset)
                message = item.get("message") or {}
                chat_id = str((message.get("chat") or {}).get("id", ""))
                from_id = str((message.get("from") or {}).get("id", ""))
                text = str(message.get("text") or "")
                command = text.split()[0].split("@", 1)[0].lower() if text.split() else ""
                if chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/stats":
                    send_message(aggregate_message())
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/statsrevoke":
                    handle_statsrevoke(text)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/statstest":
                    send_message("<b>Проверка алертов</b>\n\nКоллектор жив, Telegram отправка работает.")
        except Exception as exc:
            log(f"bot loop failed: {exc}")
            time.sleep(5)


def main():
    if not SECRET:
        raise SystemExit("KTO_COLLECTOR_SECRET is empty")
    os.makedirs(STATE_DIR, exist_ok=True)
    load_nodes()
    load_falls()
    threading.Thread(target=offline_loop, daemon=True).start()
    threading.Thread(target=bot_loop, daemon=True).start()
    if DAILY_REPORT_TIME:
        threading.Thread(target=daily_report_loop, daemon=True).start()
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    log(f"listening http://{LISTEN_HOST}:{LISTEN_PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
EOF
}

write_stats_collector_service() {
    write_root_file "/etc/systemd/system/${STATS_COLLECTOR_SERVICE}" <<EOF
[Unit]
Description=kto stats collector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${STATS_COLLECTOR_SCRIPT}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
}

install_stats_collector() {
    header
    require_panel_mode
    need_root

    local listen_host listen_port secret bot_token chat_id allowed_user stale_sec expected_nodes daily_report_time existing_config=0
    local safe_host safe_port safe_secret safe_bot safe_chat safe_user safe_stale safe_expected safe_tz safe_daily

    if "${SUDO[@]}" test -s "$STATS_COLLECTOR_CONFIG" 2>/dev/null; then
        listen_host="$(config_get KTO_COLLECTOR_LISTEN_HOST "$STATS_COLLECTOR_CONFIG")"
        listen_port="$(config_get KTO_COLLECTOR_LISTEN_PORT "$STATS_COLLECTOR_CONFIG")"
        secret="$(config_get KTO_COLLECTOR_SECRET "$STATS_COLLECTOR_CONFIG")"
        bot_token="$(config_get KTO_COLLECTOR_BOT_TOKEN "$STATS_COLLECTOR_CONFIG")"
        chat_id="$(config_get KTO_COLLECTOR_CHAT_ID "$STATS_COLLECTOR_CONFIG")"
        allowed_user="$(config_get KTO_COLLECTOR_ALLOWED_USER_ID "$STATS_COLLECTOR_CONFIG")"
        stale_sec="$(config_get KTO_COLLECTOR_STALE_SEC "$STATS_COLLECTOR_CONFIG")"
        expected_nodes="$(config_get KTO_COLLECTOR_EXPECTED_NODES "$STATS_COLLECTOR_CONFIG")"
        daily_report_time="$(config_get KTO_COLLECTOR_DAILY_REPORT_TIME "$STATS_COLLECTOR_CONFIG")"
        if [[ -n "$secret" && -n "$bot_token" && -n "$chat_id" ]]; then
            existing_config=1
        else
            warn "Конфиг коллектора неполный, пройду настройку заново."
        fi
    fi

    if (( existing_config == 1 )); then
        listen_host="${listen_host:-0.0.0.0}"
        listen_port="${listen_port:-$STATS_COLLECTOR_PORT_DEFAULT}"
        allowed_user="${allowed_user:-$STATS_ALLOWED_USER_ID_DEFAULT}"
        stale_sec="${stale_sec:-$STATS_COLLECTOR_STALE_SEC_DEFAULT}"
        expected_nodes="${expected_nodes:-$STATS_EXPECTED_NODES_DEFAULT}"
    else
        listen_host="$(ask_text "IP прослушивания коллектора" "0.0.0.0")"
        listen_port="$(ask_int "Порт коллектора" "$STATS_COLLECTOR_PORT_DEFAULT" 1 65535)"
        secret="$(ask_text "Секрет коллектора" "$(generate_secret)")"
        bot_token="$(ask_secret_value "Введите Telegram Bot Token")"
        chat_id="$(ask_text "Введите Telegram Chat ID")"
        allowed_user="$(ask_int "Разрешенный Telegram user id" "$STATS_ALLOWED_USER_ID_DEFAULT" 1 999999999999)"
        stale_sec="$(ask_int "Алерт offline после секунд" "$STATS_COLLECTOR_STALE_SEC_DEFAULT" 30 86400)"
        expected_nodes="$(ask_int "Ожидаемое кол-во обходов" "$STATS_EXPECTED_NODES_DEFAULT" 1 9999)"
        daily_report_time="$(ask_optional_time_hm "Время ежедневного отчёта по МСК (пусто = выключено)")"
    fi

    safe_host="$(escape_config_value "$listen_host")"
    safe_port="$(escape_config_value "$listen_port")"
    safe_secret="$(escape_config_value "$secret")"
    safe_bot="$(escape_config_value "$bot_token")"
    safe_chat="$(escape_config_value "$chat_id")"
    safe_user="$(escape_config_value "$allowed_user")"
    safe_stale="$(escape_config_value "$stale_sec")"
    safe_expected="$(escape_config_value "$expected_nodes")"
    safe_tz="$(escape_config_value "$STATS_COLLECTOR_TZ_DEFAULT")"
    safe_daily="$(escape_config_value "$daily_report_time")"

    if (( existing_config == 1 )); then
        stage "Обновляю коллектор статистики"
    else
        stage "Устанавливаю коллектор статистики"
    fi
    must "Установка Python" apt_install_with_update_if_missing python3
    cmd "${SUDO[@]}" mkdir -p "$STATS_COLLECTOR_STATE_DIR"
    write_root_file_mode 0600 "$STATS_COLLECTOR_CONFIG" <<EOF
KTO_COLLECTOR_LISTEN_HOST="$safe_host"
KTO_COLLECTOR_LISTEN_PORT="$safe_port"
KTO_COLLECTOR_SECRET="$safe_secret"
KTO_COLLECTOR_BOT_TOKEN="$safe_bot"
KTO_COLLECTOR_CHAT_ID="$safe_chat"
KTO_COLLECTOR_ALLOWED_USER_ID="$safe_user"
KTO_COLLECTOR_STATE_DIR="$STATS_COLLECTOR_STATE_DIR"
KTO_COLLECTOR_STALE_SEC="$safe_stale"
KTO_COLLECTOR_EXPECTED_NODES="$safe_expected"
KTO_COLLECTOR_TZ="$safe_tz"
KTO_COLLECTOR_DAILY_REPORT_TIME="$safe_daily"
EOF
    write_stats_collector_script
    write_stats_collector_service
    cmd "${SUDO[@]}" systemctl daemon-reload
    cmd "${SUDO[@]}" systemctl enable --now "$STATS_COLLECTOR_SERVICE"
    cmd "${SUDO[@]}" systemctl restart "$STATS_COLLECTOR_SERVICE" || true
    if ufw_active; then
        cmd "${SUDO[@]}" ufw allow "${listen_port}/tcp" || true
    fi

    if (( existing_config == 1 )); then
        ok "Коллектор обновлён (${SCRIPT_BUILD})"
    else
        ok "Коллектор установлен (${SCRIPT_BUILD})"
    fi
    ok "Адрес: ${listen_host}:${listen_port}"
    ok "Ожидаемо обходов: ${expected_nodes}"
    if (( existing_config == 1 )); then
        ok "Секрет: сохранён"
    else
        ok "Секрет: ${secret}"
    fi
    ok "Telegram user id: ${allowed_user}"
    if [[ -n "$daily_report_time" ]]; then
        ok "Ежедневный отчёт: ${daily_report_time} МСК"
    else
        ok "Ежедневный отчёт: выключен"
    fi
}

stats_collector_status() {
    header
    require_panel_mode
    need_root
    local state listen_host listen_port health_host health_log rc
    state="$(service_ok "$STATS_COLLECTOR_SERVICE")"
    listen_host="$(config_get KTO_COLLECTOR_LISTEN_HOST "$STATS_COLLECTOR_CONFIG")"
    listen_port="$(config_get KTO_COLLECTOR_LISTEN_PORT "$STATS_COLLECTOR_CONFIG")"
    listen_host="${listen_host:-0.0.0.0}"
    listen_port="${listen_port:-$STATS_COLLECTOR_PORT_DEFAULT}"
    if [[ "$listen_host" == "0.0.0.0" || "$listen_host" == "::" ]]; then
        health_host="127.0.0.1"
    else
        health_host="$listen_host"
    fi

    print_row "коллектор" "$STATS_COLLECTOR_SERVICE" "$state"
    print_row "конфиг" "$STATS_COLLECTOR_CONFIG" "$([[ -s "$STATS_COLLECTOR_CONFIG" ]] && echo 1 || echo 0)"
    print_row "данные" "$STATS_COLLECTOR_STATE_DIR" "$([[ -d "$STATS_COLLECTOR_STATE_DIR" ]] && echo 1 || echo 0)"
    print_row "адрес" "${listen_host}:${listen_port}" "$([[ -n "$listen_port" ]] && echo 1 || echo 0)"

    if command_exists curl; then
        health_log="$(mktemp)"
        if curl -4 -fsS --connect-timeout 3 --max-time 5 "http://${health_host}:${listen_port}/health" >"$health_log" 2>&1; then
            print_row "local health" "$(tr '\n' ' ' < "$health_log")" 1
        else
            rc=$?
            print_row "local health" "rc=${rc}: $(tr '\n' ' ' < "$health_log")" 0
        fi
        rm -f "$health_log"
    else
        print_row "local health" "curl не установлен" 0
    fi
}

write_stats_push_script() {
    write_root_file_mode 0755 "$STATS_PUSH_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

PUSH_BUILD="v140"
CONFIG="${KTO_STATS_PUSH_CONFIG:-/etc/kto-stats-push.conf}"

push_error_trap() {
    local rc="$?" line="${BASH_LINENO[0]:-?}" command="${BASH_COMMAND:-unknown}"
    echo "push ${PUSH_BUILD}: internal error rc=${rc} line=${line}: ${command}" >&2
    exit "$rc"
}
trap push_error_trap ERR

if [[ ! -r "$CONFIG" ]]; then
    echo "Config not found: $CONFIG" >&2
    exit 1
fi

# shellcheck source=/etc/kto-stats-push.conf
. "$CONFIG"

: "${KTO_PUSH_NODE_ID:?KTO_PUSH_NODE_ID is required}"
: "${KTO_PUSH_NODE_NAME:?KTO_PUSH_NODE_NAME is required}"
: "${KTO_PUSH_IFACE:?KTO_PUSH_IFACE is required}"
: "${KTO_PUSH_COLLECTOR_URL:?KTO_PUSH_COLLECTOR_URL is required}"
: "${KTO_PUSH_SECRET:?KTO_PUSH_SECRET is required}"

collector_url="${KTO_PUSH_COLLECTOR_URL%/}/push"
hostname_value="$(hostname 2>/dev/null || echo unknown)"
updated_at="$(date +%s)"
error=""
day_rx=0
day_tx=0
yesterday_rx=0
yesterday_tx=0
month_rx=0
month_tx=0
ram_total=0
ram_used=0
ram_percent=0
cpu_percent=0
uptime_sec=0
metrics_ok=false

int_or_zero() {
    local value="${1:-0}"
    if [[ "$value" =~ ^[0-9]+$ ]]; then
        echo "$value"
    else
        echo 0
    fi
}

number_or_zero() {
    local value="${1:-0}"
    if [[ "$value" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
        echo "$value"
    else
        echo 0
    fi
}

memory_stats() {
    awk '
        $1 == "MemTotal:" { total = $2 }
        $1 == "MemAvailable:" { available = $2 }
        END {
            if (total > 0) {
                used = total - available
                printf "%d %d %d\n", used * 1024, total * 1024, int((used * 100) / total)
            } else {
                printf "0 0 0\n"
            }
        }
    ' /proc/meminfo 2>/dev/null || echo "0 0 0"
}

read_cpu_totals() {
    awk '
        /^cpu / {
            idle = $5 + $6
            total = 0
            for (i = 2; i <= NF; i++) total += $i
            print total, idle
            exit
        }
    ' /proc/stat 2>/dev/null || echo "0 0"
}

cpu_usage_percent() {
    local total1 idle1 total2 idle2 total_delta idle_delta
    read -r total1 idle1 < <(read_cpu_totals)
    sleep 0.8
    read -r total2 idle2 < <(read_cpu_totals)
    total_delta=$(( ${total2:-0} - ${total1:-0} ))
    idle_delta=$(( ${idle2:-0} - ${idle1:-0} ))
    if (( total_delta <= 0 )); then
        echo 0
    else
        awk -v total="$total_delta" -v idle="$idle_delta" 'BEGIN {
            used = (100 * (total - idle)) / total
            if (used < 0) used = 0
            printf "%.1f\n", used
        }'
    fi
}

cpu_load_percent() {
    local cores
    cores="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"
    if [[ ! "$cores" =~ ^[0-9]+$ ]] || (( cores < 1 )); then
        cores=1
    fi
    awk -v cores="$cores" '{ printf "%.1f\n", ($1 / cores) * 100 }' /proc/loadavg 2>/dev/null || echo 0
}

system_uptime_seconds() {
    awk '{ printf "%d\n", $1 }' /proc/uptime 2>/dev/null || echo 0
}

read -r ram_used ram_total ram_percent < <(memory_stats)
ram_used="$(int_or_zero "$ram_used")"
ram_total="$(int_or_zero "$ram_total")"
ram_percent="$(int_or_zero "$ram_percent")"
uptime_sec="$(int_or_zero "$(system_uptime_seconds)")"
cpu_sample_percent="$(number_or_zero "$(cpu_usage_percent)")"
cpu_load_percent_value="$(number_or_zero "$(cpu_load_percent)")"
cpu_percent="$(awk -v sample="$cpu_sample_percent" -v load_value="$cpu_load_percent_value" 'BEGIN {
    value = sample > load_value ? sample : load_value
    if (value < 0) value = 0
    printf "%.1f\n", value
}')"
if (( ram_total > 0 )); then
    metrics_ok=true
fi

if ! command -v jq >/dev/null 2>&1; then
    error="jq не установлен"
elif ! command -v vnstat >/dev/null 2>&1; then
    error="vnstat не установлен"
else
    if ! traffic_json="$(vnstat -i "$KTO_PUSH_IFACE" --json 2>&1)"; then
        error="vnstat: ${traffic_json}"
    elif [[ -z "$traffic_json" ]]; then
        error="vnstat не вернул данные по интерфейсу ${KTO_PUSH_IFACE}"
    else
        stats="$(printf '%s' "$traffic_json" | jq -r '
            def day_key: (.date.year * 10000 + .date.month * 100 + .date.day);
            def month_key: (.date.year * 100 + .date.month);
            (.interfaces[0].traffic.day // []) as $days |
            (.interfaces[0].traffic.month // []) as $months |
            ($days | sort_by(day_key)) as $sorted_days |
            ($sorted_days | length) as $days_len |
            (if $days_len > 0 then $sorted_days[$days_len - 1] else {rx:0, tx:0} end) as $day |
            (if $days_len > 1 then $sorted_days[$days_len - 2] else {rx:0, tx:0} end) as $yesterday |
            ($months | max_by(month_key) // {rx:0, tx:0}) as $month |
            "\($day.rx // 0) \($day.tx // 0) \($yesterday.rx // 0) \($yesterday.tx // 0) \($month.rx // 0) \($month.tx // 0)"
        ' 2>/dev/null || true)"
        if [[ -z "$stats" ]]; then
            error="jq не смог разобрать vnstat json"
        else
            read -r day_rx day_tx yesterday_rx yesterday_tx month_rx month_tx <<< "$stats"
            day_rx="$(int_or_zero "$day_rx")"
            day_tx="$(int_or_zero "$day_tx")"
            yesterday_rx="$(int_or_zero "$yesterday_rx")"
            yesterday_tx="$(int_or_zero "$yesterday_tx")"
            month_rx="$(int_or_zero "$month_rx")"
            month_tx="$(int_or_zero "$month_tx")"
        fi
    fi
fi

day_total=$(( day_rx + day_tx ))
yesterday_total=$(( yesterday_rx + yesterday_tx ))
month_total=$(( month_rx + month_tx ))

if ! payload="$(jq -n \
    --arg id "$KTO_PUSH_NODE_ID" \
    --arg name "$KTO_PUSH_NODE_NAME" \
    --arg iface "$KTO_PUSH_IFACE" \
    --arg hostname "$hostname_value" \
    --arg error "$error" \
    --argjson day_rx "$day_rx" \
    --argjson day_tx "$day_tx" \
    --argjson day_total "$day_total" \
    --argjson yesterday_rx "$yesterday_rx" \
    --argjson yesterday_tx "$yesterday_tx" \
    --argjson yesterday_total "$yesterday_total" \
    --argjson month_rx "$month_rx" \
    --argjson month_tx "$month_tx" \
    --argjson month_total "$month_total" \
    --argjson ram_used "$ram_used" \
    --argjson ram_total "$ram_total" \
    --argjson ram_percent "$ram_percent" \
    --argjson cpu_percent "$cpu_percent" \
    --argjson uptime_sec "$uptime_sec" \
    --argjson metrics_ok "$metrics_ok" \
    --argjson updated_at "$updated_at" \
    '{
        id: $id,
        name: $name,
        iface: $iface,
        hostname: $hostname,
        day_rx: $day_rx,
        day_tx: $day_tx,
        day_total: $day_total,
        yesterday_rx: $yesterday_rx,
        yesterday_tx: $yesterday_tx,
        yesterday_total: $yesterday_total,
        month_rx: $month_rx,
        month_tx: $month_tx,
        month_total: $month_total,
        ram_used: $ram_used,
        ram_total: $ram_total,
        ram_percent: $ram_percent,
        cpu_percent: $cpu_percent,
        uptime_sec: $uptime_sec,
        metrics_ok: $metrics_ok,
        error: $error,
        updated_at: $updated_at
    }' 2>&1)"; then
    echo "push ${PUSH_BUILD}: jq payload failed: ${payload}" >&2
    exit 1
fi

curl_errors="$(mktemp)"
if response="$(curl -4 -fsS --connect-timeout 8 --max-time 20 --retry 2 --retry-delay 2 \
    -X POST "$collector_url" \
    -H "Authorization: Bearer ${KTO_PUSH_SECRET}" \
    -H "Content-Type: application/json" \
    --data "$payload" 2>"$curl_errors")"; then
    :
else
    rc=$?
    echo "push ${PUSH_BUILD}: curl failed rc=${rc}: $(tr '\n' ' ' < "$curl_errors")" >&2
    rm -f "$curl_errors"
    exit "$rc"
fi
rm -f "$curl_errors"

if printf '%s' "$response" | jq -e '.ok == true' >/dev/null 2>&1; then
    echo "push ${PUSH_BUILD}: ok node=${KTO_PUSH_NODE_NAME} ram=${ram_percent}% cpu=${cpu_percent}% uptime=${uptime_sec}s"
else
    echo "push ${PUSH_BUILD}: bad response: ${response}" >&2
    exit 1
fi
EOF
}

write_stats_push_service() {
    local interval="$1"
    write_root_file "/etc/systemd/system/${STATS_PUSH_SERVICE}" <<EOF
[Unit]
Description=kto stats push
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${STATS_PUSH_SCRIPT}
EOF

    write_root_file "/etc/systemd/system/${STATS_PUSH_TIMER}" <<EOF
[Unit]
Description=kto stats push timer

[Timer]
OnBootSec=20
OnUnitActiveSec=${interval}s
AccuracySec=5s
Unit=${STATS_PUSH_SERVICE}

[Install]
WantedBy=timers.target
EOF
}

install_stats_push_client() {
    header
    require_whitelist_mode
    need_root

    local default_iface default_name node_name node_id iface collector_url secret interval existing_config=0
    local safe_name safe_id safe_iface safe_url safe_secret safe_interval

    default_iface="$(config_get KTO_PUSH_IFACE "$STATS_PUSH_CONFIG")"
    default_iface="${default_iface:-$(default_network_interface)}"
    default_name="$(config_get KTO_PUSH_NODE_NAME "$STATS_PUSH_CONFIG")"
    default_name="${default_name:-$(hostname 2>/dev/null || echo whitelist)}"

    if "${SUDO[@]}" test -s "$STATS_PUSH_CONFIG" 2>/dev/null; then
        node_id="$(config_get KTO_PUSH_NODE_ID "$STATS_PUSH_CONFIG")"
        node_name="$(config_get KTO_PUSH_NODE_NAME "$STATS_PUSH_CONFIG")"
        iface="$(config_get KTO_PUSH_IFACE "$STATS_PUSH_CONFIG")"
        collector_url="$(config_get KTO_PUSH_COLLECTOR_URL "$STATS_PUSH_CONFIG")"
        secret="$(config_get KTO_PUSH_SECRET "$STATS_PUSH_CONFIG")"
        interval="$(config_get KTO_PUSH_INTERVAL "$STATS_PUSH_CONFIG")"
        if [[ -n "$node_id" && -n "$node_name" && -n "$iface" && -n "$collector_url" && -n "$secret" ]]; then
            existing_config=1
        else
            warn "Конфиг push неполный, пройду настройку заново."
        fi
    fi

    if (( existing_config == 1 )); then
        interval="${interval:-$STATS_PUSH_INTERVAL_DEFAULT}"
        if ! network_interface_exists "$iface"; then
            fail "Интерфейс ${iface} из конфига не найден. Проверь: ip -br link"
            return 1
        fi
        if [[ ! "$collector_url" =~ ^https?:// ]]; then
            fail "URL коллектора в конфиге должен начинаться с http:// или https://"
            return 1
        fi
    else
        node_name="$(ask_text "Название машины" "$default_name")"
        node_id="$(ask_text "ID машины" "$node_name")"
        iface="$(ask_text "Интерфейс" "${default_iface:-eth0}")"
        if ! network_interface_exists "$iface"; then
            fail "Интерфейс ${iface} не найден. Проверь: ip -br link"
            return 1
        fi
        collector_url="$(ask_text "URL коллектора")"
        if [[ ! "$collector_url" =~ ^https?:// ]]; then
            fail "URL коллектора должен начинаться с http:// или https://"
            return 1
        fi
        secret="$(ask_secret_value "Секрет коллектора")"
        interval="$(ask_int "Интервал push, сек" "$STATS_PUSH_INTERVAL_DEFAULT" 15 3600)"
    fi

    safe_name="$(escape_config_value "$node_name")"
    safe_id="$(escape_config_value "$node_id")"
    safe_iface="$(escape_config_value "$iface")"
    safe_url="$(escape_config_value "$collector_url")"
    safe_secret="$(escape_config_value "$secret")"
    safe_interval="$(escape_config_value "$interval")"

    if (( existing_config == 1 )); then
        stage "Обновляю push статистики"
    else
        stage "Устанавливаю push статистики"
    fi
    must "Установка пакетов push" apt_install_with_update_if_missing curl jq vnstat
    if ! "${SUDO[@]}" vnstat --json -i "$iface" >/dev/null 2>&1; then
        cmd "${SUDO[@]}" vnstat -i "$iface" --add || true
    fi
    cmd "${SUDO[@]}" systemctl enable --now vnstat || true
    cmd "${SUDO[@]}" systemctl restart vnstat || true
    local legacy_unit
    for legacy_unit in kto-traffic-stats-bot.service kto-traffic-report.timer kto-traffic-report.service; do
        if "${SUDO[@]}" systemctl cat "$legacy_unit" >/dev/null 2>&1; then
            cmd "${SUDO[@]}" systemctl disable --now "$legacy_unit" || true
        fi
    done
    cmd "${SUDO[@]}" rm -f /usr/local/bin/kto-traffic-stats-bot /usr/local/bin/kto-traffic-report \
        /etc/systemd/system/kto-traffic-stats-bot.service \
        /etc/systemd/system/kto-traffic-report.service \
        /etc/systemd/system/kto-traffic-report.timer \
        /etc/kto-traffic-report.conf || true

    write_root_file_mode 0600 "$STATS_PUSH_CONFIG" <<EOF
KTO_PUSH_NODE_ID="$safe_id"
KTO_PUSH_NODE_NAME="$safe_name"
KTO_PUSH_IFACE="$safe_iface"
KTO_PUSH_COLLECTOR_URL="$safe_url"
KTO_PUSH_SECRET="$safe_secret"
KTO_PUSH_INTERVAL="$safe_interval"
EOF
    write_stats_push_script
    write_stats_push_service "$interval"
    cmd "${SUDO[@]}" systemctl daemon-reload
    cmd "${SUDO[@]}" systemctl enable --now "$STATS_PUSH_TIMER"

    if (( existing_config == 1 )); then
        ok "Пуш статистики обновлён (${SCRIPT_BUILD})"
    else
        ok "Пуш статистики установлен (${SCRIPT_BUILD})"
    fi
    ok "Машина: ${node_name}"
    ok "Коллектор: ${collector_url}"
    ok "Интервал: ${interval}s"
    ok "Старые прямые Telegram-задачи на whitelist удалены"

    stage "Тестовый push"
    local push_test_log
    push_test_log="$(mktemp)"
    if "${SUDO[@]}" "$STATS_PUSH_SCRIPT" >"$push_test_log" 2>&1; then
        cat "$push_test_log" >> "$LOG_FILE" 2>/dev/null || true
        ok "Push отправлен"
    else
        warn "Push не отправился. Ниже точная причина:"
        cat "$push_test_log" >> "$LOG_FILE" 2>/dev/null || true
        sed -n '1,80p' "$push_test_log" >&2 || true
    fi
    rm -f "$push_test_log"
}

send_stats_push_once() {
    header
    require_whitelist_mode
    need_root
    if ! "${SUDO[@]}" test -f "$STATS_PUSH_CONFIG" 2>/dev/null; then
        fail "Push статистики не настроен."
        return 0
    fi
    write_stats_push_script
    stage "Отправляю push"
    if "${SUDO[@]}" "$STATS_PUSH_SCRIPT"; then
        ok "Push отправлен (${SCRIPT_BUILD})"
    else
        warn "Push не отправился."
    fi
}

stats_push_status() {
    header
    require_whitelist_mode
    need_root
    local timer_state config_ok
    timer_state="$(service_ok "$STATS_PUSH_TIMER")"
    config_ok="$([[ -s "$STATS_PUSH_CONFIG" ]] && echo 1 || echo 0)"
    print_row "push конфиг" "$STATS_PUSH_CONFIG" "$config_ok"
    print_row "push timer" "$STATS_PUSH_TIMER" "$timer_state"
}

run_stats_push_debug() {
    header
    require_whitelist_mode
    need_root

    if ! "${SUDO[@]}" test -s "$STATS_PUSH_CONFIG" 2>/dev/null; then
        fail "Push статистики не настроен."
        return 0
    fi

    local node_id node_name iface collector_url secret interval health_url debug_log rc iface_ok interval_label
    node_id="$(config_get KTO_PUSH_NODE_ID "$STATS_PUSH_CONFIG")"
    node_name="$(config_get KTO_PUSH_NODE_NAME "$STATS_PUSH_CONFIG")"
    iface="$(config_get KTO_PUSH_IFACE "$STATS_PUSH_CONFIG")"
    collector_url="$(config_get KTO_PUSH_COLLECTOR_URL "$STATS_PUSH_CONFIG")"
    secret="$(config_get KTO_PUSH_SECRET "$STATS_PUSH_CONFIG")"
    interval="$(config_get KTO_PUSH_INTERVAL "$STATS_PUSH_CONFIG")"

    if network_interface_exists "$iface"; then
        iface_ok=1
    else
        iface_ok=0
    fi
    if [[ -n "$interval" ]]; then
        interval_label="${interval}s"
    else
        interval_label="empty"
    fi

    echo -e "${BOLD}${PURPLE}[ PUSH DEBUG ]${NC}"
    print_row "config" "$STATS_PUSH_CONFIG" "$([[ -s "$STATS_PUSH_CONFIG" ]] && echo 1 || echo 0)"
    print_row "node id" "${node_id:-empty}" "$([[ -n "$node_id" ]] && echo 1 || echo 0)"
    print_row "machine" "${node_name:-empty}" "$([[ -n "$node_name" ]] && echo 1 || echo 0)"
    print_row "iface" "${iface:-empty}" "$([[ -n "$iface" && "$iface_ok" == "1" ]] && echo 1 || echo 0)"
    print_row "collector" "${collector_url:-empty}" "$([[ "$collector_url" =~ ^https?:// ]] && echo 1 || echo 0)"
    print_row "interval" "$interval_label" "$([[ -n "$interval" ]] && echo 1 || echo 0)"
    print_row "secret" "$([[ -n "$secret" ]] && echo set || echo empty)" "$([[ -n "$secret" ]] && echo 1 || echo 0)"

    if [[ -z "$collector_url" || -z "$secret" ]]; then
        fail "В конфиге нет URL коллектора или секрета."
        return 1
    fi

    echo
    stage "Проверяю health коллектора"
    health_url="${collector_url%/}/health"
    debug_log="$(mktemp)"
    if curl -4 -fsS --connect-timeout 5 --max-time 10 "$health_url" >"$debug_log" 2>&1; then
        ok "Коллектор отвечает: $(tr '\n' ' ' < "$debug_log")"
    else
        rc=$?
        warn "Health коллектора не ответил rc=${rc}: $(tr '\n' ' ' < "$debug_log")"
        warn "Проверь на панели: systemctl status kto-stats-collector && ss -lntp | grep ':1337'"
    fi
    rm -f "$debug_log"

    write_stats_push_script
    echo
    stage "Запускаю push"
    debug_log="$(mktemp)"
    if "${SUDO[@]}" "$STATS_PUSH_SCRIPT" >"$debug_log" 2>&1; then
        ok "Push успешен"
        sed -n '1,120p' "$debug_log" || true
    else
        rc=$?
        warn "Push упал rc=${rc}"
        if [[ -s "$debug_log" ]]; then
            sed -n '1,120p' "$debug_log" || true
        else
            warn "Push не вывел текст ошибки. Запусти stats-push-update до v123 и повтори debug."
        fi
        echo
        warn "Последний статус systemd:"
        "${SUDO[@]}" systemctl status "$STATS_PUSH_SERVICE" --no-pager -l 2>&1 | sed -n '1,60p' || true
    fi
    cat "$debug_log" >> "$LOG_FILE" 2>/dev/null || true
    rm -f "$debug_log"
}

stats_push_menu() {
    local choice

    while true; do
        header
        echo -e "${BOLD}${PURPLE}[ PUSH СТАТИСТИКИ ]${NC}"
        echo -e "1) Настроить push на коллектор"
        echo -e "2) Отправить push сейчас"
        echo -e "3) Статус push"
        echo -e "4) Диагностика push"
        echo -e "0) Выйти"
        echo -e "${PURPLE}==========================================${NC}"
        echo -ne "${PURPLE}>${NC} ${BOLD}Выберите действие:${NC} "
        read -r choice

        case "$choice" in
            1)
                install_stats_push_client
                system_check_pause
                ;;
            2)
                send_stats_push_once
                system_check_pause
                ;;
            3)
                stats_push_status
                system_check_pause
                ;;
            4)
                run_stats_push_debug
                system_check_pause
                ;;
            0)
                return 0
                ;;
            *)
                fail "Неверный выбор"
                sleep 1
                ;;
        esac
    done
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
    "${SUDO[@]}" systemctl is-active --quiet "$svc" 2>/dev/null && echo 1 || echo 0
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

ufw_allowed_ports() {
    local ports=""
    if command_exists ufw; then
        ports="$("${SUDO[@]}" ufw status 2>/dev/null \
            | awk '/ALLOW/ && $0 !~ /AntiScanner-Block/ {print $1}' \
            | sed 's/(v6)//g' \
            | sort -u \
            | xargs 2>/dev/null || true)"
    fi

    if [[ -n "$ports" ]]; then
        echo "$ports" | sed 's/ /, /g'
    else
        echo "-"
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

print_kernel_status() {
    local kernel="$1"
    echo
    echo -e "${BOLD}${PURPLE}[ ЯДРО ]${NC}"
    if [[ "$kernel" == *liquorix* ]]; then
        print_row "kernel" "$kernel" 1
    else
        print_row "kernel" "$kernel" 0
    fi
}

show_status() {
    header
    local cc qdisc kernel node_status docker_status cert_days cert_expiry mem_total mem_available swap
    cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "-")"
    qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "-")"
    kernel="$(uname -r)"
    mem_total="$(memory_total_mb)"
    mem_available="$(memory_available_mb)"
    swap="$(swap_total_mb)"

    echo -e "${BOLD}${PURPLE}[ СЕТЬ ]${NC}"
    print_row "mode" "$MACHINE_MODE"
    if [[ "$MACHINE_MODE" == "node" ]]; then
        print_row "profile" "$(node_profile_label)"
    fi
    print_row "BBR + FQ" "${cc} + ${qdisc}" "$([[ "$cc" == "bbr" && "$qdisc" == "fq" ]] && echo 1 || echo 0)"
    print_row "ports" "$(ufw_allowed_ports)"

    echo
    echo -e "${BOLD}${PURPLE}[ ПАМЯТЬ ]${NC}"
    print_row "RAM" "$(format_mb "$mem_available") / $(format_mb "$mem_total")"
    if zram_active; then
        print_row "zram" "$(zram_swap_summary)" 1
    elif (( swap > 0 )); then
        print_row "swap" "$(format_mb "$swap")" 1
    elif zram_recommended; then
        print_row "swap/zram" "none" 0
    else
        print_row "swap/zram" "none, optional"
    fi

    echo
    echo -e "${BOLD}${PURPLE}[ СЛУЖБЫ ]${NC}"
    print_row "ufw" "firewall" "$(service_ok ufw)"
    print_row "antiscanner" "$(antiscanner_rules_count) rules" "$(file_ok "$ANTISCANNER_SCRIPT")"
    if command_exists haproxy; then
        print_row "haproxy" "proxy" "$(service_ok haproxy)"
    fi
    print_row "fail2ban" "ssh guard" "$(service_ok fail2ban)"
    if [[ "$MACHINE_MODE" == "panel" ]]; then
        print_row "collector" "$STATS_COLLECTOR_SERVICE" "$(service_ok "$STATS_COLLECTOR_SERVICE")"
    fi

    if [[ "$MACHINE_MODE" != "node" ]]; then
        print_kernel_status "$kernel"
        return 0
    fi

    print_row "chrony" "time sync" "$(service_ok chrony)"
    if (( $(cpu_count) > 1 )); then
        print_row "irqbalance" "irq" "$(service_ok irqbalance)"
    else
        print_row "irqbalance" "single CPU, skip"
    fi

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

    if [[ "$NODE_PROFILE" == "hysteria2" ]]; then
        echo
        echo -e "${BOLD}${PURPLE}[ SSL ]${NC}"
        print_row "privkey.key" "$CERT_DIR/privkey.key" "$(file_ok "$CERT_DIR/privkey.key")"
        print_row "fullchain.pem" "$CERT_DIR/fullchain.pem" "$(file_ok "$CERT_DIR/fullchain.pem")"
        if [[ -s "$CERT_DIR/fullchain.pem" ]]; then
            cert_expiry="$(openssl x509 -enddate -noout -in "$CERT_DIR/fullchain.pem" 2>/dev/null | sed 's/notAfter=//' || true)"
            cert_days="$(openssl x509 -checkend 1209600 -noout -in "$CERT_DIR/fullchain.pem" >/dev/null 2>&1 && echo 1 || echo 0)"
            print_row "expires" "${cert_expiry:-unknown}" "$cert_days"
        fi
    fi

    print_kernel_status "$kernel"
}

menu() {
    header
    local labels=() actions=() choice action i

    echo -e "${DIM}Режим: ${MACHINE_MODE}${NC}"
    if [[ "$MACHINE_MODE" == "node" ]]; then
        echo -e "${DIM}Профиль: $(node_profile_label)${NC}"
    fi

    if [[ "$MACHINE_MODE" != "panel" ]]; then
        labels+=("Полная оптимизация")
        actions+=("optimize")
    fi

    if [[ "$MACHINE_MODE" == "node" ]]; then
        labels+=("Общее поднятие")
        actions+=("common")
        labels+=("Установка ноды Remnawave")
        actions+=("node")
        if [[ "$NODE_PROFILE" == "reality" ]]; then
            labels+=("Установка SelfSteal")
            actions+=("selfsteal")
        fi
        labels+=("Установка WARP Native")
        actions+=("warp")
    fi

    labels+=("Панель состояния")
    actions+=("status")
    if [[ "$MACHINE_MODE" == "panel" ]]; then
        labels+=("Коллектор статистики")
        actions+=("stats-collector")
        labels+=("Статус коллектора")
        actions+=("stats-collector-status")
    else
        labels+=("Speedtest")
        actions+=("speedtest")
        labels+=("Проверка IP (IP.Check.Place)")
        actions+=("ipcheck-place")
        labels+=("Проверка IP (Region Check)")
        actions+=("ipcheck-region")
    fi

    if [[ "$MACHINE_MODE" == "node" && "$NODE_PROFILE" == "hysteria2" ]]; then
        labels+=("Сгенерировать SSL-сертификат")
        actions+=("ssl")
    elif [[ "$MACHINE_MODE" == "whitelist" ]]; then
        labels+=("HAProxy")
        actions+=("haproxy")
        labels+=("Push статистики")
        actions+=("stats-push-menu")
    fi

    labels+=("Настройки")
    actions+=("settings")

    for i in "${!labels[@]}"; do
        echo -e "$((i + 1))) ${labels[$i]}"
    done
    echo -e "0) Выход"
    echo -e "${PURPLE}==========================================${NC}"
    echo -ne "${PURPLE}>${NC} ${BOLD}Выберите действие:${NC} "

    read -r choice

    if [[ "$choice" == "0" ]]; then
        echo -e "${PURPLE}Выход.${NC}"
        return 0
    fi

    if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#actions[@]} )); then
        fail "Неверный выбор"
        return 1
    fi

    action="${actions[$((choice - 1))]}"
    case "$action" in
        optimize) optimize_system ;;
        common) install_common_stack ;;
        node) install_remnawave_node ;;
        selfsteal) install_selfsteal ;;
        warp) install_warp_native ;;
        status) show_status ;;
        stats-collector) install_stats_collector ;;
        stats-collector-status) stats_collector_status ;;
        speedtest) install_speedtest ;;
        ipcheck-place) ipcheck_place ;;
        ipcheck-region) ipcheck_region ;;
        ssl) issue_ssl_certificate ;;
        haproxy) install_haproxy ;;
        stats-push-menu) stats_push_menu ;;
        settings) settings_menu ;;
        *) fail "Неверный выбор" ;;
    esac
}

main() {
    init_log
    ensure_machine_mode

    case "${1:-menu}" in
        menu) menu ;;
        mode|config) reconfigure_machine_mode ;;
        settings) settings_menu ;;
        check|system-check) system_check ;;
        disk-clean|storage-clean|clean-disk) clean_disk_now ;;
        disk-audit|disk-usage|storage-audit) header; need_root; print_disk_usage_top ;;
        dns|dns-guard) need_root; opt_dns_guard ;;
        zram|memory-guard) opt_zram ;;
        optimize) optimize_system ;;
        common|install-all|up) install_common_stack ;;
        node|install-node) install_remnawave_node ;;
        selfsteal) install_selfsteal ;;
        warp) install_warp_native ;;
        status) show_status ;;
        speedtest) install_speedtest ;;
        ipcheck-place) ipcheck_place ;;
        ipcheck-region) ipcheck_region ;;
        ssl) issue_ssl_certificate ;;
        haproxy|install-haproxy) install_haproxy ;;
        collector|collector-install|collector-update|stats-collector|stats-collector-update) install_stats_collector ;;
        collector-status|stats-collector-status) stats_collector_status ;;
        push-menu|stats-push-menu) stats_push_menu ;;
        stats-push|stats-push-install|stats-push-update) install_stats_push_client ;;
        stats-push-send) send_stats_push_once ;;
        stats-push-status) stats_push_status ;;
        stats-push-debug|push-debug) run_stats_push_debug ;;
        *) menu ;;
    esac
}

main "$@"
