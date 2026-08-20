#!/usr/bin/env bash
# shellcheck shell=bash

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || pwd)"
KTO_RAW_BASE="${KTO_RAW_BASE:-https://raw.githubusercontent.com/Alpha012/kto-optimize/main}"
SCRIPT_VERSION="1.4.8.8"
SCRIPT_BUILD="v336"
NODE_PORT="${KTO_NODE_PORT:-1488}"
PANEL_IP="${KTO_PANEL_IP:-64.188.91.72}"
WARP_INSTALL_URL="${KTO_WARP_INSTALL_URL:-https://raw.githubusercontent.com/tagashi666/vps-warp/main/warp_install.sh}"
WHITELIST_SSH_ALLOWED_IPS_DEFAULT="85.192.48.122 46.28.64.183 146.19.248.67 85.93.9.35 185.31.243.221 94.247.129.92 83.228.242.53 167.254.243.181 5.34.176.116 5.34.178.234 84.38.185.15 193.23.195.222"
WHITELIST_SSH_ALLOWED_IPS="${KTO_WHITELIST_SSH_ALLOWED_IPS:-$WHITELIST_SSH_ALLOWED_IPS_DEFAULT}"
WHITELIST_SSH_KEEP_CURRENT="${KTO_WHITELIST_SSH_KEEP_CURRENT:-1}"
FAIL2BAN_SSH_ALLOWLIST_CONF="/etc/fail2ban/jail.d/99-kto-ssh-allowlist.local"
KTO_SSH_PORT_FILE="${KTO_SSH_PORT_FILE:-/etc/kto-ssh-port}"
KTO_SSH_MANAGED_CONFIG="${KTO_SSH_MANAGED_CONFIG:-/etc/ssh/sshd_config.d/00-kto-managed.conf}"
KTO_SSH_BACKUP_DIR="${KTO_SSH_BACKUP_DIR:-/var/backups/kto-ssh}"
KTO_SSH_PORT_MIN="${KTO_SSH_PORT_MIN:-20000}"
KTO_SSH_PORT_MAX="${KTO_SSH_PORT_MAX:-29999}"
KTO_ROOT_BASE_PUBLIC_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8Drz6C97zQtb5mA5u6uVWccuWgRAWmfp5pwbQV9kf+L8V+7FrMQ9mmwMbwFKXuopKj95cyv9CyzKXOG20Z7WTaI7zq1YybluzBNTRLEhkLubkjkwJ7bN+NHxet5KT+gZIEtbJ2L4C+eYkHGfG6ucBylX0r6pY5LU0Nm+ym8vEkhT9BHiGQVU4JMDtAENyFYCew8MMLIYy9IeW20OwCK6YrG90YbIokzf8wsq5invYTAqdjytqneP5GAopAZUwkp7jIhg69xhG+WTD2h8fgZs9pSkGvKJLBxn80reJ/jQdXJulfoFeb7jCh5CyLfkluev+xh+kvkRgZklM5XruWOln Generated-by-Nova"
XANMOD_PACKAGE="${KTO_XANMOD_PACKAGE:-linux-xanmod-x64v3}"
XANMOD_KEY_URL="${KTO_XANMOD_KEY_URL:-https://dl.xanmod.org/archive.key}"
XANMOD_REPO_URL="${KTO_XANMOD_REPO_URL:-https://deb.xanmod.org}"
XANMOD_KEYRING="${KTO_XANMOD_KEYRING:-/etc/apt/keyrings/xanmod-archive-keyring.gpg}"
XANMOD_SOURCE_FILE="${KTO_XANMOD_SOURCE_FILE:-/etc/apt/sources.list.d/xanmod-release.list}"
XANMOD_GRUB_DEFAULT_FILE="${KTO_XANMOD_GRUB_DEFAULT_FILE:-/etc/default/grub.d/99-kto-xanmod.cfg}"
MOBILE443_DIR="/opt/mobile443"
MOBILE443_CONFIG="${MOBILE443_DIR}/config.conf"
MOBILE443_MANAGER="/usr/local/sbin/kto-mobile443"
ADDITIONAL_IP_MANAGER="/usr/local/sbin/kto-additional-ips"
REMNA_EGRESS_MANAGER="/usr/local/sbin/kto-remnawave-egress"
REMNA_DIR="/opt/remnawave"
REMNA_CONTAINER="remnanode"
CERT_DIR="/opt/remnawave"
CONFIG_FILE="/etc/kto-cfg.conf"
MACHINE_MODE="${KTO_MACHINE_MODE:-}"
NODE_PROFILE="${KTO_NODE_PROFILE:-}"
REMNA_API_URL="${KTO_REMNA_API_URL:-https://admin.ktoygaday.xyz}"
REMNA_API_TOKEN="${KTO_REMNA_API_TOKEN:-}"
if [[ -n "${KTO_LOG_FILE:-}" ]]; then
    LOG_FILE="$KTO_LOG_FILE"
elif [[ ${EUID:-$(id -u)} -eq 0 ]]; then
    LOG_FILE="/var/log/kto-tune.log"
else
    LOG_FILE="/tmp/kto-tune.log"
fi
ANTISCANNER_SCRIPT="/usr/local/bin/update-antiscanner.sh"
ANTISCANNER_URL="https://gist.githubusercontent.com/sngvy/07cee7ac810c9d222fbebddff8c1d1b8/raw/blacklist.txt"
ZRAM_SETUP_SCRIPT="/usr/local/sbin/kto-zram-setup"
ZRAM_SERVICE="kto-zram.service"
ZRAM_PERCENT="${KTO_ZRAM_PERCENT:-50}"
ZRAM_MAX_MB="${KTO_ZRAM_MAX_MB:-2048}"
STORAGE_GUARD_JOURNAL_CONF="/etc/systemd/journald.conf.d/99-kto-storage.conf"
KTO_LOGROTATE_CONF="/etc/logrotate.d/kto"
KTO_TUNING_SYSCTL_CONF="/etc/sysctl.d/99-kto-tuning.conf"
KTO_CONNTRACK_SYSCTL_CONF="/etc/sysctl.d/99-z-kto-conntrack.conf"
KTO_CONNTRACK_MODPROBE_CONF="/etc/modprobe.d/99-kto-nf-conntrack.conf"
KTO_LIMITS_CONF="/etc/security/limits.d/99-kto-limits.conf"
KTO_SYSTEMD_LIMITS_CONF="/etc/systemd/system.conf.d/99-kto-limits.conf"
KTO_USER_LIMITS_CONF="/etc/systemd/user.conf.d/99-kto-limits.conf"
HAPROXY_RESERVED_PORTS_SYSCTL_CONF="/etc/sysctl.d/99-z-kto-haproxy-ports.conf"
HAPROXY_CONFIG_FILE="${KTO_HAPROXY_CONFIG:-/etc/haproxy/haproxy.cfg}"
HAPROXY_BACKUP_DIR="${KTO_HAPROXY_BACKUP_DIR:-/var/backups/kto-haproxy}"
HAPROXY_FIREWALL_MANAGER="${KTO_HAPROXY_FIREWALL_MANAGER:-/usr/local/sbin/kto-haproxy-firewall}"
HAPROXY_FIREWALL_UNIT="${KTO_HAPROXY_FIREWALL_UNIT:-/etc/systemd/system/kto-haproxy-firewall.service}"
HAPROXY_FIREWALL_SERVICE="${KTO_HAPROXY_FIREWALL_SERVICE:-kto-haproxy-firewall.service}"
HAPROXY_BANDWIDTH_MANAGER="${KTO_HAPROXY_BANDWIDTH_MANAGER:-/usr/local/sbin/kto-haproxy-bandwidth}"
HAPROXY_BANDWIDTH_CONFIG="${KTO_HAPROXY_BANDWIDTH_CONFIG:-/etc/kto-haproxy-bandwidth.conf}"
HAPROXY_BANDWIDTH_UNIT="${KTO_HAPROXY_BANDWIDTH_UNIT:-/etc/systemd/system/kto-haproxy-bandwidth.service}"
HAPROXY_BANDWIDTH_SERVICE="${KTO_HAPROXY_BANDWIDTH_SERVICE:-kto-haproxy-bandwidth.service}"
HAPROXY_BACKEND_MAXCONN=15000
HAPROXY_GLOBAL_MIN_MAXCONN_DEFAULT=100000
HAPROXY_GLOBAL_MAX_MAXCONN_DEFAULT=200000
HAPROXY_CONNECTIONS_PER_CPU_DEFAULT=10000
HAPROXY_WRONG_SNI_GPC_LIMIT_DEFAULT=500
HAPROXY_SOURCE_CONN_RATE_LIMIT_DEFAULT=5000
DOCKER_DAEMON_JSON="/etc/docker/daemon.json"
MEMORY_GUARD_SYSCTL_CONF="/etc/sysctl.d/zz-kto-memory.conf"
DNS_GUARD_RESOLVED_CONF="/etc/systemd/resolved.conf.d/99-kto-dns.conf"
HOSTS_FILE="${KTO_HOSTS_FILE:-/etc/hosts}"
HOSTS_BACKUP_FILE="${KTO_HOSTS_BACKUP_FILE:-/etc/hosts.kto-backup}"
DPI_RESOLV_CONF_FILE="${KTO_DPI_RESOLV_CONF_FILE:-/etc/resolv.conf}"
DPI_RESOLVED_UPSTREAM_FILE="${KTO_DPI_RESOLVED_UPSTREAM_FILE:-/run/systemd/resolve/resolv.conf}"
DPI_PREFLIGHT_HELPER="${KTO_DPI_PREFLIGHT_HELPER:-/usr/local/lib/kto-dpi-preflight.py}"
IPV6_WHITELIST_SYSCTL_CONF="/etc/sysctl.d/98-kto-whitelist-ipv6.conf"
STATS_COLLECTOR_CONFIG="/etc/kto-stats-collector.conf"
STATS_COLLECTOR_SCRIPT="/usr/local/bin/kto-stats-collector"
STATS_COLLECTOR_SERVICE="kto-stats-collector.service"
STATS_COLLECTOR_STATE_DIR="/var/lib/kto-stats-collector"
STATS_PUSH_CONFIG="/etc/kto-stats-push.conf"
STATS_PUSH_SCRIPT="/usr/local/bin/kto-stats-push"
STATS_PUSH_HAPROXY_HELPER="/usr/local/lib/kto/kto.sh"
STATS_PUSH_TIMEOUT_DROPIN="/etc/systemd/system/kto-stats-push.service.d/99-kto-timeout.conf"
STATS_PUSH_SERVICE="kto-stats-push.service"
STATS_PUSH_TIMER="kto-stats-push.timer"
STATS_COLLECTOR_PORT_DEFAULT="${KTO_STATS_COLLECTOR_PORT_DEFAULT:-1337}"
STATS_COLLECTOR_URL_DEFAULT="${KTO_STATS_COLLECTOR_URL_DEFAULT:-http://${PANEL_IP}:${STATS_COLLECTOR_PORT_DEFAULT}}"
STATS_PUSH_INTERVAL_DEFAULT="${KTO_STATS_PUSH_INTERVAL_DEFAULT:-5}"
STATS_COLLECTOR_STALE_SEC_DEFAULT="60"
STATS_COLLECTOR_WL_OFFLINE_CONFIRM_SEC_DEFAULT="${KTO_COLLECTOR_WL_OFFLINE_CONFIRM_SEC_DEFAULT:-15}"
STATS_COLLECTOR_BL_STALE_SEC_DEFAULT="${KTO_COLLECTOR_BL_STALE_SEC_DEFAULT:-30}"
STATS_COLLECTOR_BL_OFFLINE_CONFIRM_SEC_DEFAULT="${KTO_COLLECTOR_BL_OFFLINE_CONFIRM_SEC_DEFAULT:-15}"
STATS_COLLECTOR_BL_STALE_FALLBACK_SEC_DEFAULT="${KTO_COLLECTOR_BL_STALE_FALLBACK_SEC_DEFAULT:-90}"
STATS_COLLECTOR_BL_PUSH_INTERVAL_SEC_DEFAULT="${KTO_COLLECTOR_BL_PUSH_INTERVAL_SEC_DEFAULT:-2}"
STATS_COLLECTOR_PUSH_MISS_WINDOW_SEC_DEFAULT="${KTO_COLLECTOR_PUSH_MISS_WINDOW_SEC_DEFAULT:-60}"
STATS_COLLECTOR_PUSH_MISS_THRESHOLD_DEFAULT="${KTO_COLLECTOR_PUSH_MISS_THRESHOLD_DEFAULT:-15}"
STATS_COLLECTOR_PUSH_MISS_ALERT_COOLDOWN_DEFAULT="${KTO_COLLECTOR_PUSH_MISS_ALERT_COOLDOWN_DEFAULT:-300}"
STATS_COLLECTOR_SCAN_ALERT_DELTA_DEFAULT="${KTO_COLLECTOR_SCAN_ALERT_DELTA_DEFAULT:-0}"
STATS_COLLECTOR_TZ_DEFAULT="Europe/Moscow"
STATS_ALLOWED_USER_ID_DEFAULT="646296998"
STATS_EXPECTED_NODES_DEFAULT="10"
IP_LIMIT_ENABLED_DEFAULT="${KTO_IP_LIMIT_ENABLED_DEFAULT:-0}"
IP_LIMIT_SOURCE_DEFAULT="${KTO_COLLECTOR_IP_LIMIT_SOURCE_DEFAULT:-remna}"
IP_LIMIT_MAX_IPS_DEFAULT="${KTO_IP_LIMIT_MAX_IPS_DEFAULT:-1}"
IP_LIMIT_MAX_EVENTS_DEFAULT="${KTO_IP_LIMIT_MAX_EVENTS_DEFAULT:-5000}"
IP_LIMIT_WINDOW_SEC_DEFAULT="${KTO_IP_LIMIT_WINDOW_SEC_DEFAULT:-60}"
IP_LIMIT_ALERT_COOLDOWN_DEFAULT="${KTO_IP_LIMIT_ALERT_COOLDOWN_DEFAULT:-600}"
IP_LIMIT_COLLECTOR_SCAN_SEC_DEFAULT="${KTO_COLLECTOR_IP_LIMIT_SCAN_SEC_DEFAULT:-60}"
IP_LIMIT_ALERT_THRESHOLD_DEFAULT="${KTO_COLLECTOR_IP_LIMIT_ALERT_THRESHOLD_DEFAULT:-20}"
IP_LIMIT_ALERT_TOP_DEFAULT="${KTO_COLLECTOR_IP_LIMIT_ALERT_TOP_DEFAULT:-20}"
IP_LIMIT_SCAN_SEC_DEFAULT="${KTO_IP_LIMIT_SCAN_SEC_DEFAULT:-120}"
IP_LIMIT_TAIL_LINES_DEFAULT="${KTO_IP_LIMIT_TAIL_LINES_DEFAULT:-5000}"
IP_LIMIT_XRAY_LOGS_DEFAULT="${KTO_IP_LIMIT_XRAY_LOGS_DEFAULT:-1}"
IP_LIMIT_ENFORCE_ENABLED_DEFAULT="${KTO_IP_LIMIT_ENFORCE_ENABLED_DEFAULT:-0}"
IP_LIMIT_DROP_ENABLED_DEFAULT="${KTO_IP_LIMIT_DROP_ENABLED_DEFAULT:-0}"
IP_LIMIT_PENALTY_SEC_DEFAULT="${KTO_IP_LIMIT_PENALTY_SEC_DEFAULT:-60}"
REMNA_API_CACHE_SEC_DEFAULT="${KTO_COLLECTOR_REMNA_API_CACHE_SEC_DEFAULT:-300}"
REMNA_API_INSECURE_DEFAULT="${KTO_COLLECTOR_REMNA_API_INSECURE_DEFAULT:-0}"
REMNA_NODE_ALERT_ENABLED_DEFAULT="${KTO_COLLECTOR_REMNA_NODE_ALERT_ENABLED_DEFAULT:-1}"
REMNA_NODE_POLL_SEC_DEFAULT="${KTO_COLLECTOR_REMNA_NODE_POLL_SEC_DEFAULT:-15}"
REMNA_OFFLINE_GUARD_ENABLED_DEFAULT="${KTO_COLLECTOR_REMNA_OFFLINE_GUARD_ENABLED_DEFAULT:-1}"
REMNA_OFFLINE_STATE_MAX_AGE_SEC_DEFAULT="${KTO_COLLECTOR_REMNA_OFFLINE_STATE_MAX_AGE_SEC_DEFAULT:-60}"
REMNA_OFFLINE_LOG_GRACE_SEC_DEFAULT="${KTO_COLLECTOR_REMNA_OFFLINE_LOG_GRACE_SEC_DEFAULT:-30}"
ASN_LOOKUP_ENABLED_DEFAULT="${KTO_COLLECTOR_ASN_LOOKUP_ENABLED_DEFAULT:-1}"
ASN_CACHE_SEC_DEFAULT="${KTO_COLLECTOR_ASN_CACHE_SEC_DEFAULT:-604800}"
ASN_TIMEOUT_SEC_DEFAULT="${KTO_COLLECTOR_ASN_TIMEOUT_SEC_DEFAULT:-2}"
SPEEDTEST_TIMEOUT="${KTO_SPEEDTEST_TIMEOUT:-240}"
SPEEDTEST_DOWNLOAD_TIMEOUT="${KTO_SPEEDTEST_DOWNLOAD_TIMEOUT:-180}"
SPEEDTEST_RU_URL="${KTO_SPEEDTEST_RU_URL:-https://bench.tlab.pw/bench.sh}"
DPI_DETECTOR_IMAGE="${KTO_DPI_DETECTOR_IMAGE:-ghcr.io/runnin4ik/dpi-detector:3.3.0}"
SPEEDTEST_STATIC_VERSION="1.2.0"
SPEEDTEST_PACKAGE_VERSION="1.2.0.84-1.ea6b6773cf"
SPEEDTEST_X86_64_ARCHIVE_SHA256="5690596c54ff9bed63fa3732f818a05dbc2db19ad36ed68f21ca5f64d5cfeeb7"
SPEEDTEST_AARCH64_ARCHIVE_SHA256="3953d231da3783e2bf8904b6dd72767c5c6e533e163d3742fd0437affa431bd3"
SPEEDTEST_AMD64_DEB_SHA256="35e084567a6388631fb10cf01e5e0d6b57a67d34ede2b72ba111b3d9164c8b94"
SPEEDTEST_ARM64_DEB_SHA256="98e7de9db3bf181d08bc67e647bcfc71349c8014e387289c08e54e5c55d82f37"
APT_UPDATED=0
TEST_SOURCE_IP=""
TEST_SOURCE_INTERFACE=""

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
        touch "$LOG_FILE" >/dev/null 2>&1 || LOG_FILE="/tmp/kto-tune.log"
    else
        "${SUDO[@]}" mkdir -p "$log_dir" >/dev/null 2>&1 || true
        "${SUDO[@]}" touch "$LOG_FILE" >/dev/null 2>&1 || LOG_FILE="/tmp/kto-tune.log"
        if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
            "${SUDO[@]}" chmod 0666 "$LOG_FILE" >/dev/null 2>&1 || true
        fi
    fi

    echo "===== kto v${SCRIPT_VERSION} ${SCRIPT_BUILD} $(date -Is) =====" >> "$LOG_FILE" 2>/dev/null || true
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
    header_line "kto" "${BOLD}${GREEN}"
    header_line "v${SCRIPT_VERSION}" "$DIM"
    header_line "$SCRIPT_BUILD" "$DIM"
    echo -e "${PURPLE}==========================================${NC}"
}

stage() { echo -e "${PURPLE}[..]${NC} $*"; }
ok() { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*" >&2; }
fail() { echo -e "${RED}[ОШИБКА]${NC} $*" >&2; }

enable_utf8_tty() {
    if [[ -t 0 ]]; then
        stty iutf8 2>/dev/null || true
    fi
}

ensure_utf8_locale() {
    local charmap candidate candidate_charmap
    charmap="$(locale charmap 2>/dev/null || true)"
    case "$charmap" in
        UTF-8|UTF8|utf-8|utf8)
            enable_utf8_tty
            return 0
            ;;
    esac

    for candidate in C.UTF-8 C.utf8 en_US.UTF-8 ru_RU.UTF-8; do
        candidate_charmap="$(LC_ALL="$candidate" LANG="$candidate" locale charmap 2>/dev/null || true)"
        case "$candidate_charmap" in
            UTF-8|UTF8|utf-8|utf8)
                export LANG="$candidate"
                export LC_ALL="$candidate"
                enable_utf8_tty
                return 0
                ;;
        esac
    done

    warn "UTF-8 locale не найдена. Кириллица в интерактивном вводе может отображаться криво."
}

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

trim_whitespace() {
    local value="${1:-}"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s\n' "$value"
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

run_bounded_command() {
    local timeout_sec="$1"
    shift

    if command_exists timeout; then
        timeout --foreground --signal=TERM --kill-after=3s "${timeout_sec}s" "$@"
    else
        "$@"
    fi
}

run_systemctl_bounded() {
    local timeout_sec="$1"
    shift
    run_bounded_command "$timeout_sec" "${SUDO[@]}" systemctl "$@"
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

parallel_run_tasks() {
    local parent_log="$LOG_FILE"
    local tmp_dir idx title fn log pid rc failed=0
    local -a pids=()
    local -a titles=()
    local -a logs=()
    local -a failed_titles=()

    tmp_dir="$(mktemp -d)"

    while (( $# >= 2 )); do
        title="$1"
        fn="$2"
        shift 2
        idx="${#pids[@]}"
        log="${tmp_dir}/task-${idx}.log"
        (
            LOG_FILE="$log"
            echo "===== parallel ${title} $(date -Is) =====" >> "$LOG_FILE"
            "$fn"
        ) &
        pid="$!"
        pids+=("$pid")
        titles+=("$title")
        logs+=("$log")
    done

    for idx in "${!pids[@]}"; do
        if wait "${pids[$idx]}"; then
            echo "[OK] parallel: ${titles[$idx]}" >> "$parent_log"
        else
            rc=$?
            echo "[ERR] parallel: ${titles[$idx]} rc=${rc}" >> "$parent_log"
            failed=1
            failed_titles+=("${titles[$idx]}")
        fi
    done

    for idx in "${!logs[@]}"; do
        {
            echo
            echo "===== parallel log: ${titles[$idx]} ====="
            cat "${logs[$idx]}" 2>/dev/null || true
        } >> "$parent_log"
    done

    if (( failed != 0 )); then
        {
            echo
            echo "[WARN] parallel block finished with non-critical errors:"
            for title in "${failed_titles[@]}"; do
                echo " - ${title}"
            done
        } >> "$parent_log"
    fi

    rm -rf "$tmp_dir"
    return 0
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

ROOT_FILE_UPDATED=0

write_root_file_mode_if_changed() {
    local mode="$1"
    local path="$2"
    local tmp rc

    ROOT_FILE_UPDATED=0
    tmp="$(mktemp)"
    cat > "$tmp"
    if command_exists cmp && "${SUDO[@]}" cmp -s "$tmp" "$path" 2>/dev/null; then
        rm -f "$tmp"
        return 0
    fi
    if "${SUDO[@]}" install -m "$mode" "$tmp" "$path" >> "$LOG_FILE" 2>&1; then
        ROOT_FILE_UPDATED=1
        rm -f "$tmp"
        return 0
    else
        rc=$?
        rm -f "$tmp"
        return "$rc"
    fi
}

write_root_file_if_changed() {
    local path="$1"
    write_root_file_mode_if_changed 0644 "$path"
}

install_asset_file() {
    local relative_path="$1"
    local target_path="$2"
    local mode="$3"
    local local_path="${SCRIPT_DIR}/${relative_path}"
    local raw_url="${KTO_RAW_BASE%/}/${relative_path}"
    local tmp

    if [[ ! "$raw_url" =~ ^https:// ]] && [[ "${KTO_ALLOW_INSECURE_UPDATE_URL:-0}" != "1" ]]; then
        fail "Небезопасный URL asset: ${raw_url}"
        return 1
    fi

    if [[ -f "$local_path" ]]; then
        if ! "${SUDO[@]}" install -m "$mode" "$local_path" "$target_path" >> "$LOG_FILE" 2>&1; then
            fail "Не смог установить asset: ${relative_path}"
            return 1
        fi
        return
    fi

    if ! command_exists curl; then
        apt_install_with_update_if_missing curl
    fi

    tmp="$(mktemp)"
    if ! curl -fsSL "$raw_url" -o "$tmp" >> "$LOG_FILE" 2>&1; then
        rm -f "$tmp"
        fail "Не смог скачать asset: ${relative_path}"
        return 1
    fi
    if ! "${SUDO[@]}" install -m "$mode" "$tmp" "$target_path" >> "$LOG_FILE" 2>&1; then
        rm -f "$tmp"
        fail "Не смог установить asset: ${relative_path}"
        return 1
    fi
    rm -f "$tmp"
}

legacy_suffix() {
    printf '\166\160\156'
}

legacy_path() {
    local name="$1"
    local suffix
    suffix="$(legacy_suffix)"
    case "$name" in
        config) printf '/etc/kto-%s.conf\n' "$suffix" ;;
        log-root) printf '/var/log/kto-%s-tune.log\n' "$suffix" ;;
        log-tmp) printf '/tmp/kto-%s-tune.log\n' "$suffix" ;;
        logrotate) printf '/etc/logrotate.d/kto-%s\n' "$suffix" ;;
        sysctl) printf '/etc/sysctl.d/99-%s-tuning.conf\n' "$suffix" ;;
        limits) printf '/etc/security/limits.d/99-%s-limits.conf\n' "$suffix" ;;
        systemd-limits) printf '/etc/systemd/system.conf.d/99-%s-limits.conf\n' "$suffix" ;;
        user-limits) printf '/etc/systemd/user.conf.d/99-%s-limits.conf\n' "$suffix" ;;
        *) return 1 ;;
    esac
}

migrate_superseded_file() {
    local old_path="$1"
    local new_path="$2"
    local mode="${3:-0644}"

    "${SUDO[@]}" test -e "$old_path" 2>/dev/null || return 1
    if ! "${SUDO[@]}" test -e "$new_path" 2>/dev/null; then
        cmd "${SUDO[@]}" cp -a "$old_path" "$new_path" || return 1
        cmd "${SUDO[@]}" chmod "$mode" "$new_path" || true
    fi
    cmd "${SUDO[@]}" rm -f "$old_path" || true
    return 0
}

migrate_superseded_log() {
    local old_path="$1"

    "${SUDO[@]}" test -s "$old_path" 2>/dev/null || return 1
    if [[ "$old_path" != "$LOG_FILE" ]]; then
        cmd "${SUDO[@]}" sh -c 'cat "$1" >> "$2"' sh "$old_path" "$LOG_FILE" || true
    fi
    cmd "${SUDO[@]}" rm -f "$old_path" || true
}

migrate_superseded_kto_state() {
    local changed=0
    local old_logrotate

    migrate_superseded_file "$(legacy_path config)" "$CONFIG_FILE" 0600 && changed=1 || true
    migrate_superseded_file "$(legacy_path sysctl)" "$KTO_TUNING_SYSCTL_CONF" 0644 && changed=1 || true
    migrate_superseded_file "$(legacy_path limits)" "$KTO_LIMITS_CONF" 0644 && changed=1 || true
    migrate_superseded_file "$(legacy_path systemd-limits)" "$KTO_SYSTEMD_LIMITS_CONF" 0644 && changed=1 || true
    migrate_superseded_file "$(legacy_path user-limits)" "$KTO_USER_LIMITS_CONF" 0644 && changed=1 || true

    old_logrotate="$(legacy_path logrotate)"
    if "${SUDO[@]}" test -e "$old_logrotate" 2>/dev/null; then
        if ! "${SUDO[@]}" test -e "$KTO_LOGROTATE_CONF" 2>/dev/null; then
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
        fi
        cmd "${SUDO[@]}" rm -f "$old_logrotate" || true
        changed=1
    fi
    migrate_superseded_log "$(legacy_path log-root)" || true
    migrate_superseded_log "$(legacy_path log-tmp)" || true

    if (( changed == 1 )); then
        cmd "${SUDO[@]}" sysctl --system || true
        cmd "${SUDO[@]}" systemctl daemon-reload || true
    fi
}

valid_machine_mode() {
    [[ "$1" == "node" || "$1" == "whitelist" || "$1" == "panel" ]]
}

valid_node_profile() {
    [[ "$1" == "reality" || "$1" == "hysteria2" || "$1" == "reality_hysteria2" ]]
}

node_profile_label() {
    case "${NODE_PROFILE:-}" in
        reality) echo "Reality" ;;
        hysteria2) echo "Hysteria2" ;;
        reality_hysteria2) echo "Reality + Hysteria2" ;;
        *) echo "-" ;;
    esac
}

node_profile_includes_reality() {
    [[ "${NODE_PROFILE:-}" == "reality" || "${NODE_PROFILE:-}" == "reality_hysteria2" ]]
}

node_profile_includes_hysteria2() {
    [[ "${NODE_PROFILE:-}" == "hysteria2" || "${NODE_PROFILE:-}" == "reality_hysteria2" ]]
}

haproxy_mode_supported() {
    [[ "$MACHINE_MODE" == "whitelist" ]] ||
        { [[ "$MACHINE_MODE" == "node" ]] && node_profile_includes_reality; }
}

haproxy_base_port() {
    if [[ "$MACHINE_MODE" == "node" ]] && node_profile_includes_reality; then
        echo "8443"
    else
        echo "443"
    fi
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
            gsub(/\\\$/, "$", value)
            gsub(/\\`/, "`", value)
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
    value="${value//\$/\\\$}"
    value="${value//\`/\\\`}"
    printf '%s\n' "$value"
}

generate_node_uuid() {
    local value=""
    if [[ -r /proc/sys/kernel/random/uuid ]]; then
        read -r value < /proc/sys/kernel/random/uuid || true
    elif command_exists uuidgen; then
        value="$(uuidgen 2>/dev/null || true)"
    fi
    printf '%s\n' "${value,,}"
}

text_has_replacement_char() {
    [[ "$1" == *$'\357\277\275'* ]]
}

text_is_valid_utf8() {
    if ! command -v iconv >/dev/null 2>&1; then
        return 0
    fi
    printf '%s' "$1" | iconv -f UTF-8 -t UTF-8 >/dev/null 2>&1
}

text_has_bad_utf8() {
    text_has_replacement_char "$1" || ! text_is_valid_utf8 "$1"
}

load_machine_mode() {
    local saved_mode="" saved_profile="" saved_api_url="" saved_api_token="" source_file="$CONFIG_FILE"

    if [[ -n "$MACHINE_MODE" ]]; then
        if ! valid_machine_mode "$MACHINE_MODE"; then
            warn "KTO_MACHINE_MODE должен быть node, whitelist или panel. Игнорирую."
            MACHINE_MODE=""
        fi
    fi

    if [[ -n "$NODE_PROFILE" ]]; then
        if ! valid_node_profile "$NODE_PROFILE"; then
            warn "KTO_NODE_PROFILE должен быть reality, hysteria2 или reality_hysteria2. Игнорирую."
            NODE_PROFILE=""
        fi
    fi

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
    cmd "${SUDO[@]}" rm -f /dev/shm/nginx.sock || true
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
        echo -e "3) Reality + Hysteria2"
        echo -e "${PURPLE}==========================================${NC}"
        echo -ne "${PURPLE}>${NC} ${BOLD}Выберите профиль (1-3):${NC} "
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
            3|reality_hysteria2|reality+hysteria2|Reality+Hysteria2|combo|hybrid)
                NODE_PROFILE="reality_hysteria2"
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
        if haproxy_mode_supported; then
            echo -e "4) HAProxy"
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
                if haproxy_mode_supported; then
                    haproxy_menu
                else
                    fail "HAProxy доступен для whitelist, Reality и Reality + Hysteria2."
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
    if ! node_profile_includes_hysteria2; then
        fail "SSL доступен только для профилей Hysteria2 и Reality + Hysteria2."
        exit 1
    fi
}

require_reality_profile() {
    require_node_mode
    if ! node_profile_includes_reality; then
        fail "SelfSteal доступен только для профилей Reality и Reality + Hysteria2."
        exit 1
    fi
}

require_whitelist_mode() {
    if [[ "$MACHINE_MODE" != "whitelist" ]]; then
        fail "Этот пункт доступен только для режима whitelist."
        exit 1
    fi
}

require_haproxy_mode() {
    if ! haproxy_mode_supported; then
        fail "HAProxy доступен для whitelist, Reality и Reality + Hysteria2."
        exit 1
    fi
}

require_push_mode() {
    if [[ "$MACHINE_MODE" != "node" && "$MACHINE_MODE" != "whitelist" ]]; then
        fail "Этот пункт доступен только для режима node или whitelist."
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

xanmod_kernel_versions() {
    find /lib/modules -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null |
        grep -E 'xanmod' | LC_ALL=C sort -V
}

xanmod_latest_version() {
    xanmod_kernel_versions | tail -n 1
}

xanmod_installed() {
    local version
    package_installed "$XANMOD_PACKAGE" || return 1
    version="$(xanmod_latest_version)"
    [[ -n "$version" ]] || return 1
    [[ -s "/boot/vmlinuz-${version}" && -d "/lib/modules/${version}" ]]
}

xanmod_source_configured() {
    [[ -s "$XANMOD_SOURCE_FILE" && -s "$XANMOD_KEYRING" ]] &&
        grep -Fq "$XANMOD_REPO_URL" "$XANMOD_SOURCE_FILE" 2>/dev/null
}

xanmod_x64v3_supported() {
    local loader output flags required flag

    for loader in /lib64/ld-linux-x86-64.so.2 /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2; do
        [[ -x "$loader" ]] || continue
        output="$(LC_ALL=C "$loader" --help 2>/dev/null || true)"
        if grep -Eq 'x86-64-v3[[:space:]]+\(supported' <<< "$output"; then
            return 0
        fi
        if grep -Eq 'x86-64-v3[[:space:]]+\(NOT supported' <<< "$output"; then
            return 1
        fi
    done

    flags=" $(awk -F: '/^flags[[:space:]]*:/ { print $2; exit }' /proc/cpuinfo 2>/dev/null) "
    required=(avx avx2 bmi1 bmi2 f16c fma movbe xsave)
    for flag in "${required[@]}"; do
        [[ "$flags" == *" ${flag} "* ]] || return 1
    done
    [[ "$flags" == *" abm "* || "$flags" == *" lzcnt "* ]]
}

secure_boot_enabled() {
    local state efivar value
    if command_exists mokutil; then
        state="$(LC_ALL=C mokutil --sb-state 2>/dev/null || true)"
        grep -qi 'SecureBoot enabled' <<< "$state"
        return
    fi
    efivar="$(find /sys/firmware/efi/efivars -maxdepth 1 -type f -name 'SecureBoot-*' 2>/dev/null | head -n 1)"
    [[ -n "$efivar" ]] || return 1
    value="$(od -An -t u1 -j 4 -N 1 "$efivar" 2>/dev/null | tr -d '[:space:]' || true)"
    [[ "$value" == "1" ]]
}

xanmod_boot_free_mb() {
    df -Pm /boot 2>/dev/null | awk 'NR == 2 { print $4; exit }'
}

xanmod_root_free_mb() {
    df -Pm / 2>/dev/null | awk 'NR == 2 { print $4; exit }'
}

managed_ssh_port() {
    local port=""
    if [[ -r "$KTO_SSH_PORT_FILE" ]]; then
        port="$(awk 'NR == 1 { print $1; exit }' "$KTO_SSH_PORT_FILE" 2>/dev/null || true)"
    elif [[ ${EUID:-$(id -u)} -ne 0 ]]; then
        port="$("${SUDO[@]}" awk 'NR == 1 { print $1; exit }' "$KTO_SSH_PORT_FILE" 2>/dev/null || true)"
    fi
    if [[ "$port" =~ ^[0-9]+$ ]] && (( 10#$port >= 1 && 10#$port <= 65535 )); then
        printf '%d\n' "$((10#$port))"
    fi
}

detect_ssh_port() {
    local port=""
    port="$(managed_ssh_port || true)"
    if [[ -z "$port" ]] && command_exists sshd; then
        port="$(sshd -T 2>/dev/null | awk '/^port / {print $2; exit}' || true)"
    fi
    if [[ -z "$port" && -r /etc/ssh/sshd_config ]]; then
        port="$(awk 'tolower($1)=="port" && $1 !~ /^#/ {print $2; exit}' /etc/ssh/sshd_config 2>/dev/null || true)"
    fi
    if [[ ! "$port" =~ ^[0-9]+$ ]] || (( 10#$port < 1 || 10#$port > 65535 )); then
        port=22
    fi
    printf '%d\n' "$((10#$port))"
}

ssh_port_is_listening() {
    local port="$1"
    command_exists ss || return 1
    ss -H -ltn 2>/dev/null |
        awk -v wanted="$port" '
            {
                address = $4
                sub(/^.*:/, "", address)
                if (address == wanted) found = 1
            }
            END { exit found ? 0 : 1 }
        '
}

choose_managed_ssh_port() {
    local current min max candidate attempt marker
    marker="$(managed_ssh_port || true)"
    if [[ -n "$marker" ]]; then
        printf '%s\n' "$marker"
        return 0
    fi

    current="$(detect_ssh_port)"
    if [[ "$current" =~ ^[0-9]+$ ]] && (( current != 22 )) && ssh_port_is_listening "$current"; then
        printf '%s\n' "$current"
        return 0
    fi

    min="$KTO_SSH_PORT_MIN"
    max="$KTO_SSH_PORT_MAX"
    [[ "$min" =~ ^[0-9]+$ ]] || min=20000
    [[ "$max" =~ ^[0-9]+$ ]] || max=29999
    min=$((10#$min))
    max=$((10#$max))
    if (( min < 1024 || max > 65535 || min >= max )); then
        min=20000
        max=29999
    fi

    for (( attempt = 0; attempt < 256; attempt++ )); do
        candidate=$(( min + (RANDOM * 32768 + RANDOM) % (max - min + 1) ))
        (( candidate != NODE_PORT )) || continue
        ssh_port_is_listening "$candidate" && continue
        printf '%s\n' "$candidate"
        return 0
    done
    return 1
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
        fail "Некорректный домен. Пример: node.domain.com"
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
        value="${value%$'\r'}"
        value="${value:-$default}"
        if [[ -n "$value" ]]; then
            printf '%s\n' "$value"
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
    value="${value%$'\r'}"
    printf '%s\n' "${value:-$default}"
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
    local default="${2:-}"
    local value
    while true; do
        if [[ -n "$default" ]]; then
            printf '%s [сохранён, Enter оставить]: ' "$prompt" >&2
        else
            printf '%s: ' "$prompt" >&2
        fi
        read -r -s value
        value="${value%$'\r'}"
        printf '\n' >&2
        if [[ -n "$value" ]]; then
            echo "$value"
            return 0
        fi
        if [[ -n "$default" ]]; then
            echo "$default"
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

normalize_haproxy_target() {
    local raw="${1:-}" ip port
    raw="${raw//[[:space:]]/}"
    if [[ "$raw" == *:* ]]; then
        ip="${raw%%:*}"
        port="${raw##*:}"
    else
        ip="$raw"
        port="443"
    fi
    validate_ipv4 "$ip" || return 1
    [[ "$port" =~ ^[0-9]+$ ]] || return 1
    port=$((10#$port))
    (( port >= 1 && port <= 65535 )) || return 1
    printf '%s:%d\n' "$ip" "$port"
}

normalize_haproxy_target_pool() {
    local raw="${1:-}" item target existing
    local -a items=() targets=()

    raw="${raw//;/,}"
    raw="${raw//[[:space:]]/,}"
    IFS=',' read -r -a items <<< "$raw"
    for item in "${items[@]}"; do
        [[ -n "$item" ]] || continue
        target="$(normalize_haproxy_target "$item" 2>/dev/null || true)"
        [[ -n "$target" ]] || return 1
        for existing in "${targets[@]:-}"; do
            [[ "$existing" == "$target" ]] && continue 2
        done
        targets+=("$target")
    done

    (( ${#targets[@]} > 0 )) || return 1
    local IFS=','
    printf '%s\n' "${targets[*]}"
}

haproxy_target_pool_count() {
    local normalized
    local -a targets=()
    normalized="$(normalize_haproxy_target_pool "${1:-}" 2>/dev/null || true)"
    [[ -n "$normalized" ]] || return 1
    IFS=',' read -r -a targets <<< "$normalized"
    printf '%d\n' "${#targets[@]}"
}

normalize_haproxy_server_maxconn() {
    local raw="${1:-$HAPROXY_BACKEND_MAXCONN}"
    raw="${raw//[[:space:]]/}"
    case "${raw,,}" in
        ""|0|auto|default|none)
            ;;
        *)
            [[ "$raw" =~ ^[0-9]+$ ]] || return 1
            raw=$((10#$raw))
            (( raw >= 1 && raw <= 10000000 )) || return 1
            ;;
    esac
    printf '%d\n' "$HAPROXY_BACKEND_MAXCONN"
}

haproxy_server_maxconn_label() {
    normalize_haproxy_server_maxconn "${1:-$HAPROXY_BACKEND_MAXCONN}" >/dev/null || return 1
    printf 'фиксировано %s на backend\n' "$HAPROXY_BACKEND_MAXCONN"
}

normalize_haproxy_source_ip() {
    local raw="${1:-default}"
    raw="${raw//[[:space:]]/}"
    case "${raw,,}" in
        ""|auto|default) printf 'default\n'; return 0 ;;
    esac
    validate_ipv4 "$raw" || return 1
    printf '%s\n' "$raw"
}

canonicalize_haproxy_runtime_source_ip() {
    local source_ip default_ip

    source_ip="$(normalize_haproxy_source_ip "${1:-default}" 2>/dev/null || true)"
    [[ -n "$source_ip" ]] || return 1
    if [[ "$source_ip" != default ]]; then
        default_ip="$(haproxy_default_source_ip)"
        if validate_ipv4 "$default_ip" && [[ "$source_ip" == "$default_ip" ]]; then
            source_ip=default
        fi
    fi
    printf '%s\n' "$source_ip"
}

normalize_haproxy_listen_ip() {
    local raw="${1:-*}"
    raw="${raw//[[:space:]]/}"
    case "${raw,,}" in
        ""|\*|any|all|default|0.0.0.0) printf '*\n'; return 0 ;;
    esac
    validate_ipv4 "$raw" || return 1
    printf '%s\n' "$raw"
}

normalize_haproxy_send_proxy_v2() {
    local raw="${1:-0}"
    raw="${raw//[[:space:]]/}"
    case "${raw,,}" in
        ""|0|n|no|off|false|нет) printf '0\n'; return 0 ;;
        1|y|yes|on|true|да) printf '1\n'; return 0 ;;
    esac
    return 1
}

haproxy_send_proxy_v2_label() {
    if [[ "$(normalize_haproxy_send_proxy_v2 "${1:-0}" 2>/dev/null || printf '0')" == "1" ]]; then
        printf 'ON\n'
    else
        printf 'OFF\n'
    fi
}

haproxy_route_listen_ip() {
    normalize_haproxy_listen_ip "${1:-*}"
}

# Route TSV: port, backend pool, SNI, source IP, maxconn, listener IP, send-proxy-v2.
# Legacy rows without the seventh field intentionally mean send-proxy-v2 OFF.
print_haproxy_route() {
    local port="$1" target_pool="$2" sni="$3" source_ip="${4:-default}"
    local server_maxconn="${5:-default}" listen_ip="${6:-*}" send_proxy_v2="${7:-0}"

    sni="$(normalize_haproxy_sni_list "$sni")" || return 1
    source_ip="$(normalize_haproxy_source_ip "$source_ip")" || return 1
    server_maxconn="$(normalize_haproxy_server_maxconn "$server_maxconn")" || return 1
    listen_ip="$(normalize_haproxy_listen_ip "$listen_ip")" || return 1
    send_proxy_v2="$(normalize_haproxy_send_proxy_v2 "$send_proxy_v2")" || return 1
    if [[ "$listen_ip" != "*" ]]; then
        source_ip="$listen_ip"
    elif [[ "$source_ip" != "default" ]]; then
        listen_ip="$source_ip"
    fi

    if [[ "$send_proxy_v2" == "1" ]]; then
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$port" "$target_pool" "$sni" "$source_ip" "$server_maxconn" "$listen_ip" "$send_proxy_v2"
    elif [[ "$listen_ip" != "*" ]]; then
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$port" "$target_pool" "$sni" "$source_ip" "$server_maxconn" "$listen_ip"
    elif [[ "$server_maxconn" != default ]]; then
        printf '%s\t%s\t%s\t%s\t%s\n' \
            "$port" "$target_pool" "$sni" "$source_ip" "$server_maxconn"
    else
        printf '%s\t%s\t%s\t%s\n' "$port" "$target_pool" "$sni" "$source_ip"
    fi
}

haproxy_default_source_ip() {
    ip -4 route get 1.1.1.1 2>/dev/null |
        awk '{for (i=1; i<=NF; i++) if ($i == "src") {print $(i+1); exit}}' || true
}

haproxy_default_source_interface() {
    ip -4 route get 1.1.1.1 2>/dev/null |
        awk '{for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}' || true
}

list_haproxy_additional_source_ips() {
    local default_interface default_ip line interface cidr source_ip route route_interface
    default_interface="$(haproxy_default_source_interface)"
    default_ip="$(haproxy_default_source_ip)"
    [[ -n "$default_interface" ]] || return 0
    validate_ipv4 "$default_ip" || return 0

    while read -r line; do
        interface="$(awk '{print $2}' <<< "$line")"
        interface="${interface%%@*}"
        cidr="$(awk '{print $4}' <<< "$line")"
        source_ip="${cidr%%/*}"
        [[ -n "$interface" && "$interface" != lo && "$interface" != "$default_interface" ]] || continue
        [[ "$source_ip" != "$default_ip" ]] || continue
        validate_ipv4 "$source_ip" || continue
        route="$(ip -4 route get 1.1.1.1 from "$source_ip" 2>/dev/null || true)"
        route_interface="$(awk '{for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}' <<< "$route")"
        [[ "$route_interface" == "$interface" ]] || continue
        printf '%s\t%s\n' "$source_ip" "$interface"
    done < <(ip -4 -o address show scope global 2>/dev/null || true) |
        sort -t $'\t' -k2,2V -k1,1V |
        awk -F '\t' '!seen[$1]++'
}

list_test_source_ipv4s() {
    local default_ip default_interface line interface cidr source_ip route route_interface kind
    default_ip="$(haproxy_default_source_ip)"
    default_interface="$(haproxy_default_source_interface)"

    {
        if validate_ipv4 "$default_ip" && [[ -n "$default_interface" ]]; then
            printf '%s\t%s\t%s\n' "$default_ip" "$default_interface" "основной"
        fi

        while read -r line; do
            interface="$(awk '{print $2}' <<< "$line")"
            interface="${interface%%@*}"
            cidr="$(awk '{print $4}' <<< "$line")"
            source_ip="${cidr%%/*}"
            [[ -n "$interface" && "$interface" != lo && "$source_ip" != "$default_ip" ]] || continue
            validate_ipv4 "$source_ip" || continue
            route="$(ip -4 route get 1.1.1.1 from "$source_ip" 2>/dev/null || true)"
            route_interface="$(awk '{for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}' <<< "$route")"
            [[ "$route_interface" == "$interface" ]] || continue
            kind="дополнительный"
            printf '%s\t%s\t%s\n' "$source_ip" "$interface" "$kind"
        done < <(ip -4 -o address show scope global 2>/dev/null | sort -k2,2V -k4,4V || true)
    } | awk -F '\t' 'NF >= 2 && !seen[$1]++'
}

list_haproxy_preparable_input_ips() {
    list_test_source_ipv4s | awk -F '\t' 'NF >= 2 && !seen[$1]++ { print $1 "\t" $2 }'
}

select_test_source_ipv4() {
    local requested="${1:-${KTO_TEST_SOURCE_IP:-}}" row source_ip interface kind choice index
    local -a rows=()
    TEST_SOURCE_IP=""
    TEST_SOURCE_INTERFACE=""
    requested="${requested//[[:space:]]/}"
    mapfile -t rows < <(list_test_source_ipv4s)

    if (( ${#rows[@]} == 0 )); then
        fail "Не найдено ни одного IPv4 с рабочим source-route"
        return 1
    fi

    if [[ -n "$requested" ]]; then
        for row in "${rows[@]}"; do
            IFS=$'\t' read -r source_ip interface kind <<< "$row"
            if [[ "$source_ip" == "$requested" ]]; then
                TEST_SOURCE_IP="$source_ip"
                TEST_SOURCE_INTERFACE="$interface"
                return 0
            fi
        done
        fail "IP ${requested} не найден среди рабочих исходящих адресов"
        return 1
    fi

    if (( ${#rows[@]} == 1 )); then
        IFS=$'\t' read -r TEST_SOURCE_IP TEST_SOURCE_INTERFACE _ <<< "${rows[0]}"
        return 0
    fi

    echo
    echo -e "${BOLD}${PURPLE}[ ИСХОДЯЩИЙ IP ДЛЯ ТЕСТА ]${NC}"
    for index in "${!rows[@]}"; do
        IFS=$'\t' read -r source_ip interface kind <<< "${rows[$index]}"
        printf ' %d) %s | %s | %s\n' "$(( index + 1 ))" "$source_ip" "$interface" "$kind"
    done

    while true; do
        echo -ne "${PURPLE}>${NC} ${BOLD}Выберите IP:${NC} "
        if ! read -r choice; then
            fail "Не удалось прочитать выбор IP"
            return 1
        fi
        if [[ "$choice" =~ ^[0-9]+$ ]]; then
            choice=$(( 10#$choice ))
            if (( choice >= 1 && choice <= ${#rows[@]} )); then
                IFS=$'\t' read -r TEST_SOURCE_IP TEST_SOURCE_INTERFACE _ <<< "${rows[$(( choice - 1 ))]}"
                return 0
            fi
        fi
        fail "Неверный выбор"
    done
}

write_btop_interface_config() {
    local source_config="$1" output_config="$2" interface="$3"

    if [[ ! "$interface" =~ ^[[:alnum:]_.:-]{1,15}$ ]]; then
        fail "Некорректное имя сетевого интерфейса: ${interface:-пусто}"
        return 1
    fi

    if [[ -r "$source_config" && -s "$source_config" ]]; then
        awk -v interface="$interface" '
            BEGIN {
                iface_written = 0
                boxes_written = 0
            }
            /^[[:space:]]*net_iface[[:space:]]*=/ {
                if (!iface_written) print "net_iface = \"" interface "\""
                iface_written = 1
                next
            }
            /^[[:space:]]*shown_boxes[[:space:]]*=/ {
                if (!boxes_written) {
                    line = $0
                    if (line !~ /(^|[[:space:]"])net([[:space:]"]|$)/) {
                        if (!sub(/"[[:space:]]*$/, " net\"", line)) {
                            line = "shown_boxes = \"cpu mem net proc\""
                        }
                    }
                    print line
                }
                boxes_written = 1
                next
            }
            { print }
            END {
                if (!boxes_written) print "shown_boxes = \"cpu mem net proc\""
                if (!iface_written) print "net_iface = \"" interface "\""
            }
        ' "$source_config" > "$output_config"
    else
        cat > "$output_config" <<EOF
# Temporary kto btop config. The user's btop config is not modified.
shown_boxes = "cpu mem net proc"
net_iface = "${interface}"
net_auto = true
net_sync = true
EOF
    fi

    [[ -s "$output_config" ]] || {
        fail "Не удалось подготовить временный btop config"
        return 1
    }
}

run_btop_with_config() {
    local config_file="$1" isolated_config_home="$2" help_text

    help_text="$(btop --help 2>&1 || true)"
    if grep -Eq -- '(^|[[:space:],])--config([=[:space:]]|$)' <<< "$help_text"; then
        btop --config "$config_file"
    elif grep -Eiq -- '(^|[[:space:]])-c([,[:space:]]|$).*(config|configuration)' <<< "$help_text"; then
        btop -c "$config_file"
    else
        XDG_CONFIG_HOME="$isolated_config_home" btop
    fi
}

run_btop_for_ip() {
    header
    require_whitelist_mode
    need_root
    local requested_ip="${1:-}" source_ip source_interface config_home user_config
    local temp_dir temp_config rc=0 interface_ips interface_ip_count

    if [[ ! -t 0 || ! -t 1 ]]; then
        fail "btop нужно запускать из интерактивного терминала"
        return 1
    fi
    select_test_source_ipv4 "$requested_ip" || return 1
    source_ip="$TEST_SOURCE_IP"
    source_interface="$TEST_SOURCE_INTERFACE"
    if [[ ! "$source_interface" =~ ^[[:alnum:]_.:-]{1,15}$ ]] ||
        ! ip link show dev "$source_interface" >/dev/null 2>&1; then
        fail "Интерфейс ${source_interface:-пусто} для IP ${source_ip} больше не доступен"
        return 1
    fi

    if ! command_exists btop; then
        stage "Устанавливаю btop"
        must "Установка btop" apt_install_with_update_if_missing btop || return 1
    fi
    command_exists btop || {
        fail "btop установлен, но команда не найдена в PATH"
        return 1
    }

    config_home="${XDG_CONFIG_HOME:-${HOME:-/root}/.config}"
    user_config="${config_home}/btop/btop.conf"
    temp_dir="$(mktemp -d)"
    mkdir -p "${temp_dir}/btop"
    temp_config="${temp_dir}/btop/btop.conf"
    if ! write_btop_interface_config "$user_config" "$temp_config" "$source_interface"; then
        rm -f "$temp_config"
        rmdir "${temp_dir}/btop" "$temp_dir" 2>/dev/null || true
        return 1
    fi

    interface_ips="$(list_test_source_ipv4s |
        awk -F '\t' -v interface="$source_interface" '$2 == interface { print $1 }' |
        sort -uV | paste -sd ',' -)"
    interface_ips="${interface_ips//,/, }"
    interface_ip_count="$(awk -F ',' 'NF && $1 != "" { print NF; next } { print 0 }' <<< "${interface_ips//, /,}")"

    echo
    ok "btop: ${source_ip} через ${source_interface}"
    if (( interface_ip_count > 1 )); then
        warn "На ${source_interface} несколько IP: ${interface_ips}. btop покажет их общий трафик по интерфейсу."
    else
        echo "Сетевой график закреплён за интерфейсом ${source_interface}."
    fi
    echo "Выход из btop: q"

    run_btop_with_config "$temp_config" "$temp_dir" || rc=$?
    rm -f "$temp_config"
    rmdir "${temp_dir}/btop" "$temp_dir" 2>/dev/null || true
    if (( rc != 0 && rc != 130 )); then
        fail "btop завершился с кодом ${rc}"
        return "$rc"
    fi
    return 0
}

haproxy_additional_source_ip_available() {
    local wanted="$1"
    list_haproxy_additional_source_ips |
        awk -F '\t' -v wanted="$wanted" '$1 == wanted { found = 1 } END { exit found ? 0 : 1 }'
}

select_haproxy_additional_source_ip() {
    local routes_file="${1:-}" choice source_ip interface index used_count usage_label
    local -a entries=()
    mapfile -t entries < <(list_haproxy_additional_source_ips)

    if (( ${#entries[@]} == 0 )); then
        fail "Рабочих дополнительных IP не найдено. Сначала запусти «Проверить и завести дополнительные IP»."
        return 1
    fi
    if (( ${#entries[@]} == 1 )); then
        IFS=$'\t' read -r source_ip interface <<< "${entries[0]}"
        printf 'Доступен один дополнительный IP: %s (%s)\n' "$source_ip" "$interface" >&2
        printf '%s\n' "$source_ip"
        return 0
    fi

    printf 'Доступные дополнительные исходящие IP:\n' >&2
    for index in "${!entries[@]}"; do
        IFS=$'\t' read -r source_ip interface <<< "${entries[$index]}"
        used_count=0
        if [[ -n "$routes_file" && -s "$routes_file" ]]; then
            used_count="$(awk -F '\t' -v wanted="$source_ip" '$4 == wanted { count++ } END { print count + 0 }' "$routes_file")"
        fi
        usage_label=""
        [[ "$used_count" == 0 ]] || usage_label=" — маршрутов: ${used_count}"
        printf ' %d) %s (%s)%s\n' "$(( index + 1 ))" "$source_ip" "$interface" "$usage_label" >&2
    done
    while true; do
        printf '> ' >&2
        read -r choice
        if [[ "$choice" =~ ^[0-9]+$ ]]; then
            choice=$(( 10#$choice ))
            if (( choice >= 1 && choice <= ${#entries[@]} )); then
                IFS=$'\t' read -r source_ip interface <<< "${entries[$(( choice - 1 ))]}"
                printf '%s\n' "$source_ip"
                return 0
            fi
        fi
        fail "Неверный выбор"
    done
}

haproxy_source_label() {
    local source_ip="${1:-default}" default_ip
    source_ip="$(normalize_haproxy_source_ip "$source_ip" 2>/dev/null || printf 'default')"
    if [[ "$source_ip" != default ]]; then
        printf '%s\n' "$source_ip"
        return 0
    fi
    default_ip="$(haproxy_default_source_ip)"
    if [[ -n "$default_ip" ]]; then
        printf '%s (default)\n' "$default_ip"
    else
        printf 'системный default\n'
    fi
}

normalize_haproxy_sni_list() {
    local raw="${1:-}" token base existing
    local -a tokens=() normalized=()

    raw="$(trim_whitespace "$raw")"
    case "${raw,,}" in
        ""|\*|any|all) printf 'any\n'; return 0 ;;
    esac
    raw="${raw//,/ }"
    raw="${raw//;/ }"
    IFS=' ' read -r -a tokens <<< "$raw"
    for token in "${tokens[@]}"; do
        token="${token,,}"
        token="${token%.}"
        [[ -n "$token" ]] || continue
        case "$token" in
            \*|any|all) return 1 ;;
        esac
        base="$token"
        if [[ "$base" == \*.* ]]; then
            base="${base#*.}"
        fi
        validate_domain "$base" || return 1
        for existing in "${normalized[@]:-}"; do
            [[ "$existing" == "$token" ]] && continue 2
        done
        normalized+=("$token")
    done

    (( ${#normalized[@]} > 0 )) || return 1
    local IFS=' '
    printf '%s\n' "${normalized[*]}"
}

haproxy_sni_label() {
    local normalized
    normalized="$(normalize_haproxy_sni_list "${1:-}" 2>/dev/null || true)"
    if [[ "$normalized" == any ]]; then
        printf 'любой\n'
    else
        printf '%s\n' "${normalized:-некорректный}"
    fi
}

render_haproxy_sni_acl_lines() {
    local raw="${1:-}" normalized token
    local -a values=() exact_values=() wildcard_suffixes=()

    normalized="$(normalize_haproxy_sni_list "$raw")" || return 1
    [[ "$normalized" != any ]] || return 0
    IFS=' ' read -r -a values <<< "$normalized"
    for token in "${values[@]}"; do
        if [[ "$token" == \*.* ]]; then
            wildcard_suffixes+=(".${token#*.}")
        else
            exact_values+=("$token")
        fi
    done

    local IFS=' '
    if (( ${#exact_values[@]} > 0 )); then
        printf '    acl allowed_sni req.ssl_sni -i %s\n' "${exact_values[*]}"
    fi
    if (( ${#wildcard_suffixes[@]} > 0 )); then
        printf '    acl allowed_sni req.ssl_sni -m end -i %s\n' "${wildcard_suffixes[*]}"
    fi
}

current_ssh_client_ip() {
    local ip="${SSH_CLIENT:-}"
    ip="${ip%% *}"
    validate_ipv4 "$ip" && echo "$ip"
}

existing_kto_ssh_allowed_ips() {
    command_exists ufw || return 0
    "${SUDO[@]}" ufw status 2>/dev/null | awk '
        /ALLOW/ && /# kto-ssh/ {
            for (i = 3; i <= NF; i++) {
                if ($i ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/) {
                    print $i
                    break
                }
            }
        }
    '
}

whitelist_ssh_allowed_ips() {
    local raw current ip
    raw="${WHITELIST_SSH_ALLOWED_IPS//,/ }"
    raw="${raw//;/ }"
    for ip in $raw; do
        validate_ipv4 "$ip" && echo "$ip"
    done

    while read -r ip; do
        validate_ipv4 "$ip" && echo "$ip"
    done < <(existing_kto_ssh_allowed_ips)

    if [[ "$WHITELIST_SSH_KEEP_CURRENT" != "0" ]]; then
        current="$(current_ssh_client_ip || true)"
        if [[ -n "$current" ]]; then
            echo "$current"
        fi
    fi
}

apply_whitelist_ssh_rules() {
    local ssh_port="$1"
    local ip attempt allowed_ips managed_port

    allowed_ips="$(whitelist_ssh_allowed_ips | sort -u)"

    # Once kto has migrated SSH to its persistent random port, that port must
    # stay globally reachable. Keep the old allowlist behavior only for nodes
    # which have not gone through the managed root-SSH migration yet.
    managed_port="$(managed_ssh_port 2>/dev/null || true)"
    if [[ -n "$managed_port" && "$ssh_port" == "$managed_port" ]]; then
        while read -r ip; do
            [[ -n "$ip" ]] || continue
            for (( attempt = 0; attempt < 16; attempt++ )); do
                "${SUDO[@]}" ufw --force delete allow proto tcp from "$ip" to any port "$ssh_port" >/dev/null 2>&1 || break
            done
        done <<< "$allowed_ips"
        ensure_global_ssh_ufw_rule "$ssh_port"
        return 0
    fi

    cmd "${SUDO[@]}" ufw --force delete allow "${ssh_port}/tcp" || true
    cmd "${SUDO[@]}" ufw --force delete allow ssh || true
    cmd "${SUDO[@]}" ufw --force delete allow OpenSSH || true
    while read -r ip; do
        [[ -n "$ip" ]] || continue
        for (( attempt = 0; attempt < 16; attempt++ )); do
            "${SUDO[@]}" ufw --force delete allow proto tcp from "$ip" to any port "$ssh_port" >/dev/null 2>&1 || break
        done
        cmd "${SUDO[@]}" ufw insert 1 allow proto tcp from "$ip" to any port "$ssh_port" comment 'kto-ssh' || true
    done <<< "$allowed_ips"
}

ssh_service_name() {
    if systemctl cat ssh.service >/dev/null 2>&1; then
        printf 'ssh\n'
    elif systemctl cat sshd.service >/dev/null 2>&1; then
        printf 'sshd\n'
    else
        return 1
    fi
}

ufw_allow_rule_numbers_for_port() {
    local port="$1"
    command_exists ufw || return 0
    "${SUDO[@]}" ufw status numbered 2>/dev/null | awk -v port="$port" -v tcp="${port}/tcp" '
        $0 ~ /ALLOW/ {
            number = $0
            sub(/^[[:space:]]*\[[[:space:]]*/, "", number)
            sub(/\].*$/, "", number)
            gsub(/[[:space:]]/, "", number)
            if (number !~ /^[0-9]+$/) next

            target = $0
            sub(/^[^]]*\][[:space:]]*/, "", target)
            sub(/[[:space:]]+ALLOW.*/, "", target)
            gsub(/[[:space:]]/, "", target)
            is_port = (target == tcp || target == tcp "(v6)" || target == port || target == port "(v6)")
            is_service = (port == "22" && (target == "ssh" || target == "ssh(v6)" || target == "OpenSSH" || target == "OpenSSH(v6)"))
            if (is_port || is_service) print number
        }
    ' | sort -rn
}

ufw_global_allow_exists_for_port() {
    local port="$1"
    command_exists ufw || return 1
    "${SUDO[@]}" ufw status 2>/dev/null | awk -v port="$port" -v tcp="${port}/tcp" '
        $0 !~ /\(v6\)/ && $0 ~ /ALLOW/ {
            target = $1
            gsub(/[[:space:]]/, "", target)
            is_target = (target == tcp || target == port ||
                (port == "22" && (target == "ssh" || target == "OpenSSH")))
            if (!is_target) next
            for (i = 2; i <= NF; i++) {
                if ($i != "ALLOW") continue
                if ($(i + 1) == "OUT" || $(i + 1) == "FWD") continue
                source_field = i + 1
                if ($source_field == "IN") source_field++
                if ($source_field == "Anywhere") found = 1
            }
        }
        END { exit found ? 0 : 1 }
    '
}

remove_ufw_allow_rules_for_port() {
    local port="$1" number
    local -a numbers=()
    command_exists ufw || return 0
    mapfile -t numbers < <(ufw_allow_rule_numbers_for_port "$port")
    for number in "${numbers[@]}"; do
        [[ "$number" =~ ^[0-9]+$ ]] || continue
        "${SUDO[@]}" ufw --force delete "$number" >> "$LOG_FILE" 2>&1 || true
    done
}

ensure_global_ssh_ufw_rule() {
    local port="$1"
    command_exists ufw || return 0
    if ! ufw_global_allow_exists_for_port "$port"; then
        cmd "${SUDO[@]}" ufw allow proto tcp to any port "$port" comment 'kto-ssh-open'
    fi
}

merge_root_authorized_keys() {
    local output_file="$1" user uid home key_file
    local -a key_files=(/root/.ssh/authorized_keys /root/.ssh/authorized_keys2)

    while IFS=: read -r user _ uid _ _ home _; do
        [[ -n "$user" && -n "$home" ]] || continue
        if [[ "$user" == "root" || "$uid" =~ ^[0-9]+$ && "$uid" -ge 1000 && "$uid" -lt 65534 ]]; then
            key_files+=(
                "${home}/.ssh/authorized_keys"
                "${home}/.ssh/authorized_keys2"
                "/etc/ssh/authorized_keys/${user}"
                "/etc/ssh/authorized_keys.d/${user}"
            )
        fi
    done < <(getent passwd 2>/dev/null || true)

    printf '%s\n' "$KTO_ROOT_BASE_PUBLIC_KEY" > "$output_file"
    for key_file in "${key_files[@]}"; do
        if "${SUDO[@]}" test -s "$key_file" 2>/dev/null; then
            "${SUDO[@]}" cat "$key_file" 2>> "$LOG_FILE" | awk '
                {
                    for (i = 1; i <= NF; i++) {
                        if ($i ~ /^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-|sk-(ssh-ed25519|ecdsa-sha2-)|rsa-sha2-)/ && (i + 1) <= NF) {
                            line = $i " " $(i + 1)
                            for (j = i + 2; j <= NF; j++) line = line " " $j
                            print line
                            break
                        }
                    }
                }
            ' >> "$output_file" || true
        fi
    done
    awk 'NF && !seen[$0]++ { print }' "$output_file" > "${output_file}.dedup"
    mv "${output_file}.dedup" "$output_file"
    if [[ ! -s "$output_file" ]] || ! ssh-keygen -lf "$output_file" >/dev/null 2>&1; then
        return 1
    fi
}

root_public_key_available() {
    local tmp rc=0
    command_exists ssh-keygen || return 1
    tmp="$(mktemp)"
    merge_root_authorized_keys "$tmp" || rc=$?
    rm -f "$tmp" "${tmp}.dedup"
    return "$rc"
}

restore_optional_ssh_file() {
    local backup="$1" target="$2" existed="$3"
    if [[ "$existed" == "1" ]]; then
        "${SUDO[@]}" cp -a "$backup" "$target" >> "$LOG_FILE" 2>&1 || true
    else
        "${SUDO[@]}" rm -f "$target" >> "$LOG_FILE" 2>&1 || true
    fi
}

rollback_ssh_migration() {
    local backup_dir="$1" had_main="$2" had_managed="$3" had_root_keys="$4" had_marker="$5"
    local service="$6" socket_was_enabled="$7" socket_was_active="$8" new_port="$9" new_rule_existed="${10}"

    restore_optional_ssh_file "${backup_dir}/sshd_config" /etc/ssh/sshd_config "$had_main"
    restore_optional_ssh_file "${backup_dir}/managed.conf" "$KTO_SSH_MANAGED_CONFIG" "$had_managed"
    restore_optional_ssh_file "${backup_dir}/authorized_keys" /root/.ssh/authorized_keys "$had_root_keys"
    restore_optional_ssh_file "${backup_dir}/port" "$KTO_SSH_PORT_FILE" "$had_marker"
    run_systemctl_bounded 15 daemon-reload >> "$LOG_FILE" 2>&1 || true
    if [[ "$socket_was_enabled" == "1" ]]; then
        run_systemctl_bounded 15 enable ssh.socket >> "$LOG_FILE" 2>&1 || true
    fi
    if [[ "$socket_was_active" == "1" ]]; then
        run_systemctl_bounded 15 start ssh.socket >> "$LOG_FILE" 2>&1 || true
    fi
    run_systemctl_bounded 15 restart "$service" >> "$LOG_FILE" 2>&1 || true
    if [[ "$new_rule_existed" == "0" ]]; then
        remove_ufw_allow_rules_for_port "$new_port"
    fi
}

ssh_root_access_configured() {
    local port service effective
    port="$(managed_ssh_port || true)"
    [[ -n "$port" ]] || return 1
    [[ -s "$KTO_SSH_MANAGED_CONFIG" && -s /root/.ssh/authorized_keys ]] || return 1
    grep -Fqx "Port ${port}" "$KTO_SSH_MANAGED_CONFIG" 2>/dev/null || return 1
    grep -Fqx 'PermitRootLogin prohibit-password' "$KTO_SSH_MANAGED_CONFIG" 2>/dev/null || return 1
    service="$(ssh_service_name 2>/dev/null || true)"
    [[ -n "$service" ]] || return 1
    run_systemctl_bounded 3 is-active --quiet "$service" 2>/dev/null || return 1
    ssh_port_is_listening "$port" || return 1
    if command_exists ufw && "${SUDO[@]}" ufw status 2>/dev/null | grep -q 'Status: active'; then
        ufw_global_allow_exists_for_port "$port" || return 1
    fi
    effective="$("${SUDO[@]}" sshd -T -C user=root,host=localhost,addr=127.0.0.1 2>/dev/null || true)"
    grep -Fqx 'permitrootlogin without-password' <<< "$effective" ||
        grep -Fqx 'permitrootlogin prohibit-password' <<< "$effective"
}

opt_ssh_root_access() {
    local old_port new_port service timestamp backup_dir main_tmp keys_tmp effective
    local had_main=0 had_managed=0 had_root_keys=0 had_marker=0 new_rule_existed=0
    local socket_was_enabled=0 socket_was_active=0 attempt

    command_exists sshd || {
        fail "OpenSSH server не установлен"
        return 1
    }
    command_exists ssh-keygen || apt_install_quiet openssh-client || return 1
    service="$(ssh_service_name 2>/dev/null || true)"
    [[ -n "$service" ]] || {
        fail "SSH systemd service не найден"
        return 1
    }

    keys_tmp="$(mktemp)"
    if ! merge_root_authorized_keys "$keys_tmp"; then
        rm -f "$keys_tmp" "${keys_tmp}.dedup"
        warn "SSH: public key не найден; текущие порт, UFW и параметры входа оставлены без изменений."
        warn "Чтобы включить root key-only, сначала добавь свой ключ в ~/.ssh/authorized_keys и повтори оптимизацию."
        return 0
    fi

    old_port="$(detect_ssh_port)"
    new_port="$(choose_managed_ssh_port 2>/dev/null || true)"
    [[ "$new_port" =~ ^[0-9]+$ ]] || {
        rm -f "$keys_tmp" "${keys_tmp}.dedup"
        fail "Не удалось выбрать свободный случайный SSH-порт"
        return 1
    }

    timestamp="$(date -u +%Y%m%d-%H%M%S-%N)"
    backup_dir="${KTO_SSH_BACKUP_DIR}/${timestamp}-${BASHPID:-$$}-${RANDOM}"
    cmd "${SUDO[@]}" mkdir -p "$backup_dir" /etc/ssh/sshd_config.d /root/.ssh /run/sshd
    cmd "${SUDO[@]}" chmod 0700 "$KTO_SSH_BACKUP_DIR" "$backup_dir" /root/.ssh
    if "${SUDO[@]}" test -e /etc/ssh/sshd_config; then
        had_main=1
        "${SUDO[@]}" cp -a /etc/ssh/sshd_config "${backup_dir}/sshd_config"
    fi
    if "${SUDO[@]}" test -e "$KTO_SSH_MANAGED_CONFIG"; then
        had_managed=1
        "${SUDO[@]}" cp -a "$KTO_SSH_MANAGED_CONFIG" "${backup_dir}/managed.conf"
    fi
    if "${SUDO[@]}" test -e /root/.ssh/authorized_keys; then
        had_root_keys=1
        "${SUDO[@]}" cp -a /root/.ssh/authorized_keys "${backup_dir}/authorized_keys"
    fi
    if "${SUDO[@]}" test -e "$KTO_SSH_PORT_FILE"; then
        had_marker=1
        "${SUDO[@]}" cp -a "$KTO_SSH_PORT_FILE" "${backup_dir}/port"
    fi
    run_systemctl_bounded 3 is-enabled --quiet ssh.socket 2>/dev/null && socket_was_enabled=1 || true
    run_systemctl_bounded 3 is-active --quiet ssh.socket 2>/dev/null && socket_was_active=1 || true
    ufw_global_allow_exists_for_port "$new_port" && new_rule_existed=1 || true

    main_tmp="$(mktemp)"
    if (( had_main == 1 )); then
        {
            printf 'Include %s\n' "$KTO_SSH_MANAGED_CONFIG"
            "${SUDO[@]}" cat /etc/ssh/sshd_config | awk -v managed_include="$KTO_SSH_MANAGED_CONFIG" '
                !($1 == "Include" && $2 == managed_include) { print }
            '
        } > "$main_tmp"
    else
        printf 'Include %s\n' "$KTO_SSH_MANAGED_CONFIG" > "$main_tmp"
    fi

    if ! "${SUDO[@]}" install -m 0600 -o root -g root "$keys_tmp" /root/.ssh/authorized_keys >> "$LOG_FILE" 2>&1 ||
        ! write_root_file_mode 0644 "$KTO_SSH_MANAGED_CONFIG" <<EOF
# Managed by kto. Root login is key-only; password authentication stays disabled.
Port ${new_port}
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
EOF
    then
        rm -f "$keys_tmp" "$main_tmp"
        rollback_ssh_migration "$backup_dir" "$had_main" "$had_managed" "$had_root_keys" "$had_marker" \
            "$service" "$socket_was_enabled" "$socket_was_active" "$new_port" "$new_rule_existed"
        return 1
    fi
    rm -f "$keys_tmp"
    if ! "${SUDO[@]}" install -m 0644 "$main_tmp" /etc/ssh/sshd_config >> "$LOG_FILE" 2>&1; then
        rm -f "$main_tmp"
        rollback_ssh_migration "$backup_dir" "$had_main" "$had_managed" "$had_root_keys" "$had_marker" \
            "$service" "$socket_was_enabled" "$socket_was_active" "$new_port" "$new_rule_existed"
        return 1
    fi
    rm -f "$main_tmp"

    effective="$("${SUDO[@]}" sshd -T -C user=root,host=localhost,addr=127.0.0.1 2>> "$LOG_FILE" || true)"
    if ! "${SUDO[@]}" sshd -t >> "$LOG_FILE" 2>&1 ||
        ! grep -Fqx "port ${new_port}" <<< "$effective" ||
        ! grep -Fqx 'pubkeyauthentication yes' <<< "$effective" ||
        { ! grep -Fqx 'permitrootlogin without-password' <<< "$effective" &&
          ! grep -Fqx 'permitrootlogin prohibit-password' <<< "$effective"; }; then
        rollback_ssh_migration "$backup_dir" "$had_main" "$had_managed" "$had_root_keys" "$had_marker" \
            "$service" "$socket_was_enabled" "$socket_was_active" "$new_port" "$new_rule_existed"
        fail "SSH candidate не прошёл проверку; старый config восстановлен"
        return 1
    fi
    if grep -Eq '^denyusers .*([^[:alnum:]_]|^)root([^[:alnum:]_]|$)' <<< "$effective" ||
        { grep -q '^allowusers ' <<< "$effective" && ! grep -Eq '^allowusers .*([^[:alnum:]_]|^)root(@[^ ]+)?([[:space:]]|$)' <<< "$effective"; }; then
        rollback_ssh_migration "$backup_dir" "$had_main" "$had_managed" "$had_root_keys" "$had_marker" \
            "$service" "$socket_was_enabled" "$socket_was_active" "$new_port" "$new_rule_existed"
        fail "SSH AllowUsers/DenyUsers запрещает root; config восстановлен"
        return 1
    fi

    ensure_global_ssh_ufw_rule "$new_port" || {
        rollback_ssh_migration "$backup_dir" "$had_main" "$had_managed" "$had_root_keys" "$had_marker" \
            "$service" "$socket_was_enabled" "$socket_was_active" "$new_port" "$new_rule_existed"
        return 1
    }
    run_systemctl_bounded 15 disable --now ssh.socket >> "$LOG_FILE" 2>&1 || true
    if ! run_systemctl_bounded 15 enable "$service" >> "$LOG_FILE" 2>&1 ||
        ! run_systemctl_bounded 15 restart "$service" >> "$LOG_FILE" 2>&1; then
        rollback_ssh_migration "$backup_dir" "$had_main" "$had_managed" "$had_root_keys" "$had_marker" \
            "$service" "$socket_was_enabled" "$socket_was_active" "$new_port" "$new_rule_existed"
        fail "SSH не перезапустился на новом порту; выполнен откат"
        return 1
    fi
    for (( attempt = 0; attempt < 20; attempt++ )); do
        ssh_port_is_listening "$new_port" && break
        sleep 0.25
    done
    if ! run_systemctl_bounded 3 is-active --quiet "$service" 2>/dev/null || ! ssh_port_is_listening "$new_port"; then
        rollback_ssh_migration "$backup_dir" "$had_main" "$had_managed" "$had_root_keys" "$had_marker" \
            "$service" "$socket_was_enabled" "$socket_was_active" "$new_port" "$new_rule_existed"
        fail "SSH listener ${new_port}/tcp не поднялся; выполнен откат"
        return 1
    fi

    if ! write_root_file_mode 0600 "$KTO_SSH_PORT_FILE" <<EOF
${new_port}
EOF
    then
        rollback_ssh_migration "$backup_dir" "$had_main" "$had_managed" "$had_root_keys" "$had_marker" \
            "$service" "$socket_was_enabled" "$socket_was_active" "$new_port" "$new_rule_existed"
        fail "Не удалось сохранить управляемый SSH-порт; выполнен откат"
        return 1
    fi
    if [[ "$old_port" != "$new_port" ]]; then
        remove_ufw_allow_rules_for_port "$old_port"
    fi
    if [[ "$new_port" != "22" ]]; then
        remove_ufw_allow_rules_for_port 22
    fi
    ensure_global_ssh_ufw_rule "$new_port"
    "${SUDO[@]}" ufw reload >> "$LOG_FILE" 2>&1 || true

    ok "SSH: root по ключу, порт ${new_port}/tcp открыт для всех"
    ok "Подключение: ssh -p ${new_port} root@IP"
    ok "SSH backup: ${backup_dir}"
}

write_whitelist_fail2ban_allowlist() {
    local ignore_ips
    ignore_ips="$(whitelist_ssh_allowed_ips | sort -u | paste -sd' ' -)"
    write_root_file "$FAIL2BAN_SSH_ALLOWLIST_CONF" <<EOF
[sshd]
ignoreip = 127.0.0.1/8 ::1${ignore_ips:+ $ignore_ips}
EOF
}

unban_whitelist_ssh_ips() {
    local ip
    command_exists fail2ban-client || return 0
    "${SUDO[@]}" systemctl is-active --quiet fail2ban 2>/dev/null || return 0
    while read -r ip; do
        [[ -n "$ip" ]] || continue
        "${SUDO[@]}" fail2ban-client set sshd addignoreip "$ip" >/dev/null 2>&1 || true
        "${SUDO[@]}" fail2ban-client set sshd unbanip "$ip" >/dev/null 2>&1 || true
    done < <(whitelist_ssh_allowed_ips | sort -u)
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

ask_haproxy_target() {
    local prompt="${1:-Введите выходной IP или IP:порт}"
    local value target
    while true; do
        printf '%s: ' "$prompt" >&2
        read -r value
        if target="$(normalize_haproxy_target "$value")"; then
            echo "$target"
            return 0
        fi
        fail "Некорректный target. Пример: 1.2.3.4 или 1.2.3.4:8443"
    done
}

ask_haproxy_target_default() {
    local prompt="$1" default="${2:-}" value target
    while true; do
        value="$(ask_text "$prompt" "$default")"
        if target="$(normalize_haproxy_target "$value")"; then
            echo "$target"
            return 0
        fi
        fail "Некорректный target. Пример: 1.2.3.4 или 1.2.3.4:8443"
    done
}

ask_haproxy_target_pool_default() {
    local prompt="$1" default="${2:-}" value targets
    while true; do
        value="$(ask_text "$prompt" "$default")"
        if targets="$(normalize_haproxy_target_pool "$value")"; then
            echo "$targets"
            return 0
        fi
        fail "Некорректный список. Укажи IP[:порт] через пробел или запятую."
    done
}

ask_haproxy_sni_list() {
    local prompt="$1" default="${2:-}" value normalized normalized_default="" default_label=""

    if [[ -n "$default" ]]; then
        normalized_default="$(normalize_haproxy_sni_list "$default" 2>/dev/null || true)"
        default_label="$(haproxy_sni_label "$normalized_default")"
    fi
    while true; do
        if [[ -n "$normalized_default" ]]; then
            printf '%s [сейчас: %s; Enter = любой; = оставить]: ' "$prompt" "$default_label" >&2
        else
            printf '%s [Enter = любой]: ' "$prompt" >&2
        fi
        read -r value
        value="${value%$'\r'}"
        if [[ "$value" == "=" && -n "$normalized_default" ]]; then
            printf '%s\n' "$normalized_default"
            return 0
        fi
        if normalized="$(normalize_haproxy_sni_list "$value")"; then
            echo "$normalized"
            return 0
        fi
        fail "Некорректный SNI. Примеры: example.com, *.example.com; Enter разрешает любой SNI."
    done
}

ask_haproxy_send_proxy_v2() {
    local default="${1:-0}" value normalized prompt
    default="$(normalize_haproxy_send_proxy_v2 "$default" 2>/dev/null || printf '0')"
    if [[ "$default" == "1" ]]; then
        prompt="Включить send-proxy-v2 для backend? [Y/n]"
    else
        prompt="Включить send-proxy-v2 для backend? [y/N]"
    fi
    while true; do
        printf '%s: ' "$prompt" >&2
        if ! read -r value; then
            value=""
        fi
        value="${value%$'\r'}"
        if [[ -z "$value" ]]; then
            printf '%s\n' "$default"
            return 0
        fi
        if normalized="$(normalize_haproxy_send_proxy_v2 "$value" 2>/dev/null)"; then
            printf '%s\n' "$normalized"
            return 0
        fi
        fail "Ответь y/yes для включения или n/no для выключения"
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
    ' "$HOSTS_FILE" 2>/dev/null
}

hostname_hosts_configured() {
    local host
    host="$(hostname 2>/dev/null || true)"
    [[ -n "$host" ]] || return 0
    hosts_file_has_hostname "$host" || run_bounded_command 2 getent hosts "$host" >/dev/null 2>&1
}

ensure_hostname_hosts_entry() {
    local host short tmp backup="$HOSTS_BACKUP_FILE" had_hosts=0
    host="$(hostname 2>/dev/null || true)"
    [[ -n "$host" ]] || return 0
    hostname_hosts_configured && return 0

    if [[ ! "$host" =~ ^[A-Za-z0-9._-]+$ ]]; then
        fail "Некорректный hostname для /etc/hosts: ${host}"
        return 1
    fi

    short="${host%%.*}"
    tmp="$(mktemp)"
    if "${SUDO[@]}" test -e "$HOSTS_FILE" 2>/dev/null; then
        had_hosts=1
        if ! "${SUDO[@]}" cat "$HOSTS_FILE" > "$tmp" 2>> "$LOG_FILE"; then
            rm -f "$tmp"
            fail "Не удалось прочитать /etc/hosts"
            return 1
        fi
    else
        printf '127.0.0.1\tlocalhost\n' > "$tmp"
    fi
    {
        printf '\n127.0.1.1\t%s' "$host"
        if [[ -n "$short" && "$short" != "$host" ]]; then
            printf ' %s' "$short"
        fi
        printf '\n'
    } >> "$tmp"

    if (( had_hosts == 1 )) && ! "${SUDO[@]}" test -e "$backup" 2>/dev/null; then
        if ! "${SUDO[@]}" cp -a "$HOSTS_FILE" "$backup" >> "$LOG_FILE" 2>&1; then
            rm -f "$tmp"
            fail "Не удалось создать backup /etc/hosts"
            return 1
        fi
    fi
    if ! "${SUDO[@]}" install -m 0644 "$tmp" "$HOSTS_FILE" >> "$LOG_FILE" 2>&1; then
        rm -f "$tmp"
        fail "Не удалось добавить hostname в /etc/hosts"
        return 1
    fi
    rm -f "$tmp"
    if ! hosts_file_has_hostname "$host"; then
        fail "Hostname не появился в /etc/hosts после записи"
        return 1
    fi
    echo "hostname guard: added ${host} to /etc/hosts, backup=${backup}" >> "$LOG_FILE" 2>/dev/null || true
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

dns_host_resolves() {
    local host="${1:-}"
    [[ -n "$host" ]] || return 1
    run_bounded_command 2 getent ahosts "$host" >/dev/null 2>&1
}

wait_for_dns_host() {
    local host="$1" timeout_sec="${2:-10}" deadline
    [[ "$timeout_sec" =~ ^[0-9]+$ ]] || timeout_sec=10
    deadline=$(( SECONDS + timeout_sec ))
    while (( SECONDS < deadline )); do
        dns_host_resolves "$host" && return 0
        sleep 1
    done
    return 1
}

dns_resolution_ok() {
    dns_host_resolves api.telegram.org ||
        dns_host_resolves raw.githubusercontent.com
}

wait_for_dns_resolution() {
    wait_for_dns_host api.telegram.org 5 ||
        wait_for_dns_host raw.githubusercontent.com 5
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
    local curl_tls=()
    tmp="$(mktemp)"
    url="${REMNA_API_URL%/}${path}"
    if [[ "${KTO_REMNA_API_INSECURE:-0}" == "1" ]]; then
        curl_tls=(-k)
    fi

    if [[ -n "$payload_file" ]]; then
        code="$(curl "${curl_tls[@]}" -sS -L -X "$method" \
            -H "Authorization: Bearer ${REMNA_API_TOKEN}" \
            -H "Accept: application/json" \
            -H "Content-Type: application/json" \
            --data-binary "@${payload_file}" \
            -o "$tmp" -w '%{http_code}' "$url" 2>> "$LOG_FILE" || true)"
    else
        code="$(curl "${curl_tls[@]}" -sS -L -X "$method" \
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
TRUSTED_FILE="\$(mktemp)"
LOG="/var/log/antiscanner_update.log"

cleanup() {
    rm -f "\$TEMP_FILE" "\$TRUSTED_FILE"
}
trap cleanup EXIT

if ! command -v ufw >/dev/null 2>&1; then
    echo "\$(date '+%Y-%m-%d %H:%M:%S') [ERROR] ufw not found" >> "\$LOG"
    exit 1
fi

SSH_PORT="\$(awk 'NR == 1 {print \$1; exit}' '${KTO_SSH_PORT_FILE}' 2>/dev/null || true)"
[[ "\$SSH_PORT" =~ ^[0-9]+\$ ]] || SSH_PORT="\$(sshd -T 2>/dev/null | awk '/^port / {print \$2; exit}' || true)"
SSH_PORT="\${SSH_PORT:-22}"
ufw status 2>/dev/null | awk '
    /ALLOW/ && /# kto-ssh/ {
        for (i = 3; i <= NF; i++) {
            if (\$i ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}\$/) {
                print \$i
                break
            }
        }
    }
' | sort -u > "\$TRUSTED_FILE"

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

    while IFS= read -r trusted_ip; do
        [[ "\$trusted_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}\$ ]] || continue
        for _ in {1..16}; do
            ufw --force delete allow proto tcp from "\$trusted_ip" to any port "\$SSH_PORT" >/dev/null 2>&1 || break
        done
        ufw insert 1 allow proto tcp from "\$trusted_ip" to any port "\$SSH_PORT" comment 'kto-ssh' >/dev/null 2>&1 || true
    done < "\$TRUSTED_FILE"

    ufw reload >/dev/null 2>&1 || true
    if [[ -x "${HAPROXY_FIREWALL_MANAGER}" ]]; then
        "${HAPROXY_FIREWALL_MANAGER}" >> "\$LOG" 2>&1 ||
            echo "\$(date '+%Y-%m-%d %H:%M:%S') [ERROR] failed to restore HAProxy UFW rules" >> "\$LOG"
    fi
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
    if [[ "${KTO_DESTRUCTIVE_CLEANUP:-0}" == "1" ]]; then
        cmd "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive apt-get autoremove --purge -y || true
    fi
    if command_exists journalctl; then
        cmd "${SUDO[@]}" journalctl --vacuum-size=256M --vacuum-time=7d || true
    fi
    cmd "${SUDO[@]}" rm -f /etc/apt/sources.list.d/ookla_speedtest-cli.list || true
    if package_installed snapd && [[ "${KTO_PURGE_SNAPD:-0}" == "1" ]]; then
        cmd "${SUDO[@]}" systemctl disable --now snapd.socket snapd.service || true
        cmd "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive apt-get purge -y snapd || true
    elif package_installed snapd; then
        echo "snapd purge skipped: set KTO_PURGE_SNAPD=1 to remove it" >> "$LOG_FILE"
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

optimization_fast_packages() {
    {
        optimization_packages
        printf '%s\n' cron fail2ban util-linux kmod
    } | awk 'NF && !seen[$0]++'
}

opt_install_fast_packages() {
    local packages
    mapfile -t packages < <(optimization_fast_packages)
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

    if dns_resolution_ok && [[ "${KTO_FORCE_DNS_GUARD:-0}" != "1" ]]; then
        echo "DNS guard skipped: current resolver works" >> "$LOG_FILE"
        return 0
    fi

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

    if [[ "${KTO_DESTRUCTIVE_CLEANUP:-0}" == "1" ]]; then
        cmd "${SUDO[@]}" find /var/lib/docker/containers -type f -name '*-json.log' -size +100M -exec truncate -s 0 {} + || true
        cmd "${SUDO[@]}" docker image prune -af || true
        cmd "${SUDO[@]}" docker builder prune -af || true
    fi
    cmd "${SUDO[@]}" systemctl reload docker || true
}

truncate_large_var_logs() {
    [[ "${KTO_DESTRUCTIVE_CLEANUP:-0}" == "1" ]] || return 0
    cmd "${SUDO[@]}" find /var/log -xdev -type f -size +256M \
        ! -path '/var/log/journal/*' \
        -printf 'truncate large log: %s %p\n' || true
    cmd "${SUDO[@]}" find /var/log -xdev -type f -size +256M \
        ! -path '/var/log/journal/*' \
        -exec truncate -s 0 {} + || true
}

cleanup_superseded_kto_files() {
    local path

    for path in /etc/sysctl.d/99-*-tuning.conf; do
        [[ -e "$path" ]] || continue
        [[ "$path" == "$KTO_TUNING_SYSCTL_CONF" ]] && continue
        if "${SUDO[@]}" grep -qs 'net.ipv4.tcp_congestion_control = bbr' "$path" &&
            "${SUDO[@]}" grep -qs 'net.core.default_qdisc = fq' "$path"; then
            cmd "${SUDO[@]}" rm -f "$path" || true
        fi
    done

    for path in /etc/security/limits.d/99-*-limits.conf; do
        [[ -e "$path" ]] || continue
        [[ "$path" == "$KTO_LIMITS_CONF" ]] && continue
        if "${SUDO[@]}" grep -qs 'nofile 1048576' "$path"; then
            cmd "${SUDO[@]}" rm -f "$path" || true
        fi
    done

    for path in /etc/systemd/system.conf.d/99-*-limits.conf /etc/systemd/user.conf.d/99-*-limits.conf; do
        [[ -e "$path" ]] || continue
        [[ "$path" == "$KTO_SYSTEMD_LIMITS_CONF" || "$path" == "$KTO_USER_LIMITS_CONF" ]] && continue
        if "${SUDO[@]}" grep -qs 'DefaultLimitNOFILE=1048576' "$path"; then
            cmd "${SUDO[@]}" rm -f "$path" || true
        fi
    done

    for path in /etc/logrotate.d/kto-*; do
        [[ -e "$path" ]] || continue
        [[ "$path" == "$KTO_LOGROTATE_CONF" ]] && continue
        cmd "${SUDO[@]}" rm -f "$path" || true
    done
}

opt_storage_guard() {
    cmd "${SUDO[@]}" apt-get clean || true
    cmd "${SUDO[@]}" apt-get autoclean || true
    if [[ "${KTO_DESTRUCTIVE_CLEANUP:-0}" == "1" ]]; then
        cmd "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive apt-get autoremove --purge -y || true
    fi

    cmd "${SUDO[@]}" mkdir -p /etc/systemd/journald.conf.d /etc/logrotate.d
    cleanup_superseded_kto_files
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

    if [[ "${KTO_DESTRUCTIVE_CLEANUP:-0}" == "1" ]]; then
        cmd "${SUDO[@]}" find /tmp -xdev -mindepth 1 -mtime +2 -exec rm -rf -- {} + || true
        cmd "${SUDO[@]}" find /var/tmp -xdev -mindepth 1 -mtime +7 -exec rm -rf -- {} + || true
        cmd "${SUDO[@]}" find /var/crash -type f -delete || true
        cmd "${SUDO[@]}" find /var/lib/systemd/coredump -type f -mtime +1 -delete || true
        cmd "${SUDO[@]}" find /var/log -xdev -type f \( -name '*.gz' -o -name '*.old' -o -name '*.1' \) -mtime +14 -delete || true
        truncate_large_var_logs
    fi

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
    KTO_DESTRUCTIVE_CLEANUP=1 opt_storage_guard

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
        if ! opt_zram optional; then
            warn "Продолжаю настройку памяти без ZRAM."
        fi
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

configure_xanmod_repository() {
    local key_tmp keyring_tmp codename fingerprint

    codename="$(awk -F= '$1 == "VERSION_CODENAME" { gsub(/"/, "", $2); print $2; exit }' /etc/os-release 2>/dev/null || true)"
    [[ -n "$codename" ]] || {
        fail "XanMod: не удалось определить Ubuntu codename"
        return 1
    }
    command_exists gpg || apt_install_quiet gnupg2 || return 1
    key_tmp="$(mktemp)"
    keyring_tmp="$(mktemp)"
    if command_exists curl; then
        if ! curl -fsSL --connect-timeout 10 --max-time 60 "$XANMOD_KEY_URL" -o "$key_tmp"; then
            rm -f "$key_tmp" "$keyring_tmp"
            fail "XanMod: не удалось скачать официальный signing key"
            return 1
        fi
    elif command_exists wget; then
        if ! wget -q --timeout=60 -O "$key_tmp" "$XANMOD_KEY_URL"; then
            rm -f "$key_tmp" "$keyring_tmp"
            fail "XanMod: не удалось скачать официальный signing key"
            return 1
        fi
    else
        rm -f "$key_tmp" "$keyring_tmp"
        fail "XanMod: curl/wget не найден"
        return 1
    fi
    fingerprint="$(gpg --batch --show-keys --with-colons "$key_tmp" 2>/dev/null | awk -F: '$1 == "fpr" { print $10; exit }')"
    if [[ ! "$fingerprint" =~ ^[A-Fa-f0-9]{40,64}$ ]] ||
        ! gpg --batch --yes --dearmor --output "$keyring_tmp" "$key_tmp" >/dev/null 2>&1 ||
        [[ ! -s "$keyring_tmp" ]]; then
        rm -f "$key_tmp" "$keyring_tmp"
        fail "XanMod: официальный signing key не прошёл проверку"
        return 1
    fi
    cmd "${SUDO[@]}" mkdir -p /etc/apt/keyrings
    if ! "${SUDO[@]}" install -m 0644 "$keyring_tmp" "$XANMOD_KEYRING" >> "$LOG_FILE" 2>&1; then
        rm -f "$key_tmp" "$keyring_tmp"
        fail "XanMod: не удалось установить signing key"
        return 1
    fi
    rm -f "$key_tmp" "$keyring_tmp"

    write_root_file "$XANMOD_SOURCE_FILE" <<EOF
deb [signed-by=${XANMOD_KEYRING}] ${XANMOD_REPO_URL} ${codename} main
EOF
    APT_UPDATED=0
    if ! apt_update_force; then
        fail "XanMod: apt update после подключения репозитория не прошёл"
        return 1
    fi
    printf 'XanMod signing key fingerprint: %s\n' "$fingerprint" >> "$LOG_FILE"
}

xanmod_release_available() {
    local codename="$1" release_url
    release_url="${XANMOD_REPO_URL%/}/dists/${codename}/InRelease"

    if command_exists curl; then
        curl -fsSIL --retry 2 --retry-delay 2 --connect-timeout 10 --max-time 30 \
            "$release_url" >/dev/null 2>&1 && return 0
    fi
    if command_exists wget; then
        wget -q --spider --timeout=30 --tries=2 "$release_url" >/dev/null 2>&1 && return 0
    fi
    return 1
}

prepare_xanmod_grub_state() {
    command_exists update-grub || {
        fail "XanMod: update-grub не найден"
        return 1
    }

    if awk '
        /^[[:space:]]*#/ || NF < 2 { next }
        $2 == "/boot" { found = 1 }
        END { exit found ? 0 : 1 }
    ' /etc/fstab 2>/dev/null &&
        ! awk '$2 == "/boot" { found = 1 } END { exit found ? 0 : 1 }' /proc/mounts 2>/dev/null; then
        warn "XanMod: /boot указан в fstab, но не смонтирован; пробую смонтировать перед изменением загрузчика."
        cmd "${SUDO[@]}" mkdir -p /boot
        if ! cmd "${SUDO[@]}" mount /boot; then
            fail "XanMod: отдельный /boot не удалось смонтировать; загрузчик оставлен без изменений"
            return 1
        fi
    fi

    if ! cmd "${SUDO[@]}" mkdir -p /boot/grub; then
        fail "XanMod: не удалось подготовить /boot/grub"
        return 1
    fi
    if command_exists grub-editenv && [[ ! -e /boot/grub/grubenv ]]; then
        if ! cmd "${SUDO[@]}" grub-editenv /boot/grub/grubenv create; then
            warn "XanMod: grubenv не создался; попробую обновить grub.cfg без сохранённого entry."
        fi
    fi
}

select_xanmod_grub_entry() {
    local version submenu_id entry_id saved_entry
    version="$(xanmod_latest_version)"
    [[ -n "$version" ]] || return 1

    prepare_xanmod_grub_state || return 1
    if [[ ! -s "/boot/initrd.img-${version}" ]]; then
        cmd "${SUDO[@]}" update-initramfs -c -k "$version" || return 1
    else
        cmd "${SUDO[@]}" update-initramfs -u -k "$version" || return 1
    fi
    write_root_file "$XANMOD_GRUB_DEFAULT_FILE" <<'EOF'
# Managed by kto. Keep the selected XanMod entry across package updates.
GRUB_DEFAULT=saved
GRUB_SAVEDEFAULT=false
EOF
    cmd "${SUDO[@]}" update-grub || return 1

    if ! command_exists grub-set-default || [[ ! -s /boot/grub/grub.cfg ]]; then
        warn "XanMod установлен, но grub-set-default недоступен; GRUB выберет самое новое ядро автоматически."
        return 0
    fi
    submenu_id="$(awk '
        /^submenu / && /gnulinux-advanced/ {
            line = $0
            sub(/^.*--id[[:space:]]+\047/, "", line)
            sub(/\047.*$/, "", line)
            print line
            exit
        }
    ' /boot/grub/grub.cfg 2>/dev/null || true)"
    entry_id="$(awk -v version="$version" '
        /^[[:space:]]*menuentry / && index($0, version) && $0 !~ /recovery mode/ {
            line = $0
            sub(/^.*--id[[:space:]]+\047/, "", line)
            sub(/\047.*$/, "", line)
            print line
            exit
        }
    ' /boot/grub/grub.cfg 2>/dev/null || true)"
    if [[ -z "$entry_id" ]]; then
        warn "XanMod установлен, но его GRUB entry не найден; оставляю безопасный автоматический выбор нового ядра."
        return 0
    fi
    saved_entry="$entry_id"
    [[ -z "$submenu_id" ]] || saved_entry="${submenu_id}>${entry_id}"
    if ! cmd "${SUDO[@]}" grub-set-default "$saved_entry"; then
        fail "XanMod: не удалось выбрать kernel в GRUB"
        return 1
    fi
    printf 'XanMod GRUB saved entry: %s\n' "$saved_entry" >> "$LOG_FILE"
}

opt_xanmod_kernel() {
    local attempt installed=0 free_mb root_free_mb version codename

    if [[ "$(uname -m)" != "x86_64" ]] || ! grep -qi '^ID=ubuntu' /etc/os-release 2>/dev/null; then
        echo "XanMod skipped: non-Ubuntu or non-amd64" >> "$LOG_FILE"
        return 0
    fi
    if ! xanmod_x64v3_supported; then
        fail "XanMod x64v3 не поддерживается этим CPU. Текущее ядро оставлено без изменений."
        return 1
    fi
    if secure_boot_enabled; then
        fail "XanMod: Secure Boot включён. Отключи его у провайдера перед установкой неподписанного kernel."
        return 1
    fi
    free_mb="$(xanmod_boot_free_mb)"
    if [[ "$free_mb" =~ ^[0-9]+$ ]] && (( free_mb < 300 )); then
        fail "XanMod: в /boot свободно ${free_mb} MB, нужно минимум 300 MB"
        return 1
    fi

    if xanmod_installed; then
        select_xanmod_grub_entry || return 1
        echo "XanMod skipped: x64v3 package and boot artifacts already installed" >> "$LOG_FILE"
        return 0
    fi

    root_free_mb="$(xanmod_root_free_mb)"
    if [[ "$root_free_mb" =~ ^[0-9]+$ ]] && (( root_free_mb < 1500 )); then
        fail "XanMod: на / свободно ${root_free_mb} MB, для безопасной установки нужно минимум 1500 MB"
        return 1
    fi

    codename="$(awk -F= '$1 == "VERSION_CODENAME" { gsub(/"/, "", $2); print $2; exit }' /etc/os-release 2>/dev/null || true)"
    if [[ -z "$codename" ]] ||
        { ! apt-cache show "$XANMOD_PACKAGE" >/dev/null 2>&1 && ! xanmod_release_available "$codename"; }; then
        fail "XanMod: официальный репозиторий не публикует Ubuntu ${codename:-unknown}. Текущее ядро оставлено без изменений."
        return 1
    fi
    if ! xanmod_source_configured; then
        configure_xanmod_repository || return 1
    fi

    apt_update_quiet || echo "XanMod apt update failed, trying current apt cache" >> "$LOG_FILE"
    for attempt in 1 2 3; do
        if (( attempt > 1 )); then
            printf 'XanMod install retry %s\n' "$attempt" >> "$LOG_FILE"
            cmd "${SUDO[@]}" dpkg --configure -a || true
            apt_update_force || true
        fi
        if package_installed "$XANMOD_PACKAGE"; then
            if "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 \
                install --reinstall -y "$XANMOD_PACKAGE" >> "$LOG_FILE" 2>&1 && xanmod_installed; then
                installed=1
                break
            fi
        elif apt_install_quiet "$XANMOD_PACKAGE" && xanmod_installed; then
            installed=1
            break
        fi
        sleep $(( attempt * 2 ))
    done
    if (( installed == 0 )); then
        fail "XanMod x64v3 не установился после повторов; текущее ядро и GRUB не изменены"
        return 1
    fi

    version="$(xanmod_latest_version)"
    if [[ -z "$version" || ! -s "/boot/vmlinuz-${version}" || ! -d "/lib/modules/${version}" ]]; then
        fail "XanMod: после установки отсутствуют kernel или modules"
        return 1
    fi
    select_xanmod_grub_entry || return 1
    ok "XanMod x64v3 ${version} установлен и выбран для следующей загрузки"
    if grep -RqsE 'damentz.*liquorix|liquorix' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null; then
        warn "Liquorix оставлен установленным как аварийный fallback; активным после reboot будет XanMod."
    fi
}

opt_kernel_final_check() {
    if [[ "$(uname -m)" != "x86_64" ]] || ! grep -qi '^ID=ubuntu' /etc/os-release 2>/dev/null; then
        return 0
    fi
    if xanmod_installed; then
        select_xanmod_grub_entry || warn "XanMod установлен, но не удалось повторно проверить GRUB selection."
        echo "XanMod final check: package and boot artifacts installed" >> "$LOG_FILE"
        return 0
    fi
    warn "XanMod x64v3 не установлен после первого этапа, повторяю отдельно."
    if opt_xanmod_kernel && xanmod_installed; then
        ok "XanMod x64v3 установлен. После оптимизации нужен reboot."
        return 0
    fi
    warn "XanMod x64v3 не удалось установить. Остальная оптимизация продолжена; смотри лог: $LOG_FILE"
    return 0
}

opt_kernel_network_memory_parallel() {
    parallel_run_tasks \
        "kernel" opt_xanmod_kernel \
        "network limits" opt_network_limits \
        "memory guard" opt_memory_guard
}

conntrack_capacity_values() {
    local mem_mb target_max target_buckets current_max current_buckets override
    mem_mb="$(memory_total_mb)"
    [[ "$mem_mb" =~ ^[0-9]+$ ]] || mem_mb=0

    if (( mem_mb >= 24576 )); then
        target_max=4194304
    elif (( mem_mb >= 12288 )); then
        target_max=2097152
    elif (( mem_mb >= 6144 )); then
        target_max=1048576
    elif (( mem_mb >= 3072 )); then
        target_max=524288
    else
        target_max=262144
    fi

    override="${KTO_CONNTRACK_MAX:-}"
    if [[ "$override" =~ ^[0-9]+$ ]] && (( 10#$override >= 65536 && 10#$override <= 8388608 )); then
        target_max=$((10#$override))
    fi

    current_max="$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo 0)"
    if [[ "$current_max" =~ ^[0-9]+$ ]] && (( current_max > target_max )); then
        target_max="$current_max"
    fi
    target_buckets=$(( target_max / 4 ))
    (( target_buckets >= 16384 )) || target_buckets=16384

    current_buckets="$(sysctl -n net.netfilter.nf_conntrack_buckets 2>/dev/null || echo 0)"
    if [[ "$current_buckets" =~ ^[0-9]+$ ]] && (( current_buckets > target_buckets )); then
        target_buckets="$current_buckets"
    fi
    printf '%s\t%s\n' "$target_max" "$target_buckets"
}

configure_conntrack_capacity() {
    local target_max target_buckets current_buckets applied_max count percent
    cmd "${SUDO[@]}" modprobe nf_conntrack || true
    if ! sysctl -n net.netfilter.nf_conntrack_count >/dev/null 2>&1; then
        echo "conntrack skipped: kernel module is unavailable" >> "$LOG_FILE"
        return 0
    fi

    IFS=$'\t' read -r target_max target_buckets < <(conntrack_capacity_values)
    write_root_file "$KTO_CONNTRACK_SYSCTL_CONF" <<EOF || return 1
# Managed by kto. Capacity is selected from available system memory.
net.netfilter.nf_conntrack_max = ${target_max}
net.netfilter.nf_conntrack_tcp_timeout_established = 10800
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_last_ack = 30
net.netfilter.nf_conntrack_generic_timeout = 120
EOF
    write_root_file "$KTO_CONNTRACK_MODPROBE_CONF" <<EOF || return 1
# Managed by kto. Applied when nf_conntrack is loaded at boot.
options nf_conntrack hashsize=${target_buckets}
EOF

    if ! cmd "${SUDO[@]}" sysctl -p "$KTO_CONNTRACK_SYSCTL_CONF"; then
        fail "Не удалось применить параметры conntrack"
        return 1
    fi

    current_buckets="$(sysctl -n net.netfilter.nf_conntrack_buckets 2>/dev/null || echo 0)"
    if [[ "$current_buckets" =~ ^[0-9]+$ ]] && (( current_buckets < target_buckets )); then
        if ! cmd "${SUDO[@]}" sysctl -w "net.netfilter.nf_conntrack_buckets=${target_buckets}"; then
            if [[ -e /sys/module/nf_conntrack/parameters/hashsize ]]; then
                printf '%s\n' "$target_buckets" | "${SUDO[@]}" tee \
                    /sys/module/nf_conntrack/parameters/hashsize >> "$LOG_FILE" 2>&1 || \
                    warn "Hash-таблица conntrack увеличится после reboot"
            fi
        fi
    fi

    applied_max="$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo 0)"
    count="$(sysctl -n net.netfilter.nf_conntrack_count 2>/dev/null || echo 0)"
    if [[ ! "$applied_max" =~ ^[0-9]+$ || "$applied_max" -lt "$target_max" ]]; then
        fail "Conntrack max не применился: ${applied_max:-неизвестно}, ожидалось ${target_max}"
        return 1
    fi
    if [[ "$count" =~ ^[0-9]+$ && "$applied_max" =~ ^[0-9]+$ && "$applied_max" -gt 0 ]]; then
        percent=$(( count * 100 / applied_max ))
    else
        percent=0
    fi
    ok "Conntrack: ${count}/${applied_max} (${percent}%), buckets=${target_buckets}"
}

fix_conntrack_capacity_cli() {
    header
    need_root
    stage "Исправляю ёмкость conntrack без очистки живых соединений"
    configure_conntrack_capacity
}

opt_network_limits() {
    opt_dns_guard
    opt_ipv6_mode_guard
    cleanup_superseded_kto_files

    cmd "${SUDO[@]}" modprobe tcp_bbr || true
    write_root_file "$KTO_TUNING_SYSCTL_CONF" <<'EOF'
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
net.ipv4.ip_local_port_range = 10000 65535
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
    configure_conntrack_capacity || return 1
    cmd "${SUDO[@]}" sysctl --system || true

    write_root_file "$KTO_LIMITS_CONF" <<'EOF'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF
    cmd "${SUDO[@]}" mkdir -p /etc/systemd/system.conf.d /etc/systemd/user.conf.d
    write_root_file "$KTO_SYSTEMD_LIMITS_CONF" <<'EOF'
[Manager]
DefaultLimitNOFILE=1048576
EOF
    write_root_file "$KTO_USER_LIMITS_CONF" <<'EOF'
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
    local anti_rules routes_file ports_file ufw_status_file port
    anti_rules="$(antiscanner_rules_count)"
    routes_file="$(mktemp)"
    ports_file="$(mktemp)"
    ufw_status_file="$(mktemp)"

    if [[ "${KTO_UFW_RESET:-0}" == "1" ]]; then
        cmd "${SUDO[@]}" ufw --force reset
    elif [[ "$anti_rules" =~ ^[0-9]+$ && "$anti_rules" -gt 0 ]]; then
        echo "ufw reset skipped: preserving AntiScanner rules ($anti_rules)" >> "$LOG_FILE"
    else
        echo "ufw reset skipped: preserving existing rules" >> "$LOG_FILE"
    fi
    cmd "${SUDO[@]}" ufw default deny incoming
    cmd "${SUDO[@]}" ufw default allow outgoing
    ensure_global_ssh_ufw_rule "$ssh_port"
    if [[ "$ssh_port" != "22" ]]; then
        remove_ufw_allow_rules_for_port 22
        ensure_global_ssh_ufw_rule "$ssh_port"
    fi
    extract_haproxy_routes "$HAPROXY_CONFIG_FILE" > "$routes_file"
    haproxy_listener_ports "$routes_file" > "$ports_file"
    "${SUDO[@]}" ufw status > "$ufw_status_file" 2>/dev/null || true
    if [[ "$MACHINE_MODE" == "whitelist" ]]; then
        if [[ -s "$ports_file" ]]; then
            while IFS= read -r port; do
                if ! ufw_status_rule_open_to_any "${port}/tcp" < "$ufw_status_file"; then
                    cmd "${SUDO[@]}" ufw allow "${port}/tcp"
                    printf '%s/tcp ALLOW IN Anywhere\n' "$port" >> "$ufw_status_file"
                fi
            done < "$ports_file"
        else
            if ! ufw_status_rule_open_to_any "443/tcp" < "$ufw_status_file"; then
                cmd "${SUDO[@]}" ufw allow 443/tcp
                printf '443/tcp ALLOW IN Anywhere\n' >> "$ufw_status_file"
            fi
        fi
    else
        if ! ufw_status_rule_open_to_any "443/tcp" < "$ufw_status_file"; then
            cmd "${SUDO[@]}" ufw allow 443/tcp
            printf '443/tcp ALLOW IN Anywhere\n' >> "$ufw_status_file"
        fi
        if [[ -s "$ports_file" ]]; then
            while IFS= read -r port; do
                [[ "$port" == "443" ]] && continue
                if ! ufw_status_rule_open_to_any "${port}/tcp" < "$ufw_status_file"; then
                    cmd "${SUDO[@]}" ufw allow "${port}/tcp"
                    printf '%s/tcp ALLOW IN Anywhere\n' "$port" >> "$ufw_status_file"
                fi
            done < "$ports_file"
        fi
    fi
    if [[ "$MACHINE_MODE" == "node" ]]; then
        if ! ufw_status_rule_open_to_any "443/udp" < "$ufw_status_file"; then
            cmd "${SUDO[@]}" ufw allow 443/udp
        fi
        if ! ufw_status_rule_open_to_any "${NODE_PORT}/tcp" < "$ufw_status_file"; then
            cmd "${SUDO[@]}" ufw allow "${NODE_PORT}/tcp"
        fi
    else
        cmd "${SUDO[@]}" ufw --force delete allow 443/udp || true
        if ! grep -Fqx "$NODE_PORT" "$ports_file"; then
            cmd "${SUDO[@]}" ufw --force delete allow "${NODE_PORT}/tcp" || true
        fi
    fi
    cmd "${SUDO[@]}" ufw --force enable
    if ! ensure_haproxy_firewall_guard || ! repair_haproxy_firewall_rules "$routes_file"; then
        rm -f "$routes_file" "$ports_file" "$ufw_status_file"
        return 1
    fi
    rm -f "$routes_file" "$ports_file" "$ufw_status_file"
}

opt_haproxy_firewall_final_check() {
    ensure_haproxy_firewall_guard
    repair_haproxy_firewall_rules
}

opt_antiscanner() {
    install_antiscanner
}

opt_fail2ban() {
    local ssh_port
    ssh_port="$(detect_ssh_port)"
    apt_install_quiet fail2ban || true
    write_root_file /etc/fail2ban/jail.d/99-kto-sshd.conf <<EOF
[sshd]
enabled = true
port = ${ssh_port}
bantime = 1h
findtime = 10m
maxretry = 5
EOF
    if [[ "$MACHINE_MODE" == "whitelist" ]]; then
        write_whitelist_fail2ban_allowlist
    elif "${SUDO[@]}" test -f "$FAIL2BAN_SSH_ALLOWLIST_CONF" 2>/dev/null; then
        cmd "${SUDO[@]}" rm -f "$FAIL2BAN_SSH_ALLOWLIST_CONF"
    fi
    cmd "${SUDO[@]}" systemctl enable --now fail2ban || true
    cmd "${SUDO[@]}" systemctl restart fail2ban || true
    if [[ "$MACHINE_MODE" == "whitelist" ]]; then
        unban_whitelist_ssh_ips
    fi
}

opt_zram() {
    need_root
    local mode="${1:-strict}"
    local size rc

    if zram_active; then
        ok "ZRAM уже активен: $(zram_swap_summary)"
        return 0
    fi

    if ! command_exists zramctl || ! command_exists modprobe; then
        apt_update_quiet
        apt_install_quiet util-linux kmod
    fi
    if ! command_exists zramctl; then
        if [[ "$mode" == "optional" ]]; then
            warn "zramctl не найден, ZRAM пропущен."
        else
            fail "zramctl не найден"
        fi
        return 1
    fi
    if ! command_exists modprobe; then
        if [[ "$mode" == "optional" ]]; then
            warn "modprobe не найден, ZRAM пропущен."
        else
            fail "modprobe не найден"
        fi
        return 1
    fi
    if ! "${SUDO[@]}" modprobe zram >/dev/null 2>&1; then
        if [[ "$mode" == "optional" ]]; then
            warn "ZRAM не поддерживается ядром/провайдером, пропускаю."
        else
            fail "ZRAM не поддерживается ядром/провайдером"
        fi
        return 1
    fi

    size="$(recommended_zram_mb)"
    stage "Настраиваю ZRAM ($(format_mb "$size"))"

    write_root_file_mode 0755 "$ZRAM_SETUP_SCRIPT" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

SIZE_MB="\${KTO_ZRAM_SIZE_MB:-$size}"
PREFERRED_ALGO="\${KTO_ZRAM_ALGO:-zstd}"

if awk '\$1 ~ /^\\/dev\\/zram/ {found=1} END{exit found ? 0 : 1}' /proc/swaps 2>/dev/null; then
    exit 0
fi

modprobe zram num_devices=1 2>/dev/null || modprobe zram

dev=""
for algo in "\$PREFERRED_ALGO" lz4 lzo-rle lzo; do
    if dev="\$(zramctl --find --size "\${SIZE_MB}M" --algorithm "\$algo" 2>/dev/null)"; then
        break
    fi
done

if [[ -z "\$dev" ]]; then
    dev="\$(zramctl --find --size "\${SIZE_MB}M" 2>/dev/null || true)"
fi

if [[ -z "\$dev" && -b /dev/zram0 ]]; then
    zramctl --reset /dev/zram0 2>/dev/null || true
    for algo in "\$PREFERRED_ALGO" lz4 lzo-rle lzo; do
        if dev="\$(zramctl --find --size "\${SIZE_MB}M" --algorithm "\$algo" 2>/dev/null)"; then
            break
        fi
    done
fi

[[ -n "\$dev" ]]
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
    if "${SUDO[@]}" systemctl enable --now "$ZRAM_SERVICE" >> "$LOG_FILE" 2>&1; then
        rc=0
    else
        rc=$?
        "${SUDO[@]}" systemctl disable --now "$ZRAM_SERVICE" >> "$LOG_FILE" 2>&1 || true
        "${SUDO[@]}" systemctl reset-failed "$ZRAM_SERVICE" >> "$LOG_FILE" 2>&1 || true
        if [[ "$mode" == "optional" ]]; then
            warn "ZRAM service не запустился, пропускаю."
        else
            fail "Включение ZRAM"
            tail -n 25 "$LOG_FILE" >&2 || true
        fi
        return "$rc"
    fi

    if zram_active; then
        ok "ZRAM включен: $(zram_swap_summary)"
    else
        "${SUDO[@]}" systemctl disable --now "$ZRAM_SERVICE" >> "$LOG_FILE" 2>&1 || true
        "${SUDO[@]}" systemctl reset-failed "$ZRAM_SERVICE" >> "$LOG_FILE" 2>&1 || true
        if [[ "$mode" == "optional" ]]; then
            warn "ZRAM service запустился, но swap не активен; пропускаю."
        else
            fail "ZRAM service запустился, но swap не активен"
        fi
        return 1
    fi
}

SYSTEM_CHECK_MISSING=0
SYSTEM_CHECK_WARNINGS=0
SYSTEM_CHECK_NEEDS_PREPARE=0
SYSTEM_CHECK_NEEDS_PACKAGES=0
SYSTEM_CHECK_NEEDS_KERNEL=0
SYSTEM_CHECK_NEEDS_SSH=0
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
    SYSTEM_CHECK_NEEDS_SSH=0
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

haproxy_config_listener_ports() {
    local config="${1:-$HAPROXY_CONFIG_FILE}"
    "${SUDO[@]}" test -s "$config" 2>/dev/null || return 0
    "${SUDO[@]}" awk '
        function emit_listener(endpoint, port, host) {
            gsub(/^"|"$/, "", endpoint)
            if (endpoint ~ /^(unix@|abns@|fd@)/) return
            if (endpoint ~ /^[0-9]+$/) {
                port = endpoint
                host = "*"
            } else {
                port = endpoint
                sub(/^.*:/, "", port)
                sub(/[^0-9].*$/, "", port)
                host = endpoint
                sub(/:[^:]*$/, "", host)
                gsub(/^\[/, "", host)
                gsub(/\]$/, "", host)
            }
            if (host == "localhost" || host == "127.0.0.1" || host == "::1") return
            if (port ~ /^[0-9]+$/ && port + 0 >= 1 && port + 0 <= 65535) print port + 0
        }
        $1 == "frontend" { section = "frontend"; next }
        $1 == "global" || $1 == "defaults" || $1 == "backend" || $1 == "listen" {
            section = $1
            next
        }
        section == "frontend" && $1 == "bind" {
            count = split($2, endpoints, ",")
            for (i = 1; i <= count; i++) emit_listener(endpoints[i])
        }
    ' "$config" 2>/dev/null | LC_ALL=C sort -nu
}

haproxy_listener_ports() {
    local routes_file="${1:-}" config="${2:-$HAPROXY_CONFIG_FILE}"
    {
        if [[ -n "$routes_file" && -s "$routes_file" ]]; then
            awk -F '\t' '$1 ~ /^[0-9]+$/ && $1 + 0 >= 1 && $1 + 0 <= 65535 { print $1 + 0 }' "$routes_file"
        fi
        haproxy_config_listener_ports "$config" || true
    } | awk '/^[0-9]+$/ && !seen[$1]++ { print $1 }' | LC_ALL=C sort -n
}

ufw_status_rule_open_to_any() {
    local rule="$1"
    awk -v rule="$rule" '
        $0 !~ /\(v6\)/ && $1 == rule {
            for (i = 2; i <= NF; i++) {
                if ($i != "ALLOW") continue
                if ($(i + 1) == "OUT" || $(i + 1) == "FWD") continue
                source_field = i + 1
                if ($source_field == "IN") source_field++
                if ($source_field == "Anywhere") found = 1
            }
        }
        END { exit found ? 0 : 1 }
    '
}

ufw_active() {
    command_exists ufw && "${SUDO[@]}" ufw status 2>/dev/null |
        awk '$1 == "Status:" && $2 == "active" { active=1 } END { exit active ? 0 : 1 }'
}

ufw_rule_allowed() {
    local rule="$1"
    command_exists ufw || return 1
    "${SUDO[@]}" ufw status 2>/dev/null \
        | awk -v rule="$rule" '
            $0 !~ /\(v6\)/ && $1 == rule {
                for (i = 2; i <= NF; i++) {
                    if ($i == "ALLOW" && $(i + 1) != "OUT" && $(i + 1) != "FWD") found = 1
                }
            }
            END { exit found ? 0 : 1 }
        '
}

ufw_rule_open_to_any() {
    local rule="$1"
    command_exists ufw || return 1
    "${SUDO[@]}" ufw status 2>/dev/null | ufw_status_rule_open_to_any "$rule"
}

repair_haproxy_firewall_rules() {
    local routes_file="${1:-}" ports_file status_file port added=0 failed=0 status_failed=0

    ports_file="$(mktemp)"
    status_file="$(mktemp)"
    haproxy_listener_ports "$routes_file" > "$ports_file"
    if [[ ! -s "$ports_file" ]]; then
        rm -f "$ports_file" "$status_file"
        return 0
    fi
    if ! command_exists ufw ||
        ! "${SUDO[@]}" ufw status > "$status_file" 2>/dev/null ||
        ! awk '$1 == "Status:" && $2 == "active" { active=1 } END { exit active ? 0 : 1 }' "$status_file"; then
        rm -f "$ports_file" "$status_file"
        fail "HAProxy listener-ы найдены, но UFW не активен"
        return 1
    fi

    while IFS= read -r port; do
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        if ufw_status_rule_open_to_any "${port}/tcp" < "$status_file"; then
            continue
        fi
        if cmd "${SUDO[@]}" ufw allow "${port}/tcp" comment 'kto-haproxy'; then
            added=$(( added + 1 ))
        elif cmd "${SUDO[@]}" ufw allow "${port}/tcp"; then
            added=$(( added + 1 ))
        fi
    done < "$ports_file"

    if ! "${SUDO[@]}" ufw status > "$status_file" 2>/dev/null; then
        failed=1
        status_failed=1
    else
        while IFS= read -r port; do
            [[ "$port" =~ ^[0-9]+$ ]] || continue
            if ! ufw_status_rule_open_to_any "${port}/tcp" < "$status_file"; then
                fail "UFW не создал глобальное IPv4-правило для HAProxy ${port}/tcp"
                failed=$(( failed + 1 ))
            fi
        done < "$ports_file"
    fi
    rm -f "$ports_file" "$status_file"

    if (( failed == 0 && added > 0 )); then
        ok "Восстановлено HAProxy IPv4-правил: ${added}"
    elif (( status_failed == 1 )); then
        fail "Не удалось повторно прочитать HAProxy IPv4-правила UFW"
    elif (( failed > 0 && added > 0 )); then
        warn "UFW восстановил не все HAProxy IPv4-правила: ${added}"
    fi
    (( failed == 0 ))
}

ensure_haproxy_firewall_guard() {
    local listener_ports manager_current=0 unit_current=0
    listener_ports="$(haproxy_config_listener_ports "$HAPROXY_CONFIG_FILE")"
    [[ -n "$listener_ports" ]] || return 0

    if "${SUDO[@]}" test -x "$HAPROXY_FIREWALL_MANAGER" 2>/dev/null &&
        "${SUDO[@]}" grep -Fqx 'KTO_HAPROXY_FIREWALL_BUILD="v336"' "$HAPROXY_FIREWALL_MANAGER" 2>/dev/null; then
        manager_current=1
    fi
    if "${SUDO[@]}" test -s "$HAPROXY_FIREWALL_UNIT" 2>/dev/null &&
        "${SUDO[@]}" grep -Fq "ExecStart=${HAPROXY_FIREWALL_MANAGER}" "$HAPROXY_FIREWALL_UNIT" 2>/dev/null; then
        unit_current=1
    fi

    if (( manager_current == 0 )); then
        write_root_file "$HAPROXY_FIREWALL_MANAGER" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

KTO_HAPROXY_FIREWALL_BUILD="v336"
CONFIG="${KTO_HAPROXY_CONFIG:-/etc/haproxy/haproxy.cfg}"

command -v ufw >/dev/null 2>&1 || exit 0
[[ -s "$CONFIG" ]] || exit 0
STATUS_FILE="$(mktemp)"
PORTS_FILE="$(mktemp)"
cleanup() { rm -f "$STATUS_FILE" "$PORTS_FILE"; }
trap cleanup EXIT
ufw status > "$STATUS_FILE" 2>/dev/null || exit 0
awk '$1 == "Status:" && $2 == "active" { active=1 } END { exit active ? 0 : 1 }' "$STATUS_FILE" || exit 0

listener_ports() {
    awk '
        function emit_listener(endpoint, port, host) {
            gsub(/^"|"$/, "", endpoint)
            if (endpoint ~ /^(unix@|abns@|fd@)/) return
            if (endpoint ~ /^[0-9]+$/) {
                port = endpoint
                host = "*"
            } else {
                port = endpoint
                sub(/^.*:/, "", port)
                sub(/[^0-9].*$/, "", port)
                host = endpoint
                sub(/:[^:]*$/, "", host)
                gsub(/^\[/, "", host)
                gsub(/\]$/, "", host)
            }
            if (host == "localhost" || host == "127.0.0.1" || host == "::1") return
            if (port ~ /^[0-9]+$/ && port + 0 >= 1 && port + 0 <= 65535) print port + 0
        }
        $1 == "frontend" { section = "frontend"; next }
        $1 == "global" || $1 == "defaults" || $1 == "backend" || $1 == "listen" {
            section = $1
            next
        }
        section == "frontend" && $1 == "bind" {
            count = split($2, endpoints, ",")
            for (i = 1; i <= count; i++) emit_listener(endpoints[i])
        }
    ' "$CONFIG" | LC_ALL=C sort -nu
}

rule_open_to_any() {
    local rule="$1" status_file="$2"
    awk -v rule="$rule" '
        $0 !~ /\(v6\)/ && $1 == rule {
            for (i = 2; i <= NF; i++) {
                if ($i != "ALLOW") continue
                if ($(i + 1) == "OUT" || $(i + 1) == "FWD") continue
                source_field = i + 1
                if ($source_field == "IN") source_field++
                if ($source_field == "Anywhere") found = 1
            }
        }
        END { exit found ? 0 : 1 }
    ' "$status_file"
}

failed=0
restored=0
listener_ports > "$PORTS_FILE"
while IFS= read -r port; do
    [[ "$port" =~ ^[0-9]+$ ]] || continue
    rule_open_to_any "${port}/tcp" "$STATUS_FILE" && continue
    if ufw allow "${port}/tcp" comment 'kto-haproxy' >/dev/null 2>&1 ||
        ufw allow "${port}/tcp" >/dev/null 2>&1; then
        restored=$(( restored + 1 ))
    fi
done < "$PORTS_FILE"

if ! ufw status > "$STATUS_FILE" 2>/dev/null; then
    echo "kto-haproxy-firewall: failed to read UFW status after repair" >&2
    failed=1
else
    while IFS= read -r port; do
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        if rule_open_to_any "${port}/tcp" "$STATUS_FILE"; then
            continue
        fi
        echo "kto-haproxy-firewall: failed to restore IPv4 ${port}/tcp" >&2
        failed=$(( failed + 1 ))
    done < "$PORTS_FILE"
fi

(( restored == 0 )) || echo "kto-haproxy-firewall: restored ${restored} rule(s)"
(( failed == 0 ))
EOF
        cmd "${SUDO[@]}" chmod 0755 "$HAPROXY_FIREWALL_MANAGER"
    fi

    if (( unit_current == 0 )); then
        write_root_file "$HAPROXY_FIREWALL_UNIT" <<EOF
[Unit]
Description=Restore IPv4 UFW rules for HAProxy listeners
After=network-online.target ufw.service haproxy.service antiscanner-update.service
Wants=network-online.target
ConditionPathExists=${HAPROXY_CONFIG_FILE}

[Service]
Type=oneshot
ExecStart=${HAPROXY_FIREWALL_MANAGER}

[Install]
WantedBy=multi-user.target
EOF
        cmd "${SUDO[@]}" systemctl daemon-reload
    fi
    "${SUDO[@]}" systemctl is-enabled --quiet "$HAPROXY_FIREWALL_SERVICE" 2>/dev/null ||
        cmd "${SUDO[@]}" systemctl enable "$HAPROXY_FIREWALL_SERVICE"
}

ufw_rule_from_allowed() {
    local rule="$1"
    local ip="$2"
    command_exists ufw || return 1
    "${SUDO[@]}" ufw status 2>/dev/null \
        | awk -v rule="$rule" -v ip="$ip" '
            $0 !~ /\(v6\)/ && $1 == rule {
                for (i = 2; i <= NF; i++) {
                    if ($i != "ALLOW") continue
                    if ($(i + 1) == "OUT" || $(i + 1) == "FWD") continue
                    source_field = i + 1
                    if ($source_field == "IN") source_field++
                    if ($source_field == ip) found = 1
                }
            }
            END { exit found ? 0 : 1 }
        '
}

whitelist_ssh_rules_configured() {
    local ssh_port="$1"
    local rule="${ssh_port}/tcp"
    local ip

    if ufw_rule_open_to_any "$rule"; then
        return 1
    fi
    while read -r ip; do
        [[ -n "$ip" ]] || continue
        ufw_rule_from_allowed "$rule" "$ip" || return 1
    done < <(whitelist_ssh_allowed_ips | sort -u)
}

system_check_prepare_state() {
    local issues=() dpkg_audit

    if package_installed snapd && [[ "${KTO_PURGE_SNAPD:-0}" == "1" ]]; then
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
        system_check_row skip "xanmod x64v3" "не Ubuntu amd64"
        return 0
    fi
    if ! xanmod_x64v3_supported; then
        system_check_row warn "xanmod x64v3" "CPU не поддерживает x86-64-v3; kernel не меняю"
        return 0
    fi
    if secure_boot_enabled; then
        system_check_row warn "xanmod x64v3" "Secure Boot включён; установка заблокирована"
        return 0
    fi

    if xanmod_installed; then
        if [[ "$kernel" == *xanmod* ]]; then
            system_check_row ok "xanmod x64v3" "$kernel"
        else
            system_check_row warn "xanmod x64v3" "установлен $(xanmod_latest_version), текущее ядро: $kernel; нужен reboot"
        fi
        return 0
    fi

    SYSTEM_CHECK_NEEDS_KERNEL=1
    if xanmod_source_configured; then
        system_check_row miss "xanmod x64v3" "repo есть, kernel не установлен"
    else
        system_check_row miss "xanmod x64v3" "официальный repo и kernel не установлены"
    fi
}

system_check_ssh_root_access() {
    local port
    port="$(detect_ssh_port)"
    if ssh_root_access_configured; then
        system_check_row ok "ssh root" "key-only, ${port}/tcp открыт для всех"
    elif ! root_public_key_available; then
        system_check_row warn "ssh root" "нет public key; текущий SSH не будет изменён"
    else
        SYSTEM_CHECK_NEEDS_SSH=1
        system_check_row miss "ssh root" "нужен стабильный случайный порт и root key-only"
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
    local ct_count ct_max ct_percent ct_target ct_buckets ct_config_ok=1
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
    elif dns_resolution_ok; then
        system_check_row ok "dns guard" "системный DNS работает, сохраняю"
    else
        SYSTEM_CHECK_NEEDS_NETWORK=1
        system_check_row miss "dns guard" "DNS не работает, нужен fallback"
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

    ct_count="$(sysctl -n net.netfilter.nf_conntrack_count 2>/dev/null || true)"
    ct_max="$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || true)"
    if [[ "$ct_count" =~ ^[0-9]+$ && "$ct_max" =~ ^[0-9]+$ && "$ct_max" -gt 0 ]]; then
        ct_percent=$(( ct_count * 100 / ct_max ))
        if (( ct_count >= ct_max || ct_percent >= 95 )); then
            SYSTEM_CHECK_NEEDS_NETWORK=1
            system_check_row miss "conntrack" "${ct_count}/${ct_max} (${ct_percent}%), пакеты теряются"
        elif (( ct_percent >= 75 )); then
            SYSTEM_CHECK_NEEDS_NETWORK=1
            system_check_row warn "conntrack" "${ct_count}/${ct_max} (${ct_percent}%), мало запаса"
        else
            system_check_row ok "conntrack" "${ct_count}/${ct_max} (${ct_percent}%)"
        fi

        IFS=$'\t' read -r ct_target ct_buckets < <(conntrack_capacity_values)
        root_file_has_line "$KTO_CONNTRACK_SYSCTL_CONF" \
            "net.netfilter.nf_conntrack_max = ${ct_target}" || ct_config_ok=0
        root_file_has_line "$KTO_CONNTRACK_SYSCTL_CONF" \
            "net.netfilter.nf_conntrack_tcp_timeout_established = 10800" || ct_config_ok=0
        root_file_has_line "$KTO_CONNTRACK_SYSCTL_CONF" \
            "net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30" || ct_config_ok=0
        root_file_has_line "$KTO_CONNTRACK_MODPROBE_CONF" \
            "options nf_conntrack hashsize=${ct_buckets}" || ct_config_ok=0
        if (( ct_config_ok == 1 )); then
            system_check_row ok "conntrack config" "max ${ct_target}, buckets ${ct_buckets}"
        else
            SYSTEM_CHECK_NEEDS_NETWORK=1
            system_check_row miss "conntrack config" "не настроен под объём RAM"
        fi
    else
        system_check_row skip "conntrack" "kernel module не используется"
    fi

    root_file_has_line "$KTO_TUNING_SYSCTL_CONF" "net.ipv4.tcp_congestion_control = bbr" || sysctl_file_ok=0
    root_file_has_line "$KTO_TUNING_SYSCTL_CONF" "net.core.default_qdisc = fq" || sysctl_file_ok=0
    root_file_has_line "$KTO_TUNING_SYSCTL_CONF" "fs.file-max = 2097152" || sysctl_file_ok=0
    root_file_has_line "$KTO_TUNING_SYSCTL_CONF" "net.ipv4.ip_local_port_range = 10000 65535" || sysctl_file_ok=0
    root_file_has_line "$KTO_TUNING_SYSCTL_CONF" "vm.swappiness = 1" || sysctl_file_ok=0
    if [[ "$sysctl_file_ok" == "1" ]]; then
        system_check_row ok "sysctl file" "$KTO_TUNING_SYSCTL_CONF"
    else
        SYSTEM_CHECK_NEEDS_NETWORK=1
        system_check_row miss "sysctl file" "нет или неполный $KTO_TUNING_SYSCTL_CONF"
    fi

    root_file_has_line "$KTO_LIMITS_CONF" "* soft nofile 1048576" || limits_ok=0
    root_file_has_line "$KTO_LIMITS_CONF" "* hard nofile 1048576" || limits_ok=0
    root_file_has_line "$KTO_SYSTEMD_LIMITS_CONF" "DefaultLimitNOFILE=1048576" || limits_ok=0
    root_file_has_line "$KTO_USER_LIMITS_CONF" "DefaultLimitNOFILE=1048576" || limits_ok=0
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
    local missing=() extra=() routes_file ports_file ufw_status_file port

    routes_file="$(mktemp)"
    ports_file="$(mktemp)"
    ufw_status_file="$(mktemp)"

    if ! command_exists ufw; then
        SYSTEM_CHECK_NEEDS_FIREWALL=1
        system_check_row miss "ufw" "не установлен"
        rm -f "$routes_file" "$ports_file" "$ufw_status_file"
        return 0
    fi

    if ufw_active; then
        system_check_row ok "ufw" "active"
    else
        SYSTEM_CHECK_NEEDS_FIREWALL=1
        system_check_row miss "ufw" "не active"
    fi

    ufw_global_allow_exists_for_port "$ssh_port" || missing+=("${ssh_port}/tcp global")
    if [[ "$ssh_port" != "22" ]] && ufw_rule_allowed "22/tcp"; then
        extra+=("22/tcp")
    fi
    extract_haproxy_routes "$HAPROXY_CONFIG_FILE" > "$routes_file"
    haproxy_listener_ports "$routes_file" > "$ports_file"
    if [[ "$MACHINE_MODE" != "whitelist" || ! -s "$ports_file" ]]; then
        printf '443\n' >> "$ports_file"
    fi
    LC_ALL=C sort -nu -o "$ports_file" "$ports_file"
    "${SUDO[@]}" ufw status > "$ufw_status_file" 2>/dev/null || true
    while IFS= read -r port; do
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        ufw_status_rule_open_to_any "${port}/tcp" < "$ufw_status_file" || missing+=("${port}/tcp")
    done < "$ports_file"
    if [[ "$MACHINE_MODE" == "node" ]]; then
        ufw_status_rule_open_to_any "443/udp" < "$ufw_status_file" || missing+=("443/udp")
        ufw_status_rule_open_to_any "${NODE_PORT}/tcp" < "$ufw_status_file" || missing+=("${NODE_PORT}/tcp")
    else
        ufw_rule_allowed "443/udp" && extra+=("443/udp")
        if ! grep -Fqx "$NODE_PORT" "$ports_file"; then
            ufw_rule_allowed "${NODE_PORT}/tcp" && extra+=("${NODE_PORT}/tcp")
        fi
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
    rm -f "$routes_file" "$ports_file" "$ufw_status_file"
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
    if [[ "$MACHINE_MODE" == "whitelist" ]]; then
        [[ "$(file_ok "$FAIL2BAN_SSH_ALLOWLIST_CONF")" == "1" ]] || missing+=("ssh allowlist")
    fi

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
    (( SYSTEM_CHECK_NEEDS_SSH == 1 )) && steps=$(( steps + 1 ))
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
    (( SYSTEM_CHECK_NEEDS_KERNEL == 1 )) && progress_step "Ставлю XanMod x64v3" opt_xanmod_kernel
    if (( SYSTEM_CHECK_NEEDS_SSH == 1 )); then
        progress_step "Настраиваю root SSH" opt_ssh_root_access
        ssh_port="$(detect_ssh_port)"
    fi
    (( SYSTEM_CHECK_NEEDS_NETWORK == 1 )) && progress_step "Настраиваю сеть" opt_network_limits
    (( SYSTEM_CHECK_NEEDS_STORAGE == 1 )) && progress_step "Настраиваю хранение" opt_storage_guard
    (( SYSTEM_CHECK_NEEDS_MEMORY_GUARD == 1 )) && progress_step "Настраиваю память" opt_memory_guard
    (( SYSTEM_CHECK_NEEDS_FIREWALL == 1 )) && progress_step "Настраиваю firewall" opt_firewall "$ssh_port"
    (( SYSTEM_CHECK_NEEDS_ANTISCANNER == 1 )) && progress_step "Подключаю AntiScanner" opt_antiscanner
    (( SYSTEM_CHECK_NEEDS_FAIL2BAN == 1 )) && progress_step "Настраиваю Fail2ban" opt_fail2ban
    opt_haproxy_firewall_final_check

    echo
    duration=$(( $(date +%s) - started_at ))
    ok "Недостающие блоки применены"
    ok "Время: $(format_duration "$duration")"
}

system_check_pause() {
    echo
    echo -ne "${PURPLE}>${NC} ${BOLD}Нажмите Enter, чтобы вернуться:${NC} "
    read -r
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
    system_check_ssh_root_access
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

    progress_start 11
    progress_step "Готовлю систему" opt_prepare_system
    progress_step "Ставлю базовые пакеты" opt_install_fast_packages
    progress_step "Kernel, сеть и память" opt_kernel_network_memory_parallel
    progress_step "Проверяю kernel" opt_kernel_final_check
    progress_step "Настраиваю root SSH" opt_ssh_root_access
    ssh_port="$(detect_ssh_port)"
    progress_step "Настраиваю хранение" opt_storage_guard
    progress_step "Мигрирую HAProxy" upgrade_haproxy_if_configured
    progress_step "Настраиваю firewall" opt_firewall "$ssh_port"
    progress_step "Подключаю AntiScanner" opt_antiscanner
    progress_step "Настраиваю Fail2ban" opt_fail2ban
    progress_step "Проверяю HAProxy firewall" opt_haproxy_firewall_final_check

    echo
    duration=$(( $(date +%s) - started_at ))
    ssh_port="$(detect_ssh_port)"
    ok "Оптимизация завершена. Рекомендуется: sudo reboot"
    ok "SSH-порт: ${ssh_port}/tcp"
    ok "Подключение: ssh -p ${ssh_port} root@IP"
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
    if node_profile_includes_hysteria2; then
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
      - NODE_PORT=${NODE_PORT}
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
      - NODE_PORT=${NODE_PORT}
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
    harden_selfsteal_caddy

    echo
    ok "SelfSteal установлен"
}

harden_selfsteal_caddy() {
    local caddyfile="${KTO_SELFSTEAL_CADDYFILE:-/opt/caddy/Caddyfile}"
    local container="${KTO_SELFSTEAL_CADDY_CONTAINER:-caddy-selfsteal}"
    local marker="# kto-selfsteal-timeouts-v1"
    local tmp backup

    if ! "${SUDO[@]}" test -s "$caddyfile" 2>/dev/null; then
        warn "SelfSteal Caddyfile не найден, HTTP-таймауты не применены"
        return 0
    fi
    if "${SUDO[@]}" grep -Fq "$marker" "$caddyfile" 2>/dev/null; then
        ok "SelfSteal Caddy: защитные таймауты уже применены"
        return 0
    fi

    stage "Добавляю безопасные таймауты SelfSteal Caddy"
    tmp="$(mktemp)"
    backup="${caddyfile}.kto.bak"
    if ! "${SUDO[@]}" awk -v marker="$marker" '
        !inserted && $0 ~ /^[[:space:]]*servers[[:space:]]*[{][[:space:]]*$/ {
            print
            print "\t\t" marker
            print "\t\ttimeouts {"
            print "\t\t\tread_header 5s"
            print "\t\t\tidle 15s"
            print "\t\t}"
            print "\t\tmax_header_size 64KB"
            inserted = 1
            next
        }
        { print }
        END { if (!inserted) exit 42 }
    ' "$caddyfile" > "$tmp"; then
        rm -f "$tmp"
        fail "Не нашёл глобальный servers-блок в $caddyfile"
        return 1
    fi

    "${SUDO[@]}" cp -a "$caddyfile" "$backup" >> "$LOG_FILE" 2>&1
    "${SUDO[@]}" install -m 0644 "$tmp" "$caddyfile" >> "$LOG_FILE" 2>&1
    rm -f "$tmp"

    if ! "${SUDO[@]}" docker inspect "$container" >/dev/null 2>&1; then
        warn "Контейнер $container не найден; таймауты сохранены и применятся при его запуске"
        return 0
    fi
    if ! "${SUDO[@]}" docker exec "$container" caddy validate --config /etc/caddy/Caddyfile >> "$LOG_FILE" 2>&1; then
        "${SUDO[@]}" install -m 0644 "$backup" "$caddyfile" >> "$LOG_FILE" 2>&1 || true
        fail "Caddy отклонил конфиг с таймаутами; предыдущий файл восстановлен"
        return 1
    fi
    if ! "${SUDO[@]}" docker restart --time 3 "$container" >> "$LOG_FILE" 2>&1; then
        "${SUDO[@]}" install -m 0644 "$backup" "$caddyfile" >> "$LOG_FILE" 2>&1 || true
        "${SUDO[@]}" docker restart --time 3 "$container" >> "$LOG_FILE" 2>&1 || true
        fail "Не удалось перезапустить $container; предыдущий файл восстановлен"
        return 1
    fi

    ok "SelfSteal Caddy: read_header=5s, idle=15s, max_header=64KB"
}

harden_selfsteal_caddy_now() {
    header
    need_root
    harden_selfsteal_caddy
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
    stage "Устанавливаю VPS-WARP"
    local script
    script="$(mktemp)"
    must "Скачивание VPS-WARP" curl -fsSL "$WARP_INSTALL_URL" -o "$script"

    if ! bash -n "$script" >> "$LOG_FILE" 2>&1; then
        rm -f "$script"
        fail "Скачанный установщик VPS-WARP повреждён"
        tail -n 25 "$LOG_FILE" >&2 || true
        exit 1
    fi

    if ! command_exists setsid; then
        apt_update_quiet
        apt_install_quiet util-linux
    fi
    if ! command_exists setsid; then
        rm -f "$script"
        fail "Не найден setsid для автоматической установки VPS-WARP"
        exit 1
    fi

    # Upstream intentionally reads /dev/tty. A detached session makes the
    # supplied language choice and empty WARP+ key fully non-interactive.
    if ! printf '2\n\n' | "${SUDO[@]}" env \
        HOME=/root TERM="${TERM:-xterm}" DEBIAN_FRONTEND=noninteractive \
        setsid --wait bash "$script" >> "$LOG_FILE" 2>&1; then
        rm -f "$script"
        fail "VPS-WARP не установился"
        tail -n 25 "$LOG_FILE" >&2 || true
        exit 1
    fi
    rm -f "$script"

    if ! "${SUDO[@]}" test -s /etc/wireguard/warp.conf \
        || ! "${SUDO[@]}" test -x /usr/local/bin/vps-warp \
        || ! "${SUDO[@]}" systemctl is-active --quiet wg-quick@warp; then
        "${SUDO[@]}" systemctl status wg-quick@warp --no-pager >> "$LOG_FILE" 2>&1 || true
        fail "VPS-WARP завершил установку, но туннель не поднялся"
        tail -n 25 "$LOG_FILE" >&2 || true
        exit 1
    fi

    echo
    ok "VPS-WARP установлен и активен"
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

speedtest_binary_works() {
    local binary="$1" version_output
    [[ -x "$binary" ]] || return 1
    if command_exists timeout; then
        version_output="$(timeout --foreground 10s "$binary" --version 2>&1 || true)"
    else
        version_output="$("$binary" --version 2>&1 || true)"
    fi
    grep -qi 'Speedtest by Ookla' <<< "$version_output"
}

speedtest_find_binary() {
    local binary
    for binary in /usr/local/bin/speedtest /usr/bin/speedtest; do
        if speedtest_binary_works "$binary"; then
            printf '%s\n' "$binary"
            return 0
        fi
    done
    return 1
}

speedtest_platform_profile() {
    local arch="${1:-}"
    case "$arch" in
        x86_64|amd64)
            printf '%s\t%s\t%s\t%s\t%s\n' \
                "https://install.speedtest.net/app/cli/ookla-speedtest-${SPEEDTEST_STATIC_VERSION}-linux-x86_64.tgz" \
                "$SPEEDTEST_X86_64_ARCHIVE_SHA256" \
                "https://packagecloud.io/ookla/speedtest-cli/packages/debian/bullseye/speedtest_${SPEEDTEST_PACKAGE_VERSION}_amd64.deb/download.deb" \
                "$SPEEDTEST_AMD64_DEB_SHA256" \
                "amd64"
            ;;
        aarch64|arm64)
            printf '%s\t%s\t%s\t%s\t%s\n' \
                "https://install.speedtest.net/app/cli/ookla-speedtest-${SPEEDTEST_STATIC_VERSION}-linux-aarch64.tgz" \
                "$SPEEDTEST_AARCH64_ARCHIVE_SHA256" \
                "https://packagecloud.io/ookla/speedtest-cli/packages/debian/bullseye/speedtest_${SPEEDTEST_PACKAGE_VERSION}_arm64.deb/download.deb" \
                "$SPEEDTEST_ARM64_DEB_SHA256" \
                "arm64"
            ;;
        *) return 1 ;;
    esac
}

speedtest_fetch_url() {
    local label="$1" url="$2" destination="$3" output_file="$4"
    rm -f "$destination"
    if command_exists curl; then
        stage "${label}: скачиваю через curl"
        if run_live_capture_timeout "$SPEEDTEST_DOWNLOAD_TIMEOUT" "$output_file" \
            curl -fL --progress-bar --connect-timeout 10 --retry 2 --retry-delay 2 \
            --max-time "$SPEEDTEST_DOWNLOAD_TIMEOUT" -o "$destination" "$url" && [[ -s "$destination" ]]; then
            ok "${label}: curl"
            return 0
        fi
        warn "${label}: обычный curl не сработал, пробую IPv4."
        rm -f "$destination"

        stage "${label}: повтор через curl IPv4"
        if run_live_capture_timeout "$SPEEDTEST_DOWNLOAD_TIMEOUT" "$output_file" \
            curl -4 -fL --progress-bar --connect-timeout 10 --retry 3 --retry-delay 2 \
            --max-time "$SPEEDTEST_DOWNLOAD_TIMEOUT" -o "$destination" "$url" && [[ -s "$destination" ]]; then
            ok "${label}: curl IPv4"
            return 0
        fi
        warn "${label}: curl IPv4 не сработал, пробую wget IPv4."
        rm -f "$destination"
    fi

    if command_exists wget; then
        stage "${label}: резерв через wget IPv4"
        if run_live_capture_timeout "$SPEEDTEST_DOWNLOAD_TIMEOUT" "$output_file" \
            wget -4 --timeout=20 --tries=3 -O "$destination" "$url" && [[ -s "$destination" ]]; then
            ok "${label}: wget IPv4"
            return 0
        fi
        rm -f "$destination"
    fi
    return 1
}

speedtest_verify_sha256() {
    local file="$1" expected="$2" actual
    [[ -s "$file" ]] || return 1
    actual="$(sha256sum "$file" 2>/dev/null | awk '{ print tolower($1) }')"
    if [[ -z "$actual" || "$actual" != "${expected,,}" ]]; then
        printf 'Speedtest checksum mismatch: file=%s expected=%s actual=%s\n' \
            "$file" "$expected" "${actual:--}" >> "$LOG_FILE"
        return 1
    fi
}

speedtest_install_static_archive() {
    local archive_url="$1" archive_hash="$2"
    local archive output_file extract_dir
    archive="$(mktemp)"
    output_file="$(mktemp)"
    extract_dir="$(mktemp -d)"

    if ! speedtest_fetch_url "Ookla CLI" "$archive_url" "$archive" "$output_file"; then
        rm -f "$archive" "$output_file"
        rm -rf "$extract_dir"
        return 1
    fi
    rm -f "$output_file"
    if ! speedtest_verify_sha256 "$archive" "$archive_hash"; then
        warn "Ookla CLI: контрольная сумма архива не совпала."
        rm -f "$archive"
        rm -rf "$extract_dir"
        return 1
    fi
    if ! tar -tzf "$archive" 2>> "$LOG_FILE" | grep -qx 'speedtest' ||
        ! tar xzf "$archive" -C "$extract_dir" speedtest >> "$LOG_FILE" 2>&1 ||
        ! "${SUDO[@]}" install -m 0755 "$extract_dir/speedtest" /usr/local/bin/speedtest >> "$LOG_FILE" 2>&1; then
        warn "Ookla CLI: архив не удалось безопасно распаковать."
        rm -f "$archive"
        rm -rf "$extract_dir"
        return 1
    fi
    rm -f "$archive"
    rm -rf "$extract_dir"
    if ! speedtest_binary_works /usr/local/bin/speedtest; then
        warn "Ookla CLI: установленный статический бинарник не запускается."
        "${SUDO[@]}" rm -f /usr/local/bin/speedtest >> "$LOG_FILE" 2>&1 || true
        return 1
    fi
    ok "Официальный Ookla CLI установлен в /usr/local/bin"
}

speedtest_install_packagecloud_deb() {
    local deb_url="$1" deb_hash="$2" expected_arch="$3"
    local package_dir package_file output_file package_name package_arch
    package_dir="$(mktemp -d)"
    package_file="${package_dir}/speedtest.deb"
    output_file="$(mktemp)"

    if ! speedtest_fetch_url "Ookla Packagecloud" "$deb_url" "$package_file" "$output_file"; then
        rm -f "$output_file"
        rm -rf "$package_dir"
        return 1
    fi
    rm -f "$output_file"
    if ! speedtest_verify_sha256 "$package_file" "$deb_hash"; then
        warn "Ookla Packagecloud: контрольная сумма пакета не совпала."
        rm -rf "$package_dir"
        return 1
    fi
    package_name="$(dpkg-deb -f "$package_file" Package 2>/dev/null || true)"
    package_arch="$(dpkg-deb -f "$package_file" Architecture 2>/dev/null || true)"
    if [[ "$package_name" != "speedtest" || "$package_arch" != "$expected_arch" ]]; then
        warn "Ookla Packagecloud: пакет имеет неожиданные метаданные."
        rm -rf "$package_dir"
        return 1
    fi
    if ! "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive \
        apt-get -o DPkg::Lock::Timeout=600 install -y "$package_file" >> "$LOG_FILE" 2>&1; then
        warn "Ookla Packagecloud: apt не смог установить проверенный пакет."
        rm -rf "$package_dir"
        return 1
    fi
    rm -rf "$package_dir"
    if ! speedtest_binary_works /usr/bin/speedtest; then
        warn "Ookla Packagecloud: установленный пакет не запускается."
        return 1
    fi
    ok "Официальный Ookla CLI установлен через Packagecloud"
}

install_speedtest() {
    header
    need_root
    local output filtered output_file arch rc server_id binary profile requested_source_ip source_ip source_interface
    local archive_url archive_hash deb_url deb_hash deb_arch
    local -a speedtest_args speedtest_retry_args

    server_id="${1:-${KTO_SPEEDTEST_SERVER_ID:-}}"
    requested_source_ip="${2:-}"
    if [[ -n "$server_id" ]] && ! [[ "$server_id" =~ ^[0-9]+$ ]]; then
        fail "Speedtest server id должен быть числом"
        return 1
    fi
    select_test_source_ipv4 "$requested_source_ip" || return 1
    source_ip="$TEST_SOURCE_IP"
    source_interface="$TEST_SOURCE_INTERFACE"

    stage "Готовлю Speedtest"
    binary="$(speedtest_find_binary 2>/dev/null || true)"
    if [[ -z "$binary" ]]; then
        if [[ -e /usr/local/bin/speedtest ]]; then
            warn "Старый Speedtest в /usr/local/bin не отвечает, удаляю."
            cmd "${SUDO[@]}" rm -f /usr/local/bin/speedtest || true
        fi
        cmd "${SUDO[@]}" apt-get remove -y speedtest-cli || true
        if package_installed speedtest && ! speedtest_binary_works /usr/bin/speedtest; then
            cmd "${SUDO[@]}" apt-get remove -y speedtest || true
        fi
        cmd "${SUDO[@]}" rm -f /usr/bin/speedtest /usr/local/bin/speedtest || true

        if ! apt_install_with_update_if_missing ca-certificates curl wget tar coreutils; then
            warn "Не все утилиты скачивания поставились через apt, использую уже доступные."
        fi
        if ! command_exists tar || ! command_exists sha256sum ||
            { ! command_exists curl && ! command_exists wget; }; then
            fail "Для установки Speedtest нужны tar, sha256sum и curl либо wget"
            return 1
        fi

        arch="$(uname -m)"
        if ! profile="$(speedtest_platform_profile "$arch")"; then
            fail "Архитектура ${arch} не поддерживается официальным Ookla CLI"
            return 1
        fi
        IFS=$'\t' read -r archive_url archive_hash deb_url deb_hash deb_arch <<< "$profile"

        if ! speedtest_install_packagecloud_deb "$deb_url" "$deb_hash" "$deb_arch"; then
            warn "Ookla Packagecloud не сработал, пробую резервный статический архив."
            if ! speedtest_install_static_archive "$archive_url" "$archive_hash"; then
                fail "Speedtest не установился ни одним способом"
                warn "Проверены официальный Packagecloud и статический архив через curl, curl IPv4 и wget IPv4."
                return 1
            fi
        fi

        binary="$(speedtest_find_binary 2>/dev/null || true)"
        if [[ -z "$binary" ]]; then
            fail "Speedtest установлен, но рабочий бинарник не найден"
            return 1
        fi
    else
        echo "Speedtest binary skipped: already installed at $binary" >> "$LOG_FILE"
        ok "Ookla CLI уже установлен: ${binary}"
    fi

    speedtest_args=("$binary" --accept-license --accept-gdpr --progress=yes --ip="$source_ip")
    speedtest_retry_args=("$binary" --accept-license --accept-gdpr --progress=no --ip="$source_ip")
    if [[ -n "$server_id" ]]; then
        speedtest_args+=(--server-id="$server_id")
        speedtest_retry_args+=(--server-id="$server_id")
        ok "Сервер Speedtest: ${server_id}"
    fi
    ok "Исходящий IP теста: ${source_ip} (${source_interface})"

    echo
    stage "Запускаю Speedtest"
    output_file="$(mktemp)"
    if run_speedtest_live "$output_file" "${speedtest_args[@]}"; then
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
        if run_speedtest_live "$output_file" "${speedtest_retry_args[@]}"; then
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

write_speedtest_ru_bind_wrapper() {
    local output_file="$1" executable="$2"
    shift 2
    {
        printf '#!/usr/bin/env bash\nexec'
        printf ' %q' "$executable" "$@"
        printf ' "$@"\n'
    } > "$output_file"
    chmod 0755 "$output_file"
}

download_speedtest_ru_bench() {
    local output_file="$1" source_ip="${2:-}"
    local -a wget_args=(--no-proxy -4 -q -O "$output_file" --timeout=20 --tries=3)
    local -a curl_args=(-q -4 --noproxy '*' -fsSL --connect-timeout 10 --max-time 45 \
        --retry 2 --retry-delay 2 -o "$output_file")

    [[ -z "$source_ip" ]] || wget_args+=("--bind-address=${source_ip}")
    if wget "${wget_args[@]}" "$SPEEDTEST_RU_URL"; then
        return 0
    fi

    warn "wget не скачал RU bench, пробую curl"
    [[ -z "$source_ip" ]] || curl_args+=(--interface "$source_ip")
    curl "${curl_args[@]}" "$SPEEDTEST_RU_URL"
}

speedtest_ru() {
    header
    need_root
    local source_ip="${1:-}" bench_script bind_dir="" route_line route_interface actual_ip
    local real_iperf3 real_ping real_wget real_curl

    stage "Запускаю Speedtest (RU)"
    select_test_source_ipv4 "$source_ip" || return 1
    source_ip="$TEST_SOURCE_IP"
    route_interface="$TEST_SOURCE_INTERFACE"
    route_line="$(ip -4 route get 1.1.1.1 from "$source_ip" 2>/dev/null || true)"
    if [[ -z "$route_line" || -z "$route_interface" ]]; then
        fail "Для ${source_ip} нет рабочего source-route. Сначала запусти настройку дополнительных IP."
        return 1
    fi
    stage "Тест через ${source_ip} (${route_interface})"
    apt_install_with_update_if_missing wget curl ca-certificates iperf3 iproute2 iputils-ping

    bench_script="$(mktemp)"
    cleanup_speedtest_ru() {
        trap - RETURN
        rm -f "$bench_script"
        [[ -z "$bind_dir" ]] || rm -rf "$bind_dir"
    }
    trap cleanup_speedtest_ru RETURN

    stage "Скачиваю ${SPEEDTEST_RU_URL}"
    if ! download_speedtest_ru_bench "$bench_script" "$source_ip"; then
        fail "Не удалось скачать RU bench через доступные сетевые пути"
        return 1
    fi
    if ! head -n 1 "$bench_script" | grep -Eq '^#!.*bash' \
        || ! grep -q '^speed_test()' "$bench_script" \
        || ! bash -n "$bench_script"; then
        fail "${SPEEDTEST_RU_URL} вернул невалидный Bash-скрипт"
        return 1
    fi

    echo "running: ${SPEEDTEST_RU_URL}${source_ip:+ source=${source_ip}}" >> "$LOG_FILE"
    real_iperf3="$(command -v iperf3)"
    real_ping="$(command -v ping)"
    real_wget="$(command -v wget)"
    real_curl="$(command -v curl)"
    bind_dir="$(mktemp -d)"
    write_speedtest_ru_bind_wrapper "$bind_dir/iperf3" "$real_iperf3" -B "$source_ip"
    write_speedtest_ru_bind_wrapper "$bind_dir/ping" "$real_ping" -I "$source_ip"
    write_speedtest_ru_bind_wrapper "$bind_dir/wget" "$real_wget" --no-proxy -4 "--bind-address=${source_ip}"
    write_speedtest_ru_bind_wrapper "$bind_dir/curl" "$real_curl" --noproxy '*' -4 --interface "$source_ip"

    actual_ip="$($real_curl -4 --noproxy '*' --interface "$source_ip" -fsS \
        --connect-timeout 5 --max-time 10 https://api.ipify.org 2>/dev/null || true)"
    if validate_ipv4 "$actual_ip"; then
        if [[ "$actual_ip" == "$source_ip" ]]; then
            ok "Внешний IP теста: ${actual_ip}"
        else
            warn "Source ${source_ip} выходит наружу как ${actual_ip} (NAT)"
        fi
    else
        warn "Не удалось проверить внешний IP, но source-route найден: ${route_line}"
    fi
    echo "speedtest-ru source=${source_ip} route=${route_line}" >> "$LOG_FILE"
    env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u all_proxy \
        PATH="${bind_dir}:${PATH}" bash "$bench_script"
}

NETTEST_DNS_BAD=0
NETTEST_HTTPS_BAD=0
NETTEST_RAW_OK=0
NETTEST_RAW_BAD=0
NETTEST_PING_BAD=0
NETTEST_WARN=0
NETTEST_SOURCE_IP=""
NETTEST_SOURCE_INTERFACE=""

network_test_badge() {
    case "$1" in
        ok) printf '%bOK%b' "$GREEN" "$NC" ;;
        warn) printf '%bWARN%b' "$YELLOW" "$NC" ;;
        fail) printf '%bFAIL%b' "$RED" "$NC" ;;
        skip) printf '%bSKIP%b' "$DIM" "$NC" ;;
        *) printf '%s' "$1" ;;
    esac
}

network_test_row() {
    local name="$1"
    local value="$2"
    local status="${3:-}"
    if [[ -n "$status" ]]; then
        printf " %-22s %b %b\n" "$name" "$value" "$(network_test_badge "$status")"
    else
        printf " %-22s %b\n" "$name" "$value"
    fi
}

network_test_short() {
    local text="$1"
    text="${text//$'\r'/ }"
    text="${text//$'\n'/ }"
    text="$(sed -E 's/[[:space:]]+/ /g; s/^[[:space:]]+//; s/[[:space:]]+$//' <<< "$text")"
    printf '%.160s' "$text"
}

network_test_resolve() {
    local host="$1"
    local ips status
    if command_exists dig; then
        ips="$(dig -4 -b "$NETTEST_SOURCE_IP" "$host" A +time=4 +tries=1 +short 2>/dev/null |
            awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/' | sort -u | paste -sd ' ' - || true)"
    else
        ips="$(getent ahostsv4 "$host" 2>/dev/null | awk '{print $1}' | sort -u | paste -sd ' ' - || true)"
    fi
    if [[ -n "$ips" ]]; then
        status="ok"
    else
        status="fail"
        (( NETTEST_DNS_BAD += 1 ))
        ips="не резолвится"
    fi
    network_test_row "DNS ${host}" "$ips" "$status"
}

network_test_tcp() {
    local host="$1"
    local port="${2:-443}"
    local timeout_sec="${3:-4}"
    if command_exists python3; then
        python3 - "$NETTEST_SOURCE_IP" "$host" "$port" "$timeout_sec" >/dev/null 2>&1 <<'PY'
import socket
import sys

source_ip, host, port, timeout = sys.argv[1], sys.argv[2], int(sys.argv[3]), float(sys.argv[4])
for family, socktype, proto, _, address in socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM):
    sock = socket.socket(family, socktype, proto)
    try:
        sock.settimeout(timeout)
        sock.bind((source_ip, 0))
        sock.connect(address)
        raise SystemExit(0)
    except OSError:
        pass
    finally:
        sock.close()
raise SystemExit(1)
PY
        return $?
    fi
    command_exists nc || return 127
    nc -4 -z -s "$NETTEST_SOURCE_IP" -w "$timeout_sec" "$host" "$port" >/dev/null 2>&1
}

network_test_https() {
    local label="$1"
    local url="$2"
    local output rc status
    if ! command_exists curl; then
        network_test_row "$label" "curl не найден" "skip"
        (( NETTEST_WARN += 1 ))
        return 0
    fi

    if output="$(curl -4 --noproxy '*' --interface "$NETTEST_SOURCE_IP" -sS -o /dev/null \
        -w 'http=%{http_code} connect=%{time_connect}s tls=%{time_appconnect}s total=%{time_total}s ip=%{remote_ip}' \
        --connect-timeout 4 -m 10 "$url" 2>&1)"; then
        rc=0
    else
        rc=$?
    fi

    output="$(network_test_short "$output")"
    if (( rc == 0 )); then
        status="ok"
    else
        status="fail"
        (( NETTEST_HTTPS_BAD += 1 ))
        output="rc=${rc} ${output}"
    fi
    network_test_row "$label" "$output" "$status"
}

network_test_raw_ip() {
    local ip="$1"
    local output rc status tcp_status
    if network_test_tcp "$ip" 443 4; then
        tcp_status="tcp=ok"
    else
        tcp_status="tcp=fail"
    fi

    if ! command_exists curl; then
        network_test_row "raw ${ip}" "${tcp_status}; curl не найден" "skip"
        (( NETTEST_WARN += 1 ))
        return 0
    fi

    if output="$(curl -4 --noproxy '*' --interface "$NETTEST_SOURCE_IP" -sS -o /dev/null \
        -w 'http=%{http_code} connect=%{time_connect}s tls=%{time_appconnect}s total=%{time_total}s' \
        --resolve "raw.githubusercontent.com:443:${ip}" \
        --connect-timeout 4 -m 10 https://raw.githubusercontent.com/ 2>&1)"; then
        rc=0
    else
        rc=$?
    fi

    output="$(network_test_short "$output")"
    if (( rc == 0 )); then
        status="ok"
        (( NETTEST_RAW_OK += 1 ))
    else
        status="fail"
        (( NETTEST_RAW_BAD += 1 ))
        output="rc=${rc} ${output}"
    fi
    network_test_row "raw ${ip}" "${tcp_status}; ${output}" "$status"
}

network_test_ping() {
    local target="$1"
    local label="${2:-$1}"
    local tmp loss loss_percent rtt status ping_rc=0
    if ! command_exists ping; then
        network_test_row "ping ${label}" "ping не найден" "skip"
        (( NETTEST_WARN += 1 ))
        return 0
    fi

    tmp="$(mktemp)"
    ping -4 -I "$NETTEST_SOURCE_IP" -c 10 -i 0.2 -W 2 "$target" > "$tmp" 2>&1 || ping_rc=$?
    loss="$(awk -F',' '/packet loss/ {gsub(/^[[:space:]]+|[[:space:]]+$/, "", $3); print $3; exit}' "$tmp" 2>/dev/null || true)"
    loss_percent="$(sed -nE 's/.* ([0-9]+([.][0-9]+)?)% packet loss.*/\1/p' "$tmp" | tail -n 1)"
    [[ -z "$loss_percent" ]] || loss="${loss_percent}%"
    rtt="$(awk -F'/' '/^(rtt|round-trip)/ {print $5 " ms"; exit}' "$tmp" 2>/dev/null || true)"
    rm -f "$tmp"
    if [[ -n "$loss_percent" ]] && awk -v loss="$loss_percent" 'BEGIN { exit !(loss > 0) }'; then
        status="warn"
        (( NETTEST_PING_BAD += 1 ))
    elif (( ping_rc != 0 )) || [[ -z "$loss_percent" ]]; then
        status="warn"
        (( NETTEST_PING_BAD += 1 ))
    else
        status="ok"
    fi
    network_test_row "ping ${label}" "loss=${loss:-?}${rtt:+ avg=${rtt}}" "$status"
}

network_test_mtr() {
    local target="$1"
    local label="${2:-$1}"
    local out
    local -a mtr_args=(-4 -a "$NETTEST_SOURCE_IP" -T -P 443 -c 5 -r)
    if ! command_exists mtr; then
        network_test_row "mtr ${label}" "mtr не установлен" "skip"
        return 0
    fi
    out="$(mtr "${mtr_args[@]}" "$target" 2>/dev/null | tail -n 4 | sed 's/^[[:space:]]*//' | paste -sd ' | ' - || true)"
    network_test_row "mtr ${label}" "$(network_test_short "${out:-нет вывода}")"
}

network_test_conntrack() {
    local count maximum percent status="ok" recent_full=0
    count="$(sysctl -n net.netfilter.nf_conntrack_count 2>/dev/null || true)"
    maximum="$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || true)"
    if [[ ! "$count" =~ ^[0-9]+$ || ! "$maximum" =~ ^[0-9]+$ || "$maximum" -le 0 ]]; then
        network_test_row "conntrack" "не используется" "skip"
        return 0
    fi

    percent=$(( count * 100 / maximum ))
    if (( count >= maximum || percent >= 95 )); then
        status="fail"
        (( NETTEST_CONNTRACK_BAD += 1 ))
    elif (( percent >= 75 )); then
        status="warn"
        (( NETTEST_WARN += 1 ))
    fi
    network_test_row "conntrack" "${count}/${maximum} (${percent}%)" "$status"

    if dmesg 2>/dev/null | tail -n 200 | grep -F 'nf_conntrack: table full, dropping packet' >/dev/null; then
        recent_full=1
    fi
    if (( recent_full == 1 )); then
        network_test_row "conntrack drops" "в последних kernel-сообщениях был table full" "warn"
        (( NETTEST_WARN += 1 ))
    fi
}

network_test_extra_target() {
    local target="$1"
    [[ -n "$target" ]] || return 0
    echo
    echo -e "${BOLD}${PURPLE}[ TARGET: ${target} ]${NC}"

    if [[ "$target" =~ ^https?:// ]]; then
        network_test_https "$target" "$target"
        return 0
    fi

    if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        if network_test_tcp "$target" 443 4; then
            network_test_row "tcp ${target}:443" "порт открыт" "ok"
        else
            network_test_row "tcp ${target}:443" "нет соединения" "fail"
            (( NETTEST_HTTPS_BAD += 1 ))
        fi
        network_test_ping "$target" "$target"
        return 0
    fi

    network_test_resolve "$target"
    network_test_https "https ${target}" "https://${target}/"
    network_test_mtr "$target" "$target"
}

network_test() {
    header
    local iface route_line default_route src_ip mtu dns_line host gateway ip target requested_source_ip
    local -a raw_ips default_hosts extra_targets
    requested_source_ip="${KTO_TEST_SOURCE_IP:-}"
    if [[ "${1:-}" == "--source-ip" ]]; then
        if (( $# < 2 )); then
            fail "После --source-ip нужен IPv4"
            return 1
        fi
        requested_source_ip="$2"
        shift 2
    fi
    select_test_source_ipv4 "$requested_source_ip" || return 1
    NETTEST_SOURCE_IP="$TEST_SOURCE_IP"
    NETTEST_SOURCE_INTERFACE="$TEST_SOURCE_INTERFACE"
    extra_targets=("$@")
    raw_ips=(185.199.108.133 185.199.109.133 185.199.110.133 185.199.111.133)
    default_hosts=(raw.githubusercontent.com github.com api.github.com)

    NETTEST_DNS_BAD=0
    NETTEST_HTTPS_BAD=0
    NETTEST_RAW_OK=0
    NETTEST_RAW_BAD=0
    NETTEST_PING_BAD=0
    NETTEST_CONNTRACK_BAD=0
    NETTEST_WARN=0

    echo -e "${BOLD}${PURPLE}[ СЕТЬ ]${NC}"
    route_line="$(ip -4 route get 1.1.1.1 from "$NETTEST_SOURCE_IP" 2>/dev/null || true)"
    iface="$(awk '{for (i=1; i<=NF; i++) if ($i=="dev") {print $(i+1); exit}}' <<< "$route_line")"
    src_ip="$(awk '{for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}' <<< "$route_line")"
    [[ -n "$src_ip" ]] || src_ip="$NETTEST_SOURCE_IP"
    gateway="$(awk '{for (i=1; i<=NF; i++) if ($i=="via") {print $(i+1); exit}}' <<< "$route_line")"
    default_route="$(ip -4 route show default 2>/dev/null | head -n 1 || true)"
    if [[ -n "$iface" ]]; then
        mtu="$(ip -o link show dev "$iface" 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="mtu") {print $(i+1); exit}}' || true)"
    else
        mtu=""
    fi
    network_test_row "interface" "${iface:--}${src_ip:+ src=${src_ip}}${mtu:+ mtu=${mtu}}"
    network_test_row "source route" "${route_line:--}"
    network_test_row "default route" "${default_route:--}"

    if command_exists resolvectl; then
        dns_line="$(resolvectl dns 2>/dev/null | sed -E 's/^[[:space:]]+//' | paste -sd '; ' - || true)"
    else
        dns_line="$(awk '/^nameserver/ {print $2}' /etc/resolv.conf 2>/dev/null | paste -sd ' ' - || true)"
    fi
    network_test_row "dns servers" "${dns_line:--}"

    echo
    echo -e "${BOLD}${PURPLE}[ DNS ]${NC}"
    for host in "${default_hosts[@]}"; do
        network_test_resolve "$host"
    done

    echo
    echo -e "${BOLD}${PURPLE}[ HTTPS ]${NC}"
    network_test_https "raw" "https://raw.githubusercontent.com/"
    network_test_https "github" "https://github.com/"
    network_test_https "api.github" "https://api.github.com/"
    network_test_https "cloudflare" "https://1.1.1.1/cdn-cgi/trace"
    network_test_https "google dns" "https://8.8.8.8/"

    echo
    echo -e "${BOLD}${PURPLE}[ RAW GITHUB IP ]${NC}"
    for ip in "${raw_ips[@]}"; do
        network_test_raw_ip "$ip"
    done

    echo
    echo -e "${BOLD}${PURPLE}[ CONNTRACK ]${NC}"
    network_test_conntrack

    echo
    echo -e "${BOLD}${PURPLE}[ LOSS ]${NC}"
    [[ -n "$gateway" ]] && network_test_ping "$gateway" "gateway"
    network_test_ping "1.1.1.1" "1.1.1.1"
    network_test_ping "8.8.8.8" "8.8.8.8"
    network_test_mtr "raw.githubusercontent.com" "raw"

    for target in "${extra_targets[@]}"; do
        network_test_extra_target "$target"
    done

    echo
    echo -e "${BOLD}${PURPLE}[ ИТОГ ]${NC}"
    if (( NETTEST_DNS_BAD > 0 )); then
        network_test_row "DNS" "есть проблемы резолва (${NETTEST_DNS_BAD})" "fail"
    else
        network_test_row "DNS" "резолвится" "ok"
    fi

    if (( NETTEST_RAW_BAD > 0 && NETTEST_RAW_OK > 0 )); then
        network_test_row "raw GitHub" "часть IP живая, часть тупит: похоже на маршрут/Fastly" "warn"
    elif (( NETTEST_RAW_BAD > 0 )); then
        network_test_row "raw GitHub" "все raw IP плохие" "fail"
    else
        network_test_row "raw GitHub" "все raw IP отвечают" "ok"
    fi

    if (( NETTEST_HTTPS_BAD > 0 )); then
        network_test_row "HTTPS" "есть таймауты/ошибки (${NETTEST_HTTPS_BAD})" "fail"
    else
        network_test_row "HTTPS" "базовые цели открываются" "ok"
    fi

    if (( NETTEST_PING_BAD > 0 )); then
        network_test_row "ICMP" "есть потери/таймауты, но ICMP у провайдера может резаться" "warn"
    else
        network_test_row "ICMP" "без явных потерь" "ok"
    fi

    if (( NETTEST_CONNTRACK_BAD > 0 )); then
        network_test_row "conntrack" "переполнен или уже дропал пакеты; запусти conntrack-fix" "fail"
    else
        network_test_row "conntrack" "нет признаков переполнения" "ok"
    fi

    if (( NETTEST_DNS_BAD > 0 || NETTEST_HTTPS_BAD > 0 || NETTEST_RAW_BAD > 0 || NETTEST_CONNTRACK_BAD > 0 )); then
        echo
        if (( NETTEST_CONNTRACK_BAD > 0 )); then
            warn "Conntrack переполнен: kernel отбрасывает новые пакеты. Запусти: kto.sh conntrack-fix"
        fi
        if (( NETTEST_DNS_BAD > 0 || NETTEST_HTTPS_BAD > 0 || NETTEST_RAW_BAD > 0 )); then
            warn "Если github/api живые, а raw IP выборочно таймаутятся - это обычно маршрут провайдера до Fastly/GitHub, а не Ubuntu."
            warn "Для временного костыля можно прибить raw.githubusercontent.com к рабочему IP из блока RAW GITHUB IP."
        fi
        return 0
    fi

    echo
    ok "Сеть выглядит нормально по базовым проверкам."
}

tspu_ip_tcp_probe() {
    local source_ip="$1"
    local target_ip="$2"
    local port="$3"
    local timeout_sec="${4:-3}"
    local attempts="${5:-2}"
    local output state details

    if ! command_exists python3; then
        network_test_row "TCP ${port}" "python3 не найден" "skip"
        return 4
    fi

    if ! output="$(python3 - "$source_ip" "$target_ip" "$port" "$timeout_sec" "$attempts" 2>&1 <<'PY'
import errno
import socket
import sys
import time

source_ip = sys.argv[1]
target_ip = sys.argv[2]
port = int(sys.argv[3])
timeout = float(sys.argv[4])
attempts = int(sys.argv[5])
outcomes = []
latencies = []
last_error = "-"

for attempt in range(attempts):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    started = time.monotonic()
    try:
        sock.bind((source_ip, 0))
        code = sock.connect_ex((target_ip, port))
        elapsed_ms = (time.monotonic() - started) * 1000
        latencies.append(elapsed_ms)
        if code == 0:
            outcomes.append("open")
        elif code == errno.ECONNREFUSED:
            outcomes.append("refused")
            last_error = "ECONNREFUSED"
        elif code == errno.ETIMEDOUT:
            outcomes.append("timeout")
            last_error = "ETIMEDOUT"
        else:
            outcomes.append("error")
            last_error = errno.errorcode.get(code, "ERR" + str(code))
    except socket.timeout:
        outcomes.append("timeout")
        last_error = "ETIMEDOUT"
    except OSError as exc:
        outcomes.append("error")
        last_error = errno.errorcode.get(exc.errno or 0, exc.__class__.__name__)
    finally:
        sock.close()
    if attempt + 1 < attempts:
        time.sleep(0.15)

opened = outcomes.count("open")
refused = outcomes.count("refused")
timed_out = outcomes.count("timeout")
failed = outcomes.count("error")
if opened == attempts:
    state = "open"
elif opened or (refused and refused < attempts):
    state = "unstable"
elif refused == attempts:
    state = "closed"
elif timed_out == attempts:
    state = "timeout"
else:
    state = "error"

parts = [
    "open={}/{}".format(opened, attempts),
    "refused={}".format(refused),
    "timeout={}".format(timed_out),
]
if failed:
    parts.append("error={}".format(failed))
if latencies:
    parts.append("avg={:.1f}ms".format(sum(latencies) / len(latencies)))
if last_error != "-":
    parts.append("last={}".format(last_error))
print(state + "\t" + " ".join(parts))
PY
)"; then
        network_test_row "TCP ${port}" "probe error: $(network_test_short "$output")" "fail"
        return 4
    fi

    IFS=$'\t' read -r state details <<< "$output"
    case "$state" in
        open)
            network_test_row "TCP ${port}" "$details" "ok"
            return 0
            ;;
        unstable)
            network_test_row "TCP ${port}" "$details" "warn"
            return 1
            ;;
        closed)
            network_test_row "TCP ${port}" "$details" "warn"
            return 2
            ;;
        timeout)
            network_test_row "TCP ${port}" "$details" "fail"
            return 3
            ;;
        *)
            network_test_row "TCP ${port}" "${details:-неизвестная ошибка}" "fail"
            return 4
            ;;
    esac
}

TSPU_TARGET_IP=""
TSPU_TARGET_PORT=""
TSPU_TARGET_HAS_PORT=0

parse_tspu_ipv4_target() {
    local raw="${1:-}" ip port

    raw="$(trim_whitespace "$raw")"
    raw="${raw//[[:space:]]/}"
    [[ -n "$raw" ]] || return 1

    if [[ "$raw" == *:* ]]; then
        [[ "$raw" != *:*:* ]] || return 1
        ip="${raw%%:*}"
        port="${raw#*:}"
        validate_ipv4 "$ip" || return 1
        [[ "$port" =~ ^[0-9]{1,5}$ ]] || return 1
        port=$(( 10#$port ))
        (( port >= 1 && port <= 65535 )) || return 1
        TSPU_TARGET_PORT="$port"
        TSPU_TARGET_HAS_PORT=1
    else
        ip="$raw"
        validate_ipv4 "$ip" || return 1
        TSPU_TARGET_PORT=""
        TSPU_TARGET_HAS_PORT=0
    fi

    TSPU_TARGET_IP="$ip"
}

MTR_BATCH_TARGET_COUNT=0
MTR_BATCH_INVALID_COUNT=0
MTR_BATCH_DUPLICATE_COUNT=0

parse_mtr_batch_targets() {
    local input_file="$1"
    local output_file="$2"
    local line raw token ip port label key current_label=""
    local line_number=0 max_targets="${KTO_MTR_BATCH_MAX_TARGETS:-64}"
    local -A seen=()

    [[ "$max_targets" =~ ^[0-9]+$ ]] || max_targets=64
    (( max_targets >= 1 && max_targets <= 256 )) || max_targets=64
    MTR_BATCH_TARGET_COUNT=0
    MTR_BATCH_INVALID_COUNT=0
    MTR_BATCH_DUPLICATE_COUNT=0
    : > "$output_file"

    while IFS= read -r raw || [[ -n "$raw" ]]; do
        (( line_number += 1 ))
        line="${raw%$'\r'}"
        line="$(trim_whitespace "$line")"
        [[ -n "$line" ]] || continue
        [[ "$line" == \#* ]] && continue
        case "$line" in
            done|DONE|Done|готово|ГОТОВО|Готово|end|END|конец|КОНЕЦ) continue ;;
        esac

        token=""
        if [[ "$line" =~ ([0-9]{1,3}([.][0-9]{1,3}){3})(:([^[:space:]]+))? ]]; then
            token="${BASH_REMATCH[0]}"
        elif [[ "$line" == *: ]]; then
            current_label="$(trim_whitespace "${line%:}")"
            if [[ -z "$current_label" ]]; then
                fail "Строка ${line_number}: пустое название группы"
                (( MTR_BATCH_INVALID_COUNT += 1 ))
            fi
            continue
        else
            fail "Строка ${line_number}: не найден IPv4 или IPv4:порт: ${line}"
            (( MTR_BATCH_INVALID_COUNT += 1 ))
            continue
        fi

        if ! parse_tspu_ipv4_target "$token"; then
            fail "Строка ${line_number}: некорректная цель ${token}"
            (( MTR_BATCH_INVALID_COUNT += 1 ))
            continue
        fi
        ip="$TSPU_TARGET_IP"
        port="${TSPU_TARGET_PORT:-443}"
        key="${ip}:${port}"
        if [[ -n "${seen[$key]:-}" ]]; then
            (( MTR_BATCH_DUPLICATE_COUNT += 1 ))
            continue
        fi
        if (( MTR_BATCH_TARGET_COUNT >= max_targets )); then
            fail "Строка ${line_number}: превышен лимит ${max_targets} целей"
            (( MTR_BATCH_INVALID_COUNT += 1 ))
            continue
        fi

        label="${line/"$token"/}"
        label="$(sed -E 's/^[[:space:]]*[-|:=>]+[[:space:]]*//; s/[[:space:]]*[-|:=>]+[[:space:]]*$//' <<< "$label")"
        label="$(trim_whitespace "$label")"
        label="${label//$'\t'/ }"
        [[ -n "$label" ]] || label="$current_label"
        [[ -n "$label" ]] || label="цель $(( MTR_BATCH_TARGET_COUNT + 1 ))"
        label="$(printf '%s' "$label" | cut -c1-80)"

        seen["$key"]=1
        (( MTR_BATCH_TARGET_COUNT += 1 ))
        printf '%s\t%s\t%s\n' "$label" "$ip" "$port" >> "$output_file"
    done < "$input_file"

    if (( MTR_BATCH_TARGET_COUNT == 0 )); then
        fail "Не найдено ни одной корректной цели для MTR"
        return 1
    fi
    if (( MTR_BATCH_INVALID_COUNT > 0 )); then
        fail "Исправь некорректные строки: ${MTR_BATCH_INVALID_COUNT}"
        return 1
    fi
}

collect_mtr_batch_input() {
    local output_file="$1"
    shift
    local line

    : > "$output_file"
    if (( $# > 0 )); then
        printf '%s\n' "$@" > "$output_file"
    elif [[ ! -t 0 ]]; then
        cat > "$output_file"
    else
        echo -e "${BOLD}${PURPLE}[ ЦЕЛИ TCP-MTR ]${NC}"
        echo "Вставь IPv4:порт по одному на строку. Можно указывать подписи и группы:"
        echo "  95.85.252.203:443 - клиент 1"
        echo "  клиент 5:"
        echo "  82.27.0.247:8443"
        echo "Пустые строки разрешены. Для запуска введи отдельной строкой: ГОТОВО"
        echo
        while IFS= read -r line; do
            line="${line%$'\r'}"
            case "$line" in
                done|DONE|Done|готово|ГОТОВО|Готово|end|END|конец|КОНЕЦ) break ;;
            esac
            printf '%s\n' "$line" >> "$output_file"
        done
    fi

    if [[ ! -s "$output_file" ]]; then
        fail "Список целей пуст"
        return 1
    fi
}

run_mtr_batch_target() {
    local index="$1"
    local label="$2"
    local source_ip="$3"
    local source_interface="$4"
    local target_ip="$5"
    local target_port="$6"
    local cycles="$7"
    local interval="$8"
    local max_hops="$9"
    local timeout_sec="${10}"
    local result_dir="${11}"
    local result_file status_file route_line route_interface route_source rc=0

    printf -v result_file '%s/%03d.txt' "$result_dir" "$index"
    printf -v status_file '%s/%03d.status' "$result_dir" "$index"
    {
        echo "===== ${label} | ${target_ip}:${target_port} ====="
        echo "Источник: ${source_ip} (${source_interface})"
        if ! route_line="$(ip -4 route get "$target_ip" from "$source_ip" 2>&1)"; then
            echo "Маршрут: ошибка: ${route_line}"
            printf '65\n' > "$status_file"
            return 0
        fi
        route_interface="$(awk '{for (i=1; i<=NF; i++) if ($i=="dev") {print $(i+1); exit}}' <<< "$route_line")"
        route_source="$(awk '{for (i=1; i<=NF; i++) if ($i=="from" || $i=="src") {print $(i+1); exit}}' <<< "$route_line")"
        echo "Маршрут: ${route_line}"
        if [[ "$route_interface" != "$source_interface" || ( -n "$route_source" && "$route_source" != "$source_ip" ) ]]; then
            echo "Ошибка: маршрут ушёл не через ${source_ip}/${source_interface}"
            printf '66\n' > "$status_file"
            return 0
        fi
        echo

        if run_bounded_command "$timeout_sec" "${SUDO[@]}" mtr \
            -4 -a "$source_ip" -T -P "$target_port" -c "$cycles" -i "$interval" \
            -m "$max_hops" -r -w -b "$target_ip"; then
            rc=0
        else
            rc=$?
        fi
        echo
        if (( rc == 0 )); then
            echo "Статус: завершено"
        elif (( rc == 124 || rc == 137 )); then
            echo "Статус: таймаут ${timeout_sec}s"
        else
            echo "Статус: mtr завершился с кодом ${rc}"
        fi
        printf '%s\n' "$rc" > "$status_file"
    } > "$result_file" 2>&1
    return 0
}

run_mtr_batch() {
    header
    local requested_source_ip="${KTO_TEST_SOURCE_IP:-}"
    local source_ip source_interface
    local cycles="${KTO_MTR_BATCH_CYCLES:-100}"
    local interval="${KTO_MTR_BATCH_INTERVAL:-0.2}"
    local parallel="${KTO_MTR_BATCH_PARALLEL:-4}"
    local max_hops="${KTO_MTR_BATCH_MAX_HOPS:-30}"
    local timeout_sec="${KTO_MTR_BATCH_TIMEOUT_SEC:-90}"
    local result_dir raw_file targets_file label target_ip target_port
    local index=0 completed=0 failed=0 pid status result_file status_file
    local -a pids=()

    if [[ "$MACHINE_MODE" == "panel" ]]; then
        fail "Пакетный TCP-MTR доступен для node и whitelist."
        return 1
    fi
    [[ "$cycles" =~ ^[0-9]+$ ]] && (( cycles >= 10 && cycles <= 500 )) || cycles=100
    [[ "$parallel" =~ ^[0-9]+$ ]] && (( parallel >= 1 && parallel <= 8 )) || parallel=4
    [[ "$max_hops" =~ ^[0-9]+$ ]] && (( max_hops >= 5 && max_hops <= 64 )) || max_hops=30
    [[ "$timeout_sec" =~ ^[0-9]+$ ]] && (( timeout_sec >= 20 && timeout_sec <= 600 )) || timeout_sec=90
    [[ "$interval" =~ ^(0[.][1-9][0-9]*|[1-9][0-9]*([.][0-9]+)?)$ ]] || interval=0.2

    select_test_source_ipv4 "$requested_source_ip" || return 1
    source_ip="$TEST_SOURCE_IP"
    source_interface="$TEST_SOURCE_INTERFACE"
    need_root
    must "Установка TCP-MTR" apt_install_with_update_if_missing iproute2 mtr-tiny

    result_dir="$(mktemp -d "${TMPDIR:-/tmp}/kto-mtr-batch.XXXXXX")" || {
        fail "Не удалось создать каталог результатов"
        return 1
    }
    chmod 0755 "$result_dir" 2>/dev/null || true
    raw_file="${result_dir}/input.txt"
    targets_file="${result_dir}/targets.tsv"
    if ! collect_mtr_batch_input "$raw_file" "$@"; then
        return 1
    fi
    if ! parse_mtr_batch_targets "$raw_file" "$targets_file"; then
        warn "Исходный ввод сохранён: ${raw_file}"
        return 1
    fi
    (( MTR_BATCH_DUPLICATE_COUNT == 0 )) || warn "Повторяющихся целей пропущено: ${MTR_BATCH_DUPLICATE_COUNT}"

    echo
    echo -e "${BOLD}${PURPLE}[ ПАКЕТНЫЙ TCP-MTR ]${NC}"
    network_test_row "Исходящий IP" "$source_ip"
    network_test_row "Интерфейс" "$source_interface"
    network_test_row "Целей" "$MTR_BATCH_TARGET_COUNT"
    network_test_row "Параллельно" "$parallel"
    network_test_row "Проб на цель" "$cycles"
    network_test_row "Результаты" "$result_dir"
    echo

    while IFS=$'\t' read -r label target_ip target_port; do
        (( index += 1 ))
        stage "[${index}/${MTR_BATCH_TARGET_COUNT}] ${label} | ${target_ip}:${target_port}"
        run_mtr_batch_target "$index" "$label" "$source_ip" "$source_interface" \
            "$target_ip" "$target_port" "$cycles" "$interval" "$max_hops" \
            "$timeout_sec" "$result_dir" &
        pids+=("$!")
        if (( ${#pids[@]} >= parallel )); then
            wait "${pids[0]}" || true
            pids=("${pids[@]:1}")
        fi
    done < "$targets_file"
    for pid in "${pids[@]}"; do
        wait "$pid" || true
    done

    echo
    echo -e "${BOLD}${PURPLE}[ РЕЗУЛЬТАТЫ TCP-MTR ]${NC}"
    for (( index=1; index<=MTR_BATCH_TARGET_COUNT; index++ )); do
        printf -v result_file '%s/%03d.txt' "$result_dir" "$index"
        printf -v status_file '%s/%03d.status' "$result_dir" "$index"
        echo
        if [[ -s "$result_file" ]]; then
            cat "$result_file"
        else
            echo "===== цель ${index} ====="
            echo "Статус: результат не создан"
        fi
        status="$(cat "$status_file" 2>/dev/null || echo 255)"
        if [[ "$status" == 0 ]]; then
            (( completed += 1 ))
        else
            (( failed += 1 ))
        fi
    done

    echo
    echo -e "${BOLD}${PURPLE}[ ИТОГ ]${NC}"
    network_test_row "Завершено" "${completed}/${MTR_BATCH_TARGET_COUNT}" "$([[ $failed -eq 0 ]] && echo ok || echo warn)"
    network_test_row "Файлы" "$result_dir"
    if (( failed > 0 )); then
        warn "Не завершилось целей: ${failed}. Детали сохранены в ${result_dir}"
        return 1
    fi
    ok "TCP-MTR завершён для ${completed} целей"
}

tspu_ip_http_probe() {
    local source_ip="$1"
    local target_ip="$2"
    local scheme="$3"
    local port="$4"
    local label="${scheme^^} ${port}"
    local url="${scheme}://${target_ip}:${port}/"
    local output rc status
    local -a curl_args=(
        -q -4 --noproxy '*' --interface "$source_ip"
        -sS -o /dev/null
        -w 'http=%{http_code} connect=%{time_connect}s tls=%{time_appconnect}s total=%{time_total}s remote=%{remote_ip}'
        --connect-timeout 4 --max-time 8
    )

    if ! command_exists curl; then
        network_test_row "$label" "curl не найден" "skip"
        return 4
    fi
    [[ "$scheme" == "https" ]] && curl_args+=(-k)

    if output="$(curl "${curl_args[@]}" "$url" 2>&1)"; then
        rc=0
    else
        rc=$?
    fi
    output="$(network_test_short "$output")"

    case "$rc" in
        0)
            status="ok"
            ;;
        7)
            status="warn"
            output="rc=7 порт закрыт или соединение отклонено; ${output}"
            ;;
        28)
            status="fail"
            output="rc=28 таймаут; ${output}"
            ;;
        35|52|56)
            status="warn"
            output="rc=${rc} TCP достигнут, протокол не ответил; ${output}"
            ;;
        *)
            status="fail"
            output="rc=${rc} ${output}"
            ;;
    esac
    network_test_row "$label" "$output" "$status"

    case "$rc" in
        0) return 0 ;;
        7|35|52|56) return 2 ;;
        28) return 3 ;;
        *) return 4 ;;
    esac
}

tspu_ip_path_mtu_probe() {
    local source_ip="$1"
    local target_ip="$2"
    local payload found_payload=""
    local -a payloads=(1472 1400 1200)

    if ! command_exists ping; then
        network_test_row "Path MTU" "ping не найден" "skip"
        return 0
    fi

    for payload in "${payloads[@]}"; do
        if run_bounded_command 5 ping -4 -I "$source_ip" -c 1 -W 2 -M do -s "$payload" \
            "$target_ip" >/dev/null 2>&1; then
            found_payload="$payload"
            break
        fi
    done

    if [[ -z "$found_payload" ]]; then
        network_test_row "Path MTU" "не определить: цель может блокировать ICMP" "skip"
    elif (( found_payload == 1472 )); then
        network_test_row "Path MTU" "$(( found_payload + 28 )) B проходит" "ok"
    else
        network_test_row "Path MTU" "не меньше $(( found_payload + 28 )) B; 1500 B не прошёл" "warn"
    fi
}

tspu_ip_trace() {
    local source_ip="$1"
    local target_ip="$2"
    local port="${3:-443}"
    local output rc

    echo
    echo -e "${BOLD}${PURPLE}[ TCP-ТРАССА :${port} ]${NC}"
    if ! command_exists mtr; then
        network_test_row "mtr" "mtr не установлен" "skip"
        return 0
    fi

    if output="$(run_bounded_command 25 "${SUDO[@]}" mtr -4 -n -a "$source_ip" \
        -T -P "$port" -c 5 -m 20 -r -w "$target_ip" 2>&1)"; then
        rc=0
    else
        rc=$?
    fi
    output="$(sed -n '1,22p' <<< "$output")"
    if [[ -n "$output" ]]; then
        printf '%s\n' "$output"
    else
        network_test_row "mtr" "нет вывода" "warn"
    fi
    (( rc == 0 )) || warn "mtr завершился с кодом ${rc}; промежуточные узлы могут не отвечать на probe."
}

run_tspu_ip_test() {
    header
    local requested_source_ip="${1:-}" target_input="${2:-}" target_ip target_port="" target_label
    local target_has_port=0
    local source_ip source_interface route_line route_interface route_source
    local tcp80_rc=4 tcp443_rc=4 tcp_target_rc=4 http_rc=4 https_rc=4 trace_port=443 ping_ok=0
    local tcp_open=0 tcp_reachable=0 tcp_timeout=0 tcp_total=0 rc
    local -a tcp_results=()
    local -a packages=(curl iproute2 iputils-ping python3)

    if [[ "$MACHINE_MODE" == "panel" ]]; then
        fail "Проверка ТСПУ (IP) доступна для node и whitelist."
        return 1
    fi

    select_test_source_ipv4 "$requested_source_ip" || return 1
    source_ip="$TEST_SOURCE_IP"
    source_interface="$TEST_SOURCE_INTERFACE"

    target_input="$(trim_whitespace "$target_input")"
    while ! parse_tspu_ipv4_target "$target_input"; do
        [[ -z "$target_input" ]] || fail "Некорректная цель: ${target_input}. Нужен IPv4 или IPv4:порт."
        target_input="$(trim_whitespace "$(ask_text "Целевой IPv4 или IPv4:порт")")"
    done
    target_ip="$TSPU_TARGET_IP"
    target_port="$TSPU_TARGET_PORT"
    target_has_port="$TSPU_TARGET_HAS_PORT"
    target_label="$target_ip"
    (( target_has_port == 0 )) || target_label+=":${target_port}"

    need_root
    command_exists mtr || packages+=(mtr-tiny)
    must "Установка зависимостей проверки ТСПУ (IP)" \
        apt_install_with_update_if_missing "${packages[@]}"

    NETTEST_SOURCE_IP="$source_ip"
    NETTEST_SOURCE_INTERFACE="$source_interface"
    NETTEST_PING_BAD=0
    NETTEST_WARN=0

    echo -e "${BOLD}${PURPLE}[ ПРОВЕРКА ТСПУ (IP) ]${NC}"
    network_test_row "Исходящий IP" "$source_ip"
    network_test_row "Интерфейс" "$source_interface"
    network_test_row "Целевой IP" "$target_ip"
    (( target_has_port == 0 )) || network_test_row "Целевой порт" "$target_port"

    if ! route_line="$(ip -4 route get "$target_ip" from "$source_ip" 2>&1)"; then
        network_test_row "Маршрут" "$(network_test_short "$route_line")" "fail"
        fail "До ${target_ip} нет маршрута от ${source_ip}"
        return 1
    fi
    route_interface="$(awk '{for (i=1; i<=NF; i++) if ($i=="dev") {print $(i+1); exit}}' <<< "$route_line")"
    route_source="$(awk '{for (i=1; i<=NF; i++) if ($i=="from" || $i=="src") {print $(i+1); exit}}' <<< "$route_line")"
    if [[ "$route_interface" != "$source_interface" || ( -n "$route_source" && "$route_source" != "$source_ip" ) ]]; then
        network_test_row "Маршрут" "$(network_test_short "$route_line")" "fail"
        fail "Маршрут ушёл не через выбранный IP/интерфейс; тест остановлен."
        return 1
    fi
    network_test_row "Маршрут" "$(network_test_short "$route_line")" "ok"

    echo
    echo -e "${BOLD}${PURPLE}[ ДОСТУПНОСТЬ ]${NC}"
    network_test_ping "$target_ip" "$target_ip"
    (( NETTEST_PING_BAD == 0 )) && ping_ok=1

    if (( target_has_port == 1 )); then
        if tspu_ip_tcp_probe "$source_ip" "$target_ip" "$target_port"; then tcp_target_rc=0; else tcp_target_rc=$?; fi
        tcp_results+=("$tcp_target_rc")
        if tspu_ip_http_probe "$source_ip" "$target_ip" http "$target_port"; then http_rc=0; else http_rc=$?; fi
        if tspu_ip_http_probe "$source_ip" "$target_ip" https "$target_port"; then https_rc=0; else https_rc=$?; fi
        trace_port="$target_port"
    else
        if tspu_ip_tcp_probe "$source_ip" "$target_ip" 80; then tcp80_rc=0; else tcp80_rc=$?; fi
        if tspu_ip_tcp_probe "$source_ip" "$target_ip" 443; then tcp443_rc=0; else tcp443_rc=$?; fi
        tcp_results+=("$tcp80_rc" "$tcp443_rc")
        if tspu_ip_http_probe "$source_ip" "$target_ip" http 80; then http_rc=0; else http_rc=$?; fi
        if tspu_ip_http_probe "$source_ip" "$target_ip" https 443; then https_rc=0; else https_rc=$?; fi
    fi
    tspu_ip_path_mtu_probe "$source_ip" "$target_ip"

    if (( target_has_port == 0 && tcp443_rc >= 3 && tcp80_rc < 3 )); then
        trace_port=80
    fi
    tspu_ip_trace "$source_ip" "$target_ip" "$trace_port"

    tcp_total="${#tcp_results[@]}"
    for rc in "${tcp_results[@]}"; do
        case "$rc" in
            0)
                (( tcp_open += 1 ))
                (( tcp_reachable += 1 ))
                ;;
            1|2) (( tcp_reachable += 1 )) ;;
            3) (( tcp_timeout += 1 )) ;;
        esac
    done

    echo
    echo -e "${BOLD}${PURPLE}[ ИТОГ ]${NC}"
    if (( tcp_open > 0 )); then
        network_test_row "Сетевой путь" "открытых TCP-портов: ${tcp_open}/${tcp_total}" "ok"
        (( tcp_timeout == 0 )) || network_test_row "Фильтрация" "TCP-порт уходит в таймаут" "warn"
    elif (( tcp_reachable > 0 )); then
        network_test_row "Сетевой путь" "цель отвечает RST или нестабильно" "warn"
    elif (( ping_ok == 1 )); then
        if (( target_has_port == 1 )); then
            network_test_row "Фильтрация" "ICMP проходит, TCP ${target_port} не отвечает" "warn"
        else
            network_test_row "Фильтрация" "ICMP проходит, TCP 80/443 не отвечает" "warn"
        fi
    else
        if (( target_has_port == 1 )); then
            network_test_row "Сетевой путь" "нет ответа по ICMP и TCP ${target_port}" "fail"
        else
            network_test_row "Сетевой путь" "нет ответа по ICMP и TCP 80/443" "fail"
        fi
    fi

    if (( target_has_port == 1 && tcp_target_rc == 0 && http_rc != 0 && https_rc != 0 )); then
        network_test_row "HTTP(S) ${target_port}" "TCP открыт, прикладной ответ не получен" "warn"
        warn "На порту может быть не HTTP(S) либо сервер требует доменный SNI. Это само по себе не означает блокировку."
    elif (( target_has_port == 0 && tcp443_rc == 0 && https_rc != 0 )); then
        network_test_row "HTTPS" "TCP 443 открыт, но запрос по IP не завершился" "warn"
        warn "Сервер может требовать доменный SNI; это само по себе не означает блокировку."
    elif (( http_rc == 0 || https_rc == 0 )); then
        network_test_row "HTTP(S)" "получен прикладной ответ" "ok"
    fi

    if (( target_has_port == 1 )); then
        echo "tspu-ip source=${source_ip} interface=${source_interface} target=${target_label} tcp=${tcp_target_rc} http=${http_rc} https=${https_rc}" >> "$LOG_FILE" 2>/dev/null || true
    else
        echo "tspu-ip source=${source_ip} interface=${source_interface} target=${target_ip} tcp80=${tcp80_rc} tcp443=${tcp443_rc} http=${http_rc} https=${https_rc}" >> "$LOG_FILE" 2>/dev/null || true
    fi
    warn "Один замер не доказывает ТСПУ. Для сравнения повтори ту же цель с другим исходящим IP."
    ok "Проверка ${source_ip} -> ${target_label} завершена"
}

DPI_RESOLV_SNAPSHOT_DIR=""
DPI_RESOLV_CHANGED=0

dpi_detector_snapshot_resolver() {
    [[ -z "$DPI_RESOLV_SNAPSHOT_DIR" ]] || return 0

    DPI_RESOLV_SNAPSHOT_DIR="$(mktemp -d)"
    if "${SUDO[@]}" test -e "$DPI_RESOLV_CONF_FILE" 2>/dev/null ||
        "${SUDO[@]}" test -L "$DPI_RESOLV_CONF_FILE" 2>/dev/null; then
        if ! "${SUDO[@]}" cp -a "$DPI_RESOLV_CONF_FILE" "${DPI_RESOLV_SNAPSHOT_DIR}/resolv.conf" >> "$LOG_FILE" 2>&1; then
            rm -rf "$DPI_RESOLV_SNAPSHOT_DIR"
            DPI_RESOLV_SNAPSHOT_DIR=""
            fail "Не удалось сохранить текущий /etc/resolv.conf"
            return 1
        fi
        : > "${DPI_RESOLV_SNAPSHOT_DIR}/present"
    else
        : > "${DPI_RESOLV_SNAPSHOT_DIR}/missing"
    fi
}

dpi_detector_restore_resolver() {
    local snapshot_dir="$DPI_RESOLV_SNAPSHOT_DIR" rc=0
    [[ -n "$snapshot_dir" && -d "$snapshot_dir" ]] || return 0

    if (( DPI_RESOLV_CHANGED == 1 )); then
        if ! "${SUDO[@]}" rm -f "$DPI_RESOLV_CONF_FILE" >> "$LOG_FILE" 2>&1; then
            rc=1
        elif [[ -e "${snapshot_dir}/present" ]] &&
            ! "${SUDO[@]}" cp -a "${snapshot_dir}/resolv.conf" "$DPI_RESOLV_CONF_FILE" >> "$LOG_FILE" 2>&1; then
            rc=1
        fi
        if (( rc == 0 )); then
            echo "dpi-detector resolver: original /etc/resolv.conf restored" >> "$LOG_FILE" 2>/dev/null || true
        else
            warn "Не удалось автоматически вернуть исходный /etc/resolv.conf; snapshot: ${snapshot_dir}"
        fi
    fi

    if (( rc == 0 )); then
        rm -rf "$snapshot_dir"
    fi
    DPI_RESOLV_SNAPSHOT_DIR=""
    DPI_RESOLV_CHANGED=0
    return "$rc"
}

dpi_detector_use_resolved_upstream() {
    local upstream="$DPI_RESOLVED_UPSTREAM_FILE"
    "${SUDO[@]}" test -s "$upstream" 2>/dev/null || return 1
    "${SUDO[@]}" awk '
        $1 == "nameserver" && $2 !~ /^127\./ && $2 != "::1" { found = 1 }
        END { exit found ? 0 : 1 }
    ' "$upstream" 2>/dev/null || return 1
    dpi_detector_snapshot_resolver || return 1
    DPI_RESOLV_CHANGED=1
    "${SUDO[@]}" rm -f "$DPI_RESOLV_CONF_FILE" >> "$LOG_FILE" 2>&1 || return 1
    "${SUDO[@]}" ln -s "$upstream" "$DPI_RESOLV_CONF_FILE" >> "$LOG_FILE" 2>&1 || return 1
}

dpi_detector_use_public_resolver() {
    local tmp
    tmp="$(mktemp)"
    cat > "$tmp" <<'EOF'
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 9.9.9.9
options timeout:2 attempts:2 rotate
EOF
    if ! dpi_detector_snapshot_resolver; then
        rm -f "$tmp"
        return 1
    fi
    DPI_RESOLV_CHANGED=1
    if ! "${SUDO[@]}" rm -f "$DPI_RESOLV_CONF_FILE" >> "$LOG_FILE" 2>&1 ||
        ! "${SUDO[@]}" install -m 0644 "$tmp" "$DPI_RESOLV_CONF_FILE" >> "$LOG_FILE" 2>&1; then
        rm -f "$tmp"
        return 1
    fi
    rm -f "$tmp"
}

dpi_detector_dns_diagnostics() {
    local nameservers resolved_state ufw_output
    nameservers="$("${SUDO[@]}" awk '$1 == "nameserver" { print $2 }' "$DPI_RESOLV_CONF_FILE" 2>/dev/null | paste -sd ',' - || true)"
    resolved_state="$(run_systemctl_bounded 3 is-active systemd-resolved 2>/dev/null || true)"
    ufw_output="$("${SUDO[@]}" ufw status verbose 2>/dev/null | awk -F: '/Default:/ { gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit }' || true)"
    echo "dpi-detector dns failure: nameservers=${nameservers:--} resolved=${resolved_state:-unknown} ufw_default=${ufw_output:--}" >> "$LOG_FILE" 2>/dev/null || true
    warn "DNS: ${nameservers:--}; systemd-resolved: ${resolved_state:-unknown}; UFW: ${ufw_output:--}"
}

dpi_detector_prepare_registry_dns() {
    local host="${1:-ghcr.io}"

    dns_host_resolves "$host" && return 0
    warn "DNS не резолвит ${host}. Пробую безопасное временное восстановление."

    if systemd_resolved_available; then
        run_systemctl_bounded 10 restart systemd-resolved >> "$LOG_FILE" 2>&1 || true
        if command_exists resolvectl; then
            run_bounded_command 5 "${SUDO[@]}" resolvectl flush-caches >> "$LOG_FILE" 2>&1 || true
        fi
        if wait_for_dns_host "$host" 4; then
            ok "DNS восстановлен после перезапуска systemd-resolved"
            return 0
        fi

        if dpi_detector_use_resolved_upstream && wait_for_dns_host "$host" 5; then
            warn "Локальный DNS stub 127.0.0.53 недоступен. На время теста включён upstream resolver."
            return 0
        fi
    fi

    if dpi_detector_use_public_resolver && wait_for_dns_host "$host" 6; then
        warn "На время теста включены прямые DNS 1.1.1.1/8.8.8.8. Исходный resolver будет возвращён автоматически."
        return 0
    fi

    dpi_detector_dns_diagnostics
    dpi_detector_restore_resolver || true
    fail "DNS не удалось восстановить для ${host}. Проверь OUTPUT/loopback firewall и доступ к UDP/TCP 53."
    return 1
}

dpi_detector_docker_ready() {
    local deadline
    if run_bounded_command 5 "${SUDO[@]}" docker info >/dev/null 2>&1; then
        return 0
    fi
    command_exists systemctl || {
        fail "Docker daemon недоступен, systemctl не найден"
        return 1
    }

    stage "Запускаю Docker daemon"
    run_systemctl_bounded 20 enable --now docker >> "$LOG_FILE" 2>&1 || true
    deadline=$(( SECONDS + 15 ))
    while (( SECONDS < deadline )); do
        if run_bounded_command 5 "${SUDO[@]}" docker info >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    fail "Docker daemon не отвечает"
    return 1
}

dpi_detector_image_cached() {
    run_bounded_command 10 "${SUDO[@]}" docker image inspect "$DPI_DETECTOR_IMAGE" >/dev/null 2>&1
}

dpi_detector_pull_image() {
    local output_file timeout_sec rc reason
    output_file="$(mktemp)"
    timeout_sec="${KTO_DPI_PULL_TIMEOUT:-180}"
    [[ "$timeout_sec" =~ ^[0-9]+$ && "$timeout_sec" -ge 30 ]] || timeout_sec=180

    stage "Обновляю DPI Detector ${DPI_DETECTOR_IMAGE}"
    if run_bounded_command "$timeout_sec" "${SUDO[@]}" docker pull "$DPI_DETECTOR_IMAGE" 2>&1 |
        tee -a "$LOG_FILE" "$output_file"; then
        rm -f "$output_file"
        return 0
    fi
    rc="${PIPESTATUS[0]}"

    if dpi_detector_image_cached; then
        warn "Registry временно недоступен, использую уже скачанный ${DPI_DETECTOR_IMAGE}."
        echo "dpi-detector pull failed rc=${rc}; cached image selected" >> "$LOG_FILE" 2>/dev/null || true
        rm -f "$output_file"
        return 0
    fi

    reason="ошибка registry или сети"
    if (( rc == 124 )); then
        reason="таймаут загрузки (${timeout_sec}s)"
    elif grep -Eqi 'no space left|insufficient space' "$output_file"; then
        reason="на диске закончилось место"
    elif grep -Eqi 'lookup .*(:53|no such host)|server misbehaving|operation not permitted' "$output_file"; then
        reason="DNS или firewall блокирует резолв registry"
    elif grep -Eqi 'cannot connect to the docker daemon|is the docker daemon running' "$output_file"; then
        reason="Docker daemon недоступен"
    elif grep -Eqi 'TLS handshake timeout|SSL connection timeout|i/o timeout|connection timed out' "$output_file"; then
        reason="таймаут маршрута/TLS до ghcr.io"
    elif grep -Eqi 'unauthorized|denied' "$output_file"; then
        reason="registry отклонил доступ к образу"
    fi
    rm -f "$output_file"
    fail "Не удалось скачать DPI Detector: ${reason}; локального образа нет"
    return 1
}

dpi_detector_prepare_image() {
    ensure_hostname_hosts_entry || return 1

    if ! command_exists docker || ! "${SUDO[@]}" docker compose version >/dev/null 2>&1; then
        dpi_detector_prepare_registry_dns ghcr.io || return 1
    fi
    ensure_docker
    dpi_detector_docker_ready || return 1
    dpi_detector_prepare_registry_dns ghcr.io || return 1
    dpi_detector_pull_image
}

install_dpi_preflight_helper() {
    install_asset_file scripts/kto-dpi-preflight.py "$DPI_PREFLIGHT_HELPER" 0644
}

ensure_dpi_preflight_helper() {
    if "${SUDO[@]}" test -r "$DPI_PREFLIGHT_HELPER" 2>/dev/null &&
        "${SUDO[@]}" grep -Fqx "DPI_PREFLIGHT_BUILD = \"${SCRIPT_BUILD}\"" \
            "$DPI_PREFLIGHT_HELPER" 2>/dev/null; then
        return 0
    fi

    stage "Обновляю preflight целей DPI Detector"
    install_dpi_preflight_helper
}

dpi_detector_export_targets() {
    local output_file="$1"

    if ! run_bounded_command 20 "${SUDO[@]}" docker run --rm \
        --network none \
        --user 65534:65534 \
        --cap-drop ALL \
        --security-opt no-new-privileges:true \
        --read-only \
        --entrypoint cat \
        "$DPI_DETECTOR_IMAGE" /app/tcp16.json > "$output_file" 2>> "$LOG_FILE"; then
        fail "Не удалось получить tcp16.json из ${DPI_DETECTOR_IMAGE}"
        return 1
    fi
    if [[ ! -s "$output_file" ]]; then
        fail "DPI Detector вернул пустой tcp16.json"
        return 1
    fi
    chmod 0644 "$output_file"
}

dpi_detector_probe_targets() {
    local input_file="$1" output_file="$2" uid="$3" container_name="$4"
    local connect_timeout concurrency attempts command_timeout

    connect_timeout="${KTO_DPI_PREFLIGHT_CONNECT_TIMEOUT:-2.0}"
    concurrency="${KTO_DPI_PREFLIGHT_CONCURRENCY:-48}"
    attempts="${KTO_DPI_PREFLIGHT_ATTEMPTS:-1}"
    command_timeout="${KTO_DPI_PREFLIGHT_RUN_TIMEOUT:-60}"
    [[ "$connect_timeout" =~ ^[0-9]+([.][0-9]+)?$ ]] || connect_timeout=2.0
    [[ "$concurrency" =~ ^[0-9]+$ && "$concurrency" -ge 1 && "$concurrency" -le 256 ]] || concurrency=48
    [[ "$attempts" =~ ^[0-9]+$ && "$attempts" -ge 1 && "$attempts" -le 5 ]] || attempts=1
    [[ "$command_timeout" =~ ^[0-9]+$ && "$command_timeout" -ge 15 ]] || command_timeout=60

    if ! run_bounded_command "$command_timeout" "${SUDO[@]}" docker run --rm \
        --name "$container_name" \
        --network host \
        --user "${uid}:${uid}" \
        --cap-drop ALL \
        --security-opt no-new-privileges:true \
        --pids-limit 256 \
        --read-only \
        --tmpfs "/tmp:rw,nosuid,nodev,noexec,size=32m" \
        --env HOME=/tmp \
        --env PYTHONDONTWRITEBYTECODE=1 \
        --volume "${DPI_PREFLIGHT_HELPER}:/opt/kto-dpi-preflight.py:ro" \
        --volume "${input_file}:/opt/kto-tcp16.json:ro" \
        --entrypoint python \
        "$DPI_DETECTOR_IMAGE" /opt/kto-dpi-preflight.py probe \
        --input /opt/kto-tcp16.json \
        --timeout "$connect_timeout" \
        --concurrency "$concurrency" \
        --attempts "$attempts" > "$output_file" 2>> "$LOG_FILE"; then
        "${SUDO[@]}" docker rm -f "$container_name" >/dev/null 2>&1 || true
        return 1
    fi
    [[ -s "$output_file" ]]
}

dpi_detector_combine_targets() {
    local work_dir="$1" summary_file="$2"
    local host_uid host_gid min_kept min_ratio

    host_uid="$(id -u)"
    host_gid="$(id -g)"
    min_kept="${KTO_DPI_PREFLIGHT_MIN_TARGETS:-10}"
    min_ratio="${KTO_DPI_PREFLIGHT_MIN_RATIO:-0.35}"
    [[ "$min_kept" =~ ^[0-9]+$ && "$min_kept" -ge 1 ]] || min_kept=10
    [[ "$min_ratio" =~ ^(0([.][0-9]+)?|1([.]0+)?)$ ]] || min_ratio=0.35

    run_bounded_command 30 "${SUDO[@]}" docker run --rm \
        --network none \
        --user "${host_uid}:${host_gid}" \
        --cap-drop ALL \
        --security-opt no-new-privileges:true \
        --pids-limit 64 \
        --read-only \
        --tmpfs "/tmp:rw,nosuid,nodev,noexec,size=16m" \
        --env HOME=/tmp \
        --env PYTHONDONTWRITEBYTECODE=1 \
        --volume "${DPI_PREFLIGHT_HELPER}:/opt/kto-dpi-preflight.py:ro" \
        --volume "${work_dir}:/work:rw" \
        --entrypoint python \
        "$DPI_DETECTOR_IMAGE" /opt/kto-dpi-preflight.py combine \
        --input /work/tcp16.original.json \
        --selected /work/selected.json \
        --reference /work/reference.json \
        --output /work/tcp16.filtered.json \
        --min-kept "$min_kept" \
        --min-kept-ratio "$min_ratio" > "$summary_file" 2>> "$LOG_FILE"
}

dpi_detector_print_preflight_summary() {
    local summary_file="$1"
    local total kept skipped selected_alive reference_alive differential unverified shown remaining

    total="$(awk -F '\t' '$1 == "TOTAL" { print $2; exit }' "$summary_file")"
    kept="$(awk -F '\t' '$1 == "KEPT" { print $2; exit }' "$summary_file")"
    skipped="$(awk -F '\t' '$1 == "SKIPPED" { print $2; exit }' "$summary_file")"
    selected_alive="$(awk -F '\t' '$1 == "SELECTED_ALIVE" { print $2; exit }' "$summary_file")"
    reference_alive="$(awk -F '\t' '$1 == "REFERENCE_ALIVE" { print $2; exit }' "$summary_file")"
    differential="$(awk -F '\t' '$1 == "DIFFERENTIAL" { print $2; exit }' "$summary_file")"
    unverified="$(awk -F '\t' '$1 == "UNVERIFIED" { print $2; exit }' "$summary_file")"
    if [[ ! "$total" =~ ^[0-9]+$ || ! "$kept" =~ ^[0-9]+$ || ! "$skipped" =~ ^[0-9]+$ ]]; then
        fail "Не удалось прочитать результат preflight DPI Detector"
        return 1
    fi

    echo
    echo -e "${BOLD}[ ПРЕДПРОВЕРКА TCP16 ]${NC}"
    ok "Доступных целей: ${kept}/${total}"
    echo " Выбранный маршрут: ${selected_alive:-0}/${total} TCP-портов"
    echo " Обычный маршрут:   ${reference_alive:-0}/${total} TCP-портов"
    if [[ "${differential:-0}" =~ ^[0-9]+$ ]] && (( differential > 0 )); then
        warn "Недоступны через выбранный IP, но живы через обычный маршрут: ${differential}. Они оставлены в тесте."
    fi
    if [[ "${unverified:-0}" =~ ^[0-9]+$ ]] && (( unverified > 0 )); then
        warn "Недоступны с обоих маршрутов целыми ASN-группами: ${unverified}. Они оставлены как возможная фильтрация."
    fi
    if (( skipped == 0 )); then
        return 0
    fi

    warn "Пропущены отдельные недоступные цели, у которых живы соседи того же ASN: ${skipped}"
    shown=0
    while IFS=$'\t' read -r kind target_id provider ip port selected_reason reference_reason; do
        [[ "$kind" == "SKIP" ]] || continue
        printf ' - %s | %s:%s | %s | %s / %s\n' \
            "$target_id" "$ip" "$port" "$provider" "$selected_reason" "$reference_reason"
        shown=$(( shown + 1 ))
        (( shown >= 8 )) && break
    done < "$summary_file"
    remaining=$(( skipped - shown ))
    (( remaining <= 0 )) || echo " ... и ещё ${remaining}"
}

dpi_detector_prepare_targets() {
    local work_dir="$1" selected_uid="$2" selected_container="$3" reference_container="$4"
    local enabled original_file selected_file reference_file summary_file reference_uid

    DPI_PREFLIGHT_TARGET_FILE=""
    enabled="${KTO_DPI_PREFLIGHT_ENABLED:-1}"
    if [[ "$enabled" == "0" ]]; then
        warn "Preflight целей DPI Detector отключён через KTO_DPI_PREFLIGHT_ENABLED=0."
        return 0
    fi
    [[ "$enabled" == "1" ]] || enabled=1

    ensure_dpi_preflight_helper || return 1
    mkdir -p "$work_dir"
    chmod 0755 "$work_dir"
    original_file="${work_dir}/tcp16.original.json"
    selected_file="${work_dir}/selected.json"
    reference_file="${work_dir}/reference.json"
    summary_file="${work_dir}/summary.tsv"
    reference_uid="$(id -u)"

    dpi_detector_export_targets "$original_file" || return 1
    stage "Проверяю TCP16 через выбранный IP"
    if ! dpi_detector_probe_targets "$original_file" "$selected_file" "$selected_uid" "$selected_container"; then
        fail "Preflight не смог проверить цели через выбранный IP"
        return 1
    fi
    stage "Сверяю TCP16 через обычный маршрут"
    if ! dpi_detector_probe_targets "$original_file" "$reference_file" "$reference_uid" "$reference_container"; then
        fail "Preflight не смог проверить цели через обычный маршрут"
        return 1
    fi
    if ! dpi_detector_combine_targets "$work_dir" "$summary_file"; then
        fail "Доступно слишком мало целей TCP16 или preflight вернул некорректные данные"
        [[ -s "$summary_file" ]] && cat "$summary_file" >&2
        return 1
    fi
    [[ -s "${work_dir}/tcp16.filtered.json" ]] || {
        fail "Preflight не создал итоговый tcp16.json"
        return 1
    }
    dpi_detector_print_preflight_summary "$summary_file" || return 1
    DPI_PREFLIGHT_TARGET_FILE="${work_dir}/tcp16.filtered.json"
}

dpi_detector_policy_slot() {
    local offset uid table priority used_uids rules table_routes
    used_uids="$(ps -e -o uid= 2>/dev/null | awk '{$1=$1; if ($1 != "") print $1}' | sort -u || true)"
    rules="$(ip -4 rule show 2>/dev/null || true)"

    for (( offset = 0; offset < 1000; offset++ )); do
        uid=$(( 61000 + offset ))
        table=$(( 61000 + offset ))
        priority=$(( 21000 + offset ))
        grep -qx "$uid" <<< "$used_uids" && continue
        getent passwd "$uid" >/dev/null 2>&1 && continue
        grep -Eq "^${priority}:" <<< "$rules" && continue
        grep -Eq "(^|[[:space:]])(lookup|table)[[:space:]]+${table}([[:space:]]|$)" <<< "$rules" && continue
        if grep -RqsE "^[[:space:]]*${table}[[:space:]]" /etc/iproute2/rt_tables /etc/iproute2/rt_tables.d 2>/dev/null; then
            continue
        fi
        table_routes="$(ip -4 route show table "$table" 2>/dev/null || true)"
        [[ -z "$table_routes" ]] || continue
        printf '%s\t%s\t%s\n' "$uid" "$table" "$priority"
        return 0
    done
    return 1
}

dpi_detector_prepare_source_policy() {
    local source_ip="$1" interface="$2" uid="$3" table="$4" priority="$5"
    local rule_help route_line route_interface gateway check_line check_interface check_source

    rule_help="$(ip -4 rule help 2>&1 || true)"
    if ! grep -q 'uidrange' <<< "$rule_help"; then
        fail "Этот iproute2 не поддерживает uidrange для безопасного выбора IP"
        return 1
    fi

    route_line="$(ip -4 route get 1.1.1.1 from "$source_ip" 2>/dev/null || true)"
    route_interface="$(awk '{for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}' <<< "$route_line")"
    gateway="$(awk '{for (i=1; i<=NF; i++) if ($i == "via") {print $(i+1); exit}}' <<< "$route_line")"
    if [[ "$route_interface" != "$interface" ]]; then
        fail "Source-route ${source_ip} больше не ведёт через ${interface}"
        return 1
    fi

    if [[ -n "$gateway" ]]; then
        if ! "${SUDO[@]}" ip -4 route add table "$table" default via "$gateway" dev "$interface" \
            onlink src "$source_ip" >> "$LOG_FILE" 2>&1; then
            fail "Не удалось создать временный маршрут ТСПУ через ${source_ip}"
            return 1
        fi
    elif ! "${SUDO[@]}" ip -4 route add table "$table" default dev "$interface" \
        src "$source_ip" >> "$LOG_FILE" 2>&1; then
        fail "Не удалось создать временный маршрут ТСПУ через ${source_ip}"
        return 1
    fi

    if ! "${SUDO[@]}" ip -4 rule add priority "$priority" uidrange "${uid}-${uid}" \
        lookup "$table" >> "$LOG_FILE" 2>&1; then
        "${SUDO[@]}" ip -4 route flush table "$table" >/dev/null 2>&1 || true
        fail "Не удалось закрепить контейнер ТСПУ за ${source_ip}"
        return 1
    fi
    "${SUDO[@]}" ip -4 route flush cache >/dev/null 2>&1 || true

    check_line="$(ip -4 route get 1.1.1.1 uid "$uid" 2>/dev/null || true)"
    check_interface="$(awk '{for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}' <<< "$check_line")"
    check_source="$(awk '{for (i=1; i<=NF; i++) if ($i == "src") {print $(i+1); exit}}' <<< "$check_line")"
    if [[ "$check_interface" != "$interface" || "$check_source" != "$source_ip" ]]; then
        fail "Проверка временного маршрута не прошла: ${check_line:-нет маршрута}"
        return 1
    fi
    echo "dpi-detector policy uid=${uid} table=${table} priority=${priority} route=${check_line}" >> "$LOG_FILE"
}

dpi_detector_cleanup() {
    local container_name="${1:-}" table="${2:-}" priority="${3:-}"
    local extra_container
    shift 3 || true
    if command_exists docker; then
        for extra_container in "$container_name" "$@"; do
            [[ -n "$extra_container" ]] || continue
            "${SUDO[@]}" docker rm -f "$extra_container" >/dev/null 2>&1 || true
        done
    fi
    if [[ -n "$priority" ]]; then
        "${SUDO[@]}" ip -4 rule del priority "$priority" >/dev/null 2>&1 || true
    fi
    if [[ -n "$table" ]]; then
        "${SUDO[@]}" ip -4 route flush table "$table" >/dev/null 2>&1 || true
    fi
    if [[ -n "$priority" || -n "$table" ]]; then
        "${SUDO[@]}" ip -4 route flush cache >/dev/null 2>&1 || true
    fi
}

run_dpi_detector() {
    header
    local requested_source_ip="${1:-}" source_ip source_interface
    local slot uid table priority container_name security_options rc=0
    local preflight_dir preflight_selected_name preflight_reference_name

    if [[ "$MACHINE_MODE" == "panel" ]]; then
        fail "Проверка ТСПУ доступна для node и whitelist."
        return 1
    fi
    need_root
    select_test_source_ipv4 "$requested_source_ip" || return 1
    source_ip="$TEST_SOURCE_IP"
    source_interface="$TEST_SOURCE_INTERFACE"

    if (
        local -a docker_args detector_args
        DPI_RESOLV_SNAPSHOT_DIR=""
        DPI_RESOLV_CHANGED=0
        container_name=""
        preflight_dir=""
        preflight_selected_name=""
        preflight_reference_name=""
        table=""
        priority=""
        trap 'dpi_detector_cleanup "$container_name" "$table" "$priority" "$preflight_selected_name" "$preflight_reference_name"; [[ -z "$preflight_dir" ]] || rm -rf -- "$preflight_dir"; dpi_detector_restore_resolver || true' EXIT
        trap 'exit 130' INT TERM HUP

        dpi_detector_prepare_image || exit 1
        security_options="$(run_bounded_command 5 "${SUDO[@]}" docker info --format '{{join .SecurityOptions ","}}' 2>/dev/null || true)"
        if grep -Eqi 'userns|rootless' <<< "$security_options"; then
            fail "Docker userns/rootless не поддерживается безопасной привязкой проверки ТСПУ"
            exit 1
        fi

        slot="$(dpi_detector_policy_slot 2>/dev/null || true)"
        if [[ -z "$slot" ]]; then
            fail "Не удалось найти свободные UID и routing table для проверки ТСПУ"
            exit 1
        fi
        IFS=$'\t' read -r uid table priority <<< "$slot"
        container_name="kto-dpi-detector-${uid}-$$"
        preflight_selected_name="${container_name}-selected"
        preflight_reference_name="${container_name}-reference"
        preflight_dir="$(mktemp -d)"

        stage "Закрепляю тест за ${source_ip} (${source_interface})"
        dpi_detector_prepare_source_policy "$source_ip" "$source_interface" "$uid" "$table" "$priority" || exit 1
        dpi_detector_prepare_targets "$preflight_dir" "$uid" \
            "$preflight_selected_name" "$preflight_reference_name" || exit 1

        docker_args=(
            run --rm --name "$container_name"
            --network host
            --user "${uid}:${uid}"
            --cap-drop ALL
            --security-opt no-new-privileges:true
            --pids-limit 512
            --read-only
            --tmpfs "/tmp:rw,nosuid,nodev,noexec,size=128m"
            --env HOME=/tmp
            --env PYTHONDONTWRITEBYTECODE=1
            --env "TERM=${TERM:-xterm-256color}"
            --init
        )
        if [[ -n "$DPI_PREFLIGHT_TARGET_FILE" ]]; then
            docker_args+=(--volume "${DPI_PREFLIGHT_TARGET_FILE}:/app/tcp16.json:ro")
        fi
        detector_args=(--batch)
        if [[ -t 0 && -t 1 ]]; then
            docker_args+=(-it)
        else
            detector_args=(-t 123 --batch)
            warn "Терминал не интерактивный: запускаю стандартные тесты 1, 2, 3."
        fi

        stage "Проверка ТСПУ через ${source_ip} (${source_interface})"
        warn "Активный zapret, системный proxy или принудительный WARP может исказить результат."
        "${SUDO[@]}" docker "${docker_args[@]}" "$DPI_DETECTOR_IMAGE" "${detector_args[@]}"
    ); then
        rc=0
    else
        rc=$?
    fi

    if (( rc != 0 )); then
        fail "DPI Detector завершился с кодом ${rc}"
        return "$rc"
    fi
    ok "Проверка ТСПУ завершена, временный контейнер и маршруты удалены"
}

install_additional_ip_manager() {
    install_asset_file scripts/kto-additional-ips.sh "$ADDITIONAL_IP_MANAGER" 0755
}

ensure_additional_ip_manager() {
    if "${SUDO[@]}" test -x "$ADDITIONAL_IP_MANAGER" 2>/dev/null &&
        "${SUDO[@]}" grep -Fqx "ADDITIONAL_IP_BUILD=\"${SCRIPT_BUILD}\"" "$ADDITIONAL_IP_MANAGER" 2>/dev/null; then
        return 0
    fi
    install_additional_ip_manager
}

setup_additional_ips() {
    header
    need_root
    stage "Проверяю дополнительные IP и source routes"
    must "Установка сетевых зависимостей" apt_install_with_update_if_missing curl python3 iproute2 netplan.io procps
    ensure_additional_ip_manager
    "${SUDO[@]}" "$ADDITIONAL_IP_MANAGER" setup
}

optimize_additional_ip_networks() {
    header
    need_root
    stage "Проверяю и восстанавливаю сеть всех IP"
    must "Установка сетевых зависимостей" apt_install_with_update_if_missing curl python3 iproute2 netplan.io procps
    ensure_additional_ip_manager
    "${SUDO[@]}" "$ADDITIONAL_IP_MANAGER" optimize
}

install_remna_egress_manager() {
    install_asset_file scripts/kto-remnawave-egress.sh "$REMNA_EGRESS_MANAGER" 0755
}

ensure_remna_egress_manager() {
    if "${SUDO[@]}" test -x "$REMNA_EGRESS_MANAGER" 2>/dev/null &&
        "${SUDO[@]}" grep -Fqx "REMNA_EGRESS_BUILD=\"${SCRIPT_BUILD}\"" "$REMNA_EGRESS_MANAGER" 2>/dev/null; then
        return 0
    fi
    install_remna_egress_manager
}

configure_remnawave_egress() {
    header
    require_node_mode
    if ! node_profile_includes_reality; then
        fail "Выбор исходящего IP доступен для Reality и Reality + Hysteria2."
        return 1
    fi
    need_root
    must "Установка зависимостей Remnawave egress" apt_install_with_update_if_missing curl jq iproute2 libc-bin
    ensure_remna_api_config
    ensure_remna_egress_manager
    "${SUDO[@]}" env \
        KTO_REMNA_API_URL="$REMNA_API_URL" \
        KTO_REMNA_API_TOKEN="$REMNA_API_TOKEN" \
        KTO_REMNA_API_INSECURE="${KTO_REMNA_API_INSECURE:-0}" \
        KTO_NODE_PROFILE="$NODE_PROFILE" \
        "$REMNA_EGRESS_MANAGER" "${1:-menu}"
}

download_ip_test_script() {
    local url="$1" output_file="$2" source_ip="$3"
    local -a curl_args=(-q -4 --noproxy '*' --interface "$source_ip" -fsSL \
        --connect-timeout 10 --max-time 45 --retry 2 --retry-delay 2 -o "$output_file")
    local -a wget_args=(--no-proxy -4 "--bind-address=${source_ip}" -q -O "$output_file" \
        --timeout=20 --tries=3)

    if command_exists curl && curl "${curl_args[@]}" "$url"; then
        return 0
    fi
    warn "curl не скачал тест через ${source_ip}, пробую wget"
    command_exists wget && wget "${wget_args[@]}" "$url"
}

validate_ip_test_script() {
    local script="$1" label="$2"
    if [[ ! -s "$script" ]] || ! head -n 1 "$script" | grep -Eq '^#!.*(bash|sh)' || ! bash -n "$script"; then
        fail "${label} вернул невалидный Bash-скрипт"
        return 1
    fi
}

ipcheck_place() {
    header
    local source_ip="${1:-}" script
    select_test_source_ipv4 "$source_ip" || return 1
    source_ip="$TEST_SOURCE_IP"
    stage "Проверяю IP.Check.Place через ${source_ip} (${TEST_SOURCE_INTERFACE})"
    script="$(mktemp)"
    if ! download_ip_test_script "https://IP.Check.Place" "$script" "$source_ip" ||
        ! validate_ip_test_script "$script" "IP.Check.Place"; then
        rm -f "$script"
        return 1
    fi
    if env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u all_proxy \
        bash "$script" -4 -i "$source_ip" -l en; then
        :
    else
        warn "IP.Check.Place завершился с нестандартным кодом, вывод выше оставил как есть."
    fi
    rm -f "$script"
    return 0
}

ipcheck_region() {
    header
    local source_ip="${1:-}" script
    select_test_source_ipv4 "$source_ip" || return 1
    source_ip="$TEST_SOURCE_IP"
    stage "Проверяю регион IP через ${source_ip} (${TEST_SOURCE_INTERFACE})"
    script="$(mktemp)"
    if ! download_ip_test_script "https://raw.githubusercontent.com/Davoyan/ipregion/main/ipregion.sh" "$script" "$source_ip" ||
        ! validate_ip_test_script "$script" "Region Check"; then
        rm -f "$script"
        return 1
    fi
    if env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u all_proxy \
        bash "$script" --ipv4 --interface "$source_ip"; then
        :
    else
        warn "Region Check завершился с нестандартным кодом, вывод выше оставил как есть."
    fi
    rm -f "$script"
    return 0
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
    elif [[ "$NODE_PROFILE" == "reality_hysteria2" ]]; then
        stage "Общее поднятие Reality + Hysteria2"
        do_issue_ssl_certificate "$domain"
        do_install_remnawave_node "$secret"
        do_install_selfsteal "$domain"
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

haproxy_tcp_port_owned_by_haproxy() {
    local wanted="$1" listen_ip="${2:-*}"
    listen_ip="$(normalize_haproxy_listen_ip "$listen_ip" 2>/dev/null || true)"
    [[ -n "$listen_ip" ]] || return 1
    command_exists ss || return 1
    "${SUDO[@]}" ss -H -ltnp "( sport = :${wanted} )" 2>/dev/null | awk -v wanted="$wanted" -v wanted_ip="$listen_ip" '
        {
            endpoint = $4
            count = split(endpoint, parts, ":")
            port = parts[count]
            host = endpoint
            sub(/:[^:]*$/, "", host)
            gsub(/^\[/, "", host)
            gsub(/\]$/, "", host)
            wildcard = (host == "" || host == "*" || host == "0.0.0.0" || host == "::")
            address_matches = (wanted_ip == "*" ? wildcard : host == wanted_ip)
            if (port == wanted && address_matches && tolower($0) ~ /haproxy/) found = 1
        }
        END { exit found ? 0 : 1 }
    '
}

haproxy_tcp_port_socket_details() {
    local wanted="$1" listen_ip="${2:-*}"
    listen_ip="$(normalize_haproxy_listen_ip "$listen_ip" 2>/dev/null || true)"
    [[ -n "$listen_ip" ]] || return 1
    command_exists ss || return 1
    "${SUDO[@]}" ss -H -tanp "( sport = :${wanted} )" 2>/dev/null | awk -v wanted="$wanted" -v wanted_ip="$listen_ip" '
        {
            endpoint = $4
            count = split(endpoint, parts, ":")
            port = parts[count]
            host = endpoint
            sub(/:[^:]*$/, "", host)
            gsub(/^\[/, "", host)
            gsub(/\]$/, "", host)
            wildcard = (host == "" || host == "*" || host == "0.0.0.0" || host == "::")
            address_conflicts = (wanted_ip == "*" ? 1 : (wildcard || host == wanted_ip))
            if (port == wanted && address_conflicts) {
                print
                found = 1
            }
        }
        END { exit found ? 0 : 1 }
    '
}

haproxy_tcp_port_has_socket() {
    local wanted="$1" listen_ip="${2:-*}"
    local sockets rc=0
    listen_ip="$(normalize_haproxy_listen_ip "$listen_ip" 2>/dev/null || true)"
    [[ -n "$listen_ip" ]] || return 1
    command_exists ss || return 1
    sockets="$(run_bounded_command 3 "${SUDO[@]}" ss -H -tan "( sport = :${wanted} )" 2>/dev/null)" || rc=$?
    if (( rc != 0 )); then
        printf 'ss timeout/error while checking %s:%s, rc=%s\n' \
            "$listen_ip" "$wanted" "$rc" >> "$LOG_FILE" 2>/dev/null || true
        return 0
    fi
    awk -v wanted="$wanted" -v wanted_ip="$listen_ip" '
            {
                endpoint = $4
                count = split(endpoint, parts, ":")
                port = parts[count]
                host = endpoint
                sub(/:[^:]*$/, "", host)
                gsub(/^\[/, "", host)
                gsub(/\]$/, "", host)
                wildcard = (host == "" || host == "*" || host == "0.0.0.0" || host == "::")
                address_conflicts = (wanted_ip == "*" ? 1 : (wildcard || host == wanted_ip))
                if (port == wanted && address_conflicts) found = 1
            }
            END { exit found ? 0 : 1 }
        ' <<< "$sockets"
}

haproxy_route_ports_are_free() {
    local routes_file="$1" port _target _sni _source _maxconn listen_ip _send_proxy_v2

    while IFS=$'\t' read -r port _target _sni _source _maxconn listen_ip _send_proxy_v2; do
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        listen_ip="$(haproxy_route_listen_ip "$listen_ip")"
        # Owner lookup (-p) is intentionally avoided here. It becomes very
        # expensive when the previous HAProxy worker owns many connections.
        if haproxy_tcp_port_has_socket "$port" "$listen_ip" >/dev/null 2>&1; then
            return 1
        fi
    done < "$routes_file"
    return 0
}

haproxy_service_is_stopped() {
    local service_state active_state="" main_pid="" key value

    service_state="$(run_systemctl_bounded 3 show haproxy -p ActiveState -p MainPID 2>/dev/null || true)"
    while IFS='=' read -r key value; do
        case "$key" in
            ActiveState) active_state="$value" ;;
            MainPID) main_pid="$value" ;;
        esac
    done <<< "$service_state"
    [[ "$main_pid" == "0" ]] || return 1
    [[ "$active_state" == "inactive" || "$active_state" == "failed" ]]
}

wait_for_haproxy_stopped_and_ports_free() {
    local routes_file="$1" max_wait_sec="${2:-5}" deadline

    [[ "$max_wait_sec" =~ ^[0-9]+$ ]] || max_wait_sec=5
    max_wait_sec=$((10#$max_wait_sec))
    (( max_wait_sec >= 1 && max_wait_sec <= 30 )) || max_wait_sec=5
    deadline=$(( SECONDS + max_wait_sec ))

    while :; do
        # Do not dump active HAProxy connection tables while the service is still
        # draining. Busy proxies can have hundreds of thousands of TCP sockets.
        if haproxy_service_is_stopped && haproxy_route_ports_are_free "$routes_file"; then
            return 0
        fi
        (( SECONDS >= deadline )) && break
        sleep 0.25
    done
    return 1
}

kill_stale_haproxy_route_listeners() {
    local routes_file="$1" signal="${2:-KILL}"
    local port _target _sni _source _maxconn listen_ip _send_proxy_v2 endpoint_label details listeners connected
    local foreign pids pid comm foreign_found=0 socket_filter

    while IFS=$'\t' read -r port _target _sni _source _maxconn listen_ip _send_proxy_v2; do
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        listen_ip="$(haproxy_route_listen_ip "$listen_ip")"
        endpoint_label="${listen_ip}:${port}"
        details="$(haproxy_tcp_port_socket_details "$port" "$listen_ip" 2>/dev/null || true)"
        [[ -n "$details" ]] || continue

        listeners="$(printf '%s\n' "$details" | awk 'toupper($1) == "LISTEN"' || true)"
        connected="$(printf '%s\n' "$details" | awk 'toupper($1) != "LISTEN"' || true)"
        foreign="$(printf '%s\n' "$listeners" | grep -vi haproxy || true)"
        if [[ -n "$foreign" ]]; then
            fail "HAProxy listener ${endpoint_label}/tcp занят чужим процессом:"
            printf '%s\n' "$foreign" >&2
            foreign_found=1
            continue
        fi

        if [[ -n "$connected" ]]; then
            warn "Закрываю исходящие TCP-соединения, занявшие ${endpoint_label}/tcp"
            socket_filter="( sport = :${port} )"
            [[ "$listen_ip" == "*" ]] || socket_filter="( src ${listen_ip} and sport = :${port} )"
            "${SUDO[@]}" ss -K state connected "$socket_filter" >> "$LOG_FILE" 2>&1 || true
        fi

        pids="$(printf '%s\n' "$listeners" | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u || true)"
        while IFS= read -r pid; do
            [[ "$pid" =~ ^[0-9]+$ ]] || continue
            comm="$("${SUDO[@]}" cat "/proc/${pid}/comm" 2>/dev/null || true)"
            [[ "$comm" == haproxy* ]] || continue
            warn "Завершаю stale HAProxy PID ${pid}, который держит ${endpoint_label}/tcp"
            "${SUDO[@]}" kill "-${signal}" "$pid" >> "$LOG_FILE" 2>&1 || true
        done <<< "$pids"
    done < "$routes_file"

    (( foreign_found == 0 ))
}

report_haproxy_busy_route_ports() {
    local routes_file="$1" port _target _sni _source _maxconn listen_ip _send_proxy_v2 details

    while IFS=$'\t' read -r port _target _sni _source _maxconn listen_ip _send_proxy_v2; do
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        listen_ip="$(haproxy_route_listen_ip "$listen_ip")"
        details="$(haproxy_tcp_port_socket_details "$port" "$listen_ip" 2>/dev/null || true)"
        if [[ -n "$details" ]]; then
            fail "Listener ${listen_ip}:${port}/tcp всё ещё занят:"
            printf '%s\n' "$details" >&2
        fi
    done < "$routes_file"
}

haproxy_missing_listener_ports() {
    local routes_file="$1"

    # Service state is checked separately, so endpoint verification does not
    # need ss -p. Resolving process owners can scan every FD of a busy HAProxy.
    { haproxy_tcp_listener_endpoints 2>/dev/null || true; } | awk -F '\t' -v routes_file="$routes_file" '
        {
            listeners[$1 SUBSEP $2] = 1
        }
        END {
            while ((getline route < routes_file) > 0) {
                field_count = split(route, fields, "\t")
                route_port = fields[1]
                if (route_port !~ /^[0-9]+$/) continue
                listen_ip = (field_count >= 6 && fields[6] != "" ? fields[6] : "*")
                if (!listeners[listen_ip SUBSEP route_port]) {
                    print listen_ip ":" route_port
                }
            }
            close(routes_file)
        }
    '
    return 0
}

haproxy_tcp_listener_endpoints() {
    command_exists ss || return 1
    "${SUDO[@]}" ss -H -ltn 2>/dev/null | awk '
        {
            endpoint = $4
            count = split(endpoint, parts, ":")
            port = parts[count]
            host = endpoint
            sub(/:[^:]*$/, "", host)
            gsub(/^\[/, "", host)
            gsub(/\]$/, "", host)
            if (host == "" || host == "0.0.0.0" || host == "::") host = "*"
            if (port ~ /^[0-9]+$/ && !seen[host SUBSEP port]++) {
                print host "\t" port
            }
        }
    '
}

wait_for_haproxy_routes() {
    local routes_file="$1"
    local attempts="${KTO_HAPROXY_STARTUP_ATTEMPTS:-20}"
    local max_wait_sec="${KTO_HAPROXY_STARTUP_TIMEOUT_SEC:-5}"
    local attempt missing deadline

    [[ "$attempts" =~ ^[0-9]+$ ]] || attempts=20
    attempts=$((10#$attempts))
    (( attempts >= 1 && attempts <= 120 )) || attempts=20
    [[ "$max_wait_sec" =~ ^[0-9]+$ ]] || max_wait_sec=5
    max_wait_sec=$((10#$max_wait_sec))
    (( max_wait_sec >= 1 && max_wait_sec <= 30 )) || max_wait_sec=5
    deadline=$(( SECONDS + max_wait_sec ))

    for (( attempt = 1; attempt <= attempts; attempt++ )); do
        if run_systemctl_bounded 3 is-active --quiet haproxy 2>/dev/null; then
            missing="$(haproxy_missing_listener_ports "$routes_file")"
            if [[ -z "$missing" ]]; then
                return 0
            fi
        fi
        (( SECONDS >= deadline )) && break
        sleep 0.25
    done

    missing="$(haproxy_missing_listener_ports "$routes_file")"
    missing="${missing//$'\n'/, }"
    if [[ -n "$missing" ]]; then
        warn "HAProxy не слушает настроенные адреса: ${missing}"
    else
        warn "HAProxy не перешёл в active после применения config"
    fi
    return 1
}

start_haproxy_cleanly() {
    local routes_file="$1"

    reserve_haproxy_route_ports "$routes_file" || return 1
    stage "Останавливаю старый HAProxy"
    run_systemctl_bounded 10 --no-block stop haproxy >> "$LOG_FILE" 2>&1 || true
    if ! wait_for_haproxy_stopped_and_ports_free "$routes_file" 5; then
        warn "HAProxy или его порты не освободились за 5 секунд, очищаю зависшие сокеты."
        run_systemctl_bounded 10 kill --kill-who=all --signal=KILL haproxy.service >> "$LOG_FILE" 2>&1 || true
        kill_stale_haproxy_route_listeners "$routes_file" KILL || return 1
        if ! wait_for_haproxy_stopped_and_ports_free "$routes_file" 5; then
            report_haproxy_busy_route_ports "$routes_file"
            return 1
        fi
    fi

    run_systemctl_bounded 10 reset-failed haproxy >> "$LOG_FILE" 2>&1 || true
    stage "Запускаю HAProxy"
    if ! run_systemctl_bounded 10 --no-block start haproxy >> "$LOG_FILE" 2>&1; then
        return 1
    fi
    wait_for_haproxy_routes "$routes_file"
}

print_haproxy_failure_details() {
    local config="${1:-/etc/haproxy/haproxy.cfg}"
    local details

    details="$({
        echo "=== HAProxy service ==="
        run_systemctl_bounded 5 status haproxy --no-pager -l 2>&1 || true
        echo "=== HAProxy journal ==="
        "${SUDO[@]}" journalctl -u haproxy -n 40 --no-pager -o cat 2>&1 || true
        echo "=== HAProxy limits ==="
        run_systemctl_bounded 5 show haproxy -p LimitNOFILE -p LimitNPROC -p MainPID 2>&1 || true
        echo "=== HAProxy capacity ==="
        "${SUDO[@]}" grep -E '^[[:space:]]*(maxconn|maxpipes|nosplice|nbthread)[[:space:]]' "$config" 2>&1 || true
        echo "=== HAProxy listeners ==="
        run_bounded_command 3 "${SUDO[@]}" ss -H -ltn 2>&1 || true
    })"

    printf '\n%s\n' "$details" >> "$LOG_FILE" 2>/dev/null || true
    echo >&2
    printf '%s\n' "$details" | tail -n 60 >&2
}

reload_haproxy_gracefully() {
    local routes_file="${1:-}"

    if run_systemctl_bounded 3 is-active --quiet haproxy 2>/dev/null; then
        stage "Перезагружаю HAProxy"
        if run_systemctl_bounded 15 reload haproxy >> "$LOG_FILE" 2>&1; then
            if [[ -z "$routes_file" ]] || wait_for_haproxy_routes "$routes_file"; then
                ok "HAProxy применён через reload"
                return 0
            fi
            warn "HAProxy reload завершился без рабочих listener-портов, делаю чистый start."
        else
            warn "HAProxy reload не прошёл, делаю чистый start."
        fi
    fi

    if [[ -n "$routes_file" ]] && start_haproxy_cleanly "$routes_file"; then
        ok "HAProxy применён через чистый start"
        return 0
    elif [[ -z "$routes_file" ]] && run_systemctl_bounded 15 restart haproxy >> "$LOG_FILE" 2>&1; then
        ok "HAProxy применён через restart"
        return 0
    fi
    print_haproxy_failure_details
    fail "HAProxy не запустил все настроенные listener-порты"
    return 1
}

canonicalize_haproxy_routes() {
    local routes_file="$1"
    local port target_pool sni source_ip server_maxconn listen_ip send_proxy_v2
    local normalized_target_pool normalized_sni normalized_source_ip normalized_server_maxconn normalized_listen_ip normalized_send_proxy_v2
    local canonical_sni route_line normalized_routes=""

    [[ -s "$routes_file" ]] || return 1
    while IFS=$'\t' read -r port target_pool sni source_ip server_maxconn listen_ip send_proxy_v2; do
        [[ "$port" =~ ^[0-9]+$ ]] || return 1
        port=$((10#$port))
        (( port >= 1 && port <= 65535 )) || return 1
        normalized_target_pool="$(normalize_haproxy_target_pool "$target_pool" 2>/dev/null || true)"
        normalized_sni="$(normalize_haproxy_sni_list "$sni" 2>/dev/null || true)"
        normalized_source_ip="$(normalize_haproxy_source_ip "${source_ip:-default}" 2>/dev/null || true)"
        normalized_server_maxconn="$(normalize_haproxy_server_maxconn "${server_maxconn:-default}" 2>/dev/null || true)"
        normalized_listen_ip="$(normalize_haproxy_listen_ip "${listen_ip:-*}" 2>/dev/null || true)"
        normalized_send_proxy_v2="$(normalize_haproxy_send_proxy_v2 "${send_proxy_v2:-0}" 2>/dev/null || true)"
        [[ -n "$normalized_target_pool" && -n "$normalized_sni" && -n "$normalized_source_ip" && -n "$normalized_server_maxconn" && -n "$normalized_listen_ip" && -n "$normalized_send_proxy_v2" ]] || return 1
        if [[ "$normalized_listen_ip" != "*" ]]; then
            normalized_source_ip="$normalized_listen_ip"
        elif [[ "$normalized_source_ip" != "default" ]]; then
            normalized_listen_ip="$normalized_source_ip"
        fi
        canonical_sni="$(printf '%s\n' "$normalized_sni" | tr ' ' '\n' | awk 'NF' | LC_ALL=C sort -u | paste -sd' ' -)"
        [[ -n "$canonical_sni" ]] || return 1
        printf -v route_line '%s\t%s\t%s\t%s\t%s\t%s\t%s' \
            "$port" "$normalized_target_pool" "$canonical_sni" \
            "$normalized_source_ip" "$normalized_server_maxconn" "$normalized_listen_ip" "$normalized_send_proxy_v2"
        normalized_routes+="${route_line}"$'\n'
    done < "$routes_file"
    [[ -n "$normalized_routes" ]] || return 1
    printf '%s' "$normalized_routes" |
        LC_ALL=C sort -s -t $'\t' -k1,1n -k6,6 -k2,2 -k3,3 -k4,4 -k5,5 -k7,7
}

haproxy_routes_round_trip_equal() {
    local expected_file="$1" parsed_file="$2" expected_normalized parsed_normalized log_file
    local rc=1

    expected_normalized="$(mktemp)"
    parsed_normalized="$(mktemp)"
    log_file="${LOG_FILE:-/tmp/kto-tune.log}"
    if canonicalize_haproxy_routes "$expected_file" > "$expected_normalized" &&
        canonicalize_haproxy_routes "$parsed_file" > "$parsed_normalized"; then
        if cmp -s "$expected_normalized" "$parsed_normalized"; then
            rc=0
        else
            {
                echo "=== HAProxy semantic round-trip mismatch ==="
                diff -u "$expected_normalized" "$parsed_normalized" || true
            } >> "$log_file" 2>/dev/null || true
        fi
    else
        echo "HAProxy semantic round-trip normalization failed" >> "$log_file" 2>/dev/null || true
    fi
    rm -f "$expected_normalized" "$parsed_normalized"
    return "$rc"
}

extract_haproxy_routes() {
    local config="${1:-/etc/haproxy/haproxy.cfg}"
    local raw port target_pool sni source_ip server_maxconn listen_ip send_proxy_v2
    local normalized_target_pool normalized_sni normalized_source_ip normalized_server_maxconn normalized_listen_ip normalized_send_proxy_v2
    local normalized_routes="" route_line

    "${SUDO[@]}" test -s "$config" 2>/dev/null || return 0
    raw="$("${SUDO[@]}" awk '
        $1 == "frontend" {
            section = "frontend"
            name = $2
            if (!(name in frontend_seen)) {
                frontend_order[++frontend_count] = name
                frontend_seen[name] = 1
            }
            next
        }
        $1 == "backend" {
            section = "backend"
            name = $2
            next
        }
        $1 == "global" || $1 == "defaults" || $1 == "listen" {
            section = $1
            name = $2
            next
        }
        section == "frontend" && $1 == "bind" && !(name in frontend_port) {
            address = $2
            split(address, addresses, ",")
            address = addresses[1]
            if (address ~ /^[0-9]+$/) {
                port = address
                listen_ip = "*"
            } else {
                port = address
                sub(/^.*:/, "", port)
                sub(/[^0-9].*$/, "", port)
                listen_ip = address
                sub(/:[^:]*$/, "", listen_ip)
                gsub(/^\[/, "", listen_ip)
                gsub(/\]$/, "", listen_ip)
                if (listen_ip == "" || listen_ip == "0.0.0.0" || listen_ip == "::") listen_ip = "*"
            }
            frontend_port[name] = port
            frontend_listen_ip[name] = listen_ip
            next
        }
        section == "frontend" && $1 == "#" && $2 == "kto-sni-mode" && $3 == "any" {
            frontend_sni[name] = "any"
            next
        }
        section == "frontend" && $1 == "acl" && $2 == "allowed_sni" && $3 == "req.ssl_sni" {
            suffix_match = 0
            for (i = 1; i <= NF; i++) {
                if ($i == "-m" && $(i + 1) == "end") suffix_match = 1
            }
            for (i = 1; i <= NF; i++) {
                if ($i == "-i") {
                    for (j = i + 1; j <= NF; j++) {
                        if ($j ~ /^#/) break
                        value = $j
                        if (suffix_match && value ~ /^\./) value = "*" value
                        frontend_sni[name] = frontend_sni[name] (frontend_sni[name] == "" ? "" : " ") value
                    }
                    break
                }
            }
            next
        }
        section == "frontend" && $1 == "default_backend" {
            frontend_backend[name] = $2
            next
        }
        section == "backend" && $1 == "#" && $2 == "kto-server-maxconn" {
            backend_declared_maxconn[name] = $3
            next
        }
        section == "backend" && $1 == "server" {
            target = $3
            source = "default"
            maxconn = "default"
            proxy_v2 = "0"
            for (i = 4; i <= NF; i++) {
                if ($i == "source" && (i + 1) <= NF) {
                    source = $(i + 1)
                } else if ($i == "maxconn" && (i + 1) <= NF) {
                    maxconn = $(i + 1)
                } else if ($i == "send-proxy-v2") {
                    proxy_v2 = "1"
                }
            }
            if (!(name in backend_target)) {
                backend_target[name] = target
                backend_source[name] = source
                backend_maxconn[name] = maxconn
                backend_proxy_v2[name] = proxy_v2
            } else {
                backend_target[name] = backend_target[name] "," target
                if (backend_source[name] != source || backend_maxconn[name] != maxconn || backend_proxy_v2[name] != proxy_v2) {
                    backend_inconsistent[name] = 1
                }
            }
            next
        }
        END {
            for (i = 1; i <= frontend_count; i++) {
                frontend = frontend_order[i]
                backend = frontend_backend[frontend]
                if (frontend_port[frontend] != "" && frontend_sni[frontend] != "" &&
                    backend != "" && backend_target[backend] != "" && backend_inconsistent[backend]) {
                    exit 2
                }
            }
            for (i = 1; i <= frontend_count; i++) {
                frontend = frontend_order[i]
                backend = frontend_backend[frontend]
                if (frontend_port[frontend] != "" && frontend_sni[frontend] != "" &&
                    backend_target[backend] != "" && !backend_inconsistent[backend]) {
                    source = backend_source[backend]
                    if (source == "") source = "default"
                    maxconn = backend_declared_maxconn[backend]
                    if (maxconn == "") maxconn = backend_maxconn[backend]
                    if (maxconn == "") maxconn = "default"
                    proxy_v2 = backend_proxy_v2[backend]
                    if (proxy_v2 == "") proxy_v2 = "0"
                    listen_ip = frontend_listen_ip[frontend]
                    if (listen_ip == "") listen_ip = "*"
                    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", frontend_port[frontend], backend_target[backend], frontend_sni[frontend], source, maxconn, listen_ip, proxy_v2
                }
            }
        }
    ' "$config" 2>/dev/null || true)"

    while IFS=$'\t' read -r port target_pool sni source_ip server_maxconn listen_ip send_proxy_v2; do
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        port=$((10#$port))
        (( port >= 1 && port <= 65535 )) || continue
        normalized_target_pool="$(normalize_haproxy_target_pool "$target_pool" 2>/dev/null || true)"
        normalized_sni="$(normalize_haproxy_sni_list "$sni" 2>/dev/null || true)"
        normalized_source_ip="$(normalize_haproxy_source_ip "${source_ip:-default}" 2>/dev/null || true)"
        normalized_server_maxconn="$(normalize_haproxy_server_maxconn "${server_maxconn:-default}" 2>/dev/null || true)"
        normalized_listen_ip="$(normalize_haproxy_listen_ip "${listen_ip:-*}" 2>/dev/null || true)"
        normalized_send_proxy_v2="$(normalize_haproxy_send_proxy_v2 "${send_proxy_v2:-0}" 2>/dev/null || true)"
        [[ -n "$normalized_target_pool" && -n "$normalized_sni" && -n "$normalized_source_ip" && -n "$normalized_server_maxconn" && -n "$normalized_listen_ip" && -n "$normalized_send_proxy_v2" ]] || return 0
        route_line="$(print_haproxy_route "$port" "$normalized_target_pool" "$normalized_sni" \
            "$normalized_source_ip" "$normalized_server_maxconn" "$normalized_listen_ip" "$normalized_send_proxy_v2")" || return 0
        normalized_routes+="${route_line}"$'\n'
    done <<< "$raw"
    [[ -n "$normalized_routes" ]] || return 0
    printf '%s' "$normalized_routes" | sort -s -t $'\t' -k1,1n
}

haproxy_remote_report_json() {
    local routes_file

    command_exists jq || {
        echo '[]'
        return 1
    }
    routes_file="$(mktemp)"
    extract_haproxy_routes > "$routes_file"
    if [[ ! -s "$routes_file" ]]; then
        rm -f "$routes_file"
        echo '[]'
        return 0
    fi
    jq -Rn '
        [inputs
        | select(length > 0)
        | split("\t")
        | {
            port: (.[0] | tonumber),
            targets: (.[1] | split(",") | map(select(length > 0))),
            sni: (.[2] | split(" ") | map(select(length > 0)) | sort),
            source_ip: (.[3] // "default"),
            server_maxconn: ((.[4] // "auto") | if test("^[0-9]+$") then tonumber else "auto" end),
            listen_ip: (.[5] // "*"),
            send_proxy_v2: ((.[6] // "0") == "1")
          }]
    ' < "$routes_file"
    rm -f "$routes_file"
}

haproxy_remote_apply_json() {
    local input_file routes_file previous_routes_file canonical_current canonical_wanted
    local port target_pool sni source_ip server_maxconn listen_ip send_proxy_v2 normalized route_count target_count sni_count

    command_exists jq || {
        fail "jq не найден: удалённое управление HAProxy недоступно"
        return 1
    }
    need_root
    input_file="$(mktemp)"
    routes_file="$(mktemp)"
    previous_routes_file="$(mktemp)"
    canonical_current="$(mktemp)"
    canonical_wanted="$(mktemp)"
    cat > "$input_file"

    if "${SUDO[@]}" test -s "$HAPROXY_CONFIG_FILE" 2>/dev/null &&
        ! "${SUDO[@]}" grep -Fq '# Managed by kto. Edit routes through the HAProxy menu.' "$HAPROXY_CONFIG_FILE" 2>/dev/null; then
        rm -f "$input_file" "$routes_file" "$previous_routes_file" "$canonical_current" "$canonical_wanted"
        fail "Текущий HAProxy config не управляется kto; удалённая перезапись заблокирована"
        return 1
    fi

    if ! jq -e '
        type == "array" and
        length >= 1 and length <= 128 and
        all(.[];
            type == "object" and
            ((.targets | type) == "array") and (.targets | length >= 1 and length <= 64) and
            ((.sni | type) == "array") and (.sni | length <= 64) and
            ((has("send_proxy_v2") | not) or ((.send_proxy_v2 | type) == "boolean"))
        )
    ' "$input_file" >/dev/null 2>&1; then
        rm -f "$input_file" "$routes_file" "$previous_routes_file" "$canonical_current" "$canonical_wanted"
        fail "Collector прислал некорректный список HAProxy-маршрутов"
        return 1
    fi

    while IFS=$'\t' read -r port target_pool sni source_ip server_maxconn listen_ip send_proxy_v2; do
        [[ "$port" =~ ^[0-9]+$ ]] || {
            rm -f "$input_file" "$routes_file" "$previous_routes_file" "$canonical_current" "$canonical_wanted"
            fail "Некорректный входной HAProxy-порт"
            return 1
        }
        port=$((10#$port))
        (( port >= 1 && port <= 65535 )) || {
            rm -f "$input_file" "$routes_file" "$previous_routes_file" "$canonical_current" "$canonical_wanted"
            fail "HAProxy-порт вне диапазона: $port"
            return 1
        }
        normalized="$(normalize_haproxy_target_pool "$target_pool" 2>/dev/null || true)"
        [[ -n "$normalized" ]] || {
            rm -f "$input_file" "$routes_file" "$previous_routes_file" "$canonical_current" "$canonical_wanted"
            fail "Некорректный backend у ${listen_ip:-*}:${port}"
            return 1
        }
        target_pool="$normalized"
        target_count="$(haproxy_target_pool_count "$target_pool" 2>/dev/null || echo 0)"
        (( target_count >= 1 && target_count <= 64 )) || {
            rm -f "$input_file" "$routes_file" "$previous_routes_file" "$canonical_current" "$canonical_wanted"
            fail "Слишком большой backend-пул у ${listen_ip:-*}:${port}"
            return 1
        }
        sni="$(normalize_haproxy_sni_list "$sni" 2>/dev/null || true)"
        [[ -n "$sni" ]] || {
            rm -f "$input_file" "$routes_file" "$previous_routes_file" "$canonical_current" "$canonical_wanted"
            fail "Некорректный SNI у ${listen_ip:-*}:${port}"
            return 1
        }
        sni_count="$(tr ' ' '\n' <<< "$sni" | awk 'NF { count++ } END { print count + 0 }')"
        (( sni_count >= 1 && sni_count <= 64 )) || {
            rm -f "$input_file" "$routes_file" "$previous_routes_file" "$canonical_current" "$canonical_wanted"
            fail "Слишком большой SNI allow-list у ${listen_ip:-*}:${port}"
            return 1
        }
        source_ip="$(canonicalize_haproxy_runtime_source_ip "${source_ip:-default}" 2>/dev/null || true)"
        server_maxconn="$(normalize_haproxy_server_maxconn "${server_maxconn:-default}" 2>/dev/null || true)"
        listen_ip="$(haproxy_route_ip_for_source "$source_ip" 2>/dev/null || true)"
        send_proxy_v2="$(normalize_haproxy_send_proxy_v2 "${send_proxy_v2:-0}" 2>/dev/null || true)"
        [[ -n "$source_ip" && -n "$server_maxconn" && -n "$listen_ip" && -n "$send_proxy_v2" ]] || {
            rm -f "$input_file" "$routes_file" "$previous_routes_file" "$canonical_current" "$canonical_wanted"
            fail "Некорректные параметры HAProxy-маршрута"
            return 1
        }
        if [[ -z "$listen_ip" ]]; then
            rm -f "$input_file" "$routes_file" "$previous_routes_file" "$canonical_current" "$canonical_wanted"
            fail "Для выходного IP ${source_ip} нет рабочего локального source-route"
            return 1
        fi
        print_haproxy_route "$port" "$target_pool" "$sni" "$source_ip" "$server_maxconn" "$listen_ip" "$send_proxy_v2" >> "$routes_file"
    done < <(jq -r '
        .[]
        | [
            (.port // "" | tostring),
            ((.targets // []) | map(tostring) | join(",")),
            ((.sni // []) | map(tostring) | if length == 0 then "any" else join(" ") end),
            (.source_ip // "default" | tostring),
            (.server_maxconn // "default" | tostring),
            (.listen_ip // "*" | tostring),
            ((.send_proxy_v2 // false) | if . then "1" else "0" end)
          ]
        | @tsv
    ' "$input_file")

    route_count="$(haproxy_route_count "$routes_file")"
    if (( route_count < 1 || route_count > 128 )) || ! canonicalize_haproxy_routes "$routes_file" > "$canonical_wanted"; then
        rm -f "$input_file" "$routes_file" "$previous_routes_file" "$canonical_current" "$canonical_wanted"
        fail "Семантическая проверка HAProxy-маршрутов не прошла"
        return 1
    fi

    extract_haproxy_routes > "$previous_routes_file"
    if [[ -s "$previous_routes_file" ]] && canonicalize_haproxy_routes "$previous_routes_file" > "$canonical_current" &&
        cmp -s "$canonical_current" "$canonical_wanted"; then
        rm -f "$input_file" "$routes_file" "$previous_routes_file" "$canonical_current" "$canonical_wanted"
        printf '{"ok":true,"changed":false,"routes":%s}\n' "$route_count"
        return 0
    fi

    # Route and bandwidth state are reconciled once below. Running the generic
    # post-apply pass here used to rebuild every tc filter before cleanup.
    if ! apply_haproxy_routes_config "$routes_file" 1; then
        rm -f "$input_file" "$routes_file" "$previous_routes_file" "$canonical_current" "$canonical_wanted"
        return 1
    fi
    sync_haproxy_firewall "$routes_file" "$previous_routes_file"
    reconcile_haproxy_bandwidth_after_route_change "$routes_file" "$previous_routes_file" || true

    rm -f "$input_file" "$routes_file" "$previous_routes_file" "$canonical_current" "$canonical_wanted"
    printf '{"ok":true,"changed":true,"routes":%s}\n' "$route_count"
}

haproxy_bandwidth_remote_report_json() {
    local limits_file

    command_exists jq || {
        echo '[]'
        return 1
    }
    limits_file="$(mktemp)"
    if ! load_haproxy_bandwidth_config "$limits_file"; then
        rm -f "$limits_file"
        echo '[]'
        return 1
    fi
    jq -Rn '
        [inputs
        | select(length > 0)
        | split("\t")
        | {ip: .[0], rate_mbit: (.[1] | tonumber)}]
        | sort_by(.ip | split(".") | map(tonumber))
    ' < "$limits_file"
    rm -f "$limits_file"
}

haproxy_bandwidth_remote_apply_json() {
    local input_file previous_file next_file had_config=0 ip rate extra limit_count
    local -A seen=()

    command_exists jq || {
        fail "jq не найден: удалённое управление скоростью HAProxy недоступно"
        return 1
    }
    need_root
    input_file="$(mktemp)"
    previous_file="$(mktemp)"
    next_file="$(mktemp)"
    cat > "$input_file"

    if ! jq -e '
        type == "array" and length <= 64 and
        all(.[];
            type == "object" and
            ((.ip | type) == "string") and
            ((.rate_mbit | type) == "number") and
            (.rate_mbit == (.rate_mbit | floor)) and
            (.rate_mbit >= 1 and .rate_mbit <= 100000)
        )
    ' "$input_file" >/dev/null 2>&1; then
        rm -f "$input_file" "$previous_file" "$next_file"
        fail "Collector прислал некорректные лимиты скорости HAProxy"
        return 1
    fi

    : > "$next_file"
    while IFS=$'\t' read -r ip rate extra; do
        if [[ -n "${extra:-}" ]] || ! validate_ipv4 "$ip" || ! validate_haproxy_bandwidth_rate "$rate"; then
            rm -f "$input_file" "$previous_file" "$next_file"
            fail "Некорректный лимит скорости для ${ip:-пустого IP}"
            return 1
        fi
        if [[ -n "${seen[$ip]+x}" ]]; then
            rm -f "$input_file" "$previous_file" "$next_file"
            fail "Для ${ip} прислано несколько лимитов скорости"
            return 1
        fi
        if ! haproxy_input_ip_available "$ip"; then
            rm -f "$input_file" "$previous_file" "$next_file"
            fail "Входной IP ${ip} не найден на локальных интерфейсах"
            return 1
        fi
        rate=$((10#$rate))
        seen[$ip]="$rate"
        printf '%s\t%s\n' "$ip" "$rate" >> "$next_file"
    done < <(jq -r '.[] | [(.ip | tostring), (.rate_mbit | tostring)] | @tsv' "$input_file")
    sort -t $'\t' -k1,1V -o "$next_file" "$next_file"
    limit_count="$(awk 'NF { count++ } END { print count + 0 }' "$next_file")"

    if ! "${SUDO[@]}" test -s "$HAPROXY_CONFIG_FILE" 2>/dev/null; then
        rm -f "$input_file" "$previous_file" "$next_file"
        fail "HAProxy ещё не настроен"
        return 1
    fi
    ensure_haproxy_bandwidth_manager || {
        rm -f "$input_file" "$previous_file" "$next_file"
        return 1
    }
    "${SUDO[@]}" test -e "$HAPROXY_BANDWIDTH_CONFIG" 2>/dev/null && had_config=1
    if ! load_haproxy_bandwidth_config "$previous_file"; then
        rm -f "$input_file" "$previous_file" "$next_file"
        return 1
    fi
    if cmp -s "$previous_file" "$next_file"; then
        rm -f "$input_file" "$previous_file" "$next_file"
        printf '{"ok":true,"changed":false,"limits":%s}\n' "$limit_count"
        return 0
    fi
    if ! commit_haproxy_bandwidth_config "$previous_file" "$next_file" "$had_config"; then
        rm -f "$input_file" "$previous_file" "$next_file"
        return 1
    fi
    rm -f "$input_file" "$previous_file" "$next_file"
    printf '{"ok":true,"changed":true,"limits":%s}\n' "$limit_count"
}

extract_haproxy_backend_target() {
    extract_haproxy_routes | awk -F '\t' 'NR == 1 { split($2, targets, ","); print targets[1]; exit }'
}

extract_haproxy_backend_ip() {
    extract_haproxy_backend_target | awk -F : 'NR == 1 { print $1; exit }'
}

extract_haproxy_allowed_sni() {
    extract_haproxy_routes | awk -F '\t' 'NR == 1 { print $3; exit }'
}

haproxy_route_file_has_port() {
    local routes_file="$1" wanted="$2"
    awk -F '\t' -v wanted="$wanted" '$1 == wanted { found = 1 } END { exit found ? 0 : 1 }' "$routes_file"
}

haproxy_route_file_has_endpoint() {
    local routes_file="$1" wanted_port="$2" wanted_ip
    wanted_ip="$(normalize_haproxy_listen_ip "${3:-*}" 2>/dev/null || true)"
    [[ -n "$wanted_ip" ]] || return 1
    awk -F '\t' -v wanted_port="$wanted_port" -v wanted_ip="$wanted_ip" '
        {
            listen_ip = ($6 == "" ? "*" : $6)
            if ($1 == wanted_port && listen_ip == wanted_ip) found = 1
        }
        END { exit found ? 0 : 1 }
    ' "$routes_file"
}

haproxy_route_file_conflicts_endpoint() {
    local routes_file="$1" wanted_port="$2" wanted_ip
    wanted_ip="$(normalize_haproxy_listen_ip "${3:-*}" 2>/dev/null || true)"
    [[ -n "$wanted_ip" ]] || return 1
    awk -F '\t' -v wanted_port="$wanted_port" -v wanted_ip="$wanted_ip" '
        {
            listen_ip = ($6 == "" ? "*" : $6)
            if ($1 == wanted_port && (wanted_ip == "*" || listen_ip == "*" || listen_ip == wanted_ip)) found = 1
        }
        END { exit found ? 0 : 1 }
    ' "$routes_file"
}

haproxy_route_count() {
    awk -F '\t' 'NF >= 3 { count++ } END { print count + 0 }' "$1"
}

haproxy_route_ports() {
    local routes_file="$1"
    awk -F '\t' '$1 ~ /^[0-9]+$/ { print $1 }' "$routes_file" 2>/dev/null |
        LC_ALL=C sort -n -u
}

haproxy_route_port_sets_equal() {
    local current_routes="$1" previous_routes="$2"
    cmp -s \
        <(haproxy_route_ports "$current_routes") \
        <(haproxy_route_ports "$previous_routes")
}

reserved_port_list_contains() {
    local list="${1//[[:space:]]/}" wanted="$2" item first last
    local -a entries=()
    local IFS=','

    [[ "$wanted" =~ ^[0-9]+$ ]] || return 1
    wanted=$((10#$wanted))
    read -r -a entries <<< "$list"
    for item in "${entries[@]}"; do
        if [[ "$item" =~ ^[0-9]+$ ]]; then
            (( wanted == 10#$item )) && return 0
        elif [[ "$item" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            first=$((10#${BASH_REMATCH[1]}))
            last=$((10#${BASH_REMATCH[2]}))
            (( wanted >= first && wanted <= last )) && return 0
        fi
    done
    return 1
}

merge_reserved_port_list() {
    local list="${1//[[:space:]]/}" port="$2"
    if reserved_port_list_contains "$list" "$port"; then
        printf '%s\n' "$list"
    elif [[ -n "$list" ]]; then
        printf '%s,%s\n' "$list" "$port"
    else
        printf '%s\n' "$port"
    fi
}

reserve_haproxy_route_ports() {
    local routes_file="$1" current merged port desired_line changed=0
    command_exists sysctl || {
        fail "sysctl не найден: не могу зарезервировать HAProxy-порты"
        return 1
    }

    current="$("${SUDO[@]}" sysctl -n net.ipv4.ip_local_reserved_ports 2>/dev/null || true)"
    current="${current//[[:space:]]/}"
    merged="$current"
    while IFS=$'\t' read -r port _; do
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        if ! reserved_port_list_contains "$merged" "$port"; then
            merged="$(merge_reserved_port_list "$merged" "$port")"
            changed=1
        fi
    done < "$routes_file"
    [[ -n "$merged" ]] || return 0

    desired_line="net.ipv4.ip_local_reserved_ports = ${merged}"
    if ! root_file_has_line "$HAPROXY_RESERVED_PORTS_SYSCTL_CONF" "$desired_line"; then
        write_root_file "$HAPROXY_RESERVED_PORTS_SYSCTL_CONF" <<EOF
# Managed by kto. Existing reservations are preserved when HAProxy routes change.
${desired_line}
EOF
    fi
    if (( changed == 1 )); then
        if ! "${SUDO[@]}" sysctl -w "net.ipv4.ip_local_reserved_ports=${merged}" >> "$LOG_FILE" 2>&1; then
            fail "Не удалось зарезервировать HAProxy-порты: ${merged}"
            return 1
        fi
        ok "Зарезервированы локальные порты HAProxy: ${merged}"
    fi
}

haproxy_nofile_limit() {
    local requested="${KTO_HAPROXY_NOFILE_LIMIT:-1048576}"
    local kernel_max

    if [[ ! "$requested" =~ ^[0-9]+$ ]]; then
        requested=1048576
    else
        requested=$((10#$requested))
        (( requested >= 8192 )) || requested=1048576
    fi

    kernel_max="$(cat /proc/sys/fs/nr_open 2>/dev/null || true)"
    if [[ "$kernel_max" =~ ^[0-9]+$ ]]; then
        kernel_max=$((10#$kernel_max))
        if (( kernel_max >= 8192 && requested > kernel_max )); then
            requested="$kernel_max"
        fi
    fi
    echo "$requested"
}

recommended_haproxy_maxconn() {
    local override="${KTO_HAPROXY_MAXCONN:-}"
    local total_mb maxconn nofile_limit fds_per_connection fd_reserve fd_cap
    local cpus per_cpu cpu_cap
    local conntrack_max conntrack_cap

    if [[ "$override" =~ ^[0-9]+$ ]]; then
        maxconn=$(( 10#$override ))
        (( maxconn >= 1000 && maxconn <= 10000000 )) || maxconn=0
    else
        maxconn=0
    fi

    if (( maxconn == 0 )); then
        total_mb="$(memory_total_mb)"
        [[ "$total_mb" =~ ^[0-9]+$ ]] || total_mb=0
        (( total_mb > 0 )) || total_mb=2048
        maxconn=$(( total_mb * 16 ))

        cpus="$(cpu_count)"
        [[ "$cpus" =~ ^[0-9]+$ ]] || cpus=1
        cpus=$((10#$cpus))
        (( cpus >= 1 )) || cpus=1
        per_cpu="${KTO_HAPROXY_CONNECTIONS_PER_CPU:-$HAPROXY_CONNECTIONS_PER_CPU_DEFAULT}"
        [[ "$per_cpu" =~ ^[0-9]+$ ]] || per_cpu="$HAPROXY_CONNECTIONS_PER_CPU_DEFAULT"
        per_cpu=$((10#$per_cpu))
        if (( per_cpu < 500 || per_cpu > 10000 )); then
            per_cpu="$HAPROXY_CONNECTIONS_PER_CPU_DEFAULT"
        fi
        cpu_cap=$(( cpus * per_cpu ))
        (( maxconn <= cpu_cap )) || maxconn="$cpu_cap"
    fi
    # This is the intended operating range. Hard descriptor and conntrack caps
    # below may still lower it when the host cannot safely sustain 100k.
    (( maxconn < HAPROXY_GLOBAL_MIN_MAXCONN_DEFAULT )) && maxconn="$HAPROXY_GLOBAL_MIN_MAXCONN_DEFAULT"
    (( maxconn > HAPROXY_GLOBAL_MAX_MAXCONN_DEFAULT )) && maxconn="$HAPROXY_GLOBAL_MAX_MAXCONN_DEFAULT"

    nofile_limit="$(haproxy_nofile_limit)"
    fds_per_connection="${KTO_HAPROXY_FDS_PER_CONNECTION:-3}"
    [[ "$fds_per_connection" =~ ^[0-9]+$ ]] || fds_per_connection=3
    fds_per_connection=$((10#$fds_per_connection))
    (( fds_per_connection >= 2 && fds_per_connection <= 8 )) || fds_per_connection=3

    fd_reserve="${KTO_HAPROXY_FD_RESERVE:-8192}"
    [[ "$fd_reserve" =~ ^[0-9]+$ ]] || fd_reserve=8192
    fd_reserve=$((10#$fd_reserve))
    if (( fd_reserve < 1024 || fd_reserve >= nofile_limit / 2 )); then
        fd_reserve=$(( nofile_limit / 16 ))
    fi

    # splice-* can make HAProxy reserve roughly three descriptors per connection.
    fd_cap=$(( (nofile_limit - fd_reserve) / fds_per_connection ))
    if (( fd_cap >= 1000 )); then
        fd_cap=$(( fd_cap / 1000 * 1000 ))
    fi
    (( fd_cap >= 1000 )) || fd_cap=1000
    (( maxconn <= fd_cap )) || maxconn="$fd_cap"

    conntrack_max="$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo 0)"
    if [[ "$conntrack_max" =~ ^[0-9]+$ ]] && (( conntrack_max >= 65536 )); then
        # A proxied TCP session normally occupies a client-side and a backend-side
        # conntrack entry. Keep another 25% of the table free for host traffic.
        conntrack_cap=$(( conntrack_max * 3 / 8 ))
        (( conntrack_cap >= 1000 )) && conntrack_cap=$(( conntrack_cap / 1000 * 1000 ))
        (( conntrack_cap >= 1000 )) || conntrack_cap=1000
        (( maxconn <= conntrack_cap )) || maxconn="$conntrack_cap"
    fi
    if (( maxconn >= 1000 )); then
        maxconn=$(( maxconn / 1000 * 1000 ))
    fi
    (( maxconn >= 1000 )) || maxconn=1000
    echo "$maxconn"
}

haproxy_pool_server_maxconn() {
    local global_maxconn="${1:-0}" target_count="${2:-0}" ceiling="${3:-$HAPROXY_BACKEND_MAXCONN}"

    [[ "$global_maxconn" =~ ^[0-9]+$ ]] || return 1
    [[ "$target_count" =~ ^[0-9]+$ ]] || return 1
    global_maxconn=$((10#$global_maxconn))
    target_count=$((10#$target_count))
    (( global_maxconn >= 1 && target_count >= 1 )) || return 1

    normalize_haproxy_server_maxconn "$ceiling" >/dev/null || return 1
    printf '%d\n' "$HAPROXY_BACKEND_MAXCONN"
}

haproxy_wrong_sni_gpc_limit() {
    local value="${KTO_HAPROXY_WRONG_SNI_GPC_LIMIT:-$HAPROXY_WRONG_SNI_GPC_LIMIT_DEFAULT}"
    [[ "$value" =~ ^[0-9]+$ ]] || value="$HAPROXY_WRONG_SNI_GPC_LIMIT_DEFAULT"
    value=$((10#$value))
    if (( value < 10 || value > 100000 )); then
        value="$HAPROXY_WRONG_SNI_GPC_LIMIT_DEFAULT"
    fi
    printf '%d\n' "$value"
}

haproxy_source_conn_rate_limit() {
    local value="${KTO_HAPROXY_SOURCE_CONN_RATE_LIMIT:-$HAPROXY_SOURCE_CONN_RATE_LIMIT_DEFAULT}"
    [[ "$value" =~ ^[0-9]+$ ]] || value="$HAPROXY_SOURCE_CONN_RATE_LIMIT_DEFAULT"
    value=$((10#$value))
    if (( value < 100 || value > 100000 )); then
        value="$HAPROXY_SOURCE_CONN_RATE_LIMIT_DEFAULT"
    fi
    printf '%d\n' "$value"
}

haproxy_thread_count() {
    local override="${KTO_HAPROXY_NBTHREAD:-auto}"
    local auto_max="${KTO_HAPROXY_AUTO_THREADS_MAX:-32}"
    local threads

    if [[ "$override" =~ ^[0-9]+$ ]]; then
        threads=$((10#$override))
        if (( threads >= 1 && threads <= 64 )); then
            printf '%d\n' "$threads"
            return 0
        fi
    fi

    threads="$(cpu_count)"
    [[ "$threads" =~ ^[0-9]+$ ]] || threads=1
    threads=$((10#$threads))
    if [[ "$auto_max" =~ ^[0-9]+$ ]]; then
        auto_max=$((10#$auto_max))
    else
        auto_max=32
    fi
    (( auto_max >= 1 && auto_max <= 64 )) || auto_max=32
    (( threads <= auto_max )) || threads="$auto_max"
    (( threads >= 1 )) || threads=1
    printf '%d\n' "$threads"
}

render_haproxy_routes_config() {
    local routes_file="$1" output_file="$2"
    local port backend_target_pool allowed_sni source_ip server_maxconn listen_ip send_proxy_v2
    local normalized_target_pool normalized_sni normalized_source_ip normalized_server_maxconn normalized_listen_ip normalized_send_proxy_v2
    local frontend_name backend_name server_name source_clause proxy_protocol_clause target index
    local endpoint_key bind_address route_index name_suffix
    local haproxy_threads haproxy_maxconn wrong_sni_gpc_limit source_conn_rate_limit effective_server_maxconn route_count=0
    local -a backend_targets=()
    local -A seen_endpoints=() seen_port_any=() seen_port_wildcard=() rendered_ports=()

    while IFS=$'\t' read -r port backend_target_pool allowed_sni source_ip server_maxconn listen_ip send_proxy_v2; do
        [[ "$port" =~ ^[0-9]+$ ]] || {
            fail "Некорректный входной HAProxy порт: ${port:-пусто}"
            return 1
        }
        port=$((10#$port))
        (( port >= 1 && port <= 65535 )) || {
            fail "HAProxy порт вне диапазона: $port"
            return 1
        }
        normalized_target_pool="$(normalize_haproxy_target_pool "$backend_target_pool" 2>/dev/null || true)"
        normalized_sni="$(normalize_haproxy_sni_list "$allowed_sni" 2>/dev/null || true)"
        normalized_source_ip="$(normalize_haproxy_source_ip "${source_ip:-default}" 2>/dev/null || true)"
        normalized_server_maxconn="$(normalize_haproxy_server_maxconn "${server_maxconn:-default}" 2>/dev/null || true)"
        normalized_listen_ip="$(normalize_haproxy_listen_ip "${listen_ip:-*}" 2>/dev/null || true)"
        normalized_send_proxy_v2="$(normalize_haproxy_send_proxy_v2 "${send_proxy_v2:-0}" 2>/dev/null || true)"
        [[ -n "$normalized_target_pool" && -n "$normalized_sni" && -n "$normalized_source_ip" && -n "$normalized_server_maxconn" && -n "$normalized_listen_ip" && -n "$normalized_send_proxy_v2" ]] || {
            fail "Некорректный HAProxy маршрут на порту $port"
            return 1
        }
        if [[ "$normalized_listen_ip" != "*" ]]; then
            normalized_source_ip="$normalized_listen_ip"
        elif [[ "$normalized_source_ip" != "default" ]]; then
            normalized_listen_ip="$normalized_source_ip"
        fi
        endpoint_key="${normalized_listen_ip}|${port}"
        [[ -z "${seen_endpoints[$endpoint_key]+x}" ]] || {
            fail "HAProxy listener ${normalized_listen_ip}:${port} указан дважды"
            return 1
        }
        if [[ "$normalized_listen_ip" == "*" && -n "${seen_port_any[$port]+x}" ]] ||
            [[ "$normalized_listen_ip" != "*" && -n "${seen_port_wildcard[$port]+x}" ]]; then
            fail "HAProxy wildcard *:${port} нельзя совмещать с отдельным IP на том же порту"
            return 1
        fi
        seen_endpoints[$endpoint_key]=1
        seen_port_any[$port]=1
        [[ "$normalized_listen_ip" == "*" ]] && seen_port_wildcard[$port]=1
        route_count=$(( route_count + 1 ))
    done < "$routes_file"
    (( route_count > 0 )) || {
        fail "Список HAProxy маршрутов пуст"
        return 1
    }

    haproxy_threads="$(haproxy_thread_count)"
    haproxy_maxconn="$(recommended_haproxy_maxconn)"
    wrong_sni_gpc_limit="$(haproxy_wrong_sni_gpc_limit)"
    source_conn_rate_limit="$(haproxy_source_conn_rate_limit)"

    cat > "$output_file" <<EOF
# Managed by kto. Edit routes through the HAProxy menu.
global
    maxconn ${haproxy_maxconn}
    nbthread ${haproxy_threads}
    spread-checks 5
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    tune.ssl.default-dh-param 2048

defaults
    mode tcp

    option clitcpka
    option srvtcpka
    option tcp-smart-accept
    option tcp-smart-connect
    option splice-auto
    option splice-request
    option splice-response
    option redispatch

    retries 2
    timeout connect 4s
    timeout queue 4s
    timeout client 1m
    timeout server 1m
    timeout tunnel 15m
    timeout client-fin 30s
    timeout server-fin 30s
    timeout check 3s

    default-server inter 10s fastinter 2s downinter 10s fall 3 rise 2

backend wrong_sni_names
    stick-table type string len 160 size 100k expire 30m store gpc0
EOF

    while IFS=$'\t' read -r port backend_target_pool allowed_sni source_ip server_maxconn listen_ip send_proxy_v2; do
        port=$((10#$port))
        backend_target_pool="$(normalize_haproxy_target_pool "$backend_target_pool")"
        allowed_sni="$(normalize_haproxy_sni_list "$allowed_sni")"
        source_ip="$(normalize_haproxy_source_ip "${source_ip:-default}")"
        server_maxconn="$(normalize_haproxy_server_maxconn "${server_maxconn:-default}")"
        listen_ip="$(normalize_haproxy_listen_ip "${listen_ip:-*}")"
        send_proxy_v2="$(normalize_haproxy_send_proxy_v2 "${send_proxy_v2:-0}")"
        if [[ "$listen_ip" != "*" ]]; then
            source_ip="$listen_ip"
        elif [[ "$source_ip" != "default" ]]; then
            listen_ip="$source_ip"
        fi
        bind_address="$listen_ip"
        source_clause=""
        proxy_protocol_clause=""
        [[ "$source_ip" == default ]] || source_clause=" source ${source_ip}"
        [[ "$send_proxy_v2" == "1" ]] && proxy_protocol_clause=" send-proxy-v2"
        backend_targets=()
        IFS=',' read -r -a backend_targets <<< "$backend_target_pool"
        route_index="${rendered_ports[$port]:-0}"
        rendered_ports[$port]=$(( route_index + 1 ))
        if (( route_index == 0 && port == 443 )); then
            frontend_name="vless_in"
            backend_name="vless_pool"
        elif (( route_index == 0 )); then
            frontend_name="vless_in_${port}"
            backend_name="vless_pool_${port}"
        else
            name_suffix="${listen_ip//./_}"
            frontend_name="vless_in_${port}_${name_suffix}"
            backend_name="vless_pool_${port}_${name_suffix}"
        fi

        cat >> "$output_file" <<EOF

# -------------------------
# FRONTEND : ${listen_ip}:${port}
# -------------------------
frontend ${frontend_name}
    bind ${bind_address}:${port} backlog 65535
    stick-table type ip size 100k expire 5m store gpc0,conn_rate(10s)
    tcp-request connection track-sc0 src
    tcp-request connection silent-drop if { src_get_gpc0 gt ${wrong_sni_gpc_limit} }
    tcp-request connection silent-drop if { src_conn_rate gt ${source_conn_rate_limit} }
    tcp-request inspect-delay 5s
    acl clienthello req.ssl_hello_type 1
EOF
        if [[ "$allowed_sni" == any ]]; then
            cat >> "$output_file" <<EOF
    # kto-sni-mode any
    tcp-request content accept if clienthello
    tcp-request content reject if WAIT_END
EOF
        else
            cat >> "$output_file" <<EOF
    # kto-sni-mode allow-list
    acl has_sni req.ssl_sni -m found
EOF
            render_haproxy_sni_acl_lines "$allowed_sni" >> "$output_file"
            cat >> "$output_file" <<EOF
    tcp-request content sc-inc-gpc0(0) if clienthello !allowed_sni
    tcp-request content track-sc1 req.ssl_sni,lower table wrong_sni_names if clienthello has_sni !allowed_sni
    tcp-request content sc-inc-gpc0(1) if clienthello has_sni !allowed_sni
    tcp-request content accept if clienthello allowed_sni
    tcp-request content reject if clienthello !allowed_sni
    tcp-request content reject if WAIT_END
EOF
        fi
        cat >> "$output_file" <<EOF
    default_backend ${backend_name}

backend ${backend_name}
    mode tcp
    balance leastconn
    # kto-server-maxconn ${server_maxconn}

EOF
        effective_server_maxconn="$(haproxy_pool_server_maxconn "$haproxy_maxconn" "${#backend_targets[@]}" "$server_maxconn")" || {
            fail "Не удалось рассчитать maxconn backend для ${listen_ip}:${port}"
            return 1
        }
        for index in "${!backend_targets[@]}"; do
            target="${backend_targets[$index]}"
            if (( ${#backend_targets[@]} == 1 )); then
                if (( port == 443 )); then
                    server_name="xray1"
                else
                    server_name="xray_${port}"
                fi
            else
                server_name="xray$(( index + 1 ))"
            fi
            printf '    server %s %s check weight 10%s%s maxconn %s\n' \
                "$server_name" "$target" "$source_clause" "$proxy_protocol_clause" "$effective_server_maxconn" >> "$output_file"
        done
    done < "$routes_file"
}

HAPROXY_LAST_BACKUP=""

create_haproxy_persistent_backup() {
    local label="${1:-before-apply}" config="${2:-$HAPROXY_CONFIG_FILE}"
    local safe_label timestamp backup checksum_file tmp checksum_tmp expected actual

    HAPROXY_LAST_BACKUP=""
    "${SUDO[@]}" test -s "$config" 2>/dev/null || return 0
    command_exists sha256sum || {
        fail "sha256sum не найден, безопасный HAProxy backup не создан"
        return 1
    }

    safe_label="$(printf '%s' "$label" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-')"
    [[ -n "$safe_label" ]] || safe_label="backup"
    timestamp="$(date -u +%Y%m%d-%H%M%S-%N)"
    backup="${HAPROXY_BACKUP_DIR}/haproxy-${timestamp}-${safe_label}-${BASHPID:-$$}-${RANDOM}.cfg"
    checksum_file="${backup}.sha256"
    tmp="$(mktemp)"
    checksum_tmp="$(mktemp)"

    if ! "${SUDO[@]}" cat "$config" > "$tmp" || [[ ! -s "$tmp" ]]; then
        rm -f "$tmp" "$checksum_tmp"
        fail "Не удалось прочитать текущий HAProxy config для backup"
        return 1
    fi
    expected="$(sha256sum "$tmp" | awk '{print $1}')"
    printf '%s  %s\n' "$expected" "$(basename "$backup")" > "$checksum_tmp"

    if ! "${SUDO[@]}" mkdir -p "$HAPROXY_BACKUP_DIR" >> "$LOG_FILE" 2>&1 ||
        ! "${SUDO[@]}" chmod 0700 "$HAPROXY_BACKUP_DIR" >> "$LOG_FILE" 2>&1 ||
        ! "${SUDO[@]}" install -m 0600 "$tmp" "$backup" >> "$LOG_FILE" 2>&1 ||
        ! "${SUDO[@]}" install -m 0600 "$checksum_tmp" "$checksum_file" >> "$LOG_FILE" 2>&1; then
        "${SUDO[@]}" rm -f "$backup" "$checksum_file" >> "$LOG_FILE" 2>&1 || true
        rm -f "$tmp" "$checksum_tmp"
        fail "Не удалось сохранить постоянный HAProxy backup"
        return 1
    fi
    actual="$("${SUDO[@]}" sha256sum "$backup" 2>/dev/null | awk '{print $1}' || true)"
    rm -f "$tmp" "$checksum_tmp"
    if [[ -z "$actual" || "$actual" != "$expected" ]]; then
        "${SUDO[@]}" rm -f "$backup" "$checksum_file" >> "$LOG_FILE" 2>&1 || true
        fail "Проверка записанного HAProxy backup не прошла"
        return 1
    fi

    HAPROXY_LAST_BACKUP="$backup"
    printf 'HAProxy backup: %s\n' "$backup" >> "$LOG_FILE" 2>/dev/null || true
}

verify_haproxy_backup() {
    local backup="$1" checksum_file="${1}.sha256" expected actual

    "${SUDO[@]}" test -s "$backup" 2>/dev/null || return 1
    "${SUDO[@]}" test -s "$checksum_file" 2>/dev/null || return 1
    command_exists sha256sum || return 1
    expected="$("${SUDO[@]}" awk 'NR == 1 { print $1; exit }' "$checksum_file" 2>/dev/null || true)"
    actual="$("${SUDO[@]}" sha256sum "$backup" 2>/dev/null | awk '{print $1}' || true)"
    [[ "$expected" =~ ^[a-fA-F0-9]{64}$ && "$actual" == "$expected" ]]
}

list_haproxy_backups() {
    "${SUDO[@]}" test -d "$HAPROXY_BACKUP_DIR" 2>/dev/null || return 0
    "${SUDO[@]}" find "$HAPROXY_BACKUP_DIR" -maxdepth 1 -type f -name 'haproxy-*.cfg' \
        -printf '%T@\t%p\n' 2>/dev/null | sort -t $'\t' -k1,1nr | cut -f2-
}

apply_haproxy_routes_config() {
    local routes_file="$1"
    local skip_bandwidth_reapply="${2:-0}"
    local force_clean_start="${3:-0}"
    local config="$HAPROXY_CONFIG_FILE"
    local tmp_config backup backup_routes had_config=0 haproxy_threads haproxy_maxconn haproxy_nofile route_count activation_ready=1
    local capacity_updated=0 config_changed=1

    HAPROXY_LAST_BACKUP=""
    ensure_haproxy_package
    tmp_config="$(mktemp)"
    backup="$(mktemp)"
    backup_routes="$(mktemp)"
    if ! render_haproxy_routes_config "$routes_file" "$tmp_config"; then
        rm -f "$tmp_config" "$backup" "$backup_routes"
        return 1
    fi

    stage "Проверяю HAProxy config"
    if ! "${SUDO[@]}" haproxy -c -f "$tmp_config" >> "$LOG_FILE" 2>&1; then
        rm -f "$tmp_config" "$backup" "$backup_routes"
        fail "Проверка HAProxy config"
        tail -n 25 "$LOG_FILE" >&2 || true
        return 1
    fi
    if ! reserve_haproxy_route_ports "$routes_file"; then
        rm -f "$tmp_config" "$backup" "$backup_routes"
        return 1
    fi

    if "${SUDO[@]}" test -s "$config" 2>/dev/null; then
        had_config=1
        "${SUDO[@]}" cat "$config" > "$backup"
        extract_haproxy_routes "$backup" > "$backup_routes"
        if cmp -s "$tmp_config" "$backup"; then
            config_changed=0
        else
            if ! create_haproxy_persistent_backup "before-apply" "$config"; then
                rm -f "$tmp_config" "$backup" "$backup_routes"
                return 1
            fi
            "${SUDO[@]}" cp -a "$config" "${config}.kto.bak" >> "$LOG_FILE" 2>&1 || true
        fi
    fi

    if (( config_changed == 1 )); then
        stage "Применяю HAProxy config"
        "${SUDO[@]}" install -m 0644 "$tmp_config" "$config" >> "$LOG_FILE" 2>&1
    fi

    cmd "${SUDO[@]}" mkdir -p /etc/systemd/system/haproxy.service.d
    haproxy_nofile="$(haproxy_nofile_limit)"
    if write_root_file_if_changed /etc/systemd/system/haproxy.service.d/99-kto-capacity.conf <<EOF
[Service]
LimitNOFILE=${haproxy_nofile}
EOF
    then
        capacity_updated="$ROOT_FILE_UPDATED"
    else
        fail "Не удалось записать systemd-настройки HAProxy"
        activation_ready=0
    fi
    if (( activation_ready == 1 && capacity_updated == 1 )); then
        stage "Обновляю systemd-настройки HAProxy"
        if ! run_systemctl_bounded 20 daemon-reload >> "$LOG_FILE" 2>&1; then
            fail "systemd daemon-reload не завершился за 20 секунд"
            activation_ready=0
        fi
    fi
    if (( activation_ready == 1 )) && ! run_systemctl_bounded 5 is-enabled --quiet haproxy >> "$LOG_FILE" 2>&1; then
        if ! run_systemctl_bounded 20 enable haproxy >> "$LOG_FILE" 2>&1; then
            warn "Не удалось включить автозапуск HAProxy за 20 секунд"
        fi
    fi

    if [[ "$force_clean_start" != "1" ]] &&
        (( activation_ready == 1 && config_changed == 0 && capacity_updated == 0 )) &&
        run_systemctl_bounded 3 is-active --quiet haproxy 2>/dev/null &&
        [[ -z "$(haproxy_missing_listener_ports "$routes_file")" ]]; then
        ok "HAProxy config уже актуален, reload не требуется"
    elif (( activation_ready == 1 )) && [[ "$force_clean_start" == "1" ]] &&
        start_haproxy_cleanly "$routes_file"; then
        ok "HAProxy запущен заново без старых worker-процессов"
    elif [[ "$force_clean_start" == "1" ]] || (( activation_ready == 0 )) || ! reload_haproxy_gracefully "$routes_file"; then
        "${SUDO[@]}" cp -a "$config" "${config}.kto.failed" >> "$LOG_FILE" 2>&1 || true
        warn "Неудачный config сохранён: ${config}.kto.failed"
        warn "Новый конфиг не запустился, возвращаю предыдущий."
        if (( had_config == 1 )); then
            "${SUDO[@]}" install -m 0644 "$backup" "$config" >> "$LOG_FILE" 2>&1
            if [[ -s "$backup_routes" ]] && start_haproxy_cleanly "$backup_routes"; then
                ok "Предыдущий HAProxy config восстановлен"
            elif [[ ! -s "$backup_routes" ]] && \
                run_systemctl_bounded 10 reset-failed haproxy >> "$LOG_FILE" 2>&1 && \
                run_systemctl_bounded 15 start haproxy >> "$LOG_FILE" 2>&1; then
                ok "Предыдущий HAProxy config восстановлен"
            else
                fail "Предыдущий HAProxy config тоже не запускается"
                print_haproxy_failure_details "$config"
            fi
        else
            "${SUDO[@]}" rm -f "$config" >> "$LOG_FILE" 2>&1 || true
            run_systemctl_bounded 10 --no-block stop haproxy >> "$LOG_FILE" 2>&1 || true
        fi
        rm -f "$tmp_config" "$backup" "$backup_routes"
        tail -n 25 "$LOG_FILE" >&2 || true
        return 1
    fi

    rm -f "$tmp_config" "$backup" "$backup_routes"
    haproxy_threads="$(haproxy_thread_count)"
    haproxy_maxconn="$(recommended_haproxy_maxconn)"
    route_count="$(haproxy_route_count "$routes_file")"
    ok "HAProxy маршрутов: ${route_count}"
    ok "HAProxy capacity: maxconn=${haproxy_maxconn}, nofile=${haproxy_nofile}, threads=${haproxy_threads}"
    [[ -z "$HAPROXY_LAST_BACKUP" ]] || ok "Backup: ${HAPROXY_LAST_BACKUP}"
    if [[ "$skip_bandwidth_reapply" != "1" ]] &&
        "${SUDO[@]}" test -s "$HAPROXY_BANDWIDTH_CONFIG" 2>/dev/null; then
        if ! reapply_haproxy_bandwidth_limits; then
            warn "HAProxy работает, но лимиты входных IP не переприменились. Запусти haproxy-limit-status."
        fi
    fi
}

apply_haproxy_config() {
    local backend_target="$1" allowed_sni="$2" listen_ip="${3:-}" routes_file base_port
    base_port="$(haproxy_base_port)"
    [[ -n "$listen_ip" ]] || listen_ip="$(haproxy_default_listen_ip_for_source default)"
    routes_file="$(mktemp)"
    print_haproxy_route "$base_port" "$backend_target" "$allowed_sni" default default "$listen_ip" > "$routes_file"
    if apply_haproxy_routes_config "$routes_file"; then
        rm -f "$routes_file"
        return 0
    fi
    rm -f "$routes_file"
    return 1
}

ensure_haproxy_package() {
    # Route edits need only HAProxy and ss. socat is an optional diagnostics
    # dependency and must not trigger apt during an otherwise local edit.
    if command_exists haproxy && command_exists ss; then
        return 0
    fi
    stage "Устанавливаю HAProxy"
    must "apt update" apt_update_quiet
    must "Установка HAProxy" apt_install_quiet haproxy socat iproute2
}

validate_haproxy_bandwidth_rate() {
    local rate="${1:-}"
    [[ "$rate" =~ ^[0-9]+$ ]] || return 1
    (( ${#rate} <= 6 )) || return 1
    rate=$((10#$rate))
    (( rate >= 1 && rate <= 100000 ))
}

install_haproxy_bandwidth_manager() {
    local unit_updated=0
    install_asset_file scripts/kto-haproxy-bandwidth.sh "$HAPROXY_BANDWIDTH_MANAGER" 0755 || return 1
    if write_root_file_if_changed "$HAPROXY_BANDWIDTH_UNIT" <<EOF
[Unit]
Description=KTO per-input-IP and per-direction HAProxy bandwidth shaper
Wants=network-online.target
After=network-online.target haproxy.service kto-additional-ip-routes.service

[Service]
Type=oneshot
ExecStart=${HAPROXY_BANDWIDTH_MANAGER} apply
ExecReload=${HAPROXY_BANDWIDTH_MANAGER} apply
ExecStop=${HAPROXY_BANDWIDTH_MANAGER} clear
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    then
        unit_updated="$ROOT_FILE_UPDATED"
    else
        fail "Не удалось записать systemd unit лимитов HAProxy"
        return 1
    fi
    if (( unit_updated == 1 )); then
        if ! run_systemctl_bounded 20 daemon-reload >> "$LOG_FILE" 2>&1; then
            fail "Не удалось обновить systemd для лимитов HAProxy"
            return 1
        fi
    fi
    if ! run_systemctl_bounded 5 is-enabled --quiet "$HAPROXY_BANDWIDTH_SERVICE" >> "$LOG_FILE" 2>&1; then
        if ! run_systemctl_bounded 20 enable "$HAPROXY_BANDWIDTH_SERVICE" >> "$LOG_FILE" 2>&1; then
            fail "Не удалось включить автозапуск лимитов HAProxy"
            return 1
        fi
    fi
}

ensure_haproxy_bandwidth_manager() {
    if "${SUDO[@]}" test -x "$HAPROXY_BANDWIDTH_MANAGER" 2>/dev/null &&
        "${SUDO[@]}" grep -Fqx "HAPROXY_BANDWIDTH_BUILD=\"${SCRIPT_BUILD}\"" "$HAPROXY_BANDWIDTH_MANAGER" 2>/dev/null &&
        "${SUDO[@]}" test -s "$HAPROXY_BANDWIDTH_UNIT" 2>/dev/null &&
        "${SUDO[@]}" grep -Fqx "ExecStart=${HAPROXY_BANDWIDTH_MANAGER} apply" "$HAPROXY_BANDWIDTH_UNIT" 2>/dev/null; then
        if ! run_systemctl_bounded 5 is-enabled --quiet "$HAPROXY_BANDWIDTH_SERVICE" >> "$LOG_FILE" 2>&1; then
            run_systemctl_bounded 20 enable "$HAPROXY_BANDWIDTH_SERVICE" >> "$LOG_FILE" 2>&1 || {
                fail "Не удалось включить автозапуск лимитов HAProxy"
                return 1
            }
        fi
        return 0
    fi
    must "Установка зависимостей лимита HAProxy" apt_install_with_update_if_missing iproute2 util-linux kmod || return 1
    install_haproxy_bandwidth_manager
}

require_local_haproxy_bandwidth_manager() {
    if "${SUDO[@]}" test -x "$HAPROXY_BANDWIDTH_MANAGER" 2>/dev/null; then
        return 0
    fi
    fail "Локальный менеджер лимитов HAProxy не установлен"
    warn "Автоматическая операция не скачивает компоненты. Открой меню лимитов HAProxy и установи лимит один раз."
    return 1
}

load_haproxy_bandwidth_config() {
    local output_file="$1" raw_file line_number=0 ip rate extra numeric_rate
    local -A seen=()

    : > "$output_file"
    if ! "${SUDO[@]}" test -e "$HAPROXY_BANDWIDTH_CONFIG" 2>/dev/null; then
        return 0
    fi
    raw_file="$(mktemp)"
    if ! "${SUDO[@]}" cat "$HAPROXY_BANDWIDTH_CONFIG" > "$raw_file"; then
        rm -f "$raw_file"
        fail "Не удалось прочитать ${HAPROXY_BANDWIDTH_CONFIG}"
        return 1
    fi
    while IFS=$'\t' read -r ip rate extra; do
        line_number=$(( line_number + 1 ))
        ip="${ip//$'\r'/}"
        rate="${rate//$'\r'/}"
        [[ -n "$ip" && "${ip:0:1}" != "#" ]] || continue
        if [[ -n "${extra:-}" ]] || ! validate_ipv4 "$ip" || ! validate_haproxy_bandwidth_rate "$rate"; then
            rm -f "$raw_file"
            fail "Некорректная строка ${line_number} в ${HAPROXY_BANDWIDTH_CONFIG}"
            return 1
        fi
        numeric_rate=$((10#$rate))
        if [[ -n "${seen[$ip]+x}" && "${seen[$ip]}" != "$numeric_rate" ]]; then
            rm -f "$raw_file"
            fail "Для ${ip} указано несколько разных лимитов"
            return 1
        fi
        seen[$ip]="$numeric_rate"
    done < "$raw_file"
    rm -f "$raw_file"

    for ip in "${!seen[@]}"; do
        printf '%s\t%s\n' "$ip" "${seen[$ip]}"
    done | sort -t $'\t' -k1,1V > "$output_file"
}

list_haproxy_input_ips() {
    local default_ip
    default_ip="$(haproxy_default_source_ip)"
    ip -4 -o address show scope global 2>/dev/null | awk -v default_ip="$default_ip" '
        {
            interface = $2
            sub(/@.*/, "", interface)
            split($4, cidr, "/")
            if (cidr[1] != "") {
                priority = (cidr[1] == default_ip ? 0 : 1)
                print priority "\t" cidr[1] "\t" interface
            }
        }
    ' | sort -t $'\t' -k1,1n -k3,3V -k2,2V | awk -F '\t' '!seen[$2]++ { print $2 "\t" $3 }'
}

haproxy_input_ip_available() {
    local wanted="$1"
    list_haproxy_input_ips |
        awk -F '\t' -v wanted="$wanted" '$1 == wanted { found = 1 } END { exit found ? 0 : 1 }'
}

haproxy_route_ip_for_source() {
    local source_ip actual_ip

    source_ip="$(canonicalize_haproxy_runtime_source_ip "${1:-default}" 2>/dev/null || true)"
    [[ -n "$source_ip" ]] || return 1
    if [[ "$source_ip" == "default" ]]; then
        actual_ip="$(haproxy_default_source_ip)"
    else
        actual_ip="$source_ip"
    fi
    validate_ipv4 "$actual_ip" || return 1
    haproxy_input_ip_available "$actual_ip" || return 1
    ip -4 route get 1.1.1.1 from "$actual_ip" >/dev/null 2>&1 || return 1
    printf '%s\n' "$actual_ip"
}

haproxy_default_listen_ip_for_source() {
    haproxy_route_ip_for_source "${1:-default}"
}

select_haproxy_route_source_ip() {
    local routes_file="${1:-}" current_source="${2:-}" current_ip="" default_ip
    local row source_ip interface kind choice index used_count marker
    local -a rows=()

    mapfile -t rows < <(list_test_source_ipv4s)
    (( ${#rows[@]} > 0 )) || {
        fail "Не найдено IPv4 с рабочим source-route"
        return 1
    }
    default_ip="$(haproxy_default_source_ip)"
    if [[ -n "$current_source" ]]; then
        current_ip="$(haproxy_route_ip_for_source "$current_source" 2>/dev/null || true)"
    fi

    printf 'Выберите IP HAProxy (вход и выход будут одинаковыми):\n' >&2
    for index in "${!rows[@]}"; do
        IFS=$'\t' read -r source_ip interface kind <<< "${rows[$index]}"
        used_count=0
        if [[ -n "$routes_file" && -s "$routes_file" ]]; then
            used_count="$(awk -F '\t' -v wanted="$source_ip" -v default_ip="$default_ip" '
                {
                    source = ($4 == "" || $4 == "default" ? default_ip : $4)
                    if (source == wanted) count++
                }
                END { print count + 0 }
            ' "$routes_file")"
        fi
        marker=""
        [[ "$source_ip" == "$current_ip" ]] && marker=" | текущий"
        printf ' %d) %s | %s | %s | маршрутов: %s%s\n' \
            "$(( index + 1 ))" "$source_ip" "$interface" "$kind" "$used_count" "$marker" >&2
    done

    while true; do
        printf '> ' >&2
        read -r choice || return 1
        if [[ "$choice" =~ ^[0-9]+$ ]]; then
            choice=$((10#$choice))
            if (( choice >= 1 && choice <= ${#rows[@]} )); then
                IFS=$'\t' read -r source_ip interface kind <<< "${rows[$(( choice - 1 ))]}"
                canonicalize_haproxy_runtime_source_ip "$source_ip"
                return
            fi
        fi
        fail "Неверный выбор"
    done
}

select_haproxy_route_listen_ip() {
    local current choice ip interface index marker default_index=1
    local -a entries=()

    current="$(normalize_haproxy_listen_ip "${1:-*}" 2>/dev/null || printf '*')"
    entries+=("*"$'\t'"все локальные IP")
    while IFS= read -r ip; do
        [[ -n "$ip" ]] && entries+=("$ip")
    done < <(list_haproxy_input_ips)

    printf 'Выберите входной IP HAProxy:\n' >&2
    for index in "${!entries[@]}"; do
        IFS=$'\t' read -r ip interface <<< "${entries[$index]}"
        [[ "$ip" == "$current" ]] && default_index=$(( index + 1 ))
        marker=""
        [[ "$ip" == "$current" ]] && marker=" — текущий"
        if [[ "$ip" == "*" ]]; then
            printf ' %d) * (все локальные IP)%s\n' "$(( index + 1 ))" "$marker" >&2
        else
            printf ' %d) %s (%s)%s\n' "$(( index + 1 ))" "$ip" "$interface" "$marker" >&2
        fi
    done

    while true; do
        printf '> [%d] ' "$default_index" >&2
        read -r choice
        [[ -n "$choice" ]] || choice="$default_index"
        if [[ "$choice" =~ ^[0-9]+$ ]]; then
            choice=$((10#$choice))
            if (( choice >= 1 && choice <= ${#entries[@]} )); then
                IFS=$'\t' read -r ip interface <<< "${entries[$(( choice - 1 ))]}"
                printf '%s\n' "$ip"
                return 0
            fi
        fi
        fail "Неверный выбор"
    done
}

haproxy_bandwidth_current_rate() {
    local wanted="$1"
    "${SUDO[@]}" awk -F '\t' -v wanted="$wanted" '$1 == wanted { print $2; exit }' \
        "$HAPROXY_BANDWIDTH_CONFIG" 2>/dev/null || true
}

print_haproxy_bandwidth_limits() {
    local limits_file ip rate
    limits_file="$(mktemp)"
    if ! load_haproxy_bandwidth_config "$limits_file"; then
        rm -f "$limits_file"
        return 1
    fi
    echo -e "${BOLD}${PURPLE}[ ЛИМИТ СКОРОСТИ ПО ВХОДНОМУ IP ]${NC}"
    if [[ ! -s "$limits_file" ]]; then
        echo "Не настроен. Все входные IP без ограничения скорости."
    else
        while IFS=$'\t' read -r ip rate; do
            printf '%-15s %s Mbit/s RX + %s Mbit/s TX\n' "$ip" "$rate" "$rate"
        done < "$limits_file"
    fi
    echo "RX и TX ограничиваются отдельно. Лимит затрагивает только TCP listener-портов HAProxy."
    rm -f "$limits_file"
}

select_haproxy_input_ip() {
    local choice ip interface rate index
    local -a entries=()
    mapfile -t entries < <(list_haproxy_input_ips)
    if (( ${#entries[@]} == 0 )); then
        fail "На машине не найдено локальных IPv4"
        return 1
    fi
    if (( ${#entries[@]} == 1 )); then
        IFS=$'\t' read -r ip interface <<< "${entries[0]}"
        printf 'Доступен один входной IP: %s (%s)\n' "$ip" "$interface" >&2
        printf '%s\n' "$ip"
        return 0
    fi

    printf 'Выберите входной IP HAProxy:\n' >&2
    for index in "${!entries[@]}"; do
        IFS=$'\t' read -r ip interface <<< "${entries[$index]}"
        rate="$(haproxy_bandwidth_current_rate "$ip")"
        printf ' %d) %s (%s)%s\n' "$(( index + 1 ))" "$ip" "$interface" "${rate:+ — сейчас ${rate} Mbit/s на направление}" >&2
    done
    printf ' 0) Назад\n' >&2
    while true; do
        printf '> ' >&2
        read -r choice
        [[ "$choice" == "0" ]] && return 1
        if [[ "$choice" =~ ^[0-9]+$ ]]; then
            choice=$((10#$choice))
            if (( choice >= 1 && choice <= ${#entries[@]} )); then
                IFS=$'\t' read -r ip interface <<< "${entries[$(( choice - 1 ))]}"
                printf '%s\n' "$ip"
                return 0
            fi
        fi
        fail "Неверный выбор"
    done
}

select_configured_haproxy_bandwidth_ip() {
    local limits_file choice ip rate index
    local -a entries=()
    limits_file="$(mktemp)"
    if ! load_haproxy_bandwidth_config "$limits_file"; then
        rm -f "$limits_file"
        return 1
    fi
    mapfile -t entries < "$limits_file"
    rm -f "$limits_file"
    if (( ${#entries[@]} == 0 )); then
        warn "Ограниченных входных IP нет"
        return 1
    fi
    printf 'Выберите лимит для удаления:\n' >&2
    for index in "${!entries[@]}"; do
        IFS=$'\t' read -r ip rate <<< "${entries[$index]}"
        printf ' %d) %s — %s Mbit/s RX + %s Mbit/s TX\n' \
            "$(( index + 1 ))" "$ip" "$rate" "$rate" >&2
    done
    printf ' 0) Назад\n' >&2
    while true; do
        printf '> ' >&2
        read -r choice
        [[ "$choice" == "0" ]] && return 1
        if [[ "$choice" =~ ^[0-9]+$ ]]; then
            choice=$((10#$choice))
            if (( choice >= 1 && choice <= ${#entries[@]} )); then
                IFS=$'\t' read -r ip rate <<< "${entries[$(( choice - 1 ))]}"
                printf '%s\n' "$ip"
                return 0
            fi
        fi
        fail "Неверный выбор"
    done
}

reapply_haproxy_bandwidth_limits() {
    local timeout_sec="${KTO_HAPROXY_BANDWIDTH_APPLY_TIMEOUT_SEC:-45}"

    [[ "$timeout_sec" =~ ^[0-9]+$ ]] || timeout_sec=45
    timeout_sec=$((10#$timeout_sec))
    (( timeout_sec >= 10 && timeout_sec <= 120 )) || timeout_sec=45
    require_local_haproxy_bandwidth_manager || return 1
    stage "Применяю лимиты выбранных входных IP HAProxy"
    if ! run_bounded_command "$timeout_sec" "${SUDO[@]}" "$HAPROXY_BANDWIDTH_MANAGER" apply; then
        fail "Не удалось применить лимиты входных IP HAProxy за ${timeout_sec} секунд"
        return 1
    fi
    if run_systemctl_bounded 2 is-failed --quiet "$HAPROXY_BANDWIDTH_SERVICE" >> "$LOG_FILE" 2>&1; then
        run_systemctl_bounded 3 reset-failed "$HAPROXY_BANDWIDTH_SERVICE" >> "$LOG_FILE" 2>&1 || true
    fi
}

commit_haproxy_bandwidth_config() {
    local previous_file="$1" next_file="$2" had_config="$3" restored=1
    if ! write_root_file_mode 0600 "$HAPROXY_BANDWIDTH_CONFIG" < "$next_file"; then
        fail "Не удалось сохранить ${HAPROXY_BANDWIDTH_CONFIG}"
        return 1
    fi
    if reapply_haproxy_bandwidth_limits; then
        return 0
    fi

    warn "Возвращаю предыдущие лимиты."
    if (( had_config == 1 )); then
        write_root_file_mode 0600 "$HAPROXY_BANDWIDTH_CONFIG" < "$previous_file" || restored=0
    else
        "${SUDO[@]}" rm -f "$HAPROXY_BANDWIDTH_CONFIG" >> "$LOG_FILE" 2>&1 || restored=0
    fi
    if (( restored == 0 )); then
        "${SUDO[@]}" "$HAPROXY_BANDWIDTH_MANAGER" clear || true
        run_systemctl_bounded 20 disable "$HAPROXY_BANDWIDTH_SERVICE" >> "$LOG_FILE" 2>&1 || true
        fail "Не удалось вернуть файл лимитов. Kernel-лимиты очищены, автозапуск отключён."
        return 1
    fi
    if ! "${SUDO[@]}" "$HAPROXY_BANDWIDTH_MANAGER" apply; then
        warn "Предыдущие kernel-фильтры тоже не восстановились; трафик оставлен без лимита."
    else
        ok "Предыдущие лимиты восстановлены"
    fi
    return 1
}

set_haproxy_input_bandwidth_limit() {
    local input_ip="$1" rate="$2" previous_file next_file had_config=0
    if ! validate_ipv4 "$input_ip" || ! haproxy_input_ip_available "$input_ip"; then
        fail "Входной IP ${input_ip:-пусто} не найден на локальных интерфейсах"
        return 1
    fi
    if ! validate_haproxy_bandwidth_rate "$rate"; then
        fail "Некорректный лимит. Допустимо: 1-100000 Mbit/s"
        return 1
    fi
    rate=$((10#$rate))
    if ! "${SUDO[@]}" test -s "$HAPROXY_CONFIG_FILE" 2>/dev/null; then
        fail "HAProxy ещё не настроен"
        return 1
    fi
    ensure_haproxy_bandwidth_manager || return 1

    previous_file="$(mktemp)"
    next_file="$(mktemp)"
    "${SUDO[@]}" test -e "$HAPROXY_BANDWIDTH_CONFIG" 2>/dev/null && had_config=1
    if ! load_haproxy_bandwidth_config "$previous_file"; then
        rm -f "$previous_file" "$next_file"
        return 1
    fi
    awk -F '\t' -v wanted="$input_ip" '$1 != wanted { print }' "$previous_file" > "$next_file"
    printf '%s\t%s\n' "$input_ip" "$rate" >> "$next_file"
    sort -t $'\t' -k1,1V -o "$next_file" "$next_file"

    if commit_haproxy_bandwidth_config "$previous_file" "$next_file" "$had_config"; then
        rm -f "$previous_file" "$next_file"
        ok "${input_ip}: HAProxy ограничен до ${rate} Mbit/s отдельно на RX и TX"
        ok "Другие IP и не-HAProxy трафик не ограничены"
        return 0
    fi
    rm -f "$previous_file" "$next_file"
    return 1
}

remove_haproxy_input_bandwidth_limit() {
    local input_ip="$1" manager_mode="${2:-latest}" previous_file next_file had_config=0
    validate_ipv4 "$input_ip" || {
        fail "Некорректный IPv4: ${input_ip:-пусто}"
        return 1
    }
    if [[ "$manager_mode" == "local" ]]; then
        require_local_haproxy_bandwidth_manager || return 1
    else
        ensure_haproxy_bandwidth_manager || return 1
    fi
    previous_file="$(mktemp)"
    next_file="$(mktemp)"
    "${SUDO[@]}" test -e "$HAPROXY_BANDWIDTH_CONFIG" 2>/dev/null && had_config=1
    if ! load_haproxy_bandwidth_config "$previous_file"; then
        rm -f "$previous_file" "$next_file"
        return 1
    fi
    if ! awk -F '\t' -v wanted="$input_ip" '$1 == wanted { found = 1 } END { exit found ? 0 : 1 }' "$previous_file"; then
        rm -f "$previous_file" "$next_file"
        warn "Для ${input_ip} лимит уже отсутствует"
        return 0
    fi
    awk -F '\t' -v wanted="$input_ip" '$1 != wanted { print }' "$previous_file" > "$next_file"
    if commit_haproxy_bandwidth_config "$previous_file" "$next_file" "$had_config"; then
        rm -f "$previous_file" "$next_file"
        ok "${input_ip}: лимит HAProxy удалён"
        return 0
    fi
    rm -f "$previous_file" "$next_file"
    return 1
}

set_haproxy_input_bandwidth_limit_interactive() {
    local input_ip current_rate rate
    input_ip="$(select_haproxy_input_ip)" || return 1
    current_rate="$(haproxy_bandwidth_current_rate "$input_ip")"
    rate="$(ask_int "Лимит для ${input_ip} на каждое направление, Mbit/s" "${current_rate:-2000}" 1 100000)"
    set_haproxy_input_bandwidth_limit "$input_ip" "$rate"
}

remove_haproxy_input_bandwidth_limit_interactive() {
    local input_ip
    input_ip="$(select_configured_haproxy_bandwidth_ip)" || return 1
    remove_haproxy_input_bandwidth_limit "$input_ip"
}

show_haproxy_bandwidth_status() {
    ensure_haproxy_bandwidth_manager || return 1
    "${SUDO[@]}" "$HAPROXY_BANDWIDTH_MANAGER" status
    if run_systemctl_bounded 5 is-enabled --quiet "$HAPROXY_BANDWIDTH_SERVICE" >/dev/null 2>&1; then
        printf 'Автозапуск: enabled\n'
    else
        printf 'Автозапуск: disabled\n'
    fi
}

clear_all_haproxy_bandwidth_limits() {
    if ! "${SUDO[@]}" test -x "$HAPROXY_BANDWIDTH_MANAGER" 2>/dev/null; then
        if "${SUDO[@]}" test -e "$HAPROXY_BANDWIDTH_CONFIG" 2>/dev/null; then
            fail "Менеджер лимитов отсутствует; config оставлен без изменений"
            return 1
        fi
        ok "Лимиты скорости уже отсутствуют"
        return 0
    fi
    stage "Снимаю все kernel-лимиты HAProxy"
    if ! run_bounded_command 20 "${SUDO[@]}" "$HAPROXY_BANDWIDTH_MANAGER" clear; then
        fail "Не удалось очистить kernel-фильтры HAProxy"
        return 1
    fi
    "${SUDO[@]}" rm -f "$HAPROXY_BANDWIDTH_CONFIG" >> "$LOG_FILE" 2>&1 || {
        fail "Kernel-фильтры сняты, но ${HAPROXY_BANDWIDTH_CONFIG} не удалён"
        return 1
    }
    run_systemctl_bounded 20 disable "$HAPROXY_BANDWIDTH_SERVICE" >> "$LOG_FILE" 2>&1 || true
    ok "Все лимиты скорости HAProxy сняты"
}

clear_all_haproxy_bandwidth_limits_cli() {
    header
    require_haproxy_mode
    need_root
    clear_all_haproxy_bandwidth_limits
}

haproxy_bandwidth_menu() {
    local choice
    while true; do
        header
        print_haproxy_bandwidth_limits || return 1
        echo
        echo "1) Добавить или изменить лимит"
        echo "2) Убрать лимит с IP"
        echo "3) Переприменить лимиты"
        echo "4) Подробный статус и счётчики"
        echo "5) Снять все лимиты скорости"
        echo "0) Назад"
        echo -e "${PURPLE}==========================================${NC}"
        echo -ne "${PURPLE}>${NC} ${BOLD}Выберите действие:${NC} "
        read -r choice
        case "$choice" in
            1) set_haproxy_input_bandwidth_limit_interactive || true ;;
            2) remove_haproxy_input_bandwidth_limit_interactive || true ;;
            3) ensure_haproxy_bandwidth_manager && reapply_haproxy_bandwidth_limits || true ;;
            4) show_haproxy_bandwidth_status || true ;;
            5) clear_all_haproxy_bandwidth_limits || true ;;
            0) return 0 ;;
            *) fail "Неверный выбор" ;;
        esac
        echo
        echo -ne "${PURPLE}>${NC} Нажмите Enter, чтобы продолжить..."
        read -r _
    done
}

set_haproxy_input_bandwidth_limit_cli() {
    header
    require_haproxy_mode
    need_root
    if (( $# != 2 )); then
        fail "Использование: haproxy-limit INPUT_IP MBIT_PER_DIRECTION"
        return 1
    fi
    set_haproxy_input_bandwidth_limit "$1" "$2"
}

remove_haproxy_input_bandwidth_limit_cli() {
    header
    require_haproxy_mode
    need_root
    if (( $# != 1 )); then
        fail "Использование: haproxy-limit-off INPUT_IP"
        return 1
    fi
    remove_haproxy_input_bandwidth_limit "$1"
}

show_haproxy_bandwidth_status_cli() {
    header
    require_haproxy_mode
    need_root
    show_haproxy_bandwidth_status
}

apply_haproxy_bandwidth_limits_cli() {
    header
    require_haproxy_mode
    need_root
    ensure_haproxy_bandwidth_manager || return 1
    reapply_haproxy_bandwidth_limits
}

sync_haproxy_firewall() {
    local routes_file="${1:-}" previous_routes_file="${2:-}"
    local ssh_port port generated_routes="" current_ports_file previous_known=0 failed=0
    local -A checked_previous_ports=()
    command_exists ufw || return 0
    ufw_active || return 0

    if [[ -z "$routes_file" || ! -s "$routes_file" ]]; then
        generated_routes="$(mktemp)"
        extract_haproxy_routes > "$generated_routes"
        routes_file="$generated_routes"
    fi
    current_ports_file="$(mktemp)"
    haproxy_listener_ports "$routes_file" > "$current_ports_file"
    [[ -n "$previous_routes_file" && -s "$previous_routes_file" ]] && previous_known=1
    if [[ "$MACHINE_MODE" == "whitelist" && "$previous_known" == "0" ]]; then
        ssh_port="$(detect_ssh_port)"
        apply_whitelist_ssh_rules "$ssh_port"
    fi
    repair_haproxy_firewall_rules "$routes_file" || failed=$(( failed + 1 ))

    if [[ -n "$previous_routes_file" && -s "$previous_routes_file" ]]; then
        while IFS=$'\t' read -r port _target _sni _source _maxconn _listen _send_proxy_v2; do
            [[ "$port" =~ ^[0-9]+$ ]] || continue
            [[ -z "${checked_previous_ports[$port]+x}" ]] || continue
            checked_previous_ports[$port]=1
            if ! grep -Fqx "$port" "$current_ports_file"; then
                if [[ "$MACHINE_MODE" == "node" && ( "$port" == "443" || "$port" == "$NODE_PORT" ) ]]; then
                    continue
                fi
                cmd "${SUDO[@]}" ufw --force delete allow "${port}/tcp" || true
            fi
        done < "$previous_routes_file"
    fi

    if [[ "$MACHINE_MODE" == "whitelist" && "$previous_known" == "0" ]]; then
        cmd "${SUDO[@]}" ufw --force delete allow 443/udp || true
        if ! grep -Fqx "$NODE_PORT" "$current_ports_file"; then
            cmd "${SUDO[@]}" ufw --force delete allow "${NODE_PORT}/tcp" || true
        fi
    fi
    ensure_haproxy_firewall_guard || failed=$(( failed + 1 ))
    rm -f "$current_ports_file"
    [[ -z "$generated_routes" ]] || rm -f "$generated_routes"
    (( failed == 0 ))
}

configure_haproxy_backend() {
    header
    require_haproxy_mode
    need_root
    local backend_target allowed_sni source_ip listen_ip send_proxy_v2 routes_file previous_routes_file base_port
    base_port="$(haproxy_base_port)"
    source_ip="$(select_haproxy_route_source_ip)" || return 1
    listen_ip="$(haproxy_route_ip_for_source "$source_ip")" || return 1
    if haproxy_tcp_port_listening "$base_port" "$listen_ip"; then
        fail "TCP listener ${listen_ip}:${base_port} уже занят. HAProxy config не изменён."
        if [[ "$MACHINE_MODE" == "node" ]]; then
            warn "Проверь, не использует ли Xray/gRPC адрес ${listen_ip}:${base_port}, и освободи его перед установкой HAProxy."
        fi
        return 1
    fi
    backend_target="$(ask_haproxy_target "Введите Backend IP или IP:порт")"
    allowed_sni="$(ask_haproxy_sni_list "Введите разрешенный SNI")"
    send_proxy_v2="$(ask_haproxy_send_proxy_v2 0)"

    routes_file="$(mktemp)"
    previous_routes_file="$(mktemp)"
    extract_haproxy_routes > "$previous_routes_file"
    print_haproxy_route "$base_port" "$backend_target" "$allowed_sni" "$source_ip" \
        "$HAPROXY_BACKEND_MAXCONN" "$listen_ip" "$send_proxy_v2" > "$routes_file"

    if apply_haproxy_routes_config "$routes_file"; then
        sync_haproxy_firewall "$routes_file" "$previous_routes_file"
        ok "HAProxy установлен: ${listen_ip}:${base_port}/tcp -> ${backend_target}"
        ok "Входной и исходящий IP: ${listen_ip}"
        ok "Разрешенный SNI: $(haproxy_sni_label "$allowed_sni")"
        ok "send-proxy-v2: $(haproxy_send_proxy_v2_label "$send_proxy_v2")"
    else
        rm -f "$routes_file" "$previous_routes_file"
        return 1
    fi
    rm -f "$routes_file" "$previous_routes_file"
}

print_haproxy_routes() {
    local routes_file="$1" port target_pool sni source_ip server_maxconn listen_ip send_proxy_v2
    local source_label target_label pool_count shown=0
    echo -e "${BOLD}${PURPLE}[ МАРШРУТЫ ]${NC}"
    while IFS=$'\t' read -r port target_pool sni source_ip server_maxconn listen_ip send_proxy_v2; do
        [[ -n "$port" ]] || continue
        shown=$(( shown + 1 ))
        listen_ip="$(haproxy_route_listen_ip "$listen_ip")"
        source_label="$(haproxy_source_label "${source_ip:-default}")"
        pool_count="$(haproxy_target_pool_count "$target_pool" 2>/dev/null || printf '0')"
        if (( pool_count > 1 )); then
            target_label="пул: ${pool_count} backend"
        else
            target_label="$target_pool"
        fi
        printf ' %s:%s -> %s | SNI: %s | Выход: %s | PROXY v2: %s\n' \
            "$listen_ip" "$port" "$target_label" "$(haproxy_sni_label "$sni")" "$source_label" \
            "$(haproxy_send_proxy_v2_label "${send_proxy_v2:-0}")"
    done < "$routes_file"
    (( shown > 0 )) || printf ' Маршрутов пока нет.\n'
}

check_haproxy_bindings() {
    local routes_file="$1" port _target _sni _source _maxconn listen_ip _send_proxy_v2
    local endpoint scope runtime_status total=0 ok_count=0 problem_count=0 result=0 listeners_file

    command_exists ss || {
        fail "ss не найден: проверить runtime-бинды невозможно"
        return 1
    }
    listeners_file="$(mktemp)"
    if ! haproxy_tcp_listener_endpoints > "$listeners_file"; then
        rm -f "$listeners_file"
        fail "Не удалось получить список TCP listener-ов"
        return 1
    fi

    echo -e "${BOLD}${PURPLE}[ ПРОВЕРКА БИНДОВ HAPROXY ]${NC}"
    while IFS=$'\t' read -r port _target _sni _source _maxconn listen_ip _send_proxy_v2; do
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        listen_ip="$(haproxy_route_listen_ip "$listen_ip")"
        endpoint="${listen_ip}:${port}"
        if [[ "$listen_ip" == "*" ]]; then
            scope="FULL: занимает ${port}/tcp на всех IP"
        else
            scope="ТОЧЕЧНЫЙ: только IP ${listen_ip}"
        fi

        if grep -Fqx -- "${listen_ip}"$'\t'"${port}" "$listeners_file"; then
            runtime_status="OK"
            ok_count=$(( ok_count + 1 ))
        elif [[ "$listen_ip" != "*" ]] && grep -Fqx -- "*"$'\t'"${port}" "$listeners_file"; then
            runtime_status="ОШИБКА: HAProxy реально слушает *:${port} на всех IP"
            problem_count=$(( problem_count + 1 ))
        elif awk -F '\t' -v wanted="$port" '$2 == wanted { found = 1 } END { exit found ? 0 : 1 }' "$listeners_file"; then
            runtime_status="ОШИБКА: порт слушается на другом адресе"
            problem_count=$(( problem_count + 1 ))
        else
            runtime_status="ОШИБКА: не слушается"
            problem_count=$(( problem_count + 1 ))
        fi
        total=$(( total + 1 ))
        printf ' %s — %s | Runtime: %s\n' "$endpoint" "$scope" "$runtime_status"
    done < "$routes_file"

    echo
    printf 'Проверено: %s | OK: %s | Проблем: %s\n' "$total" "$ok_count" "$problem_count"
    (( total > 0 && problem_count == 0 )) || result=1
    rm -f "$listeners_file"
    return "$result"
}

haproxy_backend_health_report() {
    awk -F ',' '
        NR == 1 && $0 ~ /^#/ {
            sub(/^#[[:space:]]*/, "", $1)
            for (i = 1; i <= NF; i++) column[$i] = i
            header = 1
            next
        }
        header == 1 {
            proxy = $(column["pxname"])
            server = $(column["svname"])
            status = $(column["status"])
            check_status = (column["check_status"] ? $(column["check_status"]) : "-")
            gsub(/\r/, "", status)
            gsub(/\r/, "", check_status)
            if (server == "BACKEND") {
                pools++
                if (status ~ /^DOWN/) pools_down++
                next
            }
            if (server == "" || server == "FRONTEND") next
            servers++
            if (status ~ /^UP/) {
                servers_up++
            } else if (status ~ /^DOWN/) {
                servers_down++
                if (detail_count < 12) {
                    detail_count++
                    details[detail_count] = proxy "/" server "\t" status "\t" check_status
                }
            } else {
                servers_other++
            }
        }
        END {
            printf "S\t%d\t%d\t%d\t%d\t%d\t%d\n", \
                pools + 0, pools_down + 0, servers + 0, servers_up + 0, \
                servers_down + 0, servers_other + 0
            for (i = 1; i <= detail_count; i++) print "D\t" details[i]
        }
    '
}

HAPROXY_DIAG_ERRORS=0
HAPROXY_DIAG_WARNINGS=0

haproxy_diagnostic_row() {
    local status="$1" name="$2" value="$3"
    case "$status" in
        fail) HAPROXY_DIAG_ERRORS=$(( HAPROXY_DIAG_ERRORS + 1 )) ;;
        warn) HAPROXY_DIAG_WARNINGS=$(( HAPROXY_DIAG_WARNINGS + 1 )) ;;
    esac
    network_test_row "$name" "$value" "$status"
}

stabilize_haproxy() {
    header
    require_haproxy_mode
    need_root
    local routes_file

    routes_file="$(mktemp)"
    extract_haproxy_routes > "$routes_file"
    if [[ ! -s "$routes_file" ]]; then
        rm -f "$routes_file"
        fail "Текущий HAProxy config не распознан; аварийный restart отменён"
        return 1
    fi
    warn "Все текущие HAProxy-сессии разорвутся один раз и переподключатся."
    if apply_haproxy_routes_config "$routes_file" 1 1; then
        rm -f "$routes_file"
        ok "HAProxy стабилизирован: старые worker-процессы удалены, маршруты сохранены"
        return 0
    fi
    rm -f "$routes_file"
    return 1
}

stabilize_haproxy_interactive() {
    local answer
    echo -ne "${YELLOW}Чисто перезапустить HAProxy и разорвать текущие сессии один раз? [y/N]:${NC} "
    read -r answer
    [[ "${answer,,}" =~ ^(y|yes|д|да)$ ]] || {
        warn "Стабилизация отменена"
        return 0
    }
    stabilize_haproxy
}

repair_haproxy_firewall_cli() {
    local ports ports_label
    header
    need_root
    ports="$(haproxy_config_listener_ports "$HAPROXY_CONFIG_FILE")"
    if [[ -z "$ports" ]]; then
        fail "В HAProxy config не найдено внешних frontend bind"
        return 1
    fi
    ensure_haproxy_firewall_guard
    repair_haproxy_firewall_rules
    ports_label="$(awk '{ printf "%s%s/tcp", separator, $1; separator=", " } END { print "" }' <<< "$ports")"
    ok "HAProxy firewall проверен: ${ports_label}"
}

diagnose_haproxy() {
    header
    require_haproxy_mode
    need_root

    local routes_file config_output config_rc=0 service_info active_state="" sub_state="" main_pid="" nofile=""
    local key value route_count missing missing_count reserved port _target _sni source_ip _maxconn listen_ip _send_proxy_v2
    local exact_inputs=0 bad_inputs=0 explicit_sources=0 bad_sources=0 default_source
    local backend_stats health_report summary_line marker pools pools_down servers servers_up servers_down servers_other
    local detail_line status_output status_summary ufw_status missing_firewall=0 result=0
    local process_info process_summary process_count=0 process_cpu="0" process_rss_kb=0 process_rss_mb=0
    local config_threads conntrack_count conntrack_max conntrack_percent capacity_summary
    local -A seen_inputs=() seen_sources=() seen_ports=()

    HAPROXY_DIAG_ERRORS=0
    HAPROXY_DIAG_WARNINGS=0
    routes_file="$(mktemp)"
    extract_haproxy_routes > "$routes_file"

    echo -e "${BOLD}${PURPLE}[ ДИАГНОСТИКА HAPROXY ]${NC}"
    if [[ ! -s "$HAPROXY_CONFIG_FILE" ]]; then
        haproxy_diagnostic_row fail "config" "${HAPROXY_CONFIG_FILE} не найден"
        rm -f "$routes_file"
        return 1
    fi

    route_count="$(haproxy_route_count "$routes_file")"
    if (( route_count > 0 )); then
        haproxy_diagnostic_row ok "маршруты" "${route_count} распознано"
    else
        haproxy_diagnostic_row fail "маршруты" "config не распознан"
    fi

    config_output="$(run_bounded_command 8 "${SUDO[@]}" haproxy -c -f "$HAPROXY_CONFIG_FILE" 2>&1)" || config_rc=$?
    if (( config_rc == 0 )); then
        haproxy_diagnostic_row ok "config check" "валиден"
    else
        haproxy_diagnostic_row fail "config check" "haproxy -c: rc=${config_rc}"
        printf '%s\n' "$config_output" | tail -n 5 | sed 's/^/   /'
    fi

    service_info="$(run_systemctl_bounded 4 show haproxy \
        -p ActiveState -p SubState -p MainPID -p LimitNOFILE 2>/dev/null || true)"
    while IFS='=' read -r key value; do
        case "$key" in
            ActiveState) active_state="$value" ;;
            SubState) sub_state="$value" ;;
            MainPID) main_pid="$value" ;;
            LimitNOFILE) nofile="$value" ;;
        esac
    done <<< "$service_info"
    if [[ "$active_state" == "active" && "$sub_state" == "running" && "$main_pid" =~ ^[1-9][0-9]*$ ]]; then
        haproxy_diagnostic_row ok "service" "active/running, PID ${main_pid}"
    else
        haproxy_diagnostic_row fail "service" "${active_state:-unknown}/${sub_state:-unknown}, PID ${main_pid:-0}"
    fi

    process_info="$(run_bounded_command 4 "${SUDO[@]}" ps -C haproxy -o pid=,ppid=,stat=,%cpu=,rss= 2>/dev/null || true)"
    process_summary="$(awk '
        NF >= 5 {
            count++
            cpu += $4
            rss += $5
        }
        END { printf "%d\t%.1f\t%d\n", count + 0, cpu + 0, rss + 0 }
    ' <<< "$process_info")"
    IFS=$'\t' read -r process_count process_cpu process_rss_kb <<< "$process_summary"
    process_rss_mb=$(( process_rss_kb / 1024 ))
    if (( process_count > 2 )); then
        haproxy_diagnostic_row warn "процессы" "${process_count}, включая старые worker; CPU ${process_cpu}%, RAM ${process_rss_mb} MB"
    elif (( process_count > 0 )); then
        haproxy_diagnostic_row ok "процессы" "${process_count}; CPU ${process_cpu}%, RAM ${process_rss_mb} MB"
    else
        haproxy_diagnostic_row fail "процессы" "не найдены"
    fi

    missing="$(haproxy_missing_listener_ports "$routes_file")"
    missing_count="$(awk 'NF { count++ } END { print count + 0 }' <<< "$missing")"
    if (( route_count > 0 && missing_count == 0 )); then
        haproxy_diagnostic_row ok "listener-ы" "${route_count}/${route_count} слушаются"
    else
        haproxy_diagnostic_row fail "listener-ы" "$(( route_count - missing_count ))/${route_count}; нет: ${missing//$'\n'/, }"
    fi

    default_source="$(haproxy_default_source_ip)"
    while IFS=$'\t' read -r port _target _sni source_ip _maxconn listen_ip _send_proxy_v2; do
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        listen_ip="$(haproxy_route_listen_ip "$listen_ip")"
        if [[ "$listen_ip" != "*" && -z "${seen_inputs[$listen_ip]+x}" ]]; then
            seen_inputs[$listen_ip]=1
            exact_inputs=$(( exact_inputs + 1 ))
            haproxy_input_ip_available "$listen_ip" || bad_inputs=$(( bad_inputs + 1 ))
        fi
        source_ip="$(normalize_haproxy_source_ip "${source_ip:-default}" 2>/dev/null || true)"
        if [[ "$source_ip" != "default" && -n "$source_ip" && -z "${seen_sources[$source_ip]+x}" ]]; then
            seen_sources[$source_ip]=1
            explicit_sources=$(( explicit_sources + 1 ))
            if ! haproxy_input_ip_available "$source_ip" ||
                ! ip -4 route get 1.1.1.1 from "$source_ip" >/dev/null 2>&1; then
                bad_sources=$(( bad_sources + 1 ))
            fi
        fi
        seen_ports[$port]=1
    done < "$routes_file"
    while IFS= read -r port; do
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        seen_ports[$port]=1
    done < <(haproxy_config_listener_ports "$HAPROXY_CONFIG_FILE")
    if (( bad_inputs == 0 )); then
        haproxy_diagnostic_row ok "входные IP" "${exact_inputs} точечных, wildcard поддерживается"
    else
        haproxy_diagnostic_row fail "входные IP" "не найдены: ${bad_inputs}/${exact_inputs}"
    fi
    if validate_ipv4 "$default_source" && (( bad_sources == 0 )); then
        haproxy_diagnostic_row ok "source routes" "default ${default_source}, дополнительных ${explicit_sources}"
    else
        haproxy_diagnostic_row fail "source routes" "default ${default_source:-нет}, ошибок ${bad_sources}/${explicit_sources}"
    fi

    reserved="$(sysctl -n net.ipv4.ip_local_reserved_ports 2>/dev/null || true)"
    for port in "${!seen_ports[@]}"; do
        reserved_port_list_contains "$reserved" "$port" || missing_firewall=$(( missing_firewall + 1 ))
    done
    if (( missing_firewall == 0 )); then
        haproxy_diagnostic_row ok "reserved ports" "все HAProxy-порты исключены из ephemeral"
    else
        haproxy_diagnostic_row warn "reserved ports" "не зарезервировано: ${missing_firewall}"
    fi

    if command_exists socat && [[ -S /run/haproxy/admin.sock ]]; then
        backend_stats="$(printf 'show stat\n' | run_bounded_command 5 "${SUDO[@]}" \
            socat -t 3 - UNIX-CONNECT:/run/haproxy/admin.sock 2>/dev/null || true)"
        health_report="$(haproxy_backend_health_report <<< "$backend_stats")"
        summary_line="$(grep -m1 $'^S\t' <<< "$health_report" || true)"
        IFS=$'\t' read -r marker pools pools_down servers servers_up servers_down servers_other <<< "$summary_line"
        pools="${pools:-0}"; pools_down="${pools_down:-0}"; servers="${servers:-0}"
        servers_up="${servers_up:-0}"; servers_down="${servers_down:-0}"; servers_other="${servers_other:-0}"
        if (( pools_down > 0 )); then
            haproxy_diagnostic_row fail "backend-ы" "пулов DOWN ${pools_down}/${pools}; серверов UP ${servers_up}/${servers}"
        elif (( servers_down > 0 || servers_other > 0 )); then
            haproxy_diagnostic_row warn "backend-ы" "UP ${servers_up}/${servers}, DOWN ${servers_down}, прочих ${servers_other}"
        elif (( servers > 0 )); then
            haproxy_diagnostic_row ok "backend-ы" "UP ${servers_up}/${servers}, пулов ${pools}"
        else
            haproxy_diagnostic_row warn "backend-ы" "stats socket не вернул серверы"
        fi
        while IFS=$'\t' read -r marker detail_line value status_summary; do
            [[ "$marker" == "D" ]] || continue
            printf '   DOWN %-28s %s | %s\n' "$detail_line" "$value" "$status_summary"
        done <<< "$health_report"
    else
        haproxy_diagnostic_row warn "backend-ы" "stats socket недоступен"
    fi

    if command_exists ufw; then
        ufw_status="$(run_bounded_command 5 "${SUDO[@]}" ufw status 2>/dev/null || true)"
        if grep -q 'Status: active' <<< "$ufw_status"; then
            missing_firewall=0
            for port in "${!seen_ports[@]}"; do
                ufw_status_rule_open_to_any "${port}/tcp" <<< "$ufw_status" ||
                    missing_firewall=$(( missing_firewall + 1 ))
            done
            if (( missing_firewall == 0 )); then
                haproxy_diagnostic_row ok "firewall" "UFW active, все порты разрешены"
            else
                haproxy_diagnostic_row fail "firewall" "нет ALLOW для ${missing_firewall} HAProxy-портов"
            fi
        else
            haproxy_diagnostic_row warn "firewall" "UFW выключен"
        fi
    else
        haproxy_diagnostic_row skip "firewall" "UFW не установлен"
    fi

    if "${SUDO[@]}" test -s "$HAPROXY_BANDWIDTH_CONFIG" 2>/dev/null; then
        if "${SUDO[@]}" test -x "$HAPROXY_BANDWIDTH_MANAGER" 2>/dev/null; then
            status_output="$(run_bounded_command 12 "${SUDO[@]}" "$HAPROXY_BANDWIDTH_MANAGER" status 2>&1 || true)"
            status_summary="$(awk '
                /^(Фильтров:|Итог:)/ {
                    if (summary != "") summary = summary " | "
                    summary = summary $0
                }
                END { print summary }
            ' <<< "$status_output")"
            if grep -Fq 'Итог: РАБОТАЕТ' <<< "$status_output"; then
                haproxy_diagnostic_row ok "лимиты скорости" "${status_summary:-работают}"
            else
                haproxy_diagnostic_row fail "лимиты скорости" "${status_summary:-ошибка проверки}"
            fi
        else
            haproxy_diagnostic_row fail "лимиты скорости" "manager не установлен"
        fi
    else
        haproxy_diagnostic_row skip "лимиты скорости" "не настроены"
    fi

    value="$(awk '$1 == "maxconn" { print $2; exit }' "$HAPROXY_CONFIG_FILE")"
    config_threads="$(awk '$1 == "nbthread" { print $2; exit }' "$HAPROXY_CONFIG_FILE")"
    conntrack_count="$(sysctl -n net.netfilter.nf_conntrack_count 2>/dev/null || true)"
    conntrack_max="$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || true)"
    capacity_summary="maxconn=${value:-unknown}, nofile=${nofile:-unknown}, threads=${config_threads:-unknown}"
    if [[ "$conntrack_count" =~ ^[0-9]+$ && "$conntrack_max" =~ ^[1-9][0-9]*$ ]]; then
        conntrack_percent=$(( conntrack_count * 100 / conntrack_max ))
        capacity_summary+=", conntrack=${conntrack_count}/${conntrack_max} (${conntrack_percent}%)"
    else
        conntrack_percent=0
    fi
    if [[ "$value" =~ ^[1-9][0-9]*$ && "$nofile" =~ ^[1-9][0-9]*$ ]]; then
        if (( conntrack_percent >= 75 )); then
            haproxy_diagnostic_row warn "capacity" "$capacity_summary"
        else
            haproxy_diagnostic_row ok "capacity" "$capacity_summary"
        fi
    else
        haproxy_diagnostic_row warn "capacity" "$capacity_summary"
    fi
    echo
    if (( HAPROXY_DIAG_ERRORS > 0 )); then
        printf '%bИтог: ОШИБКА%b | ошибок: %s | предупреждений: %s\n' \
            "$RED" "$NC" "$HAPROXY_DIAG_ERRORS" "$HAPROXY_DIAG_WARNINGS"
        result=1
    elif (( HAPROXY_DIAG_WARNINGS > 0 )); then
        printf '%bИтог: РАБОТАЕТ С ПРЕДУПРЕЖДЕНИЯМИ%b | предупреждений: %s\n' \
            "$YELLOW" "$NC" "$HAPROXY_DIAG_WARNINGS"
    else
        printf '%bИтог: РАБОТАЕТ%b\n' "$GREEN" "$NC"
    fi
    rm -f "$routes_file"
    return "$result"
}

select_haproxy_route() {
    local routes_file="$1" mode="${2:-all}" choice index=0 route_index=0
    local port target_pool sni source_ip server_maxconn listen_ip send_proxy_v2 source_label target_label pool_count
    local -a route_keys=()

    printf '%s\n' "Выберите HAProxy-маршрут:" >&2
    while IFS=$'\t' read -r port target_pool sni source_ip server_maxconn listen_ip send_proxy_v2; do
        [[ -n "$port" ]] || continue
        route_index=$(( route_index + 1 ))
        if [[ "$mode" == "extra" && "$route_index" == 1 ]]; then
            continue
        fi
        listen_ip="$(haproxy_route_listen_ip "$listen_ip")"
        route_keys+=("${port}"$'\t'"${listen_ip}")
        index=$(( index + 1 ))
        source_label="$(haproxy_source_label "${source_ip:-default}")"
        pool_count="$(haproxy_target_pool_count "$target_pool" 2>/dev/null || printf '0')"
        if (( pool_count > 1 )); then
            target_label="пул ${pool_count} backend"
        else
            target_label="$target_pool"
        fi
        printf ' %d) %s:%s/tcp -> %s | выход %s | %s\n' \
            "$index" "$listen_ip" "$port" "$target_label" "$source_label" "$sni" >&2
    done < "$routes_file"

    if (( ${#route_keys[@]} == 0 )); then
        fail "Дополнительных HAProxy-маршрутов нет"
        return 1
    fi

    while true; do
        printf '> ' >&2
        read -r choice
        if [[ "$choice" =~ ^[0-9]+$ ]]; then
            choice=$(( 10#$choice ))
            if (( choice >= 1 && choice <= ${#route_keys[@]} )); then
                printf '%s\n' "${route_keys[$((choice - 1))]}"
                return 0
            fi
        fi
        fail "Неверный выбор"
    done
}

select_haproxy_route_for_delete() {
    local routes_file="$1" choice index selected_ip ip display_ip ports route_count
    local port target_pool sni source_ip server_maxconn listen_ip send_proxy_v2 source_label target_label pool_count
    local -a input_ips=() route_rows=()

    mapfile -t input_ips < <(
        awk -F '\t' 'NF >= 3 { print ($6 == "" ? "*" : $6) }' "$routes_file" |
            LC_ALL=C sort -uV
    )
    if (( ${#input_ips[@]} == 0 )); then
        fail "HAProxy-маршруты не найдены"
        return 1
    fi

    printf '%s\n' "Выберите входной IP маршрута:" >&2
    for index in "${!input_ips[@]}"; do
        ip="${input_ips[$index]}"
        display_ip="$ip"
        [[ "$ip" == "*" ]] && display_ip="* (все локальные IP)"
        ports="$(awk -F '\t' -v wanted="$ip" '
            {
                listen_ip = ($6 == "" ? "*" : $6)
                if (listen_ip == wanted && $1 ~ /^[0-9]+$/) print $1
            }
        ' "$routes_file" | sort -n -u | paste -sd ',' -)"
        ports="${ports//,/, }"
        route_count="$(awk -F '\t' -v wanted="$ip" '
            {
                listen_ip = ($6 == "" ? "*" : $6)
                if (listen_ip == wanted) count++
            }
            END { print count + 0 }
        ' "$routes_file")"
        printf ' %d) %s | портов: %s | маршрутов: %s\n' \
            "$(( index + 1 ))" "$display_ip" "${ports:-нет}" "$route_count" >&2
    done
    printf ' 0) Назад\n' >&2

    while true; do
        printf '> ' >&2
        read -r choice
        if [[ "$choice" == "0" ]]; then
            warn "Удаление отменено"
            return 1
        fi
        if [[ "$choice" =~ ^[0-9]+$ ]]; then
            choice=$((10#$choice))
            if (( choice >= 1 && choice <= ${#input_ips[@]} )); then
                selected_ip="${input_ips[$(( choice - 1 ))]}"
                break
            fi
        fi
        fail "Неверный выбор"
    done

    mapfile -t route_rows < <(awk -F '\t' -v wanted="$selected_ip" '
        {
            listen_ip = ($6 == "" ? "*" : $6)
            if (listen_ip == wanted) print
        }
    ' "$routes_file" | sort -s -t $'\t' -k1,1n)
    if (( ${#route_rows[@]} == 0 )); then
        fail "Маршруты для ${selected_ip} больше не найдены"
        return 1
    fi

    display_ip="$selected_ip"
    [[ "$selected_ip" == "*" ]] && display_ip="* (все локальные IP)"
    if (( ${#route_rows[@]} == 1 )); then
        IFS=$'\t' read -r port target_pool sni source_ip server_maxconn listen_ip send_proxy_v2 <<< "${route_rows[0]}"
        printf 'Единственный маршрут для %s: %s/tcp\n' "$display_ip" "$port" >&2
        printf '%s\t%s\n' "$port" "$selected_ip"
        return 0
    fi

    printf 'Выберите порт для %s:\n' "$display_ip" >&2
    for index in "${!route_rows[@]}"; do
        IFS=$'\t' read -r port target_pool sni source_ip server_maxconn listen_ip send_proxy_v2 <<< "${route_rows[$index]}"
        source_label="$(haproxy_source_label "${source_ip:-default}")"
        pool_count="$(haproxy_target_pool_count "$target_pool" 2>/dev/null || printf '0')"
        if (( pool_count > 1 )); then
            target_label="пул ${pool_count} backend"
        else
            target_label="$target_pool"
        fi
        printf ' %d) %s/tcp -> %s | выход %s | SNI: %s\n' \
            "$(( index + 1 ))" "$port" "$target_label" "$source_label" "$(haproxy_sni_label "$sni")" >&2
    done
    printf ' 0) Назад\n' >&2

    while true; do
        printf '> ' >&2
        read -r choice
        if [[ "$choice" == "0" ]]; then
            warn "Удаление отменено"
            return 1
        fi
        if [[ "$choice" =~ ^[0-9]+$ ]]; then
            choice=$((10#$choice))
            if (( choice >= 1 && choice <= ${#route_rows[@]} )); then
                IFS=$'\t' read -r port target_pool sni source_ip server_maxconn listen_ip send_proxy_v2 <<< "${route_rows[$(( choice - 1 ))]}"
                printf '%s\t%s\n' "$port" "$selected_ip"
                return 0
            fi
        fi
        fail "Неверный выбор"
    done
}

default_haproxy_extra_port() {
    local routes_file="$1" listen_ip base_port port
    listen_ip="$(normalize_haproxy_listen_ip "${2:-*}")" || return 1
    base_port="$(haproxy_base_port)"
    if [[ "$listen_ip" == "*" ]]; then
        port=8443
    else
        port="$base_port"
    fi
    while (( port <= 65535 )); do
        if ! haproxy_route_file_conflicts_endpoint "$routes_file" "$port" "$listen_ip"; then
            echo "$port"
            return 0
        fi
        port=$(( port + 1 ))
    done
    return 1
}

haproxy_tcp_port_listening() {
    local wanted="$1" listen_ip="${2:-*}"
    haproxy_tcp_port_socket_details "$wanted" "$listen_ip" 2>/dev/null |
        awk 'toupper($1) == "LISTEN" { found = 1 } END { exit found ? 0 : 1 }'
}

add_haproxy_route_with_source() {
    local routes_file="$1" source_ip="${2:-auto}"
    local listen_ip default_port port backend_target allowed_sni send_proxy_v2 next_file
    if [[ "$source_ip" == "auto" ]]; then
        source_ip="$(select_haproxy_route_source_ip "$routes_file")" || return 1
    fi
    source_ip="$(canonicalize_haproxy_runtime_source_ip "$source_ip" 2>/dev/null || true)"
    if [[ -z "$source_ip" ]]; then
        fail "Некорректный исходящий IP"
        return 1
    fi
    listen_ip="$(haproxy_route_ip_for_source "$source_ip" 2>/dev/null || true)"
    if [[ -z "$listen_ip" ]]; then
        fail "Для IP $(haproxy_source_label "$source_ip") нет рабочего локального source-route"
        return 1
    fi

    default_port="$(default_haproxy_extra_port "$routes_file" "$listen_ip")" || {
        fail "Нет свободного HAProxy-порта"
        return 1
    }

    while true; do
        port="$(ask_int "Входной HAProxy порт" "$default_port" 1 65535)"
        if haproxy_route_file_conflicts_endpoint "$routes_file" "$port" "$listen_ip"; then
            fail "HAProxy listener ${listen_ip}:${port} конфликтует с уже настроенным маршрутом"
            if [[ "$listen_ip" != "*" ]] && haproxy_route_file_has_endpoint "$routes_file" "$port" "*"; then
                warn "Сначала измени существующий *:${port} через пункт 1 и привяжи его к конкретному входному IP."
            fi
            continue
        fi
        if haproxy_tcp_port_listening "$port" "$listen_ip"; then
            fail "TCP listener ${listen_ip}:${port} уже занят другим процессом"
            continue
        fi
        break
    done

    backend_target="$(ask_haproxy_target_default "Backend IP или IP:порт")"
    allowed_sni="$(ask_haproxy_sni_list "Разрешенный SNI")"
    send_proxy_v2="$(ask_haproxy_send_proxy_v2 0)"
    next_file="$(mktemp)"
    cp "$routes_file" "$next_file"
    print_haproxy_route "$port" "$backend_target" "$allowed_sni" "$source_ip" \
        "$HAPROXY_BACKEND_MAXCONN" "$listen_ip" "$send_proxy_v2" >> "$next_file"

    if apply_haproxy_routes_config "$next_file"; then
        sync_haproxy_firewall "$next_file" "$routes_file"
        mv "$next_file" "$routes_file"
        ok "Добавлен HAProxy listener ${listen_ip}:${port}: ${backend_target}"
        ok "Входной и исходящий IP: ${listen_ip}"
        ok "maxconn backend: $(haproxy_server_maxconn_label "$HAPROXY_BACKEND_MAXCONN")"
        ok "send-proxy-v2: $(haproxy_send_proxy_v2_label "$send_proxy_v2")"
        return 0
    fi
    rm -f "$next_file"
    return 1
}

add_haproxy_route() {
    add_haproxy_route_with_source "$1" auto
}

add_haproxy_source_route() {
    add_haproxy_route_with_source "$1" auto
}

set_haproxy_pool_route() {
    local routes_file="$1" port="$2" source_ip="$3" allowed_sni="$4" server_maxconn="$5" target_pool="$6"
    local listen_ip="${7:-*}" send_proxy_v2="${8:-preserve}"
    local normalized_source_ip normalized_sni normalized_maxconn normalized_pool normalized_listen_ip normalized_send_proxy_v2
    local pool_count next_file sorted_file current_port current_pool current_sni current_source current_maxconn current_listen current_send_proxy_v2
    local replaced=0

    [[ "$port" =~ ^[0-9]+$ ]] || {
        fail "Некорректный входной HAProxy порт: ${port:-пусто}"
        return 1
    }
    port=$((10#$port))
    (( port >= 1 && port <= 65535 )) || {
        fail "HAProxy порт вне диапазона: $port"
        return 1
    }
    normalized_source_ip="$(canonicalize_haproxy_runtime_source_ip "$source_ip" 2>/dev/null || true)"
    normalized_sni="$(normalize_haproxy_sni_list "$allowed_sni" 2>/dev/null || true)"
    normalized_maxconn="$(normalize_haproxy_server_maxconn "$server_maxconn" 2>/dev/null || true)"
    normalized_pool="$(normalize_haproxy_target_pool "$target_pool" 2>/dev/null || true)"
    normalized_listen_ip="$(haproxy_route_ip_for_source "$normalized_source_ip" 2>/dev/null || true)"
    if [[ "$send_proxy_v2" == "preserve" && -n "$normalized_listen_ip" ]]; then
        send_proxy_v2="$(awk -F '\t' -v port="$port" -v listen_ip="$normalized_listen_ip" '
            {
                current_listen = ($6 == "" ? "*" : $6)
                if ($1 == port && current_listen == listen_ip) {
                    print ($7 == "" ? "0" : $7)
                    found = 1
                    exit
                }
            }
            END { if (!found) print "0" }
        ' "$routes_file")"
    fi
    normalized_send_proxy_v2="$(normalize_haproxy_send_proxy_v2 "$send_proxy_v2" 2>/dev/null || true)"
    pool_count="$(haproxy_target_pool_count "$normalized_pool" 2>/dev/null || true)"
    if [[ -z "$normalized_source_ip" || -z "$normalized_sni" || -z "$normalized_maxconn" || -z "$normalized_pool" || -z "$normalized_listen_ip" || -z "$normalized_send_proxy_v2" ]] ||
        (( pool_count < 2 )); then
        fail "Некорректный HAProxy backend-пул"
        return 1
    fi
    if [[ -z "$normalized_listen_ip" ]]; then
        fail "Для выходного IP $(haproxy_source_label "$normalized_source_ip") нет рабочего локального source-route"
        return 1
    fi
    if ! haproxy_route_file_has_endpoint "$routes_file" "$port" "$normalized_listen_ip"; then
        if haproxy_route_file_conflicts_endpoint "$routes_file" "$port" "$normalized_listen_ip"; then
            fail "Listener ${normalized_listen_ip}:${port} конфликтует с уже настроенным маршрутом"
            if [[ "$normalized_listen_ip" != "*" ]] && haproxy_route_file_has_endpoint "$routes_file" "$port" "*"; then
                warn "Сначала привяжи существующий *:${port} к конкретному входному IP."
            fi
            return 1
        fi
        if haproxy_tcp_port_listening "$port" "$normalized_listen_ip"; then
            fail "TCP listener ${normalized_listen_ip}:${port} уже занят другим процессом"
            return 1
        fi
    fi

    next_file="$(mktemp)"
    while IFS=$'\t' read -r current_port current_pool current_sni current_source current_maxconn current_listen current_send_proxy_v2; do
        [[ -n "$current_port" ]] || continue
        current_listen="$(haproxy_route_listen_ip "$current_listen")"
        if [[ "$current_port" == "$port" && "$current_listen" == "$normalized_listen_ip" ]]; then
            if (( replaced == 0 )); then
                print_haproxy_route "$port" "$normalized_pool" "$normalized_sni" \
                    "$normalized_source_ip" "$normalized_maxconn" "$normalized_listen_ip" "$normalized_send_proxy_v2" >> "$next_file"
            fi
            replaced=1
            continue
        fi
        print_haproxy_route "$current_port" "$current_pool" "$current_sni" \
            "${current_source:-default}" "${current_maxconn:-default}" "$current_listen" "${current_send_proxy_v2:-0}" >> "$next_file"
    done < "$routes_file"
    if (( replaced == 0 )); then
        print_haproxy_route "$port" "$normalized_pool" "$normalized_sni" \
            "$normalized_source_ip" "$normalized_maxconn" "$normalized_listen_ip" "$normalized_send_proxy_v2" >> "$next_file"
    fi
    sorted_file="$(mktemp)"
    sort -s -t $'\t' -k1,1n "$next_file" > "$sorted_file"
    mv "$sorted_file" "$next_file"

    if apply_haproxy_routes_config "$next_file"; then
        sync_haproxy_firewall "$next_file" "$routes_file"
        mv "$next_file" "$routes_file"
        ok "HAProxy пул ${normalized_listen_ip}:${port}/tcp: ${pool_count} backend"
        ok "Входной IP: ${normalized_listen_ip}"
        ok "SNI: $(haproxy_sni_label "$normalized_sni")"
        ok "Исходящий IP: $(haproxy_source_label "$normalized_source_ip")"
        ok "maxconn backend: $(haproxy_server_maxconn_label "$normalized_maxconn")"
        ok "send-proxy-v2: $(haproxy_send_proxy_v2_label "$normalized_send_proxy_v2")"
        return 0
    fi
    rm -f "$next_file"
    return 1
}

retarget_haproxy_wildcard_route() {
    local routes_file="$1" port="$2" listen_ip="$3"
    local current_port current_pool current_sni current_source current_maxconn current_listen current_send_proxy_v2
    local next_file moved=0

    listen_ip="$(normalize_haproxy_listen_ip "$listen_ip" 2>/dev/null || true)"
    [[ -n "$listen_ip" && "$listen_ip" != "*" ]] || {
        fail "Для переноса wildcard нужен конкретный входной IP"
        return 1
    }
    if haproxy_route_file_has_endpoint "$routes_file" "$port" "$listen_ip"; then
        fail "Маршрут ${listen_ip}:${port} уже существует"
        return 1
    fi

    next_file="$(mktemp)"
    while IFS=$'\t' read -r current_port current_pool current_sni current_source current_maxconn current_listen current_send_proxy_v2; do
        [[ -n "$current_port" ]] || continue
        current_listen="$(haproxy_route_listen_ip "$current_listen")"
        if [[ "$current_port" == "$port" && "$current_listen" == "*" ]]; then
            current_listen="$listen_ip"
            moved=1
        fi
        print_haproxy_route "$current_port" "$current_pool" "$current_sni" \
            "${current_source:-default}" "${current_maxconn:-default}" "$current_listen" "${current_send_proxy_v2:-0}" >> "$next_file"
    done < "$routes_file"

    if (( moved == 0 )); then
        rm -f "$next_file"
        return 0
    fi
    mv "$next_file" "$routes_file"
    stage "Переношу wildcard *:${port} на ${listen_ip}:${port}"
}

add_haproxy_pool_route() {
    local routes_file="$1" listen_ip default_port port source_ip allowed_sni server_maxconn send_proxy_v2 raw_targets target_pool

    source_ip="$(select_haproxy_route_source_ip "$routes_file")" || return 1
    listen_ip="$(haproxy_route_ip_for_source "$source_ip")" || return 1
    default_port="$(default_haproxy_extra_port "$routes_file" "$listen_ip")" || {
        fail "Нет свободного HAProxy-порта"
        return 1
    }
    port="$(ask_int "Входной HAProxy порт" "$default_port" 1 65535)"
    allowed_sni="$(ask_haproxy_sni_list "Разрешенный SNI")"
    send_proxy_v2="$(ask_haproxy_send_proxy_v2 0)"
    server_maxconn="$HAPROXY_BACKEND_MAXCONN"
    raw_targets="$(ask_text "Backend IP[:порт] через пробел или запятую")"
    target_pool="$(normalize_haproxy_target_pool "$raw_targets" 2>/dev/null || true)"
    [[ -n "$target_pool" ]] || {
        fail "Не удалось прочитать список backend"
        return 1
    }
    set_haproxy_pool_route "$routes_file" "$port" "$source_ip" "$allowed_sni" "$server_maxconn" "$target_pool" "$listen_ip" "$send_proxy_v2"
}

set_haproxy_pool_route_cli() {
    header
    require_haproxy_mode
    need_root
    local port="${1:-}" source_ip="${2:-}" allowed_sni="${3:-}" server_maxconn="${4:-}"
    local routes_file target target_pool="" listen_ip="" normalized_listen_ip requested_listen_ip
    local listen_ip_explicit=0

    if (( $# < 4 )) || [[ -z "$port" || -z "$source_ip" || -z "$server_maxconn" ]]; then
        fail "Использование: haproxy-pool-set PORT SOURCE_IP SNI|any MAXCONN [--listen-ip IP] BACKEND1 BACKEND2 [...]"
        return 1
    fi
    shift 4
    case "${1:-}" in
        --listen-ip)
            (( $# >= 2 )) || {
                fail "После --listen-ip нужен конкретный локальный IPv4"
                return 1
            }
            listen_ip="$2"
            listen_ip_explicit=1
            shift 2
            ;;
        --listen-ip=*)
            listen_ip="${1#*=}"
            listen_ip_explicit=1
            shift
            ;;
    esac
    if (( $# < 2 )); then
        fail "Использование: haproxy-pool-set PORT SOURCE_IP SNI|any MAXCONN [--listen-ip IP] BACKEND1 BACKEND2 [...]"
        return 1
    fi
    source_ip="$(canonicalize_haproxy_runtime_source_ip "$source_ip" 2>/dev/null || true)"
    normalized_listen_ip="$(haproxy_route_ip_for_source "$source_ip" 2>/dev/null || true)"
    [[ -n "$normalized_listen_ip" ]] || {
        fail "Для исходящего IP ${source_ip:-пусто} нет рабочего локального source-route"
        return 1
    }
    if (( listen_ip_explicit == 1 )); then
        requested_listen_ip="$(normalize_haproxy_listen_ip "$listen_ip" 2>/dev/null || true)"
        if [[ "$requested_listen_ip" != "$normalized_listen_ip" ]]; then
            fail "Раздельные входной и выходной IP больше не поддерживаются: нужен ${normalized_listen_ip}"
            return 1
        fi
    fi
    listen_ip="$normalized_listen_ip"
    for target in "$@"; do
        target_pool+="${target_pool:+,}${target}"
    done
    if ! "${SUDO[@]}" test -s /etc/haproxy/haproxy.cfg 2>/dev/null; then
        fail "HAProxy ещё не настроен. Сначала запусти пункт HAProxy в меню."
        return 1
    fi

    routes_file="$(mktemp)"
    extract_haproxy_routes > "$routes_file"
    if [[ ! -s "$routes_file" ]]; then
        rm -f "$routes_file"
        fail "Текущий HAProxy config не распознан. Конфиг не изменён."
        return 1
    fi
    if [[ "$listen_ip" != "*" ]] &&
        haproxy_route_file_has_endpoint "$routes_file" "$port" "*"; then
        if ! retarget_haproxy_wildcard_route "$routes_file" "$port" "$listen_ip"; then
            rm -f "$routes_file"
            return 1
        fi
    fi
    if set_haproxy_pool_route "$routes_file" "$port" "$source_ip" "$allowed_sni" \
        "$server_maxconn" "$target_pool" "$listen_ip"; then
        rm -f "$routes_file"
        return 0
    fi
    rm -f "$routes_file"
    return 1
}

collapse_haproxy_routes_to_pool() {
    local routes_file="$1" start_port="$2" end_port="$3" source_ip="$4" allowed_sni="$5"
    local server_maxconn="$6" target_pool="$7" requested_listen_ip="${8:-}" filtered_file removed_count
    local normalized_source_ip listen_ip canonical_file

    normalized_source_ip="$(canonicalize_haproxy_runtime_source_ip "$source_ip" 2>/dev/null || true)"
    listen_ip="$(haproxy_route_ip_for_source "$normalized_source_ip" 2>/dev/null || true)"
    [[ -n "$normalized_source_ip" && -n "$listen_ip" ]] || {
        fail "Для выбранного IP нет рабочего локального source-route"
        return 1
    }
    if [[ -n "$requested_listen_ip" && "$requested_listen_ip" != "*" ]]; then
        requested_listen_ip="$(normalize_haproxy_listen_ip "$requested_listen_ip" 2>/dev/null || true)"
        if [[ "$requested_listen_ip" != "$listen_ip" ]]; then
            fail "Раздельные входной и выходной IP больше не поддерживаются: нужен ${listen_ip}"
            return 1
        fi
    fi

    [[ "$start_port" =~ ^[0-9]+$ && "$end_port" =~ ^[0-9]+$ ]] || {
        fail "Некорректный диапазон HAProxy-портов"
        return 1
    }
    start_port=$((10#$start_port))
    end_port=$((10#$end_port))
    (( start_port >= 1 && end_port >= start_port && end_port <= 65535 )) || {
        fail "Некорректный диапазон HAProxy-портов: ${start_port}-${end_port}"
        return 1
    }

    # Canonicalize first so legacy *:PORT + default/source routes cannot survive
    # a pool rewrite and recreate the old split input/output model.
    canonical_file="$(mktemp)"
    if ! build_haproxy_upgraded_routes "$routes_file" "$canonical_file"; then
        rm -f "$canonical_file"
        return 1
    fi
    cp "$canonical_file" "$routes_file"
    rm -f "$canonical_file"

    removed_count="$(awk -F '\t' -v start="$start_port" -v end="$end_port" -v listen_ip="$listen_ip" '
        {
            current_listen = ($6 == "" ? "*" : $6)
            if ($1 > start && $1 <= end && current_listen == listen_ip) count++
        }
        END { print count + 0 }
    ' "$routes_file")"
    filtered_file="$(mktemp)"
    awk -F '\t' -v start="$start_port" -v end="$end_port" -v listen_ip="$listen_ip" '
        {
            current_listen = ($6 == "" ? "*" : $6)
            if (!($1 > start && $1 <= end && current_listen == listen_ip)) print
        }
    ' "$routes_file" > "$filtered_file"

    if set_haproxy_pool_route "$filtered_file" "$start_port" "$normalized_source_ip" "$allowed_sni" "$server_maxconn" "$target_pool" "$listen_ip"; then
        sync_haproxy_firewall "$filtered_file" "$routes_file"
        mv "$filtered_file" "$routes_file"
        ok "Порты ${listen_ip}:${start_port}-${end_port} собраны в один пул на ${listen_ip}:${start_port}/tcp"
        ok "Удалено лишних listener-портов: ${removed_count}"
        return 0
    fi
    rm -f "$filtered_file"
    return 1
}

collapse_haproxy_pool_cli() {
    header
    require_haproxy_mode
    need_root
    local start_port="${1:-}" end_port="${2:-}" source_ip="${3:-}" allowed_sni="${4:-}" server_maxconn="${5:-}"
    local routes_file target target_pool=""
    shift $(( $# >= 5 ? 5 : $# ))

    if [[ -z "$start_port" || -z "$end_port" || -z "$source_ip" || -z "$server_maxconn" || $# -lt 2 ]]; then
        fail "Использование: haproxy-pool-collapse START_PORT END_PORT SOURCE_IP SNI|any MAXCONN BACKEND1 BACKEND2 [...]"
        return 1
    fi
    for target in "$@"; do
        target_pool+="${target_pool:+,}${target}"
    done
    if ! "${SUDO[@]}" test -s /etc/haproxy/haproxy.cfg 2>/dev/null; then
        fail "HAProxy ещё не настроен. Сначала запусти пункт HAProxy в меню."
        return 1
    fi

    routes_file="$(mktemp)"
    extract_haproxy_routes > "$routes_file"
    if [[ ! -s "$routes_file" ]]; then
        rm -f "$routes_file"
        fail "Текущий HAProxy config не распознан. Конфиг не изменён."
        return 1
    fi
    if collapse_haproxy_routes_to_pool "$routes_file" "$start_port" "$end_port" "$source_ip" \
        "$allowed_sni" "$server_maxconn" "$target_pool"; then
        rm -f "$routes_file"
        return 0
    fi
    rm -f "$routes_file"
    return 1
}

set_haproxy_sequential_routes() {
    local routes_file="$1" start_port="$2" source_ip="$3" allowed_sni="$4" server_maxconn="$5" target_pool="$6"
    local listen_ip="${7:-*}" send_proxy_v2="${8:-preserve}"
    local normalized_source_ip normalized_sni normalized_maxconn normalized_pool normalized_listen_ip normalized_send_proxy_v2
    local route_count end_port port target index next_file sorted_file route_send_proxy_v2
    local existing_port _existing_pool _existing_sni _existing_source _existing_maxconn existing_listen existing_send_proxy_v2 endpoint_key
    local -a targets=()
    local -A existing_proxy_v2_by_endpoint=() existing_endpoint=() existing_port_any=() existing_port_wildcard=()

    [[ "$start_port" =~ ^[0-9]+$ ]] || {
        fail "Некорректный первый HAProxy порт: ${start_port:-пусто}"
        return 1
    }
    start_port=$((10#$start_port))
    normalized_source_ip="$(canonicalize_haproxy_runtime_source_ip "$source_ip" 2>/dev/null || true)"
    normalized_sni="$(normalize_haproxy_sni_list "$allowed_sni" 2>/dev/null || true)"
    normalized_maxconn="$(normalize_haproxy_server_maxconn "$server_maxconn" 2>/dev/null || true)"
    normalized_pool="$(normalize_haproxy_target_pool "$target_pool" 2>/dev/null || true)"
    normalized_listen_ip="$(haproxy_route_ip_for_source "$normalized_source_ip" 2>/dev/null || true)"
    while IFS=$'\t' read -r existing_port _existing_pool _existing_sni _existing_source _existing_maxconn existing_listen existing_send_proxy_v2; do
        [[ "$existing_port" =~ ^[0-9]+$ ]] || continue
        existing_listen="${existing_listen:-*}"
        endpoint_key="${existing_listen}|${existing_port}"
        existing_endpoint[$endpoint_key]=1
        existing_port_any[$existing_port]=1
        [[ "$existing_listen" == "*" ]] && existing_port_wildcard[$existing_port]=1
        if [[ "${existing_send_proxy_v2:-0}" == "1" ]]; then
            existing_proxy_v2_by_endpoint[$endpoint_key]=1
        else
            existing_proxy_v2_by_endpoint[$endpoint_key]=0
        fi
    done < "$routes_file"
    if [[ "$send_proxy_v2" == "preserve" ]]; then
        normalized_send_proxy_v2="preserve"
    else
        normalized_send_proxy_v2="$(normalize_haproxy_send_proxy_v2 "$send_proxy_v2" 2>/dev/null || true)"
    fi
    [[ -n "$normalized_source_ip" && -n "$normalized_sni" && -n "$normalized_maxconn" && -n "$normalized_pool" && -n "$normalized_listen_ip" && -n "$normalized_send_proxy_v2" ]] || {
        fail "Некорректные параметры массовых HAProxy-маршрутов"
        return 1
    }
    IFS=',' read -r -a targets <<< "$normalized_pool"
    route_count="${#targets[@]}"
    (( route_count > 0 )) || {
        fail "Список backend пуст"
        return 1
    }
    end_port=$(( start_port + route_count - 1 ))
    (( start_port >= 1 && end_port <= 65535 )) || {
        fail "Диапазон HAProxy портов ${start_port}-${end_port} выходит за 1-65535"
        return 1
    }
    if [[ -z "$normalized_listen_ip" ]]; then
        fail "Для выходного IP $(haproxy_source_label "$normalized_source_ip") нет рабочего локального source-route"
        return 1
    fi
    for (( port = start_port; port <= end_port; port++ )); do
        endpoint_key="${normalized_listen_ip}|${port}"
        if [[ -z "${existing_endpoint[$endpoint_key]+x}" ]]; then
            if [[ "$normalized_listen_ip" == "*" && -n "${existing_port_any[$port]+x}" ]] ||
                [[ "$normalized_listen_ip" != "*" && -n "${existing_port_wildcard[$port]+x}" ]]; then
                fail "Listener ${normalized_listen_ip}:${port} конфликтует с уже настроенным маршрутом"
                if [[ "$normalized_listen_ip" != "*" && -n "${existing_port_wildcard[$port]+x}" ]]; then
                    warn "Сначала привяжи существующий *:${port} к конкретному входному IP."
                fi
                return 1
            fi
            if haproxy_tcp_port_listening "$port" "$normalized_listen_ip"; then
                fail "TCP listener ${normalized_listen_ip}:${port} уже занят другим процессом"
                return 1
            fi
        fi
    done

    next_file="$(mktemp)"
    awk -F '\t' -v start_port="$start_port" -v end_port="$end_port" -v listen_ip="$normalized_listen_ip" '
        {
            current_listen = ($6 == "" ? "*" : $6)
            if (!($1 >= start_port && $1 <= end_port && current_listen == listen_ip)) print
        }
    ' "$routes_file" > "$next_file"
    for index in "${!targets[@]}"; do
        port=$(( start_port + index ))
        target="${targets[$index]}"
        route_send_proxy_v2="$normalized_send_proxy_v2"
        if [[ "$route_send_proxy_v2" == "preserve" ]]; then
            endpoint_key="${normalized_listen_ip}|${port}"
            route_send_proxy_v2="${existing_proxy_v2_by_endpoint[$endpoint_key]:-0}"
        fi
        print_haproxy_route "$port" "$target" "$normalized_sni" \
            "$normalized_source_ip" "$normalized_maxconn" "$normalized_listen_ip" "$route_send_proxy_v2" >> "$next_file"
    done
    sorted_file="$(mktemp)"
    sort -t $'\t' -k1,1n "$next_file" > "$sorted_file"
    mv "$sorted_file" "$next_file"

    if apply_haproxy_routes_config "$next_file"; then
        sync_haproxy_firewall "$next_file" "$routes_file"
        mv "$next_file" "$routes_file"
        ok "HAProxy маршруты ${start_port}-${end_port}: ${route_count} backend"
        ok "Входной IP: ${normalized_listen_ip}"
        ok "SNI: $(haproxy_sni_label "$normalized_sni")"
        ok "Исходящий IP: $(haproxy_source_label "$normalized_source_ip")"
        ok "maxconn backend: $(haproxy_server_maxconn_label "$normalized_maxconn")"
        if [[ "$normalized_send_proxy_v2" == "preserve" ]]; then
            ok "send-proxy-v2: сохранено для каждого существующего маршрута; новые OFF"
        else
            ok "send-proxy-v2: $(haproxy_send_proxy_v2_label "$normalized_send_proxy_v2")"
        fi
        return 0
    fi
    rm -f "$next_file"
    return 1
}

add_haproxy_sequential_routes() {
    local routes_file="$1" listen_ip default_port start_port source_ip allowed_sni server_maxconn send_proxy_v2 raw_targets target_pool

    source_ip="$(select_haproxy_route_source_ip "$routes_file")" || return 1
    listen_ip="$(haproxy_route_ip_for_source "$source_ip")" || return 1
    default_port="$(default_haproxy_extra_port "$routes_file" "$listen_ip")" || {
        fail "Нет свободного HAProxy-порта"
        return 1
    }
    start_port="$(ask_int "Первый входной HAProxy порт" "$default_port" 1 65535)"
    allowed_sni="$(ask_haproxy_sni_list "Разрешенный SNI")"
    send_proxy_v2="$(ask_haproxy_send_proxy_v2 0)"
    server_maxconn="$HAPROXY_BACKEND_MAXCONN"
    raw_targets="$(ask_text "Backend IP[:порт] по порядку через пробел или запятую")"
    target_pool="$(normalize_haproxy_target_pool "$raw_targets" 2>/dev/null || true)"
    [[ -n "$target_pool" ]] || {
        fail "Не удалось прочитать список backend"
        return 1
    }
    set_haproxy_sequential_routes "$routes_file" "$start_port" "$source_ip" "$allowed_sni" "$server_maxconn" "$target_pool" "$listen_ip" "$send_proxy_v2"
}

set_haproxy_sequential_routes_cli() {
    header
    require_haproxy_mode
    need_root
    local start_port="${1:-}" source_ip="${2:-}" allowed_sni="${3:-}" server_maxconn="${4:-}"
    local routes_file target target_pool="" listen_ip
    shift $(( $# >= 4 ? 4 : $# ))

    if [[ -z "$start_port" || -z "$source_ip" || -z "$server_maxconn" || $# -lt 1 ]]; then
        fail "Использование: haproxy-routes-set START_PORT SOURCE_IP SNI|any MAXCONN BACKEND [...]"
        return 1
    fi
    for target in "$@"; do
        target_pool+="${target_pool:+,}${target}"
    done
    if ! "${SUDO[@]}" test -s /etc/haproxy/haproxy.cfg 2>/dev/null; then
        fail "HAProxy ещё не настроен. Сначала запусти пункт HAProxy в меню."
        return 1
    fi

    routes_file="$(mktemp)"
    extract_haproxy_routes > "$routes_file"
    if [[ ! -s "$routes_file" ]]; then
        rm -f "$routes_file"
        fail "Текущий HAProxy config не распознан. Конфиг не изменён."
        return 1
    fi
    listen_ip="$(haproxy_default_listen_ip_for_source "$source_ip")"
    if set_haproxy_sequential_routes "$routes_file" "$start_port" "$source_ip" "$allowed_sni" "$server_maxconn" "$target_pool" "$listen_ip"; then
        rm -f "$routes_file"
        return 0
    fi
    rm -f "$routes_file"
    return 1
}

edit_haproxy_route() {
    local routes_file="$1" selection port current_listen current_line current_target_pool current_sni
    local current_source current_maxconn current_send_proxy_v2 source_ip listen_ip backend_target_pool allowed_sni send_proxy_v2 next_file filtered_file
    local row_port row_pool row_sni row_source row_maxconn row_listen row_send_proxy_v2 replaced=0

    selection="$(select_haproxy_route "$routes_file")" || return 1
    IFS=$'\t' read -r port current_listen <<< "$selection"
    current_line="$(awk -F '\t' -v port="$port" -v listen_ip="$current_listen" '
        {
            current_listen = ($6 == "" ? "*" : $6)
            if ($1 == port && current_listen == listen_ip) { print; exit }
        }
    ' "$routes_file")"
    IFS=$'\t' read -r _ current_target_pool current_sni current_source current_maxconn _ current_send_proxy_v2 <<< "$current_line"
    current_source="$(normalize_haproxy_source_ip "${current_source:-default}")"
    current_maxconn="$(normalize_haproxy_server_maxconn "${current_maxconn:-default}")"
    current_send_proxy_v2="$(normalize_haproxy_send_proxy_v2 "${current_send_proxy_v2:-0}")"

    source_ip="$(select_haproxy_route_source_ip "$routes_file" "$current_source")" || return 1
    listen_ip="$(haproxy_route_ip_for_source "$source_ip" 2>/dev/null || true)"
    [[ -n "$listen_ip" ]] || {
        fail "Для выбранного IP нет рабочего source-route"
        return 1
    }
    filtered_file="$(mktemp)"
    awk -F '\t' -v port="$port" -v listen_ip="$current_listen" '
        {
            current_listen = ($6 == "" ? "*" : $6)
            if (!($1 == port && current_listen == listen_ip)) print
        }
    ' "$routes_file" > "$filtered_file"
    if haproxy_route_file_conflicts_endpoint "$filtered_file" "$port" "$listen_ip"; then
        rm -f "$filtered_file"
        fail "Listener ${listen_ip}:${port} конфликтует с другим маршрутом"
        return 1
    fi
    rm -f "$filtered_file"

    backend_target_pool="$(ask_haproxy_target_pool_default "Backend IP[:порт] или список через запятую" "$current_target_pool")"
    allowed_sni="$(ask_haproxy_sni_list "Разрешенный SNI" "$current_sni")"
    send_proxy_v2="$(ask_haproxy_send_proxy_v2 "$current_send_proxy_v2")"
    next_file="$(mktemp)"
    while IFS=$'\t' read -r row_port row_pool row_sni row_source row_maxconn row_listen row_send_proxy_v2; do
        [[ -n "$row_port" ]] || continue
        row_listen="$(haproxy_route_listen_ip "$row_listen")"
        if [[ "$row_port" == "$port" && "$row_listen" == "$current_listen" ]]; then
            print_haproxy_route "$port" "$backend_target_pool" "$allowed_sni" \
                "$source_ip" "$HAPROXY_BACKEND_MAXCONN" "$listen_ip" "$send_proxy_v2" >> "$next_file"
            replaced=1
        else
            print_haproxy_route "$row_port" "$row_pool" "$row_sni" \
                "${row_source:-default}" "${row_maxconn:-default}" "$row_listen" "${row_send_proxy_v2:-0}" >> "$next_file"
        fi
    done < "$routes_file"
    if (( replaced == 0 )); then
        rm -f "$next_file"
        fail "Выбранный HAProxy-маршрут больше не найден"
        return 1
    fi

    if apply_haproxy_routes_config "$next_file"; then
        sync_haproxy_firewall "$next_file" "$routes_file"
        mv "$next_file" "$routes_file"
        ok "Маршрут ${listen_ip}:${port}/tcp обновлён"
        ok "Входной и исходящий IP: ${listen_ip}"
        return 0
    fi
    rm -f "$next_file"
    return 1
}

replace_all_haproxy_sni() {
    local routes_file="$1" current_sni allowed_sni next_file route_count
    current_sni="$(awk -F '\t' 'NF >= 3 { print $3; exit }' "$routes_file")"
    allowed_sni="$(ask_haproxy_sni_list "Новый SNI для всех HAProxy-портов" "$current_sni")"
    next_file="$(mktemp)"
    awk -F '\t' -v OFS='\t' -v sni="$allowed_sni" '
        NF >= 3 {
            $3 = sni
            if (NF < 4) $4 = "default"
            print
            next
        }
        { print }
    ' "$routes_file" > "$next_file"

    if apply_haproxy_routes_config "$next_file"; then
        sync_haproxy_firewall "$next_file" "$routes_file"
        mv "$next_file" "$routes_file"
        route_count="$(haproxy_route_count "$routes_file")"
        ok "SNI заменён на всех HAProxy-маршрутах: ${route_count}"
        ok "Разрешенный SNI: $(haproxy_sni_label "$allowed_sni")"
        return 0
    fi
    rm -f "$next_file"
    return 1
}

haproxy_route_file_uses_input_ip() {
    local routes_file="$1" wanted_ip="$2"
    [[ "$wanted_ip" == "*" ]] && return 0
    awk -F '\t' -v wanted="$wanted_ip" '
        {
            listen_ip = ($6 == "" ? "*" : $6)
            if (listen_ip == "*" || listen_ip == wanted) found = 1
        }
        END { exit found ? 0 : 1 }
    ' "$routes_file"
}

reconcile_haproxy_bandwidth_after_route_change() {
    local routes_file="$1" previous_routes_file="$2"
    local previous_limits next_limits ip rate removed_count=0 ports_changed=0
    local removed_ips=""

    "${SUDO[@]}" test -s "$HAPROXY_BANDWIDTH_CONFIG" 2>/dev/null || return 0
    haproxy_route_port_sets_equal "$routes_file" "$previous_routes_file" || ports_changed=1

    previous_limits="$(mktemp)"
    next_limits="$(mktemp)"
    if ! load_haproxy_bandwidth_config "$previous_limits"; then
        rm -f "$previous_limits" "$next_limits"
        return 1
    fi

    while IFS=$'\t' read -r ip rate; do
        [[ -n "$ip" ]] || continue
        if haproxy_route_file_uses_input_ip "$routes_file" "$ip"; then
            printf '%s\t%s\n' "$ip" "$rate" >> "$next_limits"
        else
            removed_count=$(( removed_count + 1 ))
            removed_ips+="${removed_ips:+, }${ip}"
        fi
    done < "$previous_limits"

    if (( removed_count == 0 && ports_changed == 0 )); then
        rm -f "$previous_limits" "$next_limits"
        return 0
    fi
    require_local_haproxy_bandwidth_manager || {
        rm -f "$previous_limits" "$next_limits"
        return 1
    }

    if (( removed_count > 0 )); then
        if ! commit_haproxy_bandwidth_config "$previous_limits" "$next_limits" 1; then
            rm -f "$previous_limits" "$next_limits"
            warn "Маршруты применены, но лимиты HAProxy не синхронизировались. Запусти haproxy-limit-status."
            return 1
        fi
        ok "Удалены лимиты IP без маршрутов: ${removed_ips}"
    elif ! reapply_haproxy_bandwidth_limits; then
        rm -f "$previous_limits" "$next_limits"
        warn "Маршруты применены, но локальные tc-фильтры не синхронизировались. Запусти haproxy-limit-status."
        return 1
    fi

    rm -f "$previous_limits" "$next_limits"
}

delete_haproxy_route() {
    local routes_file="$1" selection port listen_ip next_file answer before_count after_count
    local current_line target_pool sni source_ip server_maxconn _current_listen target_label pool_count

    before_count="$(haproxy_route_count "$routes_file")"
    if (( before_count <= 1 )); then
        fail "Нельзя удалить последний HAProxy-маршрут. Сначала добавь замену."
        return 1
    fi

    selection="$(select_haproxy_route_for_delete "$routes_file")" || return 1
    IFS=$'\t' read -r port listen_ip <<< "$selection"
    current_line="$(awk -F '\t' -v port="$port" -v listen_ip="$listen_ip" '
        {
            current_listen = ($6 == "" ? "*" : $6)
            if ($1 == port && current_listen == listen_ip) { print; exit }
        }
    ' "$routes_file")"
    if [[ -z "$current_line" ]]; then
        fail "Выбранный HAProxy-маршрут больше не найден"
        return 1
    fi
    IFS=$'\t' read -r _ target_pool sni source_ip server_maxconn _current_listen _send_proxy_v2 <<< "$current_line"
    pool_count="$(haproxy_target_pool_count "$target_pool" 2>/dev/null || printf '0')"
    if (( pool_count > 1 )); then
        target_label="пул ${pool_count} backend"
    else
        target_label="$target_pool"
    fi

    echo
    warn "Будет удалён маршрут ${listen_ip}:${port}/tcp -> ${target_label}"
    printf 'SNI: %s | Выход: %s\n' "$(haproxy_sni_label "$sni")" "$(haproxy_source_label "${source_ip:-default}")"
    echo -ne "${YELLOW}Удалить этот маршрут? [y/N]:${NC} "
    read -r answer
    if [[ "${answer,,}" != "y" && "${answer,,}" != "yes" && "${answer,,}" != "д" && "${answer,,}" != "да" ]]; then
        warn "Удаление отменено"
        return 0
    fi

    next_file="$(mktemp)"
    awk -F '\t' -v port="$port" -v listen_ip="$listen_ip" '
        {
            current_listen = ($6 == "" ? "*" : $6)
            if (!($1 == port && current_listen == listen_ip)) print
        }
    ' "$routes_file" > "$next_file"
    after_count="$(haproxy_route_count "$next_file")"
    if (( after_count != before_count - 1 )); then
        rm -f "$next_file"
        fail "Безопасная проверка удаления не прошла. HAProxy config не изменён."
        return 1
    fi

    # Defer tc reconciliation until the route and a possibly stale per-IP
    # limit have reached their final state. This prevents two full tc passes.
    if apply_haproxy_routes_config "$next_file" 1; then
        sync_haproxy_firewall "$next_file" "$routes_file"
        reconcile_haproxy_bandwidth_after_route_change "$next_file" "$routes_file" || true
        mv "$next_file" "$routes_file"
        ok "HAProxy listener ${listen_ip}:${port}/tcp удалён"
        ok "Осталось HAProxy-маршрутов: ${after_count}"
        return 0
    fi
    rm -f "$next_file"
    return 1
}

HAPROXY_UPGRADE_MOVED=0

build_haproxy_upgraded_routes() {
    local routes_file="$1" output_file="$2"
    local port target_pool sni source_ip server_maxconn listen_ip send_proxy_v2
    local desired_source desired_listen key sorted_file route_count=0
    local -A emitted=()

    HAPROXY_UPGRADE_MOVED=0
    : > "$output_file"
    while IFS=$'\t' read -r port target_pool sni source_ip server_maxconn listen_ip send_proxy_v2; do
        [[ "$port" =~ ^[0-9]+$ ]] || {
            fail "Некорректный HAProxy-порт в существующем config: ${port:-пусто}"
            return 1
        }
        port=$((10#$port))
        (( port >= 1 && port <= 65535 )) || return 1
        listen_ip="$(normalize_haproxy_listen_ip "${listen_ip:-*}" 2>/dev/null || true)"
        source_ip="$(canonicalize_haproxy_runtime_source_ip "${source_ip:-default}" 2>/dev/null || true)"
        [[ -n "$listen_ip" && -n "$source_ip" ]] || {
            fail "Некорректный IP у HAProxy-маршрута на порту ${port}"
            return 1
        }

        # An exact listener is the public endpoint clients already use, so keep
        # it and align egress to it. A legacy wildcard is pinned to its source.
        if [[ "$listen_ip" != "*" ]]; then
            desired_source="$(canonicalize_haproxy_runtime_source_ip "$listen_ip" 2>/dev/null || true)"
        else
            desired_source="$source_ip"
        fi
        desired_listen="$(haproxy_route_ip_for_source "$desired_source" 2>/dev/null || true)"
        if [[ -z "$desired_source" || -z "$desired_listen" ]]; then
            fail "Маршрут ${listen_ip}:${port}: для выбранного IP нет рабочего source-route"
            return 1
        fi
        key="${desired_listen}|${port}"
        if [[ -n "${emitted[$key]+x}" ]]; then
            fail "Миграция создаёт дубликат ${desired_listen}:${port}; текущий config не изменён"
            return 1
        fi
        emitted[$key]=1
        if [[ "$listen_ip" != "$desired_listen" || "$source_ip" != "$desired_source" ]]; then
            HAPROXY_UPGRADE_MOVED=$(( HAPROXY_UPGRADE_MOVED + 1 ))
        fi
        print_haproxy_route "$port" "$target_pool" "$sni" "$desired_source" \
            "$HAPROXY_BACKEND_MAXCONN" "$desired_listen" "${send_proxy_v2:-0}" >> "$output_file" || {
            fail "Не удалось канонизировать HAProxy-маршрут ${desired_listen}:${port}"
            return 1
        }
        route_count=$(( route_count + 1 ))
    done < "$routes_file"

    (( route_count > 0 )) || {
        fail "HAProxy-маршруты не найдены"
        return 1
    }
    sorted_file="$(mktemp)"
    LC_ALL=C sort -s -t $'\t' -k6,6V -k1,1n "$output_file" > "$sorted_file"
    mv "$sorted_file" "$output_file"
}

upgrade_haproxy_routes_transaction() {
    local routes_file="$1" candidate_file rendered_file parsed_file

    candidate_file="$(mktemp)"
    rendered_file="$(mktemp)"
    parsed_file="$(mktemp)"
    if ! build_haproxy_upgraded_routes "$routes_file" "$candidate_file" ||
        ! render_haproxy_routes_config "$candidate_file" "$rendered_file"; then
        rm -f "$candidate_file" "$rendered_file" "$parsed_file"
        return 1
    fi
    ensure_haproxy_package || {
        rm -f "$candidate_file" "$rendered_file" "$parsed_file"
        return 1
    }
    if ! "${SUDO[@]}" haproxy -c -f "$rendered_file" >> "$LOG_FILE" 2>&1; then
        rm -f "$candidate_file" "$rendered_file" "$parsed_file"
        fail "HAProxy upgrade candidate не прошёл haproxy -c; текущий config не изменён"
        return 1
    fi
    extract_haproxy_routes "$rendered_file" > "$parsed_file"
    if ! haproxy_routes_round_trip_equal "$candidate_file" "$parsed_file"; then
        rm -f "$candidate_file" "$rendered_file" "$parsed_file"
        fail "HAProxy upgrade candidate не прошёл round-trip; текущий config не изменён"
        return 1
    fi
    rm -f "$rendered_file" "$parsed_file"

    if apply_haproxy_routes_config "$candidate_file"; then
        sync_haproxy_firewall "$candidate_file" "$routes_file"
        cp "$candidate_file" "$routes_file"
        rm -f "$candidate_file"
        ok "HAProxy обновлён: маршруты сохранены, input=output, backend maxconn=${HAPROXY_BACKEND_MAXCONN}"
        (( HAPROXY_UPGRADE_MOVED == 0 )) || ok "Приведено к единому IP маршрутов: ${HAPROXY_UPGRADE_MOVED}"
        return 0
    fi
    rm -f "$candidate_file"
    return 1
}

upgrade_haproxy_if_configured() {
    local routes_file rc

    haproxy_mode_supported || return 0
    "${SUDO[@]}" test -s "$HAPROXY_CONFIG_FILE" 2>/dev/null || return 0
    routes_file="$(mktemp)"
    extract_haproxy_routes > "$routes_file"
    if [[ ! -s "$routes_file" ]]; then
        rm -f "$routes_file"
        warn "HAProxy config существует, но маршруты не распознаны; автоматическая миграция пропущена"
        return 0
    fi
    if upgrade_haproxy_routes_transaction "$routes_file"; then
        rc=0
    else
        rc=$?
    fi
    rm -f "$routes_file"
    return "$rc"
}

update_haproxy_existing_config() {
    header
    require_haproxy_mode
    need_root
    local routes_file rc

    if ! "${SUDO[@]}" test -s "$HAPROXY_CONFIG_FILE" 2>/dev/null; then
        warn "HAProxy config ещё не создан. Открой меню HAProxy и выбери «Добавить маршрут»."
        return 0
    fi

    routes_file="$(mktemp)"
    extract_haproxy_routes > "$routes_file"
    if [[ ! -s "$routes_file" ]]; then
        rm -f "$routes_file"
        fail "Не смог распознать маршруты в текущем HAProxy config. Конфиг не изменён."
        return 1
    fi
    if upgrade_haproxy_routes_transaction "$routes_file"; then
        rc=0
    else
        rc=$?
    fi
    rm -f "$routes_file"
    return "$rc"
}

HAPROXY_PREPARE_IP_COUNT=0
HAPROXY_PREPARE_IP_LIST=""
HAPROXY_PREPARE_WILDCARDS=0
HAPROXY_PREPARE_ROUTES_BEFORE=0
HAPROXY_PREPARE_ROUTES_AFTER=0

build_haproxy_multi_ip_routes() {
    local routes_file="$1" output_file="$2" row ip interface
    local port target_pool sni source_ip server_maxconn listen_ip send_proxy_v2 key sorted_file
    local -a input_rows=() input_ips=()
    local -A emitted=()

    HAPROXY_PREPARE_IP_COUNT=0
    HAPROXY_PREPARE_IP_LIST=""
    HAPROXY_PREPARE_WILDCARDS=0
    HAPROXY_PREPARE_ROUTES_BEFORE=0
    HAPROXY_PREPARE_ROUTES_AFTER=0
    mapfile -t input_rows < <(list_haproxy_preparable_input_ips)
    for row in "${input_rows[@]}"; do
        IFS=$'\t' read -r ip interface <<< "$row"
        validate_ipv4 "$ip" || continue
        input_ips+=("$ip")
        HAPROXY_PREPARE_IP_LIST+="${HAPROXY_PREPARE_IP_LIST:+, }${ip} (${interface})"
    done
    HAPROXY_PREPARE_IP_COUNT="${#input_ips[@]}"
    (( HAPROXY_PREPARE_IP_COUNT > 0 )) || {
        fail "Не найдено рабочих IPv4 для адресных HAProxy listener"
        return 1
    }

    : > "$output_file"
    while IFS=$'\t' read -r port target_pool sni source_ip server_maxconn listen_ip send_proxy_v2; do
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        HAPROXY_PREPARE_ROUTES_BEFORE=$(( HAPROXY_PREPARE_ROUTES_BEFORE + 1 ))
        listen_ip="$(haproxy_route_listen_ip "$listen_ip")"
        if [[ "$listen_ip" == "*" ]]; then
            HAPROXY_PREPARE_WILDCARDS=$(( HAPROXY_PREPARE_WILDCARDS + 1 ))
            for ip in "${input_ips[@]}"; do
                key="${ip}|${port}"
                if [[ -n "${emitted[$key]+x}" ]]; then
                    fail "Нельзя безопасно разложить *:${port}: маршрут ${ip}:${port} уже существует"
                    return 1
                fi
                emitted[$key]=1
                print_haproxy_route "$port" "$target_pool" "$sni" \
                    "${source_ip:-default}" "${server_maxconn:-default}" "$ip" "${send_proxy_v2:-0}" >> "$output_file"
                HAPROXY_PREPARE_ROUTES_AFTER=$(( HAPROXY_PREPARE_ROUTES_AFTER + 1 ))
            done
        else
            key="${listen_ip}|${port}"
            if [[ -n "${emitted[$key]+x}" ]]; then
                fail "В конфиге повторяется HAProxy listener ${listen_ip}:${port}"
                return 1
            fi
            emitted[$key]=1
            print_haproxy_route "$port" "$target_pool" "$sni" \
                "${source_ip:-default}" "${server_maxconn:-default}" "$listen_ip" "${send_proxy_v2:-0}" >> "$output_file"
            HAPROXY_PREPARE_ROUTES_AFTER=$(( HAPROXY_PREPARE_ROUTES_AFTER + 1 ))
        fi
    done < "$routes_file"

    (( HAPROXY_PREPARE_ROUTES_BEFORE > 0 && HAPROXY_PREPARE_ROUTES_AFTER > 0 )) || {
        fail "HAProxy маршруты для подготовки не найдены"
        return 1
    }
    sorted_file="$(mktemp)"
    sort -s -t $'\t' -k1,1n "$output_file" > "$sorted_file"
    mv "$sorted_file" "$output_file"
}

prepare_haproxy_multi_ip_config() {
    local routes_file="$1" next_file preview_file parsed_file answer current_valid=1 runtime_valid=1 missing=""

    ensure_haproxy_package
    next_file="$(mktemp)"
    preview_file="$(mktemp)"
    parsed_file="$(mktemp)"
    if ! "${SUDO[@]}" haproxy -c -f "$HAPROXY_CONFIG_FILE" >> "$LOG_FILE" 2>&1; then
        current_valid=0
    fi
    if command_exists ss && command_exists systemctl; then
        missing="$(haproxy_missing_listener_ports "$routes_file")"
        if [[ -n "$missing" ]] || ! run_systemctl_bounded 3 is-active --quiet haproxy 2>/dev/null; then
            runtime_valid=0
        fi
    fi
    if ! build_haproxy_multi_ip_routes "$routes_file" "$next_file" ||
        ! render_haproxy_routes_config "$next_file" "$preview_file" ||
        ! "${SUDO[@]}" haproxy -c -f "$preview_file" >> "$LOG_FILE" 2>&1; then
        rm -f "$next_file" "$preview_file" "$parsed_file"
        fail "Подготовленный HAProxy config не прошёл проверку. Текущий config не изменён."
        return 1
    fi
    extract_haproxy_routes "$preview_file" > "$parsed_file"
    if ! haproxy_routes_round_trip_equal "$next_file" "$parsed_file"; then
        rm -f "$next_file" "$preview_file" "$parsed_file"
        fail "Round-trip проверка HAProxy config не прошла. Текущий config не изменён."
        return 1
    fi

    echo
    echo -e "${BOLD}${PURPLE}[ ПРОВЕРКА И ПОДГОТОВКА HAPROXY ]${NC}"
    if (( current_valid == 1 )); then
        ok "Текущий config: синтаксис OK"
    else
        warn "Текущий config: haproxy -c вернул ошибку; исправленный candidate валиден"
    fi
    if (( runtime_valid == 1 )); then
        ok "Runtime: service и listener в норме"
    else
        missing="${missing//$'\n'/, }"
        warn "Runtime: HAProxy не active или не слушает ${missing:-настроенные адреса}"
    fi
    ok "Рабочие входные IP: ${HAPROXY_PREPARE_IP_COUNT}"
    printf '  %s\n' "$HAPROXY_PREPARE_IP_LIST"
    ok "Маршрутов сейчас: ${HAPROXY_PREPARE_ROUTES_BEFORE}"
    ok "Wildcard listener: ${HAPROXY_PREPARE_WILDCARDS}"
    ok "Маршрутов после подготовки: ${HAPROXY_PREPARE_ROUTES_AFTER}"
    ok "Candidate: haproxy -c и round-trip OK"

    if (( HAPROXY_PREPARE_WILDCARDS == 0 && current_valid == 1 && runtime_valid == 1 )); then
        rm -f "$next_file" "$preview_file" "$parsed_file"
        ok "Config уже подготовлен для отдельных IP:порт. Изменения не нужны."
        return 0
    fi

    echo
    if (( HAPROXY_PREPARE_WILDCARDS > 0 )); then
        warn "Wildcard будет разложен на отдельный listener для каждого указанного IP."
    else
        warn "Валидный candidate будет применён для восстановления runtime HAProxy."
    fi
    echo -ne "${YELLOW}Создать backup и применить candidate? [y/N]:${NC} "
    read -r answer
    if [[ "${answer,,}" != "y" && "${answer,,}" != "yes" && "${answer,,}" != "д" && "${answer,,}" != "да" ]]; then
        rm -f "$next_file" "$preview_file" "$parsed_file"
        warn "Изменения отменены"
        return 0
    fi

    if apply_haproxy_routes_config "$next_file"; then
        sync_haproxy_firewall "$next_file" "$routes_file"
        mv "$next_file" "$routes_file"
        rm -f "$preview_file" "$parsed_file"
        ok "HAProxy подготовлен для независимых IP:порт"
        return 0
    fi
    rm -f "$next_file" "$preview_file" "$parsed_file"
    return 1
}

HAPROXY_PIN_WILDCARDS=0
HAPROXY_PIN_PREVIEW=""

build_haproxy_source_pinned_routes() {
    local routes_file="$1" output_file="$2"
    local port target_pool sni source_ip server_maxconn listen_ip send_proxy_v2 target_ip key default_ip
    local -A exact_endpoints=() emitted_endpoints=()

    HAPROXY_PIN_WILDCARDS=0
    HAPROXY_PIN_PREVIEW=""
    default_ip="$(haproxy_default_source_ip)"
    : > "$output_file"

    while IFS=$'\t' read -r port target_pool sni source_ip server_maxconn listen_ip send_proxy_v2; do
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        listen_ip="$(haproxy_route_listen_ip "$listen_ip")" || {
            rm -f "$output_file"
            fail "Некорректный входной IP у маршрута на порту ${port}"
            return 1
        }
        [[ "$listen_ip" != "*" ]] || continue
        key="${listen_ip}|${port}"
        if [[ -n "${exact_endpoints[$key]+x}" ]]; then
            rm -f "$output_file"
            fail "В конфиге повторяется HAProxy listener ${listen_ip}:${port}"
            return 1
        fi
        exact_endpoints[$key]=1
    done < "$routes_file"

    while IFS=$'\t' read -r port target_pool sni source_ip server_maxconn listen_ip send_proxy_v2; do
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        source_ip="$(normalize_haproxy_source_ip "${source_ip:-default}" 2>/dev/null || true)"
        server_maxconn="$(normalize_haproxy_server_maxconn "${server_maxconn:-default}" 2>/dev/null || true)"
        listen_ip="$(haproxy_route_listen_ip "$listen_ip" 2>/dev/null || true)"
        if [[ -z "$source_ip" || -z "$server_maxconn" || -z "$listen_ip" ]]; then
            rm -f "$output_file"
            fail "Некорректный HAProxy-маршрут на порту ${port}"
            return 1
        fi

        if [[ "$listen_ip" == "*" ]]; then
            target_ip="$source_ip"
            [[ "$target_ip" != "default" ]] || target_ip="$default_ip"
            if ! validate_ipv4 "$target_ip" || ! haproxy_input_ip_available "$target_ip"; then
                rm -f "$output_file"
                fail "Нельзя перенести *:${port}: выходной IP ${target_ip:-не определён} не найден на машине"
                return 1
            fi
            key="${target_ip}|${port}"
            if [[ -n "${exact_endpoints[$key]+x}" || -n "${emitted_endpoints[$key]+x}" ]]; then
                rm -f "$output_file"
                fail "Нельзя перенести *:${port}: точечный listener ${target_ip}:${port} уже существует"
                return 1
            fi
            listen_ip="$target_ip"
            HAPROXY_PIN_WILDCARDS=$(( HAPROXY_PIN_WILDCARDS + 1 ))
            HAPROXY_PIN_PREVIEW+="${HAPROXY_PIN_PREVIEW:+$'\n'}*:${port} -> ${listen_ip}:${port}"
        fi

        key="${listen_ip}|${port}"
        if [[ -n "${emitted_endpoints[$key]+x}" ]]; then
            rm -f "$output_file"
            fail "В candidate повторяется HAProxy listener ${listen_ip}:${port}"
            return 1
        fi
        emitted_endpoints[$key]=1
        print_haproxy_route "$port" "$target_pool" "$sni" \
            "$source_ip" "$server_maxconn" "$listen_ip" "${send_proxy_v2:-0}" >> "$output_file" || {
            rm -f "$output_file"
            fail "Не удалось собрать точечный маршрут ${listen_ip}:${port}"
            return 1
        }
    done < "$routes_file"

    [[ -s "$output_file" ]] || {
        fail "HAProxy маршруты не найдены"
        return 1
    }
}

pin_haproxy_wildcards_to_source_ips() {
    local routes_file="$1" next_file preview_file parsed_file answer

    ensure_haproxy_package || return 1
    next_file="$(mktemp)"
    preview_file="$(mktemp)"
    parsed_file="$(mktemp)"
    if ! build_haproxy_source_pinned_routes "$routes_file" "$next_file"; then
        rm -f "$next_file" "$preview_file" "$parsed_file"
        return 1
    fi
    if (( HAPROXY_PIN_WILDCARDS == 0 )); then
        rm -f "$next_file" "$preview_file" "$parsed_file"
        ok "FULL-биндов нет: все HAProxy listener уже точечные"
        return 0
    fi
    if ! render_haproxy_routes_config "$next_file" "$preview_file" ||
        ! "${SUDO[@]}" haproxy -c -f "$preview_file" >> "$LOG_FILE" 2>&1; then
        rm -f "$next_file" "$preview_file" "$parsed_file"
        fail "Точечный HAProxy candidate не прошёл проверку. Текущий config не изменён."
        return 1
    fi
    extract_haproxy_routes "$preview_file" > "$parsed_file"
    if ! haproxy_routes_round_trip_equal "$next_file" "$parsed_file"; then
        rm -f "$next_file" "$preview_file" "$parsed_file"
        fail "Round-trip проверка точечного HAProxy candidate не прошла."
        return 1
    fi

    echo
    echo -e "${BOLD}${PURPLE}[ FULL -> ТОЧЕЧНЫЕ БИНДЫ ]${NC}"
    printf ' %s\n' "${HAPROXY_PIN_PREVIEW//$'\n'/$'\n '}"
    echo
    warn "Каждый FULL listener будет закреплён за его настроенным выходным IP."
    warn "Перед применением создаётся backup; при ошибке запуска вернётся предыдущий config."
    echo -ne "${YELLOW}Перенести ${HAPROXY_PIN_WILDCARDS} FULL-биндов? [y/N]:${NC} "
    read -r answer
    if [[ "${answer,,}" != "y" && "${answer,,}" != "yes" && "${answer,,}" != "д" && "${answer,,}" != "да" ]]; then
        rm -f "$next_file" "$preview_file" "$parsed_file"
        warn "Изменения отменены"
        return 0
    fi

    if apply_haproxy_routes_config "$next_file"; then
        sync_haproxy_firewall "$next_file" "$routes_file"
        mv "$next_file" "$routes_file"
        rm -f "$preview_file" "$parsed_file"
        ok "FULL-бинды перенесены на точечные IP:порт"
        check_haproxy_bindings "$routes_file" || true
        return 0
    fi
    rm -f "$next_file" "$preview_file" "$parsed_file"
    return 1
}

restore_haproxy_backup() {
    local routes_file="$1" choice answer selected index status current_copy current_routes restored_routes
    local -a backups=()

    mapfile -t backups < <(list_haproxy_backups | head -n 10)
    if (( ${#backups[@]} == 0 )); then
        fail "Сохранённых HAProxy backup нет: ${HAPROXY_BACKUP_DIR}"
        return 1
    fi

    echo
    echo -e "${BOLD}${PURPLE}[ HAPROXY BACKUPS ]${NC}"
    for index in "${!backups[@]}"; do
        status="checksum FAIL"
        verify_haproxy_backup "${backups[$index]}" && status="checksum OK"
        printf ' %d) %s | %s\n' "$(( index + 1 ))" "$(basename "${backups[$index]}")" "$status"
    done
    echo " 0) Назад"
    while true; do
        echo -ne "${PURPLE}>${NC} ${BOLD}Выберите backup:${NC} "
        read -r choice
        [[ "$choice" == "0" ]] && return 0
        if [[ "$choice" =~ ^[0-9]+$ ]]; then
            choice=$((10#$choice))
            if (( choice >= 1 && choice <= ${#backups[@]} )); then
                selected="${backups[$(( choice - 1 ))]}"
                break
            fi
        fi
        fail "Неверный выбор"
    done

    if ! verify_haproxy_backup "$selected"; then
        fail "Checksum backup не совпадает. Восстановление отменено."
        return 1
    fi
    ensure_haproxy_package
    if ! "${SUDO[@]}" haproxy -c -f "$selected" >> "$LOG_FILE" 2>&1; then
        fail "Backup не прошёл haproxy -c. Восстановление отменено."
        return 1
    fi

    restored_routes="$(mktemp)"
    current_copy="$(mktemp)"
    current_routes="$(mktemp)"
    extract_haproxy_routes "$selected" > "$restored_routes"
    if [[ ! -s "$restored_routes" ]]; then
        rm -f "$restored_routes" "$current_copy" "$current_routes"
        fail "Маршруты в backup не распознаны. Восстановление отменено."
        return 1
    fi

    echo
    warn "Будет восстановлен точный config: ${selected}"
    echo -ne "${YELLOW}Создать backup текущего config и продолжить? [y/N]:${NC} "
    read -r answer
    if [[ "${answer,,}" != "y" && "${answer,,}" != "yes" && "${answer,,}" != "д" && "${answer,,}" != "да" ]]; then
        rm -f "$restored_routes" "$current_copy" "$current_routes"
        warn "Восстановление отменено"
        return 0
    fi

    if ! "${SUDO[@]}" cat "$HAPROXY_CONFIG_FILE" > "$current_copy" || [[ ! -s "$current_copy" ]]; then
        rm -f "$restored_routes" "$current_copy" "$current_routes"
        fail "Не удалось сохранить текущий config перед восстановлением"
        return 1
    fi
    extract_haproxy_routes "$current_copy" > "$current_routes"
    if ! create_haproxy_persistent_backup "before-restore" "$HAPROXY_CONFIG_FILE" ||
        ! reserve_haproxy_route_ports "$restored_routes"; then
        rm -f "$restored_routes" "$current_copy" "$current_routes"
        return 1
    fi

    stage "Восстанавливаю HAProxy backup"
    if ! "${SUDO[@]}" install -m 0644 "$selected" "$HAPROXY_CONFIG_FILE" >> "$LOG_FILE" 2>&1 ||
        ! reload_haproxy_gracefully "$restored_routes"; then
        "${SUDO[@]}" cp -a "$HAPROXY_CONFIG_FILE" "${HAPROXY_CONFIG_FILE}.kto.failed-restore" >> "$LOG_FILE" 2>&1 || true
        warn "Backup не запустился, возвращаю config, который был до восстановления."
        "${SUDO[@]}" install -m 0644 "$current_copy" "$HAPROXY_CONFIG_FILE" >> "$LOG_FILE" 2>&1 || true
        if [[ -s "$current_routes" ]]; then
            start_haproxy_cleanly "$current_routes" || true
        else
            run_systemctl_bounded 15 restart haproxy >> "$LOG_FILE" 2>&1 || true
        fi
        rm -f "$restored_routes" "$current_copy" "$current_routes"
        fail "Восстановление не применено; предыдущий config возвращён"
        return 1
    fi

    sync_haproxy_firewall "$restored_routes" "$current_routes"
    cp "$restored_routes" "$routes_file"
    rm -f "$restored_routes" "$current_copy" "$current_routes"
    ok "HAProxy backup восстановлен"
    ok "Config: ${selected}"
    ok "Backup предыдущего config: ${HAPROXY_LAST_BACKUP}"
}

haproxy_menu() {
    header
    require_haproxy_mode
    need_root
    local routes_file choice
    routes_file="$(mktemp)"

    if "${SUDO[@]}" test -s "$HAPROXY_CONFIG_FILE" 2>/dev/null; then
        extract_haproxy_routes > "$routes_file"
        if [[ ! -s "$routes_file" ]]; then
            rm -f "$routes_file"
            fail "Текущий HAProxy config не распознан. Автоматически перезаписывать его не буду."
            return 1
        fi
    fi

    while true; do
        header
        print_haproxy_routes "$routes_file"
        echo
        echo -e "1) Изменить маршрут, backend, SNI или IP"
        echo -e "2) Добавить маршрут (входной IP = выходному IP)"
        echo -e "3) Удалить маршрут"
        echo -e "4) Заменить SNI у всех маршрутов"
        echo -e "5) Обновить HAProxy, сохранив маршруты"
        echo -e "6) Добавить или заменить backend-пул"
        echo -e "7) Массово добавить backend по следующим портам"
        echo -e "8) Ограничить скорость по входному IP"
        echo -e "9) Восстановить HAProxy backup"
        echo -e "10) Проверить бинды"
        echo -e "11) Полная диагностика HAProxy"
        echo -e "12) Аварийно стабилизировать HAProxy"
        echo -e "0) Назад"
        echo -e "${PURPLE}==========================================${NC}"
        echo -ne "${PURPLE}>${NC} ${BOLD}Выберите действие:${NC} "
        read -r choice
        case "$choice" in
            1) edit_haproxy_route "$routes_file" || true ;;
            2) add_haproxy_route "$routes_file" || true ;;
            3) delete_haproxy_route "$routes_file" || true ;;
            4) replace_all_haproxy_sni "$routes_file" || true ;;
            5)
                if [[ -s "$routes_file" ]]; then
                    upgrade_haproxy_routes_transaction "$routes_file" || true
                else
                    warn "Сначала добавь хотя бы один маршрут"
                fi
                ;;
            6) add_haproxy_pool_route "$routes_file" || true ;;
            7) add_haproxy_sequential_routes "$routes_file" || true ;;
            8) haproxy_bandwidth_menu || true ;;
            9) restore_haproxy_backup "$routes_file" || true ;;
            10) check_haproxy_bindings "$routes_file" || true ;;
            11) diagnose_haproxy || true ;;
            12) stabilize_haproxy_interactive || true ;;
            0)
                rm -f "$routes_file"
                return 0
                ;;
            *) fail "Неверный выбор" ;;
        esac
        echo
        echo -ne "${PURPLE}>${NC} Нажмите Enter, чтобы продолжить..."
        read -r _
    done
}

install_haproxy() {
    haproxy_menu
}

mobile443_lte_ports_from_routes() {
    local routes_file="$1"
    awk -F '\t' '$1 ~ /^[0-9]+$/ && $1 >= 1 && $1 <= 65535 { print $1 }' "$routes_file" 2>/dev/null |
        sort -n -u | paste -sd ' ' -
}

mobile443_lte_configured() {
    "${SUDO[@]}" test -s "$MOBILE443_CONFIG" 2>/dev/null &&
        "${SUDO[@]}" grep -Eq '^ENABLE_MOBILE_ALLOW=(true|"true")$' "$MOBILE443_CONFIG" 2>/dev/null
}

mobile443_lte_ports_include() {
    local ports="$1" wanted="$2"
    [[ " $ports " == *" $wanted "* ]]
}

install_mobile443_manager() {
    install_asset_file scripts/kto-mobile443.sh "$MOBILE443_MANAGER" 0755
}

ensure_mobile443_manager() {
    if "${SUDO[@]}" test -x "$MOBILE443_MANAGER" 2>/dev/null &&
        "${SUDO[@]}" grep -Fqx "MOBILE443_BUILD=\"${SCRIPT_BUILD}\"" "$MOBILE443_MANAGER" 2>/dev/null; then
        return 0
    fi
    install_mobile443_manager
}

enable_mobile443_lte() {
    header
    require_whitelist_mode
    need_root
    local routes_file ports ssh_port

    routes_file="$(mktemp)"
    extract_haproxy_routes > "$routes_file"
    ports="$(mobile443_lte_ports_from_routes "$routes_file" 2>/dev/null || true)"
    rm -f "$routes_file"
    if [[ -z "$ports" ]]; then
        fail "Сначала настрой хотя бы один HAProxy-порт"
        return 1
    fi

    ssh_port="$(detect_ssh_port)"
    if mobile443_lte_ports_include "$ports" "$ssh_port"; then
        fail "Порт ${ssh_port} занят SSH. LTE-фильтр не включён, чтобы не потерять доступ к серверу."
        return 1
    fi

    if ! whitelist_ipv6_disabled; then
        stage "Отключаю IPv6 для whitelist-режима"
        opt_ipv6_mode_guard
        if ! whitelist_ipv6_disabled; then
            fail "Не удалось отключить IPv6. LTE-фильтр не включён."
            return 1
        fi
    fi

    if ! install_mobile443_manager; then
        return 1
    fi
    if ! "${SUDO[@]}" "$MOBILE443_MANAGER" enable "$ports"; then
        return 1
    fi
}

disable_mobile443_lte() {
    header
    require_whitelist_mode
    need_root
    ensure_mobile443_manager || return 1
    "${SUDO[@]}" "$MOBILE443_MANAGER" disable
}

print_mobile443_lte_status() {
    ensure_mobile443_manager || return 1
    "${SUDO[@]}" "$MOBILE443_MANAGER" status
}

show_mobile443_lte_status() {
    header
    require_whitelist_mode
    need_root
    print_mobile443_lte_status
}

mobile443_lte_menu() {
    require_whitelist_mode
    need_root
    local choice
    if ! mobile443_lte_configured; then
        enable_mobile443_lte || true
        return 0
    fi

    while true; do
        header
        if ! print_mobile443_lte_status; then
            fail "Не удалось прочитать состояние LTE-фильтра"
            return 0
        fi
        echo
        echo -e "1) Обновить списки и синхронизировать HAProxy-порты"
        echo -e "2) Выключить режим \"Только LTE\""
        echo -e "0) Назад"
        echo -e "${PURPLE}==========================================${NC}"
        echo -ne "${PURPLE}>${NC} ${BOLD}Выберите действие:${NC} "
        read -r choice
        case "$choice" in
            1) enable_mobile443_lte || true; return 0 ;;
            2)
                echo -ne "${YELLOW}Отключить LTE-фильтр? [y/N]:${NC} "
                read -r choice
                if [[ "${choice,,}" == "y" || "${choice,,}" == "yes" ]]; then
                    disable_mobile443_lte || true
                    return 0
                fi
                ;;
            0) return 0 ;;
            *) fail "Неверный выбор" ;;
        esac
    done
}

write_stats_collector_script() {
    install_asset_file scripts/kto-stats-collector.py "$STATS_COLLECTOR_SCRIPT" 0755
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

    local listen_host listen_port secret bot_token chat_id allowed_user stale_sec wl_offline_confirm_sec bl_stale_sec bl_offline_confirm_sec bl_stale_fallback_sec bl_push_interval_sec push_miss_window_sec push_miss_threshold push_miss_alert_cooldown scan_alert_delta expected_nodes daily_report_time ssh_base_allowed_ips dashboard_enabled dashboard_token dashboard_effective_token dashboard_host existing_config=0
    local ip_limit_enabled ip_limit_source ip_limit_max_ips ip_limit_max_events ip_limit_window_sec ip_limit_alert_cooldown ip_limit_scan_sec ip_limit_alert_threshold ip_limit_alert_top ip_limit_enforce_enabled ip_limit_drop_enabled ip_limit_penalty_sec
    local remna_api_url remna_api_token remna_api_cache_sec remna_api_insecure remna_node_alert_enabled remna_node_poll_sec remna_offline_guard_enabled remna_offline_state_max_age_sec remna_offline_log_grace_sec asn_lookup_enabled asn_cache_sec asn_timeout_sec
    local safe_host safe_port safe_secret safe_bot safe_chat safe_user safe_stale safe_wl_offline_confirm safe_bl_stale safe_bl_offline_confirm safe_bl_stale_fallback safe_bl_push_interval safe_push_miss_window safe_push_miss_threshold safe_push_miss_cooldown safe_scan_alert_delta safe_expected safe_tz safe_daily safe_ssh_base_allowed_ips safe_dashboard_enabled safe_dashboard_token
    local safe_ip_limit_enabled safe_ip_limit_source safe_ip_limit_max_ips safe_ip_limit_max_events safe_ip_limit_window safe_ip_limit_cooldown safe_ip_limit_scan_sec safe_ip_limit_alert_threshold safe_ip_limit_alert_top safe_ip_limit_enforce_enabled safe_ip_limit_drop_enabled safe_ip_limit_penalty_sec
    local safe_remna_api_url safe_remna_api_token safe_remna_api_cache_sec safe_remna_api_insecure safe_remna_node_alert_enabled safe_remna_node_poll_sec safe_remna_offline_guard_enabled safe_remna_offline_state_max_age_sec safe_remna_offline_log_grace_sec safe_asn_lookup_enabled safe_asn_cache_sec safe_asn_timeout_sec

    if "${SUDO[@]}" test -s "$STATS_COLLECTOR_CONFIG" 2>/dev/null; then
        listen_host="$(config_get KTO_COLLECTOR_LISTEN_HOST "$STATS_COLLECTOR_CONFIG")"
        listen_port="$(config_get KTO_COLLECTOR_LISTEN_PORT "$STATS_COLLECTOR_CONFIG")"
        secret="$(config_get KTO_COLLECTOR_SECRET "$STATS_COLLECTOR_CONFIG")"
        bot_token="$(config_get KTO_COLLECTOR_BOT_TOKEN "$STATS_COLLECTOR_CONFIG")"
        chat_id="$(config_get KTO_COLLECTOR_CHAT_ID "$STATS_COLLECTOR_CONFIG")"
        allowed_user="$(config_get KTO_COLLECTOR_ALLOWED_USER_ID "$STATS_COLLECTOR_CONFIG")"
        stale_sec="$(config_get KTO_COLLECTOR_STALE_SEC "$STATS_COLLECTOR_CONFIG")"
        wl_offline_confirm_sec="$(config_get KTO_COLLECTOR_WL_OFFLINE_CONFIRM_SEC "$STATS_COLLECTOR_CONFIG")"
        bl_stale_sec="$(config_get KTO_COLLECTOR_BL_STALE_SEC "$STATS_COLLECTOR_CONFIG")"
        bl_offline_confirm_sec="$(config_get KTO_COLLECTOR_BL_OFFLINE_CONFIRM_SEC "$STATS_COLLECTOR_CONFIG")"
        bl_stale_fallback_sec="$(config_get KTO_COLLECTOR_BL_STALE_FALLBACK_SEC "$STATS_COLLECTOR_CONFIG")"
        bl_push_interval_sec="$(config_get KTO_COLLECTOR_BL_PUSH_INTERVAL_SEC "$STATS_COLLECTOR_CONFIG")"
        push_miss_window_sec="$(config_get KTO_COLLECTOR_PUSH_MISS_WINDOW_SEC "$STATS_COLLECTOR_CONFIG")"
        push_miss_threshold="$(config_get KTO_COLLECTOR_PUSH_MISS_THRESHOLD "$STATS_COLLECTOR_CONFIG")"
        push_miss_alert_cooldown="$(config_get KTO_COLLECTOR_PUSH_MISS_ALERT_COOLDOWN "$STATS_COLLECTOR_CONFIG")"
        scan_alert_delta="$(config_get KTO_COLLECTOR_SCAN_ALERT_DELTA "$STATS_COLLECTOR_CONFIG")"
        expected_nodes="$(config_get KTO_COLLECTOR_EXPECTED_NODES "$STATS_COLLECTOR_CONFIG")"
        daily_report_time="$(config_get KTO_COLLECTOR_DAILY_REPORT_TIME "$STATS_COLLECTOR_CONFIG")"
        ssh_base_allowed_ips="$(config_get KTO_COLLECTOR_SSH_BASE_ALLOWED_IPS "$STATS_COLLECTOR_CONFIG")"
        dashboard_enabled="$(config_get KTO_COLLECTOR_DASHBOARD_ENABLED "$STATS_COLLECTOR_CONFIG")"
        dashboard_token="$(config_get KTO_COLLECTOR_DASHBOARD_TOKEN "$STATS_COLLECTOR_CONFIG")"
        ip_limit_enabled="$(config_get KTO_COLLECTOR_IP_LIMIT_ENABLED "$STATS_COLLECTOR_CONFIG")"
        ip_limit_source="$(config_get KTO_COLLECTOR_IP_LIMIT_SOURCE "$STATS_COLLECTOR_CONFIG")"
        ip_limit_max_ips="$(config_get KTO_COLLECTOR_IP_LIMIT_MAX_IPS "$STATS_COLLECTOR_CONFIG")"
        ip_limit_max_events="$(config_get KTO_COLLECTOR_IP_LIMIT_MAX_EVENTS "$STATS_COLLECTOR_CONFIG")"
        ip_limit_window_sec="$(config_get KTO_COLLECTOR_IP_LIMIT_WINDOW_SEC "$STATS_COLLECTOR_CONFIG")"
        ip_limit_alert_cooldown="$(config_get KTO_COLLECTOR_IP_LIMIT_ALERT_COOLDOWN "$STATS_COLLECTOR_CONFIG")"
        ip_limit_scan_sec="$(config_get KTO_COLLECTOR_IP_LIMIT_SCAN_SEC "$STATS_COLLECTOR_CONFIG")"
        ip_limit_alert_threshold="$(config_get KTO_COLLECTOR_IP_LIMIT_ALERT_THRESHOLD "$STATS_COLLECTOR_CONFIG")"
        ip_limit_alert_top="$(config_get KTO_COLLECTOR_IP_LIMIT_ALERT_TOP "$STATS_COLLECTOR_CONFIG")"
        ip_limit_enforce_enabled="$(config_get KTO_COLLECTOR_IP_LIMIT_ENFORCE_ENABLED "$STATS_COLLECTOR_CONFIG")"
        ip_limit_drop_enabled="$(config_get KTO_COLLECTOR_IP_LIMIT_DROP_ENABLED "$STATS_COLLECTOR_CONFIG")"
        ip_limit_penalty_sec="$(config_get KTO_COLLECTOR_IP_LIMIT_PENALTY_SEC "$STATS_COLLECTOR_CONFIG")"
        remna_api_url="$(config_get KTO_COLLECTOR_REMNA_API_URL "$STATS_COLLECTOR_CONFIG")"
        remna_api_token="$(config_get KTO_COLLECTOR_REMNA_API_TOKEN "$STATS_COLLECTOR_CONFIG")"
        remna_api_cache_sec="$(config_get KTO_COLLECTOR_REMNA_API_CACHE_SEC "$STATS_COLLECTOR_CONFIG")"
        remna_api_insecure="$(config_get KTO_COLLECTOR_REMNA_API_INSECURE "$STATS_COLLECTOR_CONFIG")"
        remna_node_alert_enabled="$(config_get KTO_COLLECTOR_REMNA_NODE_ALERT_ENABLED "$STATS_COLLECTOR_CONFIG")"
        remna_node_poll_sec="$(config_get KTO_COLLECTOR_REMNA_NODE_POLL_SEC "$STATS_COLLECTOR_CONFIG")"
        remna_offline_guard_enabled="$(config_get KTO_COLLECTOR_REMNA_OFFLINE_GUARD_ENABLED "$STATS_COLLECTOR_CONFIG")"
        remna_offline_state_max_age_sec="$(config_get KTO_COLLECTOR_REMNA_OFFLINE_STATE_MAX_AGE_SEC "$STATS_COLLECTOR_CONFIG")"
        remna_offline_log_grace_sec="$(config_get KTO_COLLECTOR_REMNA_OFFLINE_LOG_GRACE_SEC "$STATS_COLLECTOR_CONFIG")"
        asn_lookup_enabled="$(config_get KTO_COLLECTOR_ASN_LOOKUP_ENABLED "$STATS_COLLECTOR_CONFIG")"
        asn_cache_sec="$(config_get KTO_COLLECTOR_ASN_CACHE_SEC "$STATS_COLLECTOR_CONFIG")"
        asn_timeout_sec="$(config_get KTO_COLLECTOR_ASN_TIMEOUT_SEC "$STATS_COLLECTOR_CONFIG")"
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
        wl_offline_confirm_sec="${wl_offline_confirm_sec:-$STATS_COLLECTOR_WL_OFFLINE_CONFIRM_SEC_DEFAULT}"
        bl_stale_sec="${bl_stale_sec:-$STATS_COLLECTOR_BL_STALE_SEC_DEFAULT}"
        bl_offline_confirm_sec="${bl_offline_confirm_sec:-$STATS_COLLECTOR_BL_OFFLINE_CONFIRM_SEC_DEFAULT}"
        bl_stale_fallback_sec="${bl_stale_fallback_sec:-$STATS_COLLECTOR_BL_STALE_FALLBACK_SEC_DEFAULT}"
        bl_push_interval_sec="${bl_push_interval_sec:-$STATS_COLLECTOR_BL_PUSH_INTERVAL_SEC_DEFAULT}"
        # Migrate only values that were hard-coded defaults in older builds.
        [[ "$bl_stale_sec" == "15" ]] && bl_stale_sec="$STATS_COLLECTOR_BL_STALE_SEC_DEFAULT"
        [[ "$bl_offline_confirm_sec" == "5" ]] && bl_offline_confirm_sec="$STATS_COLLECTOR_BL_OFFLINE_CONFIRM_SEC_DEFAULT"
        [[ "$bl_stale_fallback_sec" == "45" ]] && bl_stale_fallback_sec="$STATS_COLLECTOR_BL_STALE_FALLBACK_SEC_DEFAULT"
        if [[ "$bl_push_interval_sec" == "1" || "$bl_push_interval_sec" == "5" ]]; then
            bl_push_interval_sec="$STATS_COLLECTOR_BL_PUSH_INTERVAL_SEC_DEFAULT"
        fi
        push_miss_window_sec="${push_miss_window_sec:-$STATS_COLLECTOR_PUSH_MISS_WINDOW_SEC_DEFAULT}"
        push_miss_threshold="${push_miss_threshold:-$STATS_COLLECTOR_PUSH_MISS_THRESHOLD_DEFAULT}"
        [[ "$push_miss_threshold" == "30" ]] && push_miss_threshold="$STATS_COLLECTOR_PUSH_MISS_THRESHOLD_DEFAULT"
        push_miss_alert_cooldown="${push_miss_alert_cooldown:-$STATS_COLLECTOR_PUSH_MISS_ALERT_COOLDOWN_DEFAULT}"
        scan_alert_delta="${scan_alert_delta:-$STATS_COLLECTOR_SCAN_ALERT_DELTA_DEFAULT}"
        expected_nodes="${expected_nodes:-$STATS_EXPECTED_NODES_DEFAULT}"
        ssh_base_allowed_ips="${ssh_base_allowed_ips:-$WHITELIST_SSH_ALLOWED_IPS}"
        dashboard_enabled="${dashboard_enabled:-1}"
        ip_limit_enabled="${ip_limit_enabled:-$IP_LIMIT_ENABLED_DEFAULT}"
        ip_limit_source="${ip_limit_source:-$IP_LIMIT_SOURCE_DEFAULT}"
        ip_limit_max_ips="${ip_limit_max_ips:-$IP_LIMIT_MAX_IPS_DEFAULT}"
        ip_limit_max_events="${ip_limit_max_events:-$IP_LIMIT_MAX_EVENTS_DEFAULT}"
        ip_limit_window_sec="${ip_limit_window_sec:-$IP_LIMIT_WINDOW_SEC_DEFAULT}"
        if [[ "$ip_limit_window_sec" == "600" ]]; then
            ip_limit_window_sec="$IP_LIMIT_WINDOW_SEC_DEFAULT"
        fi
        ip_limit_alert_cooldown="${ip_limit_alert_cooldown:-$IP_LIMIT_ALERT_COOLDOWN_DEFAULT}"
        ip_limit_scan_sec="${ip_limit_scan_sec:-$IP_LIMIT_COLLECTOR_SCAN_SEC_DEFAULT}"
        ip_limit_alert_threshold="${ip_limit_alert_threshold:-$IP_LIMIT_ALERT_THRESHOLD_DEFAULT}"
        ip_limit_alert_top="${ip_limit_alert_top:-$IP_LIMIT_ALERT_TOP_DEFAULT}"
        ip_limit_enforce_enabled="${ip_limit_enforce_enabled:-$IP_LIMIT_ENFORCE_ENABLED_DEFAULT}"
        ip_limit_drop_enabled="${ip_limit_drop_enabled:-$IP_LIMIT_DROP_ENABLED_DEFAULT}"
        ip_limit_penalty_sec="${ip_limit_penalty_sec:-$IP_LIMIT_PENALTY_SEC_DEFAULT}"
        remna_api_url="${remna_api_url:-$REMNA_API_URL}"
        remna_api_token="${remna_api_token:-$REMNA_API_TOKEN}"
        remna_api_cache_sec="${remna_api_cache_sec:-$REMNA_API_CACHE_SEC_DEFAULT}"
        remna_api_insecure="${remna_api_insecure:-$REMNA_API_INSECURE_DEFAULT}"
        remna_node_alert_enabled="${remna_node_alert_enabled:-$REMNA_NODE_ALERT_ENABLED_DEFAULT}"
        remna_node_poll_sec="${remna_node_poll_sec:-$REMNA_NODE_POLL_SEC_DEFAULT}"
        remna_offline_guard_enabled="${remna_offline_guard_enabled:-$REMNA_OFFLINE_GUARD_ENABLED_DEFAULT}"
        remna_offline_state_max_age_sec="${remna_offline_state_max_age_sec:-$REMNA_OFFLINE_STATE_MAX_AGE_SEC_DEFAULT}"
        remna_offline_log_grace_sec="${remna_offline_log_grace_sec:-$REMNA_OFFLINE_LOG_GRACE_SEC_DEFAULT}"
        asn_lookup_enabled="${asn_lookup_enabled:-$ASN_LOOKUP_ENABLED_DEFAULT}"
        asn_cache_sec="${asn_cache_sec:-$ASN_CACHE_SEC_DEFAULT}"
        asn_timeout_sec="${asn_timeout_sec:-$ASN_TIMEOUT_SEC_DEFAULT}"
    else
        listen_host="$(ask_text "IP прослушивания коллектора" "0.0.0.0")"
        listen_port="$(ask_int "Порт коллектора" "$STATS_COLLECTOR_PORT_DEFAULT" 1 65535)"
        secret="$(ask_text "Секрет коллектора" "$(generate_secret)")"
        bot_token="$(ask_secret_value "Введите Telegram Bot Token")"
        chat_id="$(ask_text "Введите Telegram Chat ID")"
        allowed_user="$(ask_int "Разрешенный Telegram user id" "$STATS_ALLOWED_USER_ID_DEFAULT" 1 999999999999)"
        stale_sec="$(ask_int "Алерт offline после секунд" "$STATS_COLLECTOR_STALE_SEC_DEFAULT" 30 86400)"
        wl_offline_confirm_sec="$STATS_COLLECTOR_WL_OFFLINE_CONFIRM_SEC_DEFAULT"
        bl_stale_sec="$STATS_COLLECTOR_BL_STALE_SEC_DEFAULT"
        bl_offline_confirm_sec="$STATS_COLLECTOR_BL_OFFLINE_CONFIRM_SEC_DEFAULT"
        bl_stale_fallback_sec="$STATS_COLLECTOR_BL_STALE_FALLBACK_SEC_DEFAULT"
        bl_push_interval_sec="$STATS_COLLECTOR_BL_PUSH_INTERVAL_SEC_DEFAULT"
        push_miss_window_sec="$STATS_COLLECTOR_PUSH_MISS_WINDOW_SEC_DEFAULT"
        push_miss_threshold="$STATS_COLLECTOR_PUSH_MISS_THRESHOLD_DEFAULT"
        push_miss_alert_cooldown="$STATS_COLLECTOR_PUSH_MISS_ALERT_COOLDOWN_DEFAULT"
        scan_alert_delta="$STATS_COLLECTOR_SCAN_ALERT_DELTA_DEFAULT"
        expected_nodes="$(ask_int "Ожидаемое кол-во обходов" "$STATS_EXPECTED_NODES_DEFAULT" 1 9999)"
        daily_report_time="$(ask_optional_time_hm "Время ежедневного отчёта по МСК (пусто = выключено)")"
        ssh_base_allowed_ips="$WHITELIST_SSH_ALLOWED_IPS"
        dashboard_enabled="1"
        dashboard_token=""
        ip_limit_enabled="$IP_LIMIT_ENABLED_DEFAULT"
        ip_limit_source="$IP_LIMIT_SOURCE_DEFAULT"
        ip_limit_max_ips="$IP_LIMIT_MAX_IPS_DEFAULT"
        ip_limit_max_events="$IP_LIMIT_MAX_EVENTS_DEFAULT"
        ip_limit_window_sec="$IP_LIMIT_WINDOW_SEC_DEFAULT"
        ip_limit_alert_cooldown="$IP_LIMIT_ALERT_COOLDOWN_DEFAULT"
        ip_limit_scan_sec="$IP_LIMIT_COLLECTOR_SCAN_SEC_DEFAULT"
        ip_limit_alert_threshold="$IP_LIMIT_ALERT_THRESHOLD_DEFAULT"
        ip_limit_alert_top="$IP_LIMIT_ALERT_TOP_DEFAULT"
        ip_limit_enforce_enabled="$IP_LIMIT_ENFORCE_ENABLED_DEFAULT"
        ip_limit_drop_enabled="$IP_LIMIT_DROP_ENABLED_DEFAULT"
        ip_limit_penalty_sec="$IP_LIMIT_PENALTY_SEC_DEFAULT"
        remna_api_url="$REMNA_API_URL"
        remna_api_token="$REMNA_API_TOKEN"
        remna_api_cache_sec="$REMNA_API_CACHE_SEC_DEFAULT"
        remna_api_insecure="$REMNA_API_INSECURE_DEFAULT"
        remna_node_alert_enabled="$REMNA_NODE_ALERT_ENABLED_DEFAULT"
        remna_node_poll_sec="$REMNA_NODE_POLL_SEC_DEFAULT"
        remna_offline_guard_enabled="$REMNA_OFFLINE_GUARD_ENABLED_DEFAULT"
        remna_offline_state_max_age_sec="$REMNA_OFFLINE_STATE_MAX_AGE_SEC_DEFAULT"
        remna_offline_log_grace_sec="$REMNA_OFFLINE_LOG_GRACE_SEC_DEFAULT"
        asn_lookup_enabled="$ASN_LOOKUP_ENABLED_DEFAULT"
        asn_cache_sec="$ASN_CACHE_SEC_DEFAULT"
        asn_timeout_sec="$ASN_TIMEOUT_SEC_DEFAULT"
    fi
    if [[ -n "${KTO_COLLECTOR_REMNA_API_URL:-}" ]]; then
        remna_api_url="$KTO_COLLECTOR_REMNA_API_URL"
    fi
    if [[ -n "${KTO_COLLECTOR_SSH_BASE_ALLOWED_IPS:-}" ]]; then
        ssh_base_allowed_ips="$KTO_COLLECTOR_SSH_BASE_ALLOWED_IPS"
    fi
    if [[ -n "${KTO_COLLECTOR_DASHBOARD_ENABLED:-}" ]]; then
        dashboard_enabled="$KTO_COLLECTOR_DASHBOARD_ENABLED"
    fi
    if [[ -n "${KTO_COLLECTOR_DASHBOARD_TOKEN:-}" ]]; then
        dashboard_token="$KTO_COLLECTOR_DASHBOARD_TOKEN"
    fi
    if [[ -n "${KTO_COLLECTOR_REMNA_API_TOKEN:-}" ]]; then
        remna_api_token="$KTO_COLLECTOR_REMNA_API_TOKEN"
    fi
    if [[ -n "${KTO_COLLECTOR_REMNA_API_CACHE_SEC:-}" ]]; then
        remna_api_cache_sec="$KTO_COLLECTOR_REMNA_API_CACHE_SEC"
    fi
    if [[ -n "${KTO_COLLECTOR_REMNA_API_INSECURE:-}" ]]; then
        remna_api_insecure="$KTO_COLLECTOR_REMNA_API_INSECURE"
    fi
    if [[ -n "${KTO_COLLECTOR_REMNA_NODE_ALERT_ENABLED:-}" ]]; then
        remna_node_alert_enabled="$KTO_COLLECTOR_REMNA_NODE_ALERT_ENABLED"
    fi
    if [[ -n "${KTO_COLLECTOR_REMNA_NODE_POLL_SEC:-}" ]]; then
        remna_node_poll_sec="$KTO_COLLECTOR_REMNA_NODE_POLL_SEC"
    fi
    if [[ -n "${KTO_COLLECTOR_REMNA_OFFLINE_GUARD_ENABLED:-}" ]]; then
        remna_offline_guard_enabled="$KTO_COLLECTOR_REMNA_OFFLINE_GUARD_ENABLED"
    fi
    if [[ -n "${KTO_COLLECTOR_REMNA_OFFLINE_STATE_MAX_AGE_SEC:-}" ]]; then
        remna_offline_state_max_age_sec="$KTO_COLLECTOR_REMNA_OFFLINE_STATE_MAX_AGE_SEC"
    fi
    if [[ -n "${KTO_COLLECTOR_REMNA_OFFLINE_LOG_GRACE_SEC:-}" ]]; then
        remna_offline_log_grace_sec="$KTO_COLLECTOR_REMNA_OFFLINE_LOG_GRACE_SEC"
    fi
    if [[ -n "${KTO_COLLECTOR_BL_STALE_SEC:-}" ]]; then
        bl_stale_sec="$KTO_COLLECTOR_BL_STALE_SEC"
    fi
    if [[ -n "${KTO_COLLECTOR_WL_OFFLINE_CONFIRM_SEC:-}" ]]; then
        wl_offline_confirm_sec="$KTO_COLLECTOR_WL_OFFLINE_CONFIRM_SEC"
    fi
    if [[ -n "${KTO_COLLECTOR_BL_OFFLINE_CONFIRM_SEC:-}" ]]; then
        bl_offline_confirm_sec="$KTO_COLLECTOR_BL_OFFLINE_CONFIRM_SEC"
    fi
    if [[ -n "${KTO_COLLECTOR_BL_STALE_FALLBACK_SEC:-}" ]]; then
        bl_stale_fallback_sec="$KTO_COLLECTOR_BL_STALE_FALLBACK_SEC"
    fi
    if [[ -n "${KTO_COLLECTOR_BL_PUSH_INTERVAL_SEC:-}" ]]; then
        bl_push_interval_sec="$KTO_COLLECTOR_BL_PUSH_INTERVAL_SEC"
    fi
    if [[ -n "${KTO_COLLECTOR_PUSH_MISS_WINDOW_SEC:-}" ]]; then
        push_miss_window_sec="$KTO_COLLECTOR_PUSH_MISS_WINDOW_SEC"
    fi
    if [[ -n "${KTO_COLLECTOR_PUSH_MISS_THRESHOLD:-}" ]]; then
        push_miss_threshold="$KTO_COLLECTOR_PUSH_MISS_THRESHOLD"
    fi
    if [[ -n "${KTO_COLLECTOR_PUSH_MISS_ALERT_COOLDOWN:-}" ]]; then
        push_miss_alert_cooldown="$KTO_COLLECTOR_PUSH_MISS_ALERT_COOLDOWN"
    fi
    if [[ -n "${KTO_COLLECTOR_IP_LIMIT_ENABLED:-}" ]]; then
        ip_limit_enabled="$KTO_COLLECTOR_IP_LIMIT_ENABLED"
    fi
    if [[ -n "${KTO_COLLECTOR_IP_LIMIT_SOURCE:-}" ]]; then
        ip_limit_source="$KTO_COLLECTOR_IP_LIMIT_SOURCE"
    fi
    if [[ -n "${KTO_COLLECTOR_IP_LIMIT_MAX_IPS:-}" ]]; then
        ip_limit_max_ips="$KTO_COLLECTOR_IP_LIMIT_MAX_IPS"
    fi
    if [[ -n "${KTO_COLLECTOR_IP_LIMIT_MAX_EVENTS:-}" ]]; then
        ip_limit_max_events="$KTO_COLLECTOR_IP_LIMIT_MAX_EVENTS"
    fi
    if [[ -n "${KTO_COLLECTOR_IP_LIMIT_WINDOW_SEC:-}" ]]; then
        ip_limit_window_sec="$KTO_COLLECTOR_IP_LIMIT_WINDOW_SEC"
    fi
    if [[ -n "${KTO_COLLECTOR_IP_LIMIT_ALERT_COOLDOWN:-}" ]]; then
        ip_limit_alert_cooldown="$KTO_COLLECTOR_IP_LIMIT_ALERT_COOLDOWN"
    fi
    if [[ -n "${KTO_COLLECTOR_IP_LIMIT_SCAN_SEC:-}" ]]; then
        ip_limit_scan_sec="$KTO_COLLECTOR_IP_LIMIT_SCAN_SEC"
    fi
    if [[ -n "${KTO_COLLECTOR_IP_LIMIT_ALERT_THRESHOLD:-}" ]]; then
        ip_limit_alert_threshold="$KTO_COLLECTOR_IP_LIMIT_ALERT_THRESHOLD"
    fi
    if [[ -n "${KTO_COLLECTOR_IP_LIMIT_ALERT_TOP:-}" ]]; then
        ip_limit_alert_top="$KTO_COLLECTOR_IP_LIMIT_ALERT_TOP"
    fi
    if [[ -n "${KTO_COLLECTOR_IP_LIMIT_ENFORCE_ENABLED:-}" ]]; then
        ip_limit_enforce_enabled="$KTO_COLLECTOR_IP_LIMIT_ENFORCE_ENABLED"
    fi
    if [[ -n "${KTO_COLLECTOR_IP_LIMIT_DROP_ENABLED:-}" ]]; then
        ip_limit_drop_enabled="$KTO_COLLECTOR_IP_LIMIT_DROP_ENABLED"
    fi
    if [[ -n "${KTO_COLLECTOR_IP_LIMIT_PENALTY_SEC:-}" ]]; then
        ip_limit_penalty_sec="$KTO_COLLECTOR_IP_LIMIT_PENALTY_SEC"
    fi
    if [[ -n "${KTO_COLLECTOR_ASN_LOOKUP_ENABLED:-}" ]]; then
        asn_lookup_enabled="$KTO_COLLECTOR_ASN_LOOKUP_ENABLED"
    fi
    if [[ -n "${KTO_COLLECTOR_ASN_CACHE_SEC:-}" ]]; then
        asn_cache_sec="$KTO_COLLECTOR_ASN_CACHE_SEC"
    fi
    if [[ -n "${KTO_COLLECTOR_ASN_TIMEOUT_SEC:-}" ]]; then
        asn_timeout_sec="$KTO_COLLECTOR_ASN_TIMEOUT_SEC"
    fi

    # IP limit is monitoring-only in current builds. Clear legacy force settings.
    ip_limit_enforce_enabled="0"
    ip_limit_drop_enabled="0"

    safe_host="$(escape_config_value "$listen_host")"
    safe_port="$(escape_config_value "$listen_port")"
    safe_secret="$(escape_config_value "$secret")"
    safe_bot="$(escape_config_value "$bot_token")"
    safe_chat="$(escape_config_value "$chat_id")"
    safe_user="$(escape_config_value "$allowed_user")"
    safe_stale="$(escape_config_value "$stale_sec")"
    safe_wl_offline_confirm="$(escape_config_value "$wl_offline_confirm_sec")"
    safe_bl_stale="$(escape_config_value "$bl_stale_sec")"
    safe_bl_offline_confirm="$(escape_config_value "$bl_offline_confirm_sec")"
    safe_bl_stale_fallback="$(escape_config_value "$bl_stale_fallback_sec")"
    safe_bl_push_interval="$(escape_config_value "$bl_push_interval_sec")"
    safe_push_miss_window="$(escape_config_value "$push_miss_window_sec")"
    safe_push_miss_threshold="$(escape_config_value "$push_miss_threshold")"
    safe_push_miss_cooldown="$(escape_config_value "$push_miss_alert_cooldown")"
    safe_scan_alert_delta="$(escape_config_value "$scan_alert_delta")"
    safe_expected="$(escape_config_value "$expected_nodes")"
    safe_tz="$(escape_config_value "$STATS_COLLECTOR_TZ_DEFAULT")"
    safe_daily="$(escape_config_value "$daily_report_time")"
    safe_ssh_base_allowed_ips="$(escape_config_value "$ssh_base_allowed_ips")"
    safe_dashboard_enabled="$(escape_config_value "$dashboard_enabled")"
    safe_dashboard_token="$(escape_config_value "$dashboard_token")"
    safe_ip_limit_enabled="$(escape_config_value "$ip_limit_enabled")"
    safe_ip_limit_source="$(escape_config_value "$ip_limit_source")"
    safe_ip_limit_max_ips="$(escape_config_value "$ip_limit_max_ips")"
    safe_ip_limit_max_events="$(escape_config_value "$ip_limit_max_events")"
    safe_ip_limit_window="$(escape_config_value "$ip_limit_window_sec")"
    safe_ip_limit_cooldown="$(escape_config_value "$ip_limit_alert_cooldown")"
    safe_ip_limit_scan_sec="$(escape_config_value "$ip_limit_scan_sec")"
    safe_ip_limit_alert_threshold="$(escape_config_value "$ip_limit_alert_threshold")"
    safe_ip_limit_alert_top="$(escape_config_value "$ip_limit_alert_top")"
    safe_ip_limit_enforce_enabled="$(escape_config_value "$ip_limit_enforce_enabled")"
    safe_ip_limit_drop_enabled="$(escape_config_value "$ip_limit_drop_enabled")"
    safe_ip_limit_penalty_sec="$(escape_config_value "$ip_limit_penalty_sec")"
    safe_remna_api_url="$(escape_config_value "$remna_api_url")"
    safe_remna_api_token="$(escape_config_value "$remna_api_token")"
    safe_remna_api_cache_sec="$(escape_config_value "$remna_api_cache_sec")"
    safe_remna_api_insecure="$(escape_config_value "$remna_api_insecure")"
    safe_remna_node_alert_enabled="$(escape_config_value "$remna_node_alert_enabled")"
    safe_remna_node_poll_sec="$(escape_config_value "$remna_node_poll_sec")"
    safe_remna_offline_guard_enabled="$(escape_config_value "$remna_offline_guard_enabled")"
    safe_remna_offline_state_max_age_sec="$(escape_config_value "$remna_offline_state_max_age_sec")"
    safe_remna_offline_log_grace_sec="$(escape_config_value "$remna_offline_log_grace_sec")"
    safe_asn_lookup_enabled="$(escape_config_value "$asn_lookup_enabled")"
    safe_asn_cache_sec="$(escape_config_value "$asn_cache_sec")"
    safe_asn_timeout_sec="$(escape_config_value "$asn_timeout_sec")"

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
KTO_COLLECTOR_WL_OFFLINE_CONFIRM_SEC="$safe_wl_offline_confirm"
KTO_COLLECTOR_BL_STALE_SEC="$safe_bl_stale"
KTO_COLLECTOR_BL_OFFLINE_CONFIRM_SEC="$safe_bl_offline_confirm"
KTO_COLLECTOR_BL_STALE_FALLBACK_SEC="$safe_bl_stale_fallback"
KTO_COLLECTOR_BL_PUSH_INTERVAL_SEC="$safe_bl_push_interval"
KTO_COLLECTOR_PUSH_MISS_WINDOW_SEC="$safe_push_miss_window"
KTO_COLLECTOR_PUSH_MISS_THRESHOLD="$safe_push_miss_threshold"
KTO_COLLECTOR_PUSH_MISS_ALERT_COOLDOWN="$safe_push_miss_cooldown"
KTO_COLLECTOR_SCAN_ALERT_DELTA="$safe_scan_alert_delta"
KTO_COLLECTOR_EXPECTED_NODES="$safe_expected"
KTO_COLLECTOR_TZ="$safe_tz"
KTO_COLLECTOR_DAILY_REPORT_TIME="$safe_daily"
KTO_COLLECTOR_SSH_BASE_ALLOWED_IPS="$safe_ssh_base_allowed_ips"
KTO_COLLECTOR_DASHBOARD_ENABLED="$safe_dashboard_enabled"
KTO_COLLECTOR_DASHBOARD_TOKEN="$safe_dashboard_token"
KTO_COLLECTOR_IP_LIMIT_ENABLED="$safe_ip_limit_enabled"
KTO_COLLECTOR_IP_LIMIT_SOURCE="$safe_ip_limit_source"
KTO_COLLECTOR_IP_LIMIT_MAX_IPS="$safe_ip_limit_max_ips"
KTO_COLLECTOR_IP_LIMIT_MAX_EVENTS="$safe_ip_limit_max_events"
KTO_COLLECTOR_IP_LIMIT_WINDOW_SEC="$safe_ip_limit_window"
KTO_COLLECTOR_IP_LIMIT_ALERT_COOLDOWN="$safe_ip_limit_cooldown"
KTO_COLLECTOR_IP_LIMIT_SCAN_SEC="$safe_ip_limit_scan_sec"
KTO_COLLECTOR_IP_LIMIT_ALERT_THRESHOLD="$safe_ip_limit_alert_threshold"
KTO_COLLECTOR_IP_LIMIT_ALERT_TOP="$safe_ip_limit_alert_top"
KTO_COLLECTOR_IP_LIMIT_ENFORCE_ENABLED="$safe_ip_limit_enforce_enabled"
KTO_COLLECTOR_IP_LIMIT_DROP_ENABLED="$safe_ip_limit_drop_enabled"
KTO_COLLECTOR_IP_LIMIT_PENALTY_SEC="$safe_ip_limit_penalty_sec"
KTO_COLLECTOR_REMNA_API_URL="$safe_remna_api_url"
KTO_COLLECTOR_REMNA_API_TOKEN="$safe_remna_api_token"
KTO_COLLECTOR_REMNA_API_CACHE_SEC="$safe_remna_api_cache_sec"
KTO_COLLECTOR_REMNA_API_INSECURE="$safe_remna_api_insecure"
KTO_COLLECTOR_REMNA_NODE_ALERT_ENABLED="$safe_remna_node_alert_enabled"
KTO_COLLECTOR_REMNA_NODE_POLL_SEC="$safe_remna_node_poll_sec"
KTO_COLLECTOR_REMNA_OFFLINE_GUARD_ENABLED="$safe_remna_offline_guard_enabled"
KTO_COLLECTOR_REMNA_OFFLINE_STATE_MAX_AGE_SEC="$safe_remna_offline_state_max_age_sec"
KTO_COLLECTOR_REMNA_OFFLINE_LOG_GRACE_SEC="$safe_remna_offline_log_grace_sec"
KTO_COLLECTOR_ASN_LOOKUP_ENABLED="$safe_asn_lookup_enabled"
KTO_COLLECTOR_ASN_CACHE_SEC="$safe_asn_cache_sec"
KTO_COLLECTOR_ASN_TIMEOUT_SEC="$safe_asn_timeout_sec"
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
    dashboard_effective_token="$("${SUDO[@]}" "$STATS_COLLECTOR_SCRIPT" --dashboard-token 2>/dev/null || true)"
    dashboard_host="$listen_host"
    if [[ "$dashboard_host" == "0.0.0.0" || "$dashboard_host" == "::" ]]; then
        dashboard_host="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
        dashboard_host="${dashboard_host:-<IP-коллектора>}"
    fi
    if [[ -n "$dashboard_effective_token" ]]; then
        ok "WL-панель: http://${dashboard_host}:${listen_port}/panel/"
        ok "Токен панели: ${dashboard_effective_token}"
        ok "Показать токен позже: sudo ${STATS_COLLECTOR_SCRIPT} --dashboard-token"
    else
        warn "WL-панель: выключена"
    fi
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
    ok "WL offline alert: ${stale_sec:-$STATS_COLLECTOR_STALE_SEC_DEFAULT}s + confirm ${wl_offline_confirm_sec:-$STATS_COLLECTOR_WL_OFFLINE_CONFIRM_SEC_DEFAULT}s"
    ok "BL offline alert: ${bl_stale_sec:-$STATS_COLLECTOR_BL_STALE_SEC_DEFAULT}s + confirm ${bl_offline_confirm_sec:-$STATS_COLLECTOR_BL_OFFLINE_CONFIRM_SEC_DEFAULT}s"
    ok "BL push target: ${bl_push_interval_sec:-$STATS_COLLECTOR_BL_PUSH_INTERVAL_SEC_DEFAULT}s, miss >${push_miss_threshold:-$STATS_COLLECTOR_PUSH_MISS_THRESHOLD_DEFAULT}/${push_miss_window_sec:-$STATS_COLLECTOR_PUSH_MISS_WINDOW_SEC_DEFAULT}s"
    if [[ -n "$remna_api_token" ]]; then
        ok "Remnawave API enrichment: включён"
        ok "Remnawave node alerts: ${remna_node_alert_enabled:-$REMNA_NODE_ALERT_ENABLED_DEFAULT}, poll ${remna_node_poll_sec:-$REMNA_NODE_POLL_SEC_DEFAULT}s"
        ok "Remnawave offline guard: ${remna_offline_guard_enabled:-$REMNA_OFFLINE_GUARD_ENABLED_DEFAULT}, state ${remna_offline_state_max_age_sec:-$REMNA_OFFLINE_STATE_MAX_AGE_SEC_DEFAULT}s, logs ${remna_offline_log_grace_sec:-$REMNA_OFFLINE_LOG_GRACE_SEC_DEFAULT}s"
    else
        warn "Remnawave API enrichment: токен не задан"
    fi
    ok "IP limit source: ${ip_limit_source:-$IP_LIMIT_SOURCE_DEFAULT}, enabled=${ip_limit_enabled:-0}, alert >${ip_limit_alert_threshold:-$IP_LIMIT_ALERT_THRESHOLD_DEFAULT} IP"
    ok "IP limit mode: только сбор и алерты, без ограничений"
    if [[ "${asn_lookup_enabled:-1}" == "1" ]]; then
        ok "ASN/ISP lookup: включён"
    else
        warn "ASN/ISP lookup: выключен"
    fi
}

stats_collector_status() {
    header
    require_panel_mode
    need_root
    local state listen_host listen_port health_host health_log rc remna_api_url remna_api_token remna_node_alert_enabled remna_node_poll_sec remna_offline_guard_enabled remna_offline_state_max_age_sec remna_offline_log_grace_sec stale_sec wl_offline_confirm_sec bl_stale_sec bl_offline_confirm_sec bl_stale_fallback_sec bl_push_interval_sec push_miss_window_sec push_miss_threshold push_miss_alert_cooldown remna_test_id remna_test_log remna_code remna_probe dashboard_enabled dashboard_token
    local ip_limit_enabled ip_limit_source ip_limit_scan_sec ip_limit_alert_threshold ip_limit_alert_top ip_limit_max_events asn_lookup_enabled asn_cache_sec
    state="$(service_ok "$STATS_COLLECTOR_SERVICE")"
    listen_host="$(config_get KTO_COLLECTOR_LISTEN_HOST "$STATS_COLLECTOR_CONFIG")"
    listen_port="$(config_get KTO_COLLECTOR_LISTEN_PORT "$STATS_COLLECTOR_CONFIG")"
    dashboard_enabled="$(config_get KTO_COLLECTOR_DASHBOARD_ENABLED "$STATS_COLLECTOR_CONFIG")"
    dashboard_token="$("${SUDO[@]}" "$STATS_COLLECTOR_SCRIPT" --dashboard-token 2>/dev/null || true)"
    remna_api_url="$(config_get KTO_COLLECTOR_REMNA_API_URL "$STATS_COLLECTOR_CONFIG")"
    remna_api_token="$(config_get KTO_COLLECTOR_REMNA_API_TOKEN "$STATS_COLLECTOR_CONFIG")"
    remna_node_alert_enabled="$(config_get KTO_COLLECTOR_REMNA_NODE_ALERT_ENABLED "$STATS_COLLECTOR_CONFIG")"
    remna_node_poll_sec="$(config_get KTO_COLLECTOR_REMNA_NODE_POLL_SEC "$STATS_COLLECTOR_CONFIG")"
    remna_offline_guard_enabled="$(config_get KTO_COLLECTOR_REMNA_OFFLINE_GUARD_ENABLED "$STATS_COLLECTOR_CONFIG")"
    remna_offline_state_max_age_sec="$(config_get KTO_COLLECTOR_REMNA_OFFLINE_STATE_MAX_AGE_SEC "$STATS_COLLECTOR_CONFIG")"
    remna_offline_log_grace_sec="$(config_get KTO_COLLECTOR_REMNA_OFFLINE_LOG_GRACE_SEC "$STATS_COLLECTOR_CONFIG")"
    stale_sec="$(config_get KTO_COLLECTOR_STALE_SEC "$STATS_COLLECTOR_CONFIG")"
    wl_offline_confirm_sec="$(config_get KTO_COLLECTOR_WL_OFFLINE_CONFIRM_SEC "$STATS_COLLECTOR_CONFIG")"
    bl_stale_sec="$(config_get KTO_COLLECTOR_BL_STALE_SEC "$STATS_COLLECTOR_CONFIG")"
    bl_offline_confirm_sec="$(config_get KTO_COLLECTOR_BL_OFFLINE_CONFIRM_SEC "$STATS_COLLECTOR_CONFIG")"
    bl_stale_fallback_sec="$(config_get KTO_COLLECTOR_BL_STALE_FALLBACK_SEC "$STATS_COLLECTOR_CONFIG")"
    bl_push_interval_sec="$(config_get KTO_COLLECTOR_BL_PUSH_INTERVAL_SEC "$STATS_COLLECTOR_CONFIG")"
    push_miss_window_sec="$(config_get KTO_COLLECTOR_PUSH_MISS_WINDOW_SEC "$STATS_COLLECTOR_CONFIG")"
    push_miss_threshold="$(config_get KTO_COLLECTOR_PUSH_MISS_THRESHOLD "$STATS_COLLECTOR_CONFIG")"
    push_miss_alert_cooldown="$(config_get KTO_COLLECTOR_PUSH_MISS_ALERT_COOLDOWN "$STATS_COLLECTOR_CONFIG")"
    ip_limit_enabled="$(config_get KTO_COLLECTOR_IP_LIMIT_ENABLED "$STATS_COLLECTOR_CONFIG")"
    ip_limit_source="$(config_get KTO_COLLECTOR_IP_LIMIT_SOURCE "$STATS_COLLECTOR_CONFIG")"
    ip_limit_scan_sec="$(config_get KTO_COLLECTOR_IP_LIMIT_SCAN_SEC "$STATS_COLLECTOR_CONFIG")"
    ip_limit_alert_threshold="$(config_get KTO_COLLECTOR_IP_LIMIT_ALERT_THRESHOLD "$STATS_COLLECTOR_CONFIG")"
    ip_limit_alert_top="$(config_get KTO_COLLECTOR_IP_LIMIT_ALERT_TOP "$STATS_COLLECTOR_CONFIG")"
    ip_limit_max_events="$(config_get KTO_COLLECTOR_IP_LIMIT_MAX_EVENTS "$STATS_COLLECTOR_CONFIG")"
    asn_lookup_enabled="$(config_get KTO_COLLECTOR_ASN_LOOKUP_ENABLED "$STATS_COLLECTOR_CONFIG")"
    asn_cache_sec="$(config_get KTO_COLLECTOR_ASN_CACHE_SEC "$STATS_COLLECTOR_CONFIG")"
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
    print_row "WL panel" "/panel/ / enabled ${dashboard_enabled:-1}" "$([[ "${dashboard_enabled:-1}" == "1" && -n "$dashboard_token" ]] && echo 1 || echo 0)"
    print_row "panel token" "${dashboard_token:-unavailable}" "$([[ -n "$dashboard_token" ]] && echo 1 || echo 0)"
    print_row "wl stale" "${stale_sec:-$STATS_COLLECTOR_STALE_SEC_DEFAULT}s + confirm ${wl_offline_confirm_sec:-$STATS_COLLECTOR_WL_OFFLINE_CONFIRM_SEC_DEFAULT}s" 1
    print_row "bl stale" "${bl_stale_sec:-$STATS_COLLECTOR_BL_STALE_SEC_DEFAULT}s + confirm ${bl_offline_confirm_sec:-$STATS_COLLECTOR_BL_OFFLINE_CONFIRM_SEC_DEFAULT}s" 1
    print_row "bl push" "target ${bl_push_interval_sec:-$STATS_COLLECTOR_BL_PUSH_INTERVAL_SEC_DEFAULT}s / fallback ${bl_stale_fallback_sec:-$STATS_COLLECTOR_BL_STALE_FALLBACK_SEC_DEFAULT}s" 1
    print_row "push miss" ">${push_miss_threshold:-$STATS_COLLECTOR_PUSH_MISS_THRESHOLD_DEFAULT}/${push_miss_window_sec:-$STATS_COLLECTOR_PUSH_MISS_WINDOW_SEC_DEFAULT}s cooldown ${push_miss_alert_cooldown:-$STATS_COLLECTOR_PUSH_MISS_ALERT_COOLDOWN_DEFAULT}s" 1
    print_row "Remnawave API" "${remna_api_url:-empty} / $([[ -n "$remna_api_token" ]] && echo token-set || echo no-token)" "$([[ -n "$remna_api_url" && -n "$remna_api_token" ]] && echo 1 || echo 0)"
    print_row "Remnawave node alert" "${remna_node_alert_enabled:-$REMNA_NODE_ALERT_ENABLED_DEFAULT} / poll ${remna_node_poll_sec:-$REMNA_NODE_POLL_SEC_DEFAULT}s" "$([[ "${remna_node_alert_enabled:-$REMNA_NODE_ALERT_ENABLED_DEFAULT}" == "1" && -n "$remna_api_url" && -n "$remna_api_token" ]] && echo 1 || echo 0)"
    print_row "Remnawave offline guard" "${remna_offline_guard_enabled:-$REMNA_OFFLINE_GUARD_ENABLED_DEFAULT} / state ${remna_offline_state_max_age_sec:-$REMNA_OFFLINE_STATE_MAX_AGE_SEC_DEFAULT}s / logs ${remna_offline_log_grace_sec:-$REMNA_OFFLINE_LOG_GRACE_SEC_DEFAULT}s" "$([[ "${remna_offline_guard_enabled:-$REMNA_OFFLINE_GUARD_ENABLED_DEFAULT}" == "1" ]] && echo 1 || echo 0)"
    print_row "ip source" "${ip_limit_source:-$IP_LIMIT_SOURCE_DEFAULT} / enabled ${ip_limit_enabled:-0}" 1
    print_row "ip alert" ">${ip_limit_alert_threshold:-$IP_LIMIT_ALERT_THRESHOLD_DEFAULT} IP / top ${ip_limit_alert_top:-$IP_LIMIT_ALERT_TOP_DEFAULT} / scan ${ip_limit_scan_sec:-$IP_LIMIT_COLLECTOR_SCAN_SEC_DEFAULT}s"
    print_row "ip mode" "alerts only / no restrictions" 1
    print_row "ip max events" "${ip_limit_max_events:-$IP_LIMIT_MAX_EVENTS_DEFAULT}"
    print_row "asn lookup" "${asn_lookup_enabled:-1} / cache ${asn_cache_sec:-$ASN_CACHE_SEC_DEFAULT}s" "$([[ "${asn_lookup_enabled:-1}" == "1" ]] && echo 1 || echo 0)"
    print_row "ip db" "${STATS_COLLECTOR_STATE_DIR}/ip_limit.sqlite" "$("${SUDO[@]}" test -s "${STATS_COLLECTOR_STATE_DIR}/ip_limit.sqlite" 2>/dev/null && echo 1 || echo 0)"
    if "${SUDO[@]}" test -s "${STATS_COLLECTOR_STATE_DIR}/sni_allow.json" 2>/dev/null; then
        print_row "sni allow" "${STATS_COLLECTOR_STATE_DIR}/sni_allow.json" 1
    else
        print_row "sni allow" "empty" 1
    fi

    if command_exists curl; then
        health_log="$(mktemp)"
        if curl -4 -fsS --connect-timeout 3 --max-time 5 "http://${health_host}:${listen_port}/health" >"$health_log" 2>&1; then
            print_row "local health" "$(tr '\n' ' ' < "$health_log")" 1
        else
            rc=$?
            print_row "local health" "rc=${rc}: $(tr '\n' ' ' < "$health_log")" 0
        fi
        rm -f "$health_log"
        if [[ -n "$remna_api_url" && -n "$remna_api_token" ]]; then
            remna_test_id="$("${SUDO[@]}" python3 - <<PY 2>/dev/null || true
import sqlite3
path = "${STATS_COLLECTOR_STATE_DIR}/ip_limit.sqlite"
try:
    conn = sqlite3.connect(path)
    row = conn.execute(
        "SELECT user FROM ip_limit_events GROUP BY user ORDER BY max(last_seen) DESC LIMIT 1"
    ).fetchone()
    if row and str(row[0]).strip():
        print(str(row[0]).strip())
except Exception:
    pass
PY
)"
            if [[ -n "$remna_test_id" ]]; then
                remna_test_log="$(mktemp)"
                remna_code="$(curl -4 -k -sS --connect-timeout 3 --max-time 8 \
                    -H "Authorization: Bearer ${remna_api_token}" \
                    -H "Accept: application/json" \
                    -o "$remna_test_log" \
                    -w '%{http_code}' \
                    "${remna_api_url%/}/api/users/by-id/${remna_test_id}" 2>>"$remna_test_log" || true)"
                if [[ "$remna_code" =~ ^2[0-9][0-9]$ ]]; then
                    remna_probe="$(python3 - "$remna_test_log" <<'PY' 2>/dev/null || true
import json
import sys

def extract(payload):
    if not isinstance(payload, dict):
        return None
    candidates = [payload]
    for key in ("response", "user", "data"):
        value = payload.get(key)
        if isinstance(value, dict):
            candidates.append(value)
            for nested_key in ("user", "data"):
                nested = value.get(nested_key)
                if isinstance(nested, dict):
                    candidates.append(nested)
    user_keys = {"username", "email", "tag", "status", "expireAt", "trafficLimitBytes", "userTraffic"}
    for candidate in candidates:
        if any(key in candidate for key in user_keys):
            return candidate
    return None

try:
    with open(sys.argv[1], "r", encoding="utf-8") as fh:
        user = extract(json.load(fh))
except Exception:
    user = None

if not user:
    print("no-user")
else:
    name = ""
    for key in ("username", "email", "tag"):
        value = str(user.get(key) or "").strip()
        if value:
            name = value
            break
    status = str(user.get("status") or "").strip()
    parts = []
    if name:
        parts.append(f"user={name}")
    if status:
        parts.append(f"status={status}")
    print(" ".join(parts) if parts else "user-found")
PY
)"
                    if [[ -n "$remna_probe" && "$remna_probe" != "no-user" ]]; then
                        print_row "Remnawave lookup" "id=${remna_test_id} http=${remna_code} ${remna_probe}" 1
                    else
                        print_row "Remnawave lookup" "id=${remna_test_id} http=${remna_code} no-user: $(head -c 120 "$remna_test_log" | tr '\n' ' ')" 0
                    fi
                else
                    print_row "Remnawave lookup" "id=${remna_test_id} http=${remna_code:-curl}: $(head -c 120 "$remna_test_log" | tr '\n' ' ')" 0
                fi
                rm -f "$remna_test_log"
            else
                print_row "Remnawave lookup" "нет активных ID в ip_limit.sqlite"
            fi
        fi
    else
        print_row "local health" "curl не установлен" 0
    fi
}

stats_collector_alerts_menu() {
    header
    require_panel_mode
    need_root
    local list_file result_file query result_line result_action result_name rc was_active

    if ! "${SUDO[@]}" test -s "$STATS_COLLECTOR_CONFIG" 2>/dev/null; then
        fail "Коллектор ещё не настроен. Сначала установи его через пункт «Коллектор статистики»."
        return 1
    fi

    write_stats_collector_script
    while true; do
        header
        echo -e "${BOLD}${PURPLE}[ УВЕДОМЛЕНИЯ КОЛЛЕКТОРА ]${NC}"
        echo -e "${BOLD}Не получать push-уведомления:${NC}"
        list_file="$(mktemp)"
        if "${SUDO[@]}" env KTO_STATS_COLLECTOR_CONFIG="$STATS_COLLECTOR_CONFIG" \
            "$STATS_COLLECTOR_SCRIPT" --connection-alerts-list > "$list_file" 2>> "$LOG_FILE"; then
            if [[ -s "$list_file" ]]; then
                while IFS= read -r result_name; do
                    [[ -n "$result_name" ]] && printf '  - %s\n' "$result_name"
                done < "$list_file"
            else
                echo -e "  ${DIM}нет${NC}"
            fi
        else
            rm -f "$list_file"
            fail "Не удалось прочитать список отключённых уведомлений"
            return 1
        fi
        rm -f "$list_file"

        echo
        echo -e "${DIM}Статистика, SLA и downtime продолжат работать. Меняются только lost/restored уведомления.${NC}"
        echo -e "${DIM}Ввод обычной машины отключает уведомления, повторный ввод включает обратно.${NC}"
        echo -ne "${PURPLE}>${NC} ${BOLD}Название машины [0 - назад]:${NC} "
        read -r query
        query="$(trim_whitespace "$query")"
        if [[ -z "$query" || "$query" == "0" ]]; then
            return 0
        fi

        was_active=0
        if "${SUDO[@]}" systemctl is-active --quiet "$STATS_COLLECTOR_SERVICE" 2>/dev/null; then
            was_active=1
            if ! "${SUDO[@]}" systemctl stop "$STATS_COLLECTOR_SERVICE" >> "$LOG_FILE" 2>&1; then
                fail "Не удалось временно остановить коллектор"
                return 1
            fi
        fi

        result_file="$(mktemp)"
        if "${SUDO[@]}" env KTO_STATS_COLLECTOR_CONFIG="$STATS_COLLECTOR_CONFIG" \
            "$STATS_COLLECTOR_SCRIPT" --connection-alerts-toggle "$query" > "$result_file" 2>&1; then
            rc=0
        else
            rc=$?
        fi

        if (( was_active == 1 )); then
            if ! "${SUDO[@]}" systemctl start "$STATS_COLLECTOR_SERVICE" >> "$LOG_FILE" 2>&1; then
                cat "$result_file" >> "$LOG_FILE" 2>/dev/null || true
                rm -f "$result_file"
                fail "Состояние сохранено, но коллектор не запустился обратно"
                return 1
            fi
        fi

        result_line="$(tail -n 1 "$result_file" 2>/dev/null | tr -d '\r')"
        cat "$result_file" >> "$LOG_FILE" 2>/dev/null || true
        rm -f "$result_file"
        IFS=$'\t' read -r result_action result_name <<< "$result_line"
        if (( rc != 0 )); then
            fail "${result_name:-Не удалось изменить уведомления}"
        elif [[ "$result_action" == "disabled" ]]; then
            ok "Lost/restored уведомления отключены: ${result_name}"
        elif [[ "$result_action" == "enabled" ]]; then
            ok "Lost/restored уведомления включены: ${result_name}"
        else
            fail "Коллектор вернул непонятный ответ"
        fi

        echo
        echo -ne "${PURPLE}>${NC} Нажмите Enter, чтобы продолжить..."
        read -r _
    done
}

write_stats_push_script() {
    install_asset_file scripts/kto-stats-push.sh "$STATS_PUSH_SCRIPT" 0755
    if ! "${SUDO[@]}" mkdir -p "$(dirname "$STATS_PUSH_HAPROXY_HELPER")" >> "$LOG_FILE" 2>&1; then
        fail "Не удалось создать каталог HAProxy helper"
        return 1
    fi
    install_asset_file kto.sh "$STATS_PUSH_HAPROXY_HELPER" 0755
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
TimeoutStartSec=360
EOF

    write_root_file "/etc/systemd/system/${STATS_PUSH_TIMER}" <<EOF
[Unit]
Description=kto stats push timer

[Timer]
OnBootSec=20
OnUnitActiveSec=${interval}s
AccuracySec=1s
Unit=${STATS_PUSH_SERVICE}

[Install]
WantedBy=timers.target
EOF
}

install_stats_push_client() {
    header
    require_push_mode
    need_root

    local default_iface default_name node_name node_id node_uuid node_kind require_signed_response iface collector_url secret interval existing_config=0
    local ip_limit_enabled ip_limit_log_file ip_limit_docker_container ip_limit_user_regex ip_limit_ip_regex ip_limit_scan_sec ip_limit_tail_lines ip_limit_max_events ip_limit_xray_logs
    local safe_name safe_id safe_uuid safe_kind safe_require_signed_response safe_iface safe_url safe_secret safe_interval
    local safe_ip_limit_enabled safe_ip_limit_log_file safe_ip_limit_docker safe_ip_limit_user_regex safe_ip_limit_ip_regex safe_ip_limit_scan_sec safe_ip_limit_tail_lines safe_ip_limit_max_events safe_ip_limit_xray_logs
    node_uuid=""
    node_kind=""
    require_signed_response=""

    default_iface="$(config_get KTO_PUSH_IFACE "$STATS_PUSH_CONFIG")"
    default_iface="${default_iface:-$(default_network_interface)}"
    default_name="$(config_get KTO_PUSH_NODE_NAME "$STATS_PUSH_CONFIG")"
    if text_has_bad_utf8 "$default_name"; then
        warn "В старом push-конфиге имя машины уже с битой кодировкой, попрошу ввести его заново."
        default_name=""
    fi
    default_name="${default_name:-$(hostname 2>/dev/null || echo whitelist)}"

    if "${SUDO[@]}" test -s "$STATS_PUSH_CONFIG" 2>/dev/null; then
        node_id="$(config_get KTO_PUSH_NODE_ID "$STATS_PUSH_CONFIG")"
        node_name="$(config_get KTO_PUSH_NODE_NAME "$STATS_PUSH_CONFIG")"
        node_uuid="$(config_get KTO_PUSH_NODE_UUID "$STATS_PUSH_CONFIG")"
        node_kind="$(config_get KTO_PUSH_NODE_KIND "$STATS_PUSH_CONFIG")"
        require_signed_response="$(config_get KTO_PUSH_REQUIRE_SIGNED_RESPONSE "$STATS_PUSH_CONFIG")"
        iface="$(config_get KTO_PUSH_IFACE "$STATS_PUSH_CONFIG")"
        collector_url="$(config_get KTO_PUSH_COLLECTOR_URL "$STATS_PUSH_CONFIG")"
        secret="$(config_get KTO_PUSH_SECRET "$STATS_PUSH_CONFIG")"
        interval="$(config_get KTO_PUSH_INTERVAL "$STATS_PUSH_CONFIG")"
        ip_limit_enabled="$(config_get KTO_IP_LIMIT_ENABLED "$STATS_PUSH_CONFIG")"
        ip_limit_log_file="$(config_get KTO_IP_LIMIT_LOG_FILE "$STATS_PUSH_CONFIG")"
        ip_limit_docker_container="$(config_get KTO_IP_LIMIT_DOCKER_CONTAINER "$STATS_PUSH_CONFIG")"
        ip_limit_user_regex="$(config_get KTO_IP_LIMIT_USER_REGEX "$STATS_PUSH_CONFIG")"
        ip_limit_ip_regex="$(config_get KTO_IP_LIMIT_IP_REGEX "$STATS_PUSH_CONFIG")"
        ip_limit_scan_sec="$(config_get KTO_IP_LIMIT_SCAN_SEC "$STATS_PUSH_CONFIG")"
        ip_limit_tail_lines="$(config_get KTO_IP_LIMIT_TAIL_LINES "$STATS_PUSH_CONFIG")"
        ip_limit_max_events="$(config_get KTO_IP_LIMIT_MAX_EVENTS "$STATS_PUSH_CONFIG")"
        ip_limit_xray_logs="$(config_get KTO_IP_LIMIT_XRAY_LOGS "$STATS_PUSH_CONFIG")"
        if text_has_bad_utf8 "$node_name" || text_has_bad_utf8 "$node_id"; then
            warn "В push-конфиге имя машины сохранено с битой кодировкой, пройду настройку заново."
            node_name=""
            node_id=""
        fi
        if [[ -n "$node_id" && -n "$node_name" && -n "$iface" && -n "$collector_url" && -n "$secret" ]]; then
            existing_config=1
        else
            warn "Конфиг push неполный, пройду настройку заново."
        fi
    fi

    if (( existing_config == 1 )); then
        interval="${interval:-$STATS_PUSH_INTERVAL_DEFAULT}"
        node_id="${node_id:-$node_name}"
        ip_limit_enabled="${ip_limit_enabled:-$IP_LIMIT_ENABLED_DEFAULT}"
        ip_limit_log_file="${ip_limit_log_file:-}"
        ip_limit_docker_container="${ip_limit_docker_container:-$REMNA_CONTAINER}"
        ip_limit_user_regex="${ip_limit_user_regex:-}"
        ip_limit_ip_regex="${ip_limit_ip_regex:-}"
        ip_limit_scan_sec="${ip_limit_scan_sec:-$IP_LIMIT_SCAN_SEC_DEFAULT}"
        ip_limit_tail_lines="${ip_limit_tail_lines:-$IP_LIMIT_TAIL_LINES_DEFAULT}"
        if [[ "$ip_limit_tail_lines" == "500" ]]; then
            ip_limit_tail_lines="$IP_LIMIT_TAIL_LINES_DEFAULT"
        fi
        ip_limit_max_events="${ip_limit_max_events:-$IP_LIMIT_MAX_EVENTS_DEFAULT}"
        ip_limit_xray_logs="${ip_limit_xray_logs:-$IP_LIMIT_XRAY_LOGS_DEFAULT}"
        require_signed_response="${require_signed_response:-0}"
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
        if text_has_bad_utf8 "$node_name"; then
            fail "Название машины прочиталось невалидным UTF-8. Включил stty iutf8, повтори ввод без исправления кириллицы backspace."
            return 1
        fi
        node_id="$node_name"
        iface="$(ask_text "Интерфейс" "${iface:-${default_iface:-eth0}}")"
        if ! network_interface_exists "$iface"; then
            fail "Интерфейс ${iface} не найден. Проверь: ip -br link"
            return 1
        fi
        collector_url="$(ask_text "URL коллектора" "${collector_url:-$STATS_COLLECTOR_URL_DEFAULT}")"
        if [[ ! "$collector_url" =~ ^https?:// ]]; then
            fail "URL коллектора должен начинаться с http:// или https://"
            return 1
        fi
        secret="$(ask_secret_value "Секрет коллектора" "${secret:-}")"
        interval="$(ask_int "Интервал push, сек" "${interval:-$STATS_PUSH_INTERVAL_DEFAULT}" 1 3600)"
        ip_limit_enabled="$IP_LIMIT_ENABLED_DEFAULT"
        ip_limit_log_file=""
        ip_limit_docker_container="$REMNA_CONTAINER"
        ip_limit_user_regex=""
        ip_limit_ip_regex=""
        ip_limit_scan_sec="$IP_LIMIT_SCAN_SEC_DEFAULT"
        ip_limit_tail_lines="$IP_LIMIT_TAIL_LINES_DEFAULT"
        ip_limit_max_events="$IP_LIMIT_MAX_EVENTS_DEFAULT"
        ip_limit_xray_logs="$IP_LIMIT_XRAY_LOGS_DEFAULT"
        require_signed_response=0
    fi

    node_uuid="${node_uuid,,}"
    if [[ ! "$node_uuid" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]]; then
        node_uuid="$(generate_node_uuid)"
    fi
    if [[ ! "$node_uuid" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]]; then
        fail "Не удалось создать UUID машины."
        return 1
    fi
    if [[ "$MACHINE_MODE" == "whitelist" ]]; then
        node_kind="wl"
    else
        node_kind="bl"
    fi
    if [[ "$require_signed_response" != "1" ]]; then
        require_signed_response=0
    fi

    safe_name="$(escape_config_value "$node_name")"
    safe_id="$(escape_config_value "$node_id")"
    safe_uuid="$(escape_config_value "$node_uuid")"
    safe_kind="$(escape_config_value "$node_kind")"
    safe_require_signed_response="$(escape_config_value "$require_signed_response")"
    safe_iface="$(escape_config_value "$iface")"
    safe_url="$(escape_config_value "$collector_url")"
    safe_secret="$(escape_config_value "$secret")"
    safe_interval="$(escape_config_value "$interval")"
    safe_ip_limit_enabled="$(escape_config_value "$ip_limit_enabled")"
    safe_ip_limit_log_file="$(escape_config_value "$ip_limit_log_file")"
    safe_ip_limit_docker="$(escape_config_value "$ip_limit_docker_container")"
    safe_ip_limit_user_regex="$(escape_config_value "$ip_limit_user_regex")"
    safe_ip_limit_ip_regex="$(escape_config_value "$ip_limit_ip_regex")"
    safe_ip_limit_scan_sec="$(escape_config_value "$ip_limit_scan_sec")"
    safe_ip_limit_tail_lines="$(escape_config_value "$ip_limit_tail_lines")"
    safe_ip_limit_max_events="$(escape_config_value "$ip_limit_max_events")"
    safe_ip_limit_xray_logs="$(escape_config_value "$ip_limit_xray_logs")"

    if (( existing_config == 1 )); then
        stage "Обновляю push статистики"
    else
        stage "Устанавливаю push статистики"
    fi
    must "Установка пакетов push" apt_install_with_update_if_missing curl jq vnstat iptables conntrack socat openssl
    local monitor_iface
    while IFS= read -r monitor_iface; do
        [[ -n "$monitor_iface" ]] || continue
        if ! "${SUDO[@]}" vnstat --json -i "$monitor_iface" >/dev/null 2>&1; then
            cmd "${SUDO[@]}" vnstat -i "$monitor_iface" --add || true
        fi
    done < <(
        {
            printf '%s\n' "$iface"
            list_haproxy_additional_source_ips | awk -F '\t' '{print $2}'
        } | awk 'NF && !seen[$0]++'
    )
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
KTO_PUSH_NODE_UUID="$safe_uuid"
KTO_PUSH_NODE_KIND="$safe_kind"
KTO_PUSH_IFACE="$safe_iface"
KTO_PUSH_COLLECTOR_URL="$safe_url"
KTO_PUSH_SECRET="$safe_secret"
KTO_PUSH_REQUIRE_SIGNED_RESPONSE="$safe_require_signed_response"
KTO_PUSH_INTERVAL="$safe_interval"
KTO_IP_LIMIT_ENABLED="$safe_ip_limit_enabled"
KTO_IP_LIMIT_LOG_FILE="$safe_ip_limit_log_file"
KTO_IP_LIMIT_DOCKER_CONTAINER="$safe_ip_limit_docker"
KTO_IP_LIMIT_USER_REGEX="$safe_ip_limit_user_regex"
KTO_IP_LIMIT_IP_REGEX="$safe_ip_limit_ip_regex"
KTO_IP_LIMIT_SCAN_SEC="$safe_ip_limit_scan_sec"
KTO_IP_LIMIT_TAIL_LINES="$safe_ip_limit_tail_lines"
KTO_IP_LIMIT_MAX_EVENTS="$safe_ip_limit_max_events"
KTO_IP_LIMIT_XRAY_LOGS="$safe_ip_limit_xray_logs"
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
    require_push_mode
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
    require_push_mode
    need_root
    local timer_state config_ok
    timer_state="$(service_ok "$STATS_PUSH_TIMER")"
    config_ok="$([[ -s "$STATS_PUSH_CONFIG" ]] && echo 1 || echo 0)"
    print_row "push конфиг" "$STATS_PUSH_CONFIG" "$config_ok"
    print_row "push timer" "$STATS_PUSH_TIMER" "$timer_state"
}

stats_push_delete_client() {
    local had_push=0
    if "${SUDO[@]}" test -e "$STATS_PUSH_CONFIG" 2>/dev/null \
        || "${SUDO[@]}" test -e "$STATS_PUSH_SCRIPT" 2>/dev/null \
        || "${SUDO[@]}" test -e "$STATS_PUSH_HAPROXY_HELPER" 2>/dev/null \
        || "${SUDO[@]}" systemctl cat "$STATS_PUSH_TIMER" >/dev/null 2>&1 \
        || "${SUDO[@]}" systemctl cat "$STATS_PUSH_SERVICE" >/dev/null 2>&1; then
        had_push=1
    fi

    stage "Удаляю push статистики"
    cmd "${SUDO[@]}" systemctl disable --now "$STATS_PUSH_TIMER" "$STATS_PUSH_SERVICE" || true
    cmd "${SUDO[@]}" rm -f \
        "$STATS_PUSH_CONFIG" \
        "$STATS_PUSH_SCRIPT" \
        "$STATS_PUSH_HAPROXY_HELPER" \
        "$STATS_PUSH_TIMEOUT_DROPIN" \
        "/etc/systemd/system/${STATS_PUSH_TIMER}" \
        "/etc/systemd/system/${STATS_PUSH_SERVICE}"
    cmd "${SUDO[@]}" rm -rf /var/lib/kto-stats-push
    cmd "${SUDO[@]}" systemctl daemon-reload || true
    cmd "${SUDO[@]}" systemctl reset-failed "$STATS_PUSH_TIMER" "$STATS_PUSH_SERVICE" || true
    if (( had_push == 1 )); then
        ok "Push статистики полностью удалён"
    else
        ok "Push статистики не был настроен"
    fi
}

stats_collector_clear_runtime_state() {
    local had_collector=0 unit_exists=0 backup_dir ts moved=0 file
    if "${SUDO[@]}" test -d "$STATS_COLLECTOR_STATE_DIR" 2>/dev/null \
        || "${SUDO[@]}" systemctl cat "$STATS_COLLECTOR_SERVICE" >/dev/null 2>&1; then
        had_collector=1
    fi
    if (( had_collector == 0 )); then
        ok "State коллектора не найден"
        return 0
    fi

    if "${SUDO[@]}" systemctl cat "$STATS_COLLECTOR_SERVICE" >/dev/null 2>&1; then
        unit_exists=1
        cmd "${SUDO[@]}" systemctl stop "$STATS_COLLECTOR_SERVICE" || true
    fi

    ts="$(date +%Y%m%d-%H%M%S)"
    backup_dir="${STATS_COLLECTOR_STATE_DIR}/backup-before-delete-${ts}"
    cmd "${SUDO[@]}" mkdir -p "$backup_dir"

    for file in \
        nodes.json \
        falls.json \
        daily_report_date \
        node_names.json \
        bl_groups.json \
        stats_off.json \
        connection_alerts_off.json \
        update_state.json \
        remna_nodes.json \
        ip_limit.sqlite \
        ip_limit.sqlite-shm \
        ip_limit.sqlite-wal; do
        if "${SUDO[@]}" test -e "${STATS_COLLECTOR_STATE_DIR}/${file}" 2>/dev/null; then
            cmd "${SUDO[@]}" mv "${STATS_COLLECTOR_STATE_DIR}/${file}" "${backup_dir}/${file}"
            moved=1
        fi
    done

    if (( unit_exists == 1 )); then
        cmd "${SUDO[@]}" systemctl start "$STATS_COLLECTOR_SERVICE" || true
    fi

    if (( moved == 1 )); then
        ok "State коллектора очищен"
        ok "Бэкап: ${backup_dir}"
    else
        ok "В state коллектора нечего чистить"
    fi
}

stats_push_delete_all() {
    header
    need_root
    stats_push_delete_client
    stats_collector_clear_runtime_state
    ok "Готово. Машины появятся заново только после новой настройки/запуска push."
}

run_stats_push_debug() {
    header
    require_push_mode
    need_root

    if ! "${SUDO[@]}" test -s "$STATS_PUSH_CONFIG" 2>/dev/null; then
        fail "Push статистики не настроен."
        return 0
    fi

    local node_id node_name iface collector_url secret interval health_url debug_log rc iface_ok interval_label
    local ip_limit_enabled ip_limit_log_file ip_limit_docker_container ip_limit_scan_sec ip_limit_tail_lines ip_limit_max_events ip_limit_xray_logs
    node_id="$(config_get KTO_PUSH_NODE_ID "$STATS_PUSH_CONFIG")"
    node_name="$(config_get KTO_PUSH_NODE_NAME "$STATS_PUSH_CONFIG")"
    iface="$(config_get KTO_PUSH_IFACE "$STATS_PUSH_CONFIG")"
    collector_url="$(config_get KTO_PUSH_COLLECTOR_URL "$STATS_PUSH_CONFIG")"
    secret="$(config_get KTO_PUSH_SECRET "$STATS_PUSH_CONFIG")"
    interval="$(config_get KTO_PUSH_INTERVAL "$STATS_PUSH_CONFIG")"
    ip_limit_enabled="$(config_get KTO_IP_LIMIT_ENABLED "$STATS_PUSH_CONFIG")"
    ip_limit_log_file="$(config_get KTO_IP_LIMIT_LOG_FILE "$STATS_PUSH_CONFIG")"
    ip_limit_docker_container="$(config_get KTO_IP_LIMIT_DOCKER_CONTAINER "$STATS_PUSH_CONFIG")"
    ip_limit_scan_sec="$(config_get KTO_IP_LIMIT_SCAN_SEC "$STATS_PUSH_CONFIG")"
    ip_limit_tail_lines="$(config_get KTO_IP_LIMIT_TAIL_LINES "$STATS_PUSH_CONFIG")"
    ip_limit_max_events="$(config_get KTO_IP_LIMIT_MAX_EVENTS "$STATS_PUSH_CONFIG")"
    ip_limit_xray_logs="$(config_get KTO_IP_LIMIT_XRAY_LOGS "$STATS_PUSH_CONFIG")"

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
    print_row "ip limit" "${ip_limit_enabled:-0}" "$([[ "${ip_limit_enabled:-0}" == "1" ]] && echo 1 || echo 0)"
    print_row "ip log file" "${ip_limit_log_file:-empty}"
    print_row "ip docker" "${ip_limit_docker_container:-empty}"
    print_row "ip scan" "${ip_limit_scan_sec:-$IP_LIMIT_SCAN_SEC_DEFAULT}s"
    print_row "ip tail" "${ip_limit_tail_lines:-$IP_LIMIT_TAIL_LINES_DEFAULT}"
    print_row "ip max events" "${ip_limit_max_events:-$IP_LIMIT_MAX_EVENTS_DEFAULT}"
    print_row "ip xray logs" "${ip_limit_xray_logs:-$IP_LIMIT_XRAY_LOGS_DEFAULT}"

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
            warn "Push не вывел текст ошибки. Запусти stats-push-update и повтори debug."
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
        echo -e "5) Полностью удалить push / очистить collector state"
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
            5)
                stats_push_delete_all
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
    if [[ "$kernel" == *xanmod* ]]; then
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

    if node_profile_includes_hysteria2; then
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
        if node_profile_includes_reality; then
            labels+=("Установка SelfSteal")
            actions+=("selfsteal")
        fi
        labels+=("Установка VPS-WARP")
        actions+=("warp")
        labels+=("Push статистики")
        actions+=("stats-push-menu")
    fi

    labels+=("Панель состояния")
    actions+=("status")
    labels+=("Тест сети")
    actions+=("network-test")
    if [[ "$MACHINE_MODE" != "panel" ]]; then
        labels+=("Проверка ТСПУ")
        actions+=("dpi-test")
        labels+=("Проверка ТСПУ (IP)")
        actions+=("dpi-ip-test")
        labels+=("Пакетный TCP-MTR")
        actions+=("mtr-batch")
    fi
    if [[ "$MACHINE_MODE" != "panel" ]]; then
        labels+=("Проверить и завести дополнительные IP")
        actions+=("additional-ips")
        labels+=("Оптимизировать сеть всех IP")
        actions+=("additional-ips-optimize")
    fi
    if [[ "$MACHINE_MODE" == "node" ]] && node_profile_includes_reality; then
        labels+=("Исходящий IP Remnawave")
        actions+=("remnawave-egress")
    fi
    if [[ "$MACHINE_MODE" == "panel" ]]; then
        labels+=("Коллектор статистики")
        actions+=("stats-collector")
        labels+=("Статус коллектора")
        actions+=("stats-collector-status")
        labels+=("Не получать push-уведомления")
        actions+=("stats-collector-alerts")
        labels+=("Очистить список статистики")
        actions+=("stats-push-delete")
    else
        labels+=("Speedtest")
        actions+=("speedtest")
        labels+=("Speedtest (RU)")
        actions+=("speedtest-ru")
        labels+=("Проверка IP (IP.Check.Place)")
        actions+=("ipcheck-place")
        labels+=("Проверка IP (Region Check)")
        actions+=("ipcheck-region")
    fi

    if [[ "$MACHINE_MODE" == "node" ]] && node_profile_includes_hysteria2; then
        labels+=("Сгенерировать SSL-сертификат")
        actions+=("ssl")
    fi
    if [[ "$MACHINE_MODE" == "whitelist" ]]; then
        labels+=("btop")
        actions+=("btop")
        labels+=("HAProxy")
        actions+=("haproxy")
        if mobile443_lte_configured; then
            labels+=("Режим \"Только LTE\" (включён)")
        else
            labels+=("Включение режима \"Только LTE\"")
        fi
        actions+=("mobile443-lte")
        labels+=("Статус режима \"Только LTE\"")
        actions+=("mobile443-lte-status")
        labels+=("Push статистики")
        actions+=("stats-push-menu")
    elif [[ "$MACHINE_MODE" == "node" ]] && node_profile_includes_reality; then
        labels+=("HAProxy (мост, 8443/tcp)")
        actions+=("haproxy")
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
        network-test) network_test ;;
        dpi-test) run_dpi_detector ;;
        dpi-ip-test) run_tspu_ip_test ;;
        mtr-batch) run_mtr_batch || true ;;
        additional-ips) setup_additional_ips || true ;;
        additional-ips-optimize) optimize_additional_ip_networks || true ;;
        remnawave-egress) configure_remnawave_egress || true ;;
        stats-collector) install_stats_collector ;;
        stats-collector-status) stats_collector_status ;;
        stats-collector-alerts) stats_collector_alerts_menu ;;
        stats-push-delete) stats_push_delete_all ;;
        speedtest) install_speedtest ;;
        speedtest-ru) speedtest_ru ;;
        ipcheck-place) ipcheck_place ;;
        ipcheck-region) ipcheck_region ;;
        btop) run_btop_for_ip || true ;;
        ssl) issue_ssl_certificate ;;
        haproxy) install_haproxy ;;
        haproxy-update) update_haproxy_existing_config ;;
        mobile443-lte) mobile443_lte_menu ;;
        mobile443-lte-status) show_mobile443_lte_status ;;
        stats-push-menu) stats_push_menu ;;
        settings) settings_menu ;;
        *) fail "Неверный выбор" ;;
    esac
}

main() {
    if [[ "${1:-}" == "haproxy-remote-report" ]]; then
        haproxy_remote_report_json
        return
    fi
    if [[ "${1:-}" == "haproxy-bandwidth-remote-report" ]]; then
        haproxy_bandwidth_remote_report_json
        return
    fi
    init_log
    ensure_utf8_locale
    case "${1:-}" in
        haproxy-remote-apply)
            load_machine_mode
            haproxy_remote_apply_json
            return
            ;;
        haproxy-bandwidth-remote-apply)
            load_machine_mode
            haproxy_bandwidth_remote_apply_json
            return
            ;;
    esac
    migrate_superseded_kto_state
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
        selfsteal-harden|selfsteal-timeouts) harden_selfsteal_caddy_now ;;
        warp) install_warp_native ;;
        status) show_status ;;
        network-test|net-test|netcheck|network-check|diag-network|diagnose-network) shift; network_test "$@" || true ;;
        conntrack-fix|fix-conntrack|conntrack-optimize) fix_conntrack_capacity_cli ;;
        dpi-test|dpi-detector|tspu-test|tspu) run_dpi_detector "${2:-}" ;;
        dpi-ip-test|dpi-ip|tspu-ip-test|tspu-ip) shift; run_tspu_ip_test "${1:-}" "${2:-}" ;;
        mtr-batch|batch-mtr|multi-mtr|tcp-mtr-batch) shift; run_mtr_batch "$@" ;;
        additional-ips|extra-ips|multi-ip|multiwan) setup_additional_ips ;;
        additional-ips-optimize|extra-ips-optimize|multi-ip-optimize|multiwan-optimize|network-repair) optimize_additional_ip_networks ;;
        remnawave-egress|remna-egress|reality-egress|xray-egress) shift; configure_remnawave_egress "${1:-menu}" ;;
        speedtest) install_speedtest "${2:-}" "${3:-}" ;;
        speedtest-ru|speedtestru|bench-ru|benchru) speedtest_ru "${2:-}" ;;
        ipcheck-place) ipcheck_place "${2:-}" ;;
        ipcheck-region) ipcheck_region "${2:-}" ;;
        btop|btop-ip|monitor-ip) run_btop_for_ip "${2:-}" ;;
        ssl) issue_ssl_certificate ;;
        haproxy|install-haproxy) install_haproxy ;;
        haproxy-update|update-haproxy|haproxy-refresh) update_haproxy_existing_config ;;
        haproxy-pool-set|haproxy-set-pool) shift; set_haproxy_pool_route_cli "$@" ;;
        haproxy-pool-collapse|haproxy-collapse-pool) shift; collapse_haproxy_pool_cli "$@" ;;
        haproxy-routes-set|haproxy-set-routes) shift; set_haproxy_sequential_routes_cli "$@" ;;
        haproxy-limit|haproxy-bandwidth-limit) shift; set_haproxy_input_bandwidth_limit_cli "$@" ;;
        haproxy-limit-off|haproxy-bandwidth-off) shift; remove_haproxy_input_bandwidth_limit_cli "$@" ;;
        haproxy-limit-clear|haproxy-bandwidth-clear) clear_all_haproxy_bandwidth_limits_cli ;;
        haproxy-limit-apply|haproxy-bandwidth-apply|haproxy-limit-reapply) apply_haproxy_bandwidth_limits_cli ;;
        haproxy-limit-status|haproxy-bandwidth-status) show_haproxy_bandwidth_status_cli ;;
        haproxy-diagnose|haproxy-diagnostic|haproxy-diag|haproxy-status) diagnose_haproxy || true ;;
        haproxy-firewall-repair|haproxy-ufw-repair|repair-haproxy-firewall) repair_haproxy_firewall_cli ;;
        haproxy-stabilize|haproxy-recover) stabilize_haproxy ;;
        mobile443-lte|lte-only) mobile443_lte_menu ;;
        mobile443-lte-enable|lte-only-enable) enable_mobile443_lte ;;
        mobile443-lte-disable|lte-only-disable) disable_mobile443_lte ;;
        mobile443-lte-status|lte-only-status) show_mobile443_lte_status ;;
        collector|collector-install|collector-update|stats-collector|stats-collector-update) install_stats_collector ;;
        collector-status|stats-collector-status) stats_collector_status ;;
        collector-alerts|stats-collector-alerts|push-alerts) stats_collector_alerts_menu ;;
        push-menu|stats-push-menu) stats_push_menu ;;
        stats-push|stats-push-install|stats-push-update) install_stats_push_client ;;
        stats-push-send) send_stats_push_once ;;
        stats-push-status) stats_push_status ;;
        stats-push-debug|push-debug) run_stats_push_debug ;;
        stats-push-delete|push-delete|stats-delete|stats-clear) stats_push_delete_all ;;
        *) menu ;;
    esac
}

main "$@"
