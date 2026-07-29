#!/usr/bin/env bash
# shellcheck shell=bash

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || pwd)"
KTO_RAW_BASE="${KTO_RAW_BASE:-https://raw.githubusercontent.com/Alpha012/kto-optimize/main}"
SCRIPT_VERSION="1.4.8.8"
SCRIPT_BUILD="v249"
NODE_PORT="${KTO_NODE_PORT:-1488}"
PANEL_IP="${KTO_PANEL_IP:-64.188.91.72}"
WARP_INSTALL_URL="${KTO_WARP_INSTALL_URL:-https://raw.githubusercontent.com/tagashi666/vps-warp/main/warp_install.sh}"
WHITELIST_SSH_ALLOWED_IPS_DEFAULT="85.192.48.122 46.28.64.183 146.19.248.67 85.93.9.35 185.31.243.221 94.247.129.92 83.228.242.53 167.254.243.181 5.34.176.116 5.34.178.234 84.38.185.15 193.23.195.222"
WHITELIST_SSH_ALLOWED_IPS="${KTO_WHITELIST_SSH_ALLOWED_IPS:-$WHITELIST_SSH_ALLOWED_IPS_DEFAULT}"
WHITELIST_SSH_KEEP_CURRENT="${KTO_WHITELIST_SSH_KEEP_CURRENT:-1}"
MOBILE443_DIR="/opt/mobile443"
MOBILE443_CONFIG="${MOBILE443_DIR}/config.conf"
MOBILE443_MANAGER="/usr/local/sbin/kto-mobile443"
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
KTO_LIMITS_CONF="/etc/security/limits.d/99-kto-limits.conf"
KTO_SYSTEMD_LIMITS_CONF="/etc/systemd/system.conf.d/99-kto-limits.conf"
KTO_USER_LIMITS_CONF="/etc/systemd/user.conf.d/99-kto-limits.conf"
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
STATS_COLLECTOR_PORT_DEFAULT="${KTO_STATS_COLLECTOR_PORT_DEFAULT:-1337}"
STATS_COLLECTOR_URL_DEFAULT="${KTO_STATS_COLLECTOR_URL_DEFAULT:-http://${PANEL_IP}:${STATS_COLLECTOR_PORT_DEFAULT}}"
STATS_PUSH_INTERVAL_DEFAULT="${KTO_STATS_PUSH_INTERVAL_DEFAULT:-5}"
STATS_COLLECTOR_STALE_SEC_DEFAULT="60"
STATS_COLLECTOR_BL_STALE_SEC_DEFAULT="${KTO_COLLECTOR_BL_STALE_SEC_DEFAULT:-15}"
STATS_COLLECTOR_BL_OFFLINE_CONFIRM_SEC_DEFAULT="${KTO_COLLECTOR_BL_OFFLINE_CONFIRM_SEC_DEFAULT:-5}"
STATS_COLLECTOR_BL_STALE_FALLBACK_SEC_DEFAULT="${KTO_COLLECTOR_BL_STALE_FALLBACK_SEC_DEFAULT:-45}"
STATS_COLLECTOR_BL_PUSH_INTERVAL_SEC_DEFAULT="${KTO_COLLECTOR_BL_PUSH_INTERVAL_SEC_DEFAULT:-1}"
STATS_COLLECTOR_PUSH_MISS_WINDOW_SEC_DEFAULT="${KTO_COLLECTOR_PUSH_MISS_WINDOW_SEC_DEFAULT:-60}"
STATS_COLLECTOR_PUSH_MISS_THRESHOLD_DEFAULT="${KTO_COLLECTOR_PUSH_MISS_THRESHOLD_DEFAULT:-30}"
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
SPEEDTEST_STATIC_VERSION="1.2.0"
SPEEDTEST_PACKAGE_VERSION="1.2.0.84-1.ea6b6773cf"
SPEEDTEST_X86_64_ARCHIVE_SHA256="5690596c54ff9bed63fa3732f818a05dbc2db19ad36ed68f21ca5f64d5cfeeb7"
SPEEDTEST_AARCH64_ARCHIVE_SHA256="3953d231da3783e2bf8904b6dd72767c5c6e533e163d3742fd0437affa431bd3"
SPEEDTEST_AMD64_DEB_SHA256="35e084567a6388631fb10cf01e5e0d6b57a67d34ede2b72ba111b3d9164c8b94"
SPEEDTEST_ARM64_DEB_SHA256="98e7de9db3bf181d08bc67e647bcfc71349c8014e387289c08e54e5c55d82f37"
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
        if [[ "$MACHINE_MODE" == "whitelist" ]]; then
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
                if [[ "$MACHINE_MODE" == "whitelist" ]]; then
                    haproxy_menu
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
    raw="$(printf '%s' "$raw" | tr -d '[:space:]')"
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

normalize_haproxy_sni_list() {
    local raw="${1:-}" token base existing
    local -a tokens=() normalized=()

    raw="${raw//,/ }"
    raw="${raw//;/ }"
    IFS=' ' read -r -a tokens <<< "$raw"
    for token in "${tokens[@]}"; do
        token="${token,,}"
        token="${token%.}"
        [[ -n "$token" ]] || continue
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

render_haproxy_sni_acl_lines() {
    local raw="${1:-}" normalized token
    local -a values=() exact_values=() wildcard_suffixes=()

    normalized="$(normalize_haproxy_sni_list "$raw")" || return 1
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

whitelist_ssh_allowed_ips() {
    local raw current ip
    raw="${WHITELIST_SSH_ALLOWED_IPS//,/ }"
    raw="${raw//;/ }"
    for ip in $raw; do
        validate_ipv4 "$ip" && echo "$ip"
    done

    if [[ "$WHITELIST_SSH_KEEP_CURRENT" != "0" ]]; then
        current="$(current_ssh_client_ip || true)"
        if [[ -n "$current" ]]; then
            echo "$current"
        fi
    fi
}

apply_whitelist_ssh_rules() {
    local ssh_port="$1"
    local ip

    cmd "${SUDO[@]}" ufw --force delete allow "${ssh_port}/tcp" || true
    cmd "${SUDO[@]}" ufw --force delete allow ssh || true
    cmd "${SUDO[@]}" ufw --force delete allow OpenSSH || true
    while read -r ip; do
        [[ -n "$ip" ]] || continue
        cmd "${SUDO[@]}" ufw allow proto tcp from "$ip" to any port "$ssh_port" comment 'kto-ssh' || true
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

ask_haproxy_sni_list() {
    local prompt="$1" default="${2:-}" value normalized
    while true; do
        value="$(ask_text "$prompt" "$default")"
        if normalized="$(normalize_haproxy_sni_list "$value")"; then
            echo "$normalized"
            return 0
        fi
        fail "Некорректный SNI. Примеры: example.com, *.example.com; несколько значений — через пробел."
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

opt_liquorix_kernel() {
    local attempt installed=0

    if [[ "$(uname -m)" != "x86_64" ]] || ! grep -qi '^ID=ubuntu' /etc/os-release 2>/dev/null; then
        echo "Liquorix skipped: non-Ubuntu or non-amd64" >> "$LOG_FILE"
        return 0
    fi

    if liquorix_installed; then
        echo "Liquorix skipped: packages already installed" >> "$LOG_FILE"
        return 0
    fi

    if liquorix_source_configured; then
        apt_update_quiet || echo "Liquorix apt update failed, trying current apt cache" >> "$LOG_FILE"
    else
        if ! cmd "${SUDO[@]}" add-apt-repository ppa:damentz/liquorix -y; then
            warn "Liquorix: не смог добавить PPA."
            return 1
        fi
        if ! apt_update_force; then
            warn "Liquorix: apt update после PPA не прошёл."
            return 1
        fi
    fi

    for attempt in 1 2 3 4; do
        if (( attempt > 1 )); then
            echo "Liquorix install retry ${attempt}" >> "$LOG_FILE"
            cmd "${SUDO[@]}" dpkg --configure -a || true
            apt_update_force || true
        fi
        if apt_install_quiet linux-image-liquorix-amd64 linux-headers-liquorix-amd64 && liquorix_installed; then
            installed=1
            break
        fi
        sleep $(( attempt * 2 ))
    done

    if (( installed == 0 )); then
        warn "Liquorix: пакеты kernel не поставились после повторов."
        return 1
    fi

    return 0
}

opt_kernel_final_check() {
    if [[ "$(uname -m)" != "x86_64" ]] || ! grep -qi '^ID=ubuntu' /etc/os-release 2>/dev/null; then
        return 0
    fi
    if liquorix_installed; then
        echo "Liquorix final check: packages installed" >> "$LOG_FILE"
        return 0
    fi
    warn "Liquorix: не установлен после первого этапа, повторяю отдельно."
    if opt_liquorix_kernel && liquorix_installed; then
        ok "Liquorix kernel установлен. После оптимизации нужен reboot."
        return 0
    fi
    warn "Liquorix kernel не удалось установить. Остальная оптимизация продолжена; смотри лог: $LOG_FILE"
    return 0
}

opt_kernel_network_memory_parallel() {
    parallel_run_tasks \
        "kernel" opt_liquorix_kernel \
        "network limits" opt_network_limits \
        "memory guard" opt_memory_guard
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
    local anti_rules routes_file="" port target sni
    anti_rules="$(antiscanner_rules_count)"

    if [[ "${KTO_UFW_RESET:-0}" == "1" ]]; then
        cmd "${SUDO[@]}" ufw --force reset
    elif [[ "$anti_rules" =~ ^[0-9]+$ && "$anti_rules" -gt 0 ]]; then
        echo "ufw reset skipped: preserving AntiScanner rules ($anti_rules)" >> "$LOG_FILE"
    else
        echo "ufw reset skipped: preserving existing rules" >> "$LOG_FILE"
    fi
    cmd "${SUDO[@]}" ufw default deny incoming
    cmd "${SUDO[@]}" ufw default allow outgoing
    if [[ "$MACHINE_MODE" == "whitelist" ]]; then
        apply_whitelist_ssh_rules "$ssh_port"
    else
        cmd "${SUDO[@]}" ufw allow "${ssh_port}/tcp"
    fi
    if [[ "$MACHINE_MODE" == "whitelist" ]]; then
        routes_file="$(mktemp)"
        extract_haproxy_routes > "$routes_file"
        if [[ -s "$routes_file" ]]; then
            while IFS=$'\t' read -r port target sni; do
                [[ "$port" =~ ^[0-9]+$ ]] || continue
                cmd "${SUDO[@]}" ufw allow "${port}/tcp"
            done < "$routes_file"
        else
            cmd "${SUDO[@]}" ufw allow 443/tcp
        fi
    else
        cmd "${SUDO[@]}" ufw allow 443/tcp
    fi
    if [[ "$MACHINE_MODE" == "node" ]]; then
        cmd "${SUDO[@]}" ufw allow 443/udp
        cmd "${SUDO[@]}" ufw allow "${NODE_PORT}/tcp"
    else
        cmd "${SUDO[@]}" ufw --force delete allow 443/udp || true
        if [[ -z "$routes_file" ]] || ! haproxy_route_file_has_port "$routes_file" "$NODE_PORT"; then
            cmd "${SUDO[@]}" ufw --force delete allow "${NODE_PORT}/tcp" || true
        fi
    fi
    cmd "${SUDO[@]}" ufw --force enable
    [[ -z "$routes_file" ]] || rm -f "$routes_file"
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

ufw_rule_open_to_any() {
    local rule="$1"
    command_exists ufw || return 1
    "${SUDO[@]}" ufw status 2>/dev/null \
        | awk -v rule="$rule" '$0 ~ /ALLOW/ && $1 == rule && $3 ~ /^Anywhere/ {found=1} END{exit found ? 0 : 1}'
}

ufw_rule_from_allowed() {
    local rule="$1"
    local ip="$2"
    command_exists ufw || return 1
    "${SUDO[@]}" ufw status 2>/dev/null \
        | awk -v rule="$rule" -v ip="$ip" '$0 ~ /ALLOW/ && $1 == rule && $3 == ip {found=1} END{exit found ? 0 : 1}'
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

    root_file_has_line "$KTO_TUNING_SYSCTL_CONF" "net.ipv4.tcp_congestion_control = bbr" || sysctl_file_ok=0
    root_file_has_line "$KTO_TUNING_SYSCTL_CONF" "net.core.default_qdisc = fq" || sysctl_file_ok=0
    root_file_has_line "$KTO_TUNING_SYSCTL_CONF" "fs.file-max = 2097152" || sysctl_file_ok=0
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
    local missing=() extra=() routes_file="" port target sni

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

    if [[ "$MACHINE_MODE" == "whitelist" ]]; then
        whitelist_ssh_rules_configured "$ssh_port" || missing+=("ssh allowlist")
    else
        ufw_rule_allowed "${ssh_port}/tcp" || missing+=("${ssh_port}/tcp")
    fi
    if [[ "$MACHINE_MODE" == "whitelist" ]]; then
        routes_file="$(mktemp)"
        extract_haproxy_routes > "$routes_file"
        if [[ -s "$routes_file" ]]; then
            while IFS=$'\t' read -r port target sni; do
                [[ "$port" =~ ^[0-9]+$ ]] || continue
                ufw_rule_allowed "${port}/tcp" || missing+=("${port}/tcp")
            done < "$routes_file"
        else
            ufw_rule_allowed "443/tcp" || missing+=("443/tcp")
        fi
    else
        ufw_rule_allowed "443/tcp" || missing+=("443/tcp")
    fi
    if [[ "$MACHINE_MODE" == "node" ]]; then
        ufw_rule_allowed "443/udp" || missing+=("443/udp")
        ufw_rule_allowed "${NODE_PORT}/tcp" || missing+=("${NODE_PORT}/tcp")
    else
        ufw_rule_allowed "443/udp" && extra+=("443/udp")
        if [[ -z "$routes_file" ]] || ! haproxy_route_file_has_port "$routes_file" "$NODE_PORT"; then
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
    [[ -z "$routes_file" ]] || rm -f "$routes_file"
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

    progress_start 8
    progress_step "Готовлю систему" opt_prepare_system
    progress_step "Ставлю базовые пакеты" opt_install_fast_packages
    progress_step "Kernel, сеть и память" opt_kernel_network_memory_parallel
    progress_step "Проверяю kernel" opt_kernel_final_check
    progress_step "Настраиваю хранение" opt_storage_guard
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
    local output filtered output_file arch rc server_id binary profile
    local archive_url archive_hash deb_url deb_hash deb_arch
    local -a speedtest_args speedtest_retry_args

    server_id="${1:-${KTO_SPEEDTEST_SERVER_ID:-}}"
    if [[ -n "$server_id" ]] && ! [[ "$server_id" =~ ^[0-9]+$ ]]; then
        fail "Speedtest server id должен быть числом"
        return 1
    fi

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

    speedtest_args=("$binary" --accept-license --accept-gdpr --progress=yes)
    speedtest_retry_args=("$binary" --accept-license --accept-gdpr --progress=no)
    if [[ -n "$server_id" ]]; then
        speedtest_args+=(--server-id="$server_id")
        speedtest_retry_args+=(--server-id="$server_id")
        ok "Сервер Speedtest: ${server_id}"
    fi

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

speedtest_ru() {
    header
    need_root
    local bench_script

    stage "Запускаю Speedtest (RU)"
    apt_install_with_update_if_missing wget ca-certificates

    bench_script="$(mktemp)"
    cleanup_speedtest_ru() {
        trap - RETURN
        rm -f "$bench_script"
    }
    trap cleanup_speedtest_ru RETURN

    must "Скачивание bench.tlab.pw" wget -qO "$bench_script" https://bench.tlab.pw
    if ! head -n 1 "$bench_script" | grep -Eq '^#!.*bash' \
        || ! grep -q '^speed_test()' "$bench_script" \
        || ! bash -n "$bench_script"; then
        fail "bench.tlab.pw вернул неожиданный скрипт"
        return 1
    fi

    echo "running: wget -qO- https://bench.tlab.pw | bash" >> "$LOG_FILE"
    bash "$bench_script"
}

NETTEST_DNS_BAD=0
NETTEST_HTTPS_BAD=0
NETTEST_RAW_OK=0
NETTEST_RAW_BAD=0
NETTEST_PING_BAD=0
NETTEST_WARN=0

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
    ips="$(getent ahostsv4 "$host" 2>/dev/null | awk '{print $1}' | sort -u | paste -sd ' ' - || true)"
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
    if command_exists timeout; then
        timeout --foreground "${timeout_sec}s" bash -c 'cat </dev/null >/dev/tcp/"$1"/"$2"' _ "$host" "$port" >/dev/null 2>&1
    else
        bash -c 'cat </dev/null >/dev/tcp/"$1"/"$2"' _ "$host" "$port" >/dev/null 2>&1
    fi
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

    if output="$(curl -4 -sS -o /dev/null \
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

    if output="$(curl -4 -sS -o /dev/null \
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
    local tmp loss rtt status
    if ! command_exists ping; then
        network_test_row "ping ${label}" "ping не найден" "skip"
        (( NETTEST_WARN += 1 ))
        return 0
    fi

    tmp="$(mktemp)"
    if ping -c 4 -W 2 "$target" > "$tmp" 2>&1; then
        status="ok"
    else
        status="warn"
        (( NETTEST_PING_BAD += 1 ))
    fi
    loss="$(awk -F',' '/packet loss/ {gsub(/^[[:space:]]+|[[:space:]]+$/, "", $3); print $3; exit}' "$tmp" 2>/dev/null || true)"
    rtt="$(awk -F'/' '/^(rtt|round-trip)/ {print $5 " ms"; exit}' "$tmp" 2>/dev/null || true)"
    rm -f "$tmp"
    network_test_row "ping ${label}" "loss=${loss:-?}${rtt:+ avg=${rtt}}" "$status"
}

network_test_mtr() {
    local target="$1"
    local label="${2:-$1}"
    local out
    if ! command_exists mtr; then
        network_test_row "mtr ${label}" "mtr не установлен" "skip"
        return 0
    fi
    out="$(mtr -4 -T -P 443 -c 5 -r "$target" 2>/dev/null | tail -n 4 | sed 's/^[[:space:]]*//' | paste -sd ' | ' - || true)"
    network_test_row "mtr ${label}" "$(network_test_short "${out:-нет вывода}")"
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
    local iface route_line default_route src_ip mtu dns_line host gateway ip target
    local -a raw_ips default_hosts extra_targets
    extra_targets=("$@")
    raw_ips=(185.199.108.133 185.199.109.133 185.199.110.133 185.199.111.133)
    default_hosts=(raw.githubusercontent.com github.com api.github.com)

    NETTEST_DNS_BAD=0
    NETTEST_HTTPS_BAD=0
    NETTEST_RAW_OK=0
    NETTEST_RAW_BAD=0
    NETTEST_PING_BAD=0
    NETTEST_WARN=0

    echo -e "${BOLD}${PURPLE}[ СЕТЬ ]${NC}"
    route_line="$(ip -4 route get 1.1.1.1 2>/dev/null || true)"
    iface="$(awk '{for (i=1; i<=NF; i++) if ($i=="dev") {print $(i+1); exit}}' <<< "$route_line")"
    src_ip="$(awk '{for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}' <<< "$route_line")"
    gateway="$(ip -4 route show default 2>/dev/null | awk '{print $3; exit}' || true)"
    default_route="$(ip -4 route show default 2>/dev/null | head -n 1 || true)"
    if [[ -n "$iface" ]]; then
        mtu="$(ip -o link show dev "$iface" 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="mtu") {print $(i+1); exit}}' || true)"
    else
        mtu=""
    fi
    network_test_row "interface" "${iface:--}${src_ip:+ src=${src_ip}}${mtu:+ mtu=${mtu}}"
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

    if (( NETTEST_DNS_BAD > 0 || NETTEST_HTTPS_BAD > 0 || NETTEST_RAW_BAD > 0 )); then
        echo
        warn "Если github/api живые, а raw IP выборочно таймаутятся - это обычно маршрут провайдера до Fastly/GitHub, а не Ubuntu."
        warn "Для временного костыля можно прибить raw.githubusercontent.com к рабочему IP из блока RAW GITHUB IP."
        return 1
    fi

    echo
    ok "Сеть выглядит нормально по базовым проверкам."
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

reload_haproxy_gracefully() {
    if "${SUDO[@]}" systemctl is-active --quiet haproxy 2>/dev/null; then
        if "${SUDO[@]}" systemctl reload haproxy >> "$LOG_FILE" 2>&1; then
            ok "HAProxy применён через reload"
            return 0
        fi
        warn "HAProxy reload не прошёл, делаю restart."
    fi

    if "${SUDO[@]}" systemctl restart haproxy >> "$LOG_FILE" 2>&1; then
        ok "HAProxy применён через restart"
        return 0
    fi
    fail "Не удалось запустить HAProxy"
    return 1
}

extract_haproxy_routes() {
    local config="${1:-/etc/haproxy/haproxy.cfg}"
    local raw port target sni normalized_target normalized_sni

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
            sub(/^.*:/, "", address)
            sub(/[^0-9].*$/, "", address)
            frontend_port[name] = address
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
        section == "backend" && $1 == "server" && !(name in backend_target) {
            backend_target[name] = $3
            next
        }
        END {
            for (i = 1; i <= frontend_count; i++) {
                frontend = frontend_order[i]
                backend = frontend_backend[frontend]
                if (frontend_port[frontend] != "" && frontend_sni[frontend] != "" && backend_target[backend] != "") {
                    printf "%s\t%s\t%s\n", frontend_port[frontend], backend_target[backend], frontend_sni[frontend]
                }
            }
        }
    ' "$config" 2>/dev/null || true)"

    while IFS=$'\t' read -r port target sni; do
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        port=$((10#$port))
        (( port >= 1 && port <= 65535 )) || continue
        normalized_target="$(normalize_haproxy_target "$target" 2>/dev/null || true)"
        normalized_sni="$(normalize_haproxy_sni_list "$sni" 2>/dev/null || true)"
        [[ -n "$normalized_target" && -n "$normalized_sni" ]] || continue
        printf '%d\t%s\t%s\n' "$port" "$normalized_target" "$normalized_sni"
    done <<< "$raw" | sort -t $'\t' -k1,1n
}

extract_haproxy_backend_target() {
    extract_haproxy_routes | awk -F '\t' 'NR == 1 { print $2; exit }'
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

haproxy_route_count() {
    awk -F '\t' 'NF >= 3 { count++ } END { print count + 0 }' "$1"
}

recommended_haproxy_maxconn() {
    local override="${KTO_HAPROXY_MAXCONN:-}"
    local total_mb maxconn

    if [[ "$override" =~ ^[0-9]+$ ]]; then
        maxconn=$(( 10#$override ))
        if (( maxconn >= 1000 && maxconn <= 500000 )); then
            echo "$maxconn"
            return 0
        fi
    fi

    total_mb="$(memory_total_mb)"
    [[ "$total_mb" =~ ^[0-9]+$ ]] || total_mb=0
    (( total_mb > 0 )) || total_mb=2048

    # Two proxy-side sockets and HAProxy buffers make RAM the real connection limit.
    maxconn=$(( total_mb * 16 ))
    (( maxconn < 10000 )) && maxconn=10000
    (( maxconn > 500000 )) && maxconn=500000
    echo "$maxconn"
}

render_haproxy_routes_config() {
    local routes_file="$1" output_file="$2"
    local port backend_target allowed_sni normalized_target normalized_sni
    local frontend_name backend_name server_name haproxy_threads haproxy_maxconn route_count=0
    local -A seen_ports=()

    while IFS=$'\t' read -r port backend_target allowed_sni; do
        [[ "$port" =~ ^[0-9]+$ ]] || {
            fail "Некорректный входной HAProxy порт: ${port:-пусто}"
            return 1
        }
        port=$((10#$port))
        (( port >= 1 && port <= 65535 )) || {
            fail "HAProxy порт вне диапазона: $port"
            return 1
        }
        [[ -z "${seen_ports[$port]+x}" ]] || {
            fail "HAProxy порт $port указан дважды"
            return 1
        }
        normalized_target="$(normalize_haproxy_target "$backend_target" 2>/dev/null || true)"
        normalized_sni="$(normalize_haproxy_sni_list "$allowed_sni" 2>/dev/null || true)"
        [[ -n "$normalized_target" && -n "$normalized_sni" ]] || {
            fail "Некорректный HAProxy маршрут на порту $port"
            return 1
        }
        seen_ports[$port]=1
        route_count=$(( route_count + 1 ))
    done < "$routes_file"
    (( route_count > 0 )) || {
        fail "Список HAProxy маршрутов пуст"
        return 1
    }

    haproxy_threads="$(cpu_count)"
    (( haproxy_threads > 64 )) && haproxy_threads=64
    haproxy_maxconn="$(recommended_haproxy_maxconn)"

    cat > "$output_file" <<EOF
# Managed by kto. Edit routes through the HAProxy menu.
global
    maxconn ${haproxy_maxconn}
    nbthread ${haproxy_threads}
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    tune.ssl.default-dh-param 2048

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
    timeout client-fin 30s
    timeout server-fin 30s

    default-server inter 30s fall 8 rise 3

backend wrong_sni_names
    stick-table type string len 160 size 100k expire 30m store gpc0
EOF

    while IFS=$'\t' read -r port backend_target allowed_sni; do
        port=$((10#$port))
        backend_target="$(normalize_haproxy_target "$backend_target")"
        allowed_sni="$(normalize_haproxy_sni_list "$allowed_sni")"
        if (( port == 443 )); then
            frontend_name="vless_in"
            backend_name="vless_pool"
            server_name="xray1"
        else
            frontend_name="vless_in_${port}"
            backend_name="vless_pool_${port}"
            server_name="xray_${port}"
        fi

        cat >> "$output_file" <<EOF

# -------------------------
# FRONTEND : ${port}
# -------------------------
frontend ${frontend_name}
    bind *:${port} backlog 65535
    stick-table type ip size 100k expire 30m store gpc0,conn_rate(10s)
    tcp-request inspect-delay 5s
    acl clienthello req.ssl_hello_type 1
    acl has_sni req.ssl_sni -m found
EOF
        render_haproxy_sni_acl_lines "$allowed_sni" >> "$output_file"
        cat >> "$output_file" <<EOF
    tcp-request content track-sc0 src if clienthello !allowed_sni
    tcp-request content sc-inc-gpc0(0) if clienthello !allowed_sni
    tcp-request content track-sc1 req.ssl_sni,lower table wrong_sni_names if clienthello has_sni !allowed_sni
    tcp-request content sc-inc-gpc0(1) if clienthello has_sni !allowed_sni
    tcp-request content accept if clienthello allowed_sni
    tcp-request content reject if clienthello !allowed_sni
    tcp-request content reject if WAIT_END
    default_backend ${backend_name}

backend ${backend_name}
    mode tcp
    balance leastconn

    server ${server_name} ${backend_target} check weight 10
EOF
    done < "$routes_file"
}

apply_haproxy_routes_config() {
    local routes_file="$1"
    local config=/etc/haproxy/haproxy.cfg
    local tmp_config backup had_config=0 haproxy_threads haproxy_maxconn route_count

    ensure_haproxy_package
    tmp_config="$(mktemp)"
    backup="$(mktemp)"
    if ! render_haproxy_routes_config "$routes_file" "$tmp_config"; then
        rm -f "$tmp_config" "$backup"
        return 1
    fi

    stage "Проверяю HAProxy config"
    if ! "${SUDO[@]}" haproxy -c -f "$tmp_config" >> "$LOG_FILE" 2>&1; then
        rm -f "$tmp_config" "$backup"
        fail "Проверка HAProxy config"
        tail -n 25 "$LOG_FILE" >&2 || true
        return 1
    fi

    if "${SUDO[@]}" test -s "$config" 2>/dev/null; then
        had_config=1
        "${SUDO[@]}" cat "$config" > "$backup"
        "${SUDO[@]}" cp -a "$config" "${config}.kto.bak" >> "$LOG_FILE" 2>&1 || true
    fi

    stage "Применяю HAProxy config"
    "${SUDO[@]}" install -m 0644 "$tmp_config" "$config" >> "$LOG_FILE" 2>&1

    cmd "${SUDO[@]}" mkdir -p /etc/systemd/system/haproxy.service.d
    write_root_file /etc/systemd/system/haproxy.service.d/99-kto-capacity.conf <<'EOF'
[Service]
LimitNOFILE=1048576
EOF
    cmd "${SUDO[@]}" systemctl daemon-reload
    cmd "${SUDO[@]}" systemctl enable haproxy || true

    if ! reload_haproxy_gracefully; then
        warn "Новый конфиг не запустился, возвращаю предыдущий."
        if (( had_config == 1 )); then
            "${SUDO[@]}" install -m 0644 "$backup" "$config" >> "$LOG_FILE" 2>&1
            "${SUDO[@]}" systemctl restart haproxy >> "$LOG_FILE" 2>&1 || true
        else
            "${SUDO[@]}" rm -f "$config" >> "$LOG_FILE" 2>&1 || true
            "${SUDO[@]}" systemctl stop haproxy >> "$LOG_FILE" 2>&1 || true
        fi
        rm -f "$tmp_config" "$backup"
        tail -n 25 "$LOG_FILE" >&2 || true
        return 1
    fi

    rm -f "$tmp_config" "$backup"
    haproxy_threads="$(cpu_count)"
    (( haproxy_threads > 64 )) && haproxy_threads=64
    haproxy_maxconn="$(recommended_haproxy_maxconn)"
    route_count="$(haproxy_route_count "$routes_file")"
    ok "HAProxy маршрутов: ${route_count}"
    ok "HAProxy capacity: maxconn=${haproxy_maxconn}, threads=${haproxy_threads}"
}

apply_haproxy_config() {
    local backend_target="$1" allowed_sni="$2" routes_file
    routes_file="$(mktemp)"
    printf '443\t%s\t%s\n' "$backend_target" "$allowed_sni" > "$routes_file"
    if apply_haproxy_routes_config "$routes_file"; then
        rm -f "$routes_file"
        return 0
    fi
    rm -f "$routes_file"
    return 1
}

ensure_haproxy_package() {
    if command_exists haproxy && command_exists socat; then
        return 0
    fi
    stage "Устанавливаю HAProxy"
    must "apt update" apt_update_quiet
    must "Установка HAProxy" apt_install_quiet haproxy socat
}

harden_whitelist_haproxy_firewall() {
    local routes_file="${1:-}" previous_routes_file="${2:-}"
    local ssh_port port target sni generated_routes=""
    command_exists ufw || return 0
    ufw_active || return 0

    if [[ -z "$routes_file" || ! -s "$routes_file" ]]; then
        generated_routes="$(mktemp)"
        extract_haproxy_routes > "$generated_routes"
        routes_file="$generated_routes"
    fi
    ssh_port="$(detect_ssh_port)"

    apply_whitelist_ssh_rules "$ssh_port"
    while IFS=$'\t' read -r port target sni; do
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        if ! cmd "${SUDO[@]}" ufw allow "${port}/tcp" comment 'kto-haproxy'; then
            cmd "${SUDO[@]}" ufw allow "${port}/tcp" || true
        fi
    done < "$routes_file"

    if [[ -n "$previous_routes_file" && -s "$previous_routes_file" ]]; then
        while IFS=$'\t' read -r port target sni; do
            [[ "$port" =~ ^[0-9]+$ ]] || continue
            if ! haproxy_route_file_has_port "$routes_file" "$port"; then
                cmd "${SUDO[@]}" ufw --force delete allow "${port}/tcp" || true
            fi
        done < "$previous_routes_file"
    fi

    cmd "${SUDO[@]}" ufw --force delete allow 443/udp || true
    if ! haproxy_route_file_has_port "$routes_file" "$NODE_PORT"; then
        cmd "${SUDO[@]}" ufw --force delete allow "${NODE_PORT}/tcp" || true
    fi
    [[ -z "$generated_routes" ]] || rm -f "$generated_routes"
}

configure_haproxy_backend() {
    header
    require_whitelist_mode
    need_root
    local backend_target allowed_sni routes_file previous_routes_file
    backend_target="$(ask_haproxy_target "Введите выходной IP или IP:порт")"
    allowed_sni="$(ask_haproxy_sni_list "Введите разрешенный SNI")"

    routes_file="$(mktemp)"
    previous_routes_file="$(mktemp)"
    extract_haproxy_routes > "$previous_routes_file"
    printf '443\t%s\t%s\n' "$backend_target" "$allowed_sni" > "$routes_file"

    if apply_haproxy_routes_config "$routes_file"; then
        harden_whitelist_haproxy_firewall "$routes_file" "$previous_routes_file"
        ok "HAProxy установлен: 443 -> ${backend_target}"
        ok "Разрешенный SNI: ${allowed_sni}"
    else
        rm -f "$routes_file" "$previous_routes_file"
        return 1
    fi
    rm -f "$routes_file" "$previous_routes_file"
}

print_haproxy_routes() {
    local routes_file="$1" port target sni
    echo -e "${BOLD}${PURPLE}[ МАРШРУТЫ ]${NC}"
    while IFS=$'\t' read -r port target sni; do
        [[ -n "$port" ]] || continue
        printf ' %5s/tcp -> %-21s SNI: %s\n' "$port" "$target" "$sni"
    done < "$routes_file"
}

select_haproxy_route() {
    local routes_file="$1" mode="${2:-all}" choice index=0 port target sni
    local -a ports=()

    printf '%s\n' "Выберите HAProxy-порт:" >&2
    while IFS=$'\t' read -r port target sni; do
        [[ -n "$port" ]] || continue
        if [[ "$mode" == "extra" && "$port" == "443" ]]; then
            continue
        fi
        ports+=("$port")
        index=$(( index + 1 ))
        printf ' %d) %s/tcp -> %s | %s\n' "$index" "$port" "$target" "$sni" >&2
    done < "$routes_file"

    if (( ${#ports[@]} == 0 )); then
        fail "Дополнительных HAProxy-портов нет"
        return 1
    fi

    while true; do
        printf '> ' >&2
        read -r choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#ports[@]} )); then
            echo "${ports[$((choice - 1))]}"
            return 0
        fi
        fail "Неверный выбор"
    done
}

default_haproxy_extra_port() {
    local routes_file="$1" port=8443
    while (( port <= 65535 )); do
        if ! haproxy_route_file_has_port "$routes_file" "$port"; then
            echo "$port"
            return 0
        fi
        port=$(( port + 1 ))
    done
    return 1
}

haproxy_tcp_port_listening() {
    local wanted="$1"
    command_exists ss || return 1
    ss -H -ltn 2>/dev/null | awk -v wanted="$wanted" '
        {
            address = $4
            sub(/^.*:/, "", address)
            if (address == wanted) found = 1
        }
        END { exit found ? 0 : 1 }
    '
}

add_haproxy_route() {
    local routes_file="$1" default_port port backend_target allowed_sni next_file
    default_port="$(default_haproxy_extra_port "$routes_file")" || {
        fail "Нет свободного HAProxy-порта"
        return 1
    }

    while true; do
        port="$(ask_int "Входной HAProxy порт" "$default_port" 1 65535)"
        if haproxy_route_file_has_port "$routes_file" "$port"; then
            fail "HAProxy порт $port уже настроен"
            continue
        fi
        if haproxy_tcp_port_listening "$port"; then
            fail "TCP-порт $port уже занят другим процессом"
            continue
        fi
        break
    done

    backend_target="$(ask_haproxy_target_default "Выходной IP или IP:порт")"
    allowed_sni="$(ask_haproxy_sni_list "Разрешенный SNI")"
    next_file="$(mktemp)"
    cp "$routes_file" "$next_file"
    printf '%s\t%s\t%s\n' "$port" "$backend_target" "$allowed_sni" >> "$next_file"

    if apply_haproxy_routes_config "$next_file"; then
        harden_whitelist_haproxy_firewall "$next_file" "$routes_file"
        mv "$next_file" "$routes_file"
        ok "Добавлен порт ${port}: ${backend_target}"
        return 0
    fi
    rm -f "$next_file"
    return 1
}

edit_haproxy_route() {
    local routes_file="$1" port current_line current_target current_sni backend_target allowed_sni next_file
    port="$(select_haproxy_route "$routes_file")" || return 1
    current_line="$(awk -F '\t' -v port="$port" '$1 == port { print; exit }' "$routes_file")"
    IFS=$'\t' read -r _ current_target current_sni <<< "$current_line"

    backend_target="$(ask_haproxy_target_default "Выходной IP или IP:порт" "$current_target")"
    allowed_sni="$(ask_haproxy_sni_list "Разрешенный SNI" "$current_sni")"
    next_file="$(mktemp)"
    awk -F '\t' -v OFS='\t' -v port="$port" -v target="$backend_target" -v sni="$allowed_sni" '
        $1 == port { print port, target, sni; next }
        { print }
    ' "$routes_file" > "$next_file"

    if apply_haproxy_routes_config "$next_file"; then
        harden_whitelist_haproxy_firewall "$next_file" "$routes_file"
        mv "$next_file" "$routes_file"
        ok "Маршрут ${port}/tcp обновлён"
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
        NF >= 3 { print $1, $2, sni; next }
        { print }
    ' "$routes_file" > "$next_file"

    if apply_haproxy_routes_config "$next_file"; then
        harden_whitelist_haproxy_firewall "$next_file" "$routes_file"
        mv "$next_file" "$routes_file"
        route_count="$(haproxy_route_count "$routes_file")"
        ok "SNI заменён на всех HAProxy-маршрутах: ${route_count}"
        ok "Разрешенный SNI: ${allowed_sni}"
        return 0
    fi
    rm -f "$next_file"
    return 1
}

delete_haproxy_route() {
    local routes_file="$1" port next_file
    port="$(select_haproxy_route "$routes_file" extra)" || return 1
    next_file="$(mktemp)"
    awk -F '\t' -v port="$port" '$1 != port { print }' "$routes_file" > "$next_file"

    if apply_haproxy_routes_config "$next_file"; then
        harden_whitelist_haproxy_firewall "$next_file" "$routes_file"
        mv "$next_file" "$routes_file"
        ok "HAProxy порт ${port}/tcp удалён"
        return 0
    fi
    rm -f "$next_file"
    return 1
}

update_haproxy_existing_config() {
    header
    require_whitelist_mode
    need_root
    local routes_file

    if ! "${SUDO[@]}" test -s /etc/haproxy/haproxy.cfg 2>/dev/null; then
        warn "HAProxy config не найден, создаю базовый порт 443."
        configure_haproxy_backend
        return
    fi

    routes_file="$(mktemp)"
    extract_haproxy_routes > "$routes_file"
    if [[ ! -s "$routes_file" ]]; then
        rm -f "$routes_file"
        fail "Не смог распознать маршруты в текущем HAProxy config. Конфиг не изменён."
        return 1
    fi

    if apply_haproxy_routes_config "$routes_file"; then
        harden_whitelist_haproxy_firewall "$routes_file" "$routes_file"
        ok "HAProxy обновлён без повторного ввода, маршруты сохранены"
        rm -f "$routes_file"
        return 0
    fi
    rm -f "$routes_file"
    return 1
}

haproxy_menu() {
    header
    require_whitelist_mode
    need_root
    local routes_file choice
    routes_file="$(mktemp)"

    if ! "${SUDO[@]}" test -s /etc/haproxy/haproxy.cfg 2>/dev/null; then
        warn "HAProxy ещё не настроен. Сначала создаю базовый порт 443."
        if ! configure_haproxy_backend; then
            rm -f "$routes_file"
            return 1
        fi
    fi

    extract_haproxy_routes > "$routes_file"
    if [[ ! -s "$routes_file" ]]; then
        rm -f "$routes_file"
        fail "Текущий HAProxy config не распознан. Автоматически перезаписывать его не буду."
        return 1
    fi

    while true; do
        header
        print_haproxy_routes "$routes_file"
        echo
        echo -e "1) Изменить маршрут"
        echo -e "2) Добавить порт"
        echo -e "3) Удалить дополнительный порт"
        echo -e "4) Заменить SNI у всех маршрутов"
        echo -e "5) Обновить HAProxy, сохранив маршруты"
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
                if apply_haproxy_routes_config "$routes_file"; then
                    harden_whitelist_haproxy_firewall "$routes_file" "$routes_file"
                    ok "HAProxy обновлён, все маршруты сохранены"
                fi
                ;;
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

    local listen_host listen_port secret bot_token chat_id allowed_user stale_sec bl_stale_sec bl_offline_confirm_sec bl_stale_fallback_sec bl_push_interval_sec scan_alert_delta expected_nodes daily_report_time existing_config=0
    local ip_limit_enabled ip_limit_source ip_limit_max_ips ip_limit_max_events ip_limit_window_sec ip_limit_alert_cooldown ip_limit_scan_sec ip_limit_alert_threshold ip_limit_alert_top ip_limit_enforce_enabled ip_limit_drop_enabled ip_limit_penalty_sec
    local remna_api_url remna_api_token remna_api_cache_sec remna_api_insecure remna_node_alert_enabled remna_node_poll_sec remna_offline_guard_enabled remna_offline_state_max_age_sec remna_offline_log_grace_sec asn_lookup_enabled asn_cache_sec asn_timeout_sec
    local safe_host safe_port safe_secret safe_bot safe_chat safe_user safe_stale safe_bl_stale safe_bl_offline_confirm safe_bl_stale_fallback safe_bl_push_interval safe_scan_alert_delta safe_expected safe_tz safe_daily
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
        bl_stale_sec="${bl_stale_sec:-$STATS_COLLECTOR_BL_STALE_SEC_DEFAULT}"
        bl_offline_confirm_sec="${bl_offline_confirm_sec:-$STATS_COLLECTOR_BL_OFFLINE_CONFIRM_SEC_DEFAULT}"
        bl_stale_fallback_sec="${bl_stale_fallback_sec:-$STATS_COLLECTOR_BL_STALE_FALLBACK_SEC_DEFAULT}"
        bl_push_interval_sec="${bl_push_interval_sec:-$STATS_COLLECTOR_BL_PUSH_INTERVAL_SEC_DEFAULT}"
        if [[ "$bl_push_interval_sec" == "5" ]]; then
            bl_push_interval_sec="$STATS_COLLECTOR_BL_PUSH_INTERVAL_SEC_DEFAULT"
        fi
        push_miss_window_sec="${push_miss_window_sec:-$STATS_COLLECTOR_PUSH_MISS_WINDOW_SEC_DEFAULT}"
        push_miss_threshold="${push_miss_threshold:-$STATS_COLLECTOR_PUSH_MISS_THRESHOLD_DEFAULT}"
        push_miss_alert_cooldown="${push_miss_alert_cooldown:-$STATS_COLLECTOR_PUSH_MISS_ALERT_COOLDOWN_DEFAULT}"
        scan_alert_delta="${scan_alert_delta:-$STATS_COLLECTOR_SCAN_ALERT_DELTA_DEFAULT}"
        expected_nodes="${expected_nodes:-$STATS_EXPECTED_NODES_DEFAULT}"
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
    local state listen_host listen_port health_host health_log rc remna_api_url remna_api_token remna_node_alert_enabled remna_node_poll_sec remna_offline_guard_enabled remna_offline_state_max_age_sec remna_offline_log_grace_sec bl_stale_sec bl_offline_confirm_sec bl_stale_fallback_sec bl_push_interval_sec push_miss_window_sec push_miss_threshold push_miss_alert_cooldown remna_test_id remna_test_log remna_code remna_probe
    local ip_limit_enabled ip_limit_source ip_limit_scan_sec ip_limit_alert_threshold ip_limit_alert_top ip_limit_max_events asn_lookup_enabled asn_cache_sec
    state="$(service_ok "$STATS_COLLECTOR_SERVICE")"
    listen_host="$(config_get KTO_COLLECTOR_LISTEN_HOST "$STATS_COLLECTOR_CONFIG")"
    listen_port="$(config_get KTO_COLLECTOR_LISTEN_PORT "$STATS_COLLECTOR_CONFIG")"
    remna_api_url="$(config_get KTO_COLLECTOR_REMNA_API_URL "$STATS_COLLECTOR_CONFIG")"
    remna_api_token="$(config_get KTO_COLLECTOR_REMNA_API_TOKEN "$STATS_COLLECTOR_CONFIG")"
    remna_node_alert_enabled="$(config_get KTO_COLLECTOR_REMNA_NODE_ALERT_ENABLED "$STATS_COLLECTOR_CONFIG")"
    remna_node_poll_sec="$(config_get KTO_COLLECTOR_REMNA_NODE_POLL_SEC "$STATS_COLLECTOR_CONFIG")"
    remna_offline_guard_enabled="$(config_get KTO_COLLECTOR_REMNA_OFFLINE_GUARD_ENABLED "$STATS_COLLECTOR_CONFIG")"
    remna_offline_state_max_age_sec="$(config_get KTO_COLLECTOR_REMNA_OFFLINE_STATE_MAX_AGE_SEC "$STATS_COLLECTOR_CONFIG")"
    remna_offline_log_grace_sec="$(config_get KTO_COLLECTOR_REMNA_OFFLINE_LOG_GRACE_SEC "$STATS_COLLECTOR_CONFIG")"
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
        || "${SUDO[@]}" systemctl cat "$STATS_PUSH_TIMER" >/dev/null 2>&1 \
        || "${SUDO[@]}" systemctl cat "$STATS_PUSH_SERVICE" >/dev/null 2>&1; then
        had_push=1
    fi

    stage "Удаляю push статистики"
    cmd "${SUDO[@]}" systemctl disable --now "$STATS_PUSH_TIMER" "$STATS_PUSH_SERVICE" || true
    cmd "${SUDO[@]}" rm -f \
        "$STATS_PUSH_CONFIG" \
        "$STATS_PUSH_SCRIPT" \
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
    elif [[ "$MACHINE_MODE" == "whitelist" ]]; then
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
        stats-collector) install_stats_collector ;;
        stats-collector-status) stats_collector_status ;;
        stats-collector-alerts) stats_collector_alerts_menu ;;
        stats-push-delete) stats_push_delete_all ;;
        speedtest) install_speedtest ;;
        speedtest-ru) speedtest_ru ;;
        ipcheck-place) ipcheck_place ;;
        ipcheck-region) ipcheck_region ;;
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
    init_log
    ensure_utf8_locale
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
        warp) install_warp_native ;;
        status) show_status ;;
        network-test|net-test|netcheck|network-check|diag-network|diagnose-network) shift; network_test "$@" ;;
        speedtest) install_speedtest "${2:-}" ;;
        speedtest-ru|speedtestru|bench-ru|benchru) speedtest_ru "${2:-}" ;;
        ipcheck-place) ipcheck_place ;;
        ipcheck-region) ipcheck_region ;;
        ssl) issue_ssl_certificate ;;
        haproxy|install-haproxy) install_haproxy ;;
        haproxy-update|update-haproxy|haproxy-refresh) update_haproxy_existing_config ;;
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
