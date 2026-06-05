#!/usr/bin/env bash
# shellcheck shell=bash

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_VERSION="3.6.4"
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
GCLOUD_PROFILE_NAME="VLESS-GCloud-Codex"
GCLOUD_INBOUND_TAG="VLESS_GCLOUD_CODEX"
GCLOUD_NODE_NAME="🇫🇮 Google Cloud by Codex"
GCLOUD_HOST_REMARK="Finland Battles by Codex"
GCLOUD_TARGET_PROFILES_LEGACY_DEFAULT="VLESS-Test-DNS"
GCLOUD_TARGET_PROFILES_DEFAULT="Hysteria-Petersburg-DNS|VLESS-Moscow-DNS|VLESS-Novosibirsk-DNS"
GCLOUD_TARGET_PROFILES_NONE="__none__"
GCLOUD_TARGET_PROFILES="${KTO_GCLOUD_TARGET_PROFILES:-}"
GCLOUD_TARGET_OUTBOUND_TAG="Finland"
GCLOUD_USERNAME="mash"
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
    [[ "$1" == "node" || "$1" == "whitelist" ]]
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

gcloud_target_profiles_list() {
    local raw="${GCLOUD_TARGET_PROFILES:-$GCLOUD_TARGET_PROFILES_DEFAULT}"
    [[ "$raw" == "$GCLOUD_TARGET_PROFILES_NONE" ]] && return 0
    printf '%s\n' "$raw" | tr '|' '\n' | sed '/^[[:space:]]*$/d'
}

gcloud_target_profiles_display() {
    local profiles
    profiles="$(gcloud_target_profiles_list | awk 'BEGIN{out=""} {out = out ? out ", " $0 : $0} END{print out}')"
    echo "${profiles:-нет}"
}

gcloud_target_profile_exists() {
    local name="$1"
    gcloud_target_profiles_list | grep -Fxq "$name"
}

gcloud_add_target_profile() {
    local name="$1"
    [[ -n "$name" ]] || return 1
    if gcloud_target_profile_exists "$name"; then
        return 0
    fi
    if [[ -n "${GCLOUD_TARGET_PROFILES:-}" && "$GCLOUD_TARGET_PROFILES" != "$GCLOUD_TARGET_PROFILES_NONE" ]]; then
        GCLOUD_TARGET_PROFILES="${GCLOUD_TARGET_PROFILES}|${name}"
    else
        GCLOUD_TARGET_PROFILES="$name"
    fi
}

gcloud_remove_target_profile() {
    local name="$1"
    GCLOUD_TARGET_PROFILES="$(gcloud_target_profiles_list | awk -v name="$name" 'BEGIN{out=""} $0 != name {out = out ? out "|" $0 : $0} END{print out}')"
    if [[ -z "$GCLOUD_TARGET_PROFILES" ]]; then
        GCLOUD_TARGET_PROFILES="$GCLOUD_TARGET_PROFILES_NONE"
    fi
}

load_machine_mode() {
    local saved_mode="" saved_profile="" saved_api_url="" saved_api_token="" saved_gcloud_targets="" source_file="$CONFIG_FILE"
    CONFIG_SOURCE_FILE=""

    if [[ -n "$MACHINE_MODE" ]]; then
        if ! valid_machine_mode "$MACHINE_MODE"; then
            warn "KTO_MACHINE_MODE должен быть node или whitelist. Игнорирую."
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

    saved_gcloud_targets="$(config_get GCLOUD_TARGET_PROFILES "$source_file")"
    if [[ -z "${KTO_GCLOUD_TARGET_PROFILES+x}" && -n "$saved_gcloud_targets" ]]; then
        GCLOUD_TARGET_PROFILES="$saved_gcloud_targets"
    fi
    if [[ -z "${GCLOUD_TARGET_PROFILES:-}" ]]; then
        GCLOUD_TARGET_PROFILES="$GCLOUD_TARGET_PROFILES_DEFAULT"
    elif [[ "$GCLOUD_TARGET_PROFILES" == "$GCLOUD_TARGET_PROFILES_LEGACY_DEFAULT" ]]; then
        GCLOUD_TARGET_PROFILES="$GCLOUD_TARGET_PROFILES_DEFAULT"
    fi

    if [[ "$MACHINE_MODE" != "node" ]]; then
        NODE_PROFILE=""
    fi
}

save_machine_mode() {
    local safe_mode safe_profile safe_url safe_token safe_gcloud_targets
    safe_mode="$(escape_config_value "$MACHINE_MODE")"
    safe_profile="$(escape_config_value "$NODE_PROFILE")"
    safe_url="$(escape_config_value "$REMNA_API_URL")"
    safe_token="$(escape_config_value "$REMNA_API_TOKEN")"
    safe_gcloud_targets="$(escape_config_value "${GCLOUD_TARGET_PROFILES:-$GCLOUD_TARGET_PROFILES_DEFAULT}")"

    write_root_file_mode 0600 "$CONFIG_FILE" <<EOF
MACHINE_MODE="$safe_mode"
NODE_PROFILE="$safe_profile"
REMNA_API_URL="$safe_url"
REMNA_API_TOKEN="$safe_token"
GCLOUD_TARGET_PROFILES="$safe_gcloud_targets"
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
        cmd "${SUDO[@]}" ufw allow 443/udp || true
        if [[ "$MACHINE_MODE" == "node" ]]; then
            cmd "${SUDO[@]}" ufw allow "${NODE_PORT}/tcp" || true
        else
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
        echo -e "${PURPLE}==========================================${NC}"
        echo -ne "${PURPLE}>${NC} ${BOLD}Выберите режим (1-2):${NC} "
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
        cleanup_runtime_state
        save_machine_mode
        echo
        ok "Конфиг обновлён: $(config_label)"
        ok "Старая нода/SelfSteal очищены"
    else
        echo
        ok "Настройки не изменились"
    fi
}

configure_gcloud_target_profiles() {
    local choice profile

    need_root
    while true; do
        header
        echo -e "${BOLD}${PURPLE}[ РЕДАКТИРУЕМЫЕ ПРОФИЛИ ]${NC}"
        echo -e "Текущие: $(gcloud_target_profiles_display)"
        echo
        echo -e "1) Изменить"
        echo -e "2) Удалить"
        echo -e "0) Выйти"
        echo -e "${PURPLE}==========================================${NC}"
        echo -ne "${PURPLE}>${NC} ${BOLD}Выберите действие:${NC} "
        read -r choice

        case "$choice" in
            1)
                while true; do
                    printf 'Добавить профиль: '
                    read -r profile
                    if [[ "$profile" == "0" ]]; then
                        break
                    fi
                    if [[ -z "$profile" ]]; then
                        fail "Название пустое"
                        continue
                    fi
                    gcloud_add_target_profile "$profile"
                    save_machine_mode
                    ok "Добавлено: ${profile}"
                done
                ;;
            2)
                printf 'Удалить профиль: '
                read -r profile
                if [[ "$profile" == "0" ]]; then
                    continue
                fi
                if [[ -z "$profile" ]]; then
                    fail "Название пустое"
                    sleep 1
                    continue
                fi
                gcloud_remove_target_profile "$profile"
                save_machine_mode
                ok "Больше не меняю: ${profile}"
                sleep 1
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

settings_menu() {
    local choice

    while true; do
        header
        echo -e "${BOLD}${PURPLE}[ НАСТРОЙКИ ]${NC}"
        echo -e "1) Изменение режима"
        echo -e "2) Изменение редактируемых профилей"
        echo -e "3) Проверка системы"
        echo -e "0) Выйти"
        echo -e "${PURPLE}==========================================${NC}"
        echo -ne "${PURPLE}>${NC} ${BOLD}Выберите действие:${NC} "
        read -r choice

        case "$choice" in
            1)
                reconfigure_machine_mode
                ;;
            2)
                configure_gcloud_target_profiles
                ;;
            3)
                system_check
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

apt_update_quiet() {
    if [[ "$APT_UPDATED" == "1" ]]; then
        echo "apt update skipped: cache already refreshed" >> "$LOG_FILE"
        return 0
    fi
    apt_update_force
}

apt_update_force() {
    "${SUDO[@]}" apt-get -o DPkg::Lock::Timeout=600 update >> "$LOG_FILE" 2>&1
    APT_UPDATED=1
}

package_installed() {
    local pkg="$1"
    dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"
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

    "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive \
        apt-get -o DPkg::Lock::Timeout=600 install -y \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" \
        "${missing[@]}" >> "$LOG_FILE" 2>&1
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
        echo -e "${PURPLE}>${NC} ${BOLD}${prompt}${NC}" >&2
        read -r ip
        if validate_ipv4 "$ip"; then
            echo "$ip"
            return 0
        fi
        fail "Некорректный IPv4. Пример: 1.2.3.4"
    done
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

build_gcloud_profile_config() {
    local private_key="$1"
    local domain="$2"

    jq -n \
        --arg tag "$GCLOUD_INBOUND_TAG" \
        --arg privateKey "$private_key" \
        --arg domain "$domain" \
        '{
          log: {loglevel: "none"},
          dns: {servers: ["1.1.1.1"]},
          inbounds: [
            {
              tag: $tag,
              port: 443,
              listen: "0.0.0.0",
              protocol: "vless",
              settings: {clients: [], decryption: "none"},
              sniffing: {enabled: false, destOverride: ["quic", "tls", "http"]},
              streamSettings: {
                network: "raw",
                security: "reality",
                realitySettings: {
                  show: false,
                  xver: 0,
                  target: "127.0.0.1:9443",
                  shortIds: [""],
                  privateKey: $privateKey,
                  fingerprint: "qq",
                  serverNames: [$domain]
                }
              }
            }
          ],
          outbounds: [
            {tag: "DIRECT", protocol: "freedom", settings: {domainStrategy: "AsIs"}},
            {tag: "BLOCK", protocol: "blackhole"},
            {
              tag: "WARP",
              protocol: "freedom",
              settings: {domainStrategy: "UseIP"},
              streamSettings: {sockopt: {interface: "warp", tcpFastOpen: true}}
            }
          ],
          routing: {
            rules: [
              {ip: ["geoip:private"], outboundTag: "BLOCK"},
              {protocol: ["bittorrent"], outboundTag: "BLOCK"},
              {network: "udp", outboundTag: "DIRECT"}
            ]
          }
        }'
}

upsert_gcloud_profile() {
    local private_key="$1"
    local domain="$2"
    local uuid config_file payload response
    uuid="$(remna_profile_uuid_by_name "$GCLOUD_PROFILE_NAME")"
    config_file="$(mktemp)"
    payload="$(mktemp)"
    build_gcloud_profile_config "$private_key" "$domain" > "$config_file"

    if [[ -n "$uuid" ]]; then
        jq -n --arg uuid "$uuid" --arg name "$GCLOUD_PROFILE_NAME" --slurpfile config "$config_file" \
            '{uuid: $uuid, name: $name, config: $config[0]}' > "$payload"
        response="$(remna_api PATCH /api/config-profiles "$payload")"
    else
        jq -n --arg name "$GCLOUD_PROFILE_NAME" --slurpfile config "$config_file" \
            '{name: $name, config: $config[0]}' > "$payload"
        response="$(remna_api POST /api/config-profiles "$payload")"
    fi

    rm -f "$config_file" "$payload"
    echo "$response" | jq -r '.response.uuid'
}

gcloud_inbound_uuid() {
    local profile_uuid="$1"
    remna_api GET "/api/config-profiles/${profile_uuid}/inbounds" \
        | jq -r --arg tag "$GCLOUD_INBOUND_TAG" '.response.inbounds[]? | select(.tag == $tag) | .uuid' \
        | head -n 1
}

upsert_gcloud_node() {
    local ip="$1"
    local profile_uuid="$2"
    local inbound_uuid="$3"
    local uuid payload response
    uuid="$(remna_node_uuid_by_name "$GCLOUD_NODE_NAME")"
    if [[ -z "$uuid" ]]; then
        uuid="$(remna_node_uuid_by_address "$ip")"
        if [[ -n "$uuid" ]]; then
            echo "Google Cloud node: reuse by address ${ip}: ${uuid}" >> "$LOG_FILE"
        fi
    fi
    payload="$(mktemp)"

    jq -n \
        --arg uuid "$uuid" \
        --arg name "$GCLOUD_NODE_NAME" \
        --arg address "$ip" \
        --arg profileUuid "$profile_uuid" \
        --arg inboundUuid "$inbound_uuid" \
        --argjson port "$NODE_PORT" \
        '{
          name: $name,
          address: $address,
          port: $port,
          countryCode: "FI",
          isTrafficTrackingActive: false,
          configProfile: {
            activeConfigProfileUuid: $profileUuid,
            activeInbounds: [$inboundUuid]
          },
          tags: ["CODEX", "GOOGLE_CLOUD"]
        } + (if $uuid != "" then {uuid: $uuid} else {} end)' > "$payload"

    if [[ -n "$uuid" ]]; then
        response="$(remna_api PATCH /api/nodes "$payload")"
    else
        response="$(remna_api POST /api/nodes "$payload")"
    fi

    rm -f "$payload"
    echo "$response" | jq -r '.response.uuid'
}

upsert_gcloud_host() {
    local ip="$1"
    local profile_uuid="$2"
    local inbound_uuid="$3"
    local node_uuid="$4"
    local uuid payload response
    uuid="$(remna_host_uuid_by_remark "$GCLOUD_HOST_REMARK")"
    if [[ -z "$uuid" ]]; then
        uuid="$(remna_host_uuid_by_address "$ip")"
        if [[ -n "$uuid" ]]; then
            echo "Google Cloud host: reuse by address ${ip}: ${uuid}" >> "$LOG_FILE"
        fi
    fi
    payload="$(mktemp)"

    jq -n \
        --arg uuid "$uuid" \
        --arg remark "$GCLOUD_HOST_REMARK" \
        --arg address "$ip" \
        --arg profileUuid "$profile_uuid" \
        --arg inboundUuid "$inbound_uuid" \
        --arg nodeUuid "$node_uuid" \
        '{
          remark: $remark,
          address: $address,
          port: 443,
          inbound: {
            configProfileUuid: $profileUuid,
            configProfileInboundUuid: $inboundUuid
          },
          nodes: [$nodeUuid],
          isDisabled: true,
          isHidden: true,
          securityLayer: "DEFAULT"
        } + (if $uuid != "" then {uuid: $uuid} else {} end)' > "$payload"

    if [[ -n "$uuid" ]]; then
        response="$(remna_api PATCH /api/hosts "$payload")"
    else
        response="$(remna_api POST /api/hosts "$payload")"
    fi

    rm -f "$payload"
    echo "$response" | jq -r '.response.uuid'
}

remna_user_vless_uuid() {
    local username="$1"
    local user_json sub_json vless_uuid
    user_json="$(remna_api GET "/api/users/by-username/${username}")"
    vless_uuid="$(echo "$user_json" | jq -r '.response.vlessUuid // empty')"
    if [[ -n "$vless_uuid" ]]; then
        echo "$vless_uuid"
        return 0
    fi

    sub_json="$(remna_api GET "/api/subscriptions/by-username/${username}")"
    echo "$sub_json" | jq -r '.response.links[]? | capture("^vless://(?<id>[^@]+)@").id' | head -n 1
}

patch_gcloud_target_profile() {
    local target_name="$1"
    local ip="$2"
    local public_key="$3"
    local domain="$4"
    local vless_uuid="$5"
    local profiles target_uuid target_config patched_config payload response
    profiles="$(remna_api GET /api/config-profiles)"
    target_uuid="$(echo "$profiles" | jq -r --arg name "$target_name" '.response.configProfiles[]? | select(.name == $name) | .uuid' | head -n 1)"
    if [[ -z "$target_uuid" ]]; then
        fail "Профиль ${target_name} не найден"
        return 1
    fi

    target_config="$(mktemp)"
    patched_config="$(mktemp)"
    payload="$(mktemp)"

    echo "$profiles" | jq --arg name "$target_name" \
        '.response.configProfiles[] | select(.name == $name) | .config' > "$target_config"

    if ! jq -e --arg tag "$GCLOUD_TARGET_OUTBOUND_TAG" '.outbounds[]? | select(.tag == $tag)' "$target_config" >/dev/null; then
        rm -f "$target_config" "$patched_config" "$payload"
        fail "Outbound ${GCLOUD_TARGET_OUTBOUND_TAG} не найден в ${target_name}"
        return 1
    fi

    jq \
        --arg tag "$GCLOUD_TARGET_OUTBOUND_TAG" \
        --arg ip "$ip" \
        --arg id "$vless_uuid" \
        --arg publicKey "$public_key" \
        --arg domain "$domain" \
        '.outbounds |= map(
          if .tag == $tag then
            .settings.vnext[0].address = $ip
            | .settings.vnext[0].port = 443
            | .settings.vnext[0].users[0].id = $id
            | .settings.vnext[0].users[0].flow = "xtls-rprx-vision"
            | .settings.vnext[0].users[0].encryption = "none"
            | .streamSettings.network = "raw"
            | .streamSettings.security = "reality"
            | .streamSettings.realitySettings.shortId = ""
            | .streamSettings.realitySettings.publicKey = $publicKey
            | .streamSettings.realitySettings.serverName = $domain
            | .streamSettings.realitySettings.fingerprint = "qq"
          else . end
        )' "$target_config" > "$patched_config"

    jq -n --arg uuid "$target_uuid" --arg name "$target_name" --slurpfile config "$patched_config" \
        '{uuid: $uuid, name: $name, config: $config[0]}' > "$payload"
    response="$(remna_api PATCH /api/config-profiles "$payload")"
    rm -f "$target_config" "$patched_config" "$payload"

    echo "$response" | jq -r '.response.uuid' >/dev/null
}

wait_gcloud_node_online() {
    local name="$1"
    local node_json
    for _ in {1..60}; do
        node_json="$(remna_api GET /api/nodes)"
        if echo "$node_json" | jq -e --arg name "$name" '.response[]? | select(.name == $name and .isConnected == true and .isDisabled == false)' >/dev/null; then
            return 0
        fi
        sleep 5
    done
    warn "Нода ${name} пока не online. Профиль Finland не трогаю."
    return 1
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
    packages=(ca-certificates curl wget gnupg2 software-properties-common ufw openssl dnsutils)
    if [[ "$MACHINE_MODE" == "node" ]]; then
        packages+=(chrony cpufrequtils logrotate tar xz-utils)
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
    cmd "${SUDO[@]}" ufw allow 443/udp
    if [[ "$MACHINE_MODE" == "node" ]]; then
        cmd "${SUDO[@]}" ufw allow "${NODE_PORT}/tcp"
    else
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
    if command_exists journalctl; then
        "${SUDO[@]}" journalctl -k -b --no-pager 2>/dev/null \
            | grep -Eci 'out of memory|oom-killer|killed process' || true
    elif command_exists dmesg; then
        "${SUDO[@]}" dmesg 2>/dev/null \
            | grep -Eci 'out of memory|oom-killer|killed process' || true
    else
        echo 0
    fi
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
    local total available swap zram_size oom_count
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
    else
        system_check_row ok "OOM" "не найдено в текущей загрузке"
    fi
}

system_check_network_limits() {
    local cc qdisc limits_ok=1 sysctl_file_ok=1 service_issues=() cpus
    cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "-")"
    qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "-")"

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
    ufw_rule_allowed "443/udp" || missing+=("443/udp")
    if [[ "$MACHINE_MODE" == "node" ]]; then
        ufw_rule_allowed "${NODE_PORT}/tcp" || missing+=("${NODE_PORT}/tcp")
    elif ufw_rule_allowed "${NODE_PORT}/tcp"; then
        extra+=("${NODE_PORT}/tcp")
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

    progress_start 7
    progress_step "Готовлю систему" opt_prepare_system
    progress_step "Ставлю пакеты" opt_install_packages
    progress_step "Обновляю kernel" opt_liquorix_kernel
    progress_step "Настраиваю сеть" opt_network_limits
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

print_speedtest_result() {
    local output="$1"
    local filtered server isp latency download download_detail upload upload_detail loss url

    filtered="$(sed -n '/Speedtest by Ookla/,/Result URL:/p' <<< "$output")"
    [[ -n "$filtered" ]] || return 1

    server="$(awk '/^[[:space:]]*Server:/ {sub(/^[[:space:]]*Server:[[:space:]]*/, ""); print; exit}' <<< "$filtered")"
    isp="$(awk '/^[[:space:]]*ISP:/ {sub(/^[[:space:]]*ISP:[[:space:]]*/, ""); print; exit}' <<< "$filtered")"
    latency="$(awk '/^[[:space:]]*Idle Latency:/ {sub(/^[[:space:]]*Idle Latency:[[:space:]]*/, ""); print; exit}' <<< "$filtered")"
    download="$(awk '/^[[:space:]]*Download:/ {sub(/^[[:space:]]*Download:[[:space:]]*/, ""); print; exit}' <<< "$filtered")"
    download_detail="$(awk 'seen && /^[[:space:]]+[0-9.]+[[:space:]]+ms/ {sub(/^[[:space:]]+/,""); print; exit} /^[[:space:]]*Download:/ {seen=1}' <<< "$filtered")"
    upload="$(awk '/^[[:space:]]*Upload:/ {sub(/^[[:space:]]*Upload:[[:space:]]*/, ""); print; exit}' <<< "$filtered")"
    upload_detail="$(awk 'seen && /^[[:space:]]+[0-9.]+[[:space:]]+ms/ {sub(/^[[:space:]]+/,""); print; exit} /^[[:space:]]*Upload:/ {seen=1}' <<< "$filtered")"
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
    local output filtered
    stage "Готовлю Speedtest"
    if ! [[ -x /usr/local/bin/speedtest ]]; then
        cmd "${SUDO[@]}" apt-get remove -y speedtest-cli || true
        cmd "${SUDO[@]}" rm -f /usr/bin/speedtest /usr/local/bin/speedtest || true
        if [[ "$(uname -m)" == "aarch64" || "$(uname -m)" == "arm64" ]]; then
            curl -fsSL https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-aarch64.tgz | "${SUDO[@]}" tar xz -C /usr/local/bin speedtest >> "$LOG_FILE" 2>&1
        else
            curl -fsSL https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-x86_64.tgz | "${SUDO[@]}" tar xz -C /usr/local/bin speedtest >> "$LOG_FILE" 2>&1
        fi
    else
        echo "Speedtest binary skipped: already installed" >> "$LOG_FILE"
    fi
    echo
    stage "Запускаю Ookla"
    if ! output="$(/usr/local/bin/speedtest --accept-license --accept-gdpr --progress=no 2>&1)"; then
        if ! output="$(/usr/local/bin/speedtest --accept-license --accept-gdpr 2>&1)"; then
            fail "Speedtest"
            printf '%s\n' "$output" >&2
            return 1
        fi
    fi
    if print_speedtest_result "$output"; then
        return 0
    fi

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

install_google_cloud_stack() {
    header
    require_reality_profile
    need_root
    local domain started_at duration secret ip key_json public_key private_key
    local profile_uuid inbound_uuid node_uuid host_uuid vless_uuid target_profile
    local target_profiles=()

    domain="$(ask_domain "Введите домен")"
    started_at="$(date +%s)"
    echo

    stage "Готовлю Google Cloud"
    apt_update_quiet
    apt_install_quiet curl jq
    ensure_remna_api_config
    remna_api GET /api/system/health >/dev/null

    stage "Генерирую ключи"
    secret="$(remna_api GET /api/keygen | jq -r '.response.pubKey // empty')"
    if [[ -z "$secret" ]]; then
        fail "Не получил SECRET_KEY из панели"
        exit 1
    fi

    key_json="$(remna_api GET /api/system/tools/x25519/generate)"
    public_key="$(echo "$key_json" | jq -r '.response.keypairs[0].publicKey // empty')"
    private_key="$(echo "$key_json" | jq -r '.response.keypairs[0].privateKey // empty')"
    if [[ -z "$public_key" || -z "$private_key" ]]; then
        fail "Не получил Reality keypair"
        exit 1
    fi

    ip="$(external_ipv4)"

    stage "Профиль ${GCLOUD_PROFILE_NAME}"
    profile_uuid="$(upsert_gcloud_profile "$private_key" "$domain")"
    inbound_uuid="$(gcloud_inbound_uuid "$profile_uuid")"
    if [[ -z "$profile_uuid" || -z "$inbound_uuid" ]]; then
        fail "Не получил inbound ${GCLOUD_INBOUND_TAG}"
        exit 1
    fi

    stage "Нода ${GCLOUD_NODE_NAME}"
    node_uuid="$(upsert_gcloud_node "$ip" "$profile_uuid" "$inbound_uuid")"
    if [[ -z "$node_uuid" ]]; then
        fail "Не получил UUID ноды"
        exit 1
    fi
    remna_enable_node "$node_uuid"

    do_install_remnawave_node "$secret"
    do_install_selfsteal "$domain"

    stage "Хост ${GCLOUD_HOST_REMARK}"
    host_uuid="$(upsert_gcloud_host "$ip" "$profile_uuid" "$inbound_uuid" "$node_uuid")"
    if [[ -z "$host_uuid" ]]; then
        fail "Не получил UUID хоста"
        exit 1
    fi

    stage "Жду online ноды"
    if ! wait_gcloud_node_online "$GCLOUD_NODE_NAME"; then
        exit 1
    fi

    stage "Патчу профили"
    vless_uuid="$(remna_user_vless_uuid "$GCLOUD_USERNAME")"
    if [[ -z "$vless_uuid" ]]; then
        fail "Не получил VLESS UUID пользователя ${GCLOUD_USERNAME}"
        exit 1
    fi
    mapfile -t target_profiles < <(gcloud_target_profiles_list)
    if (( ${#target_profiles[@]} == 0 )); then
        fail "Редактируемые профили не заданы"
        exit 1
    fi
    for target_profile in "${target_profiles[@]}"; do
        stage "Патчу ${target_profile}"
        patch_gcloud_target_profile "$target_profile" "$ip" "$public_key" "$domain" "$vless_uuid"
    done

    duration=$(( $(date +%s) - started_at ))
    echo
    ok "Google Cloud готов"
    ok "Нода: ${GCLOUD_NODE_NAME}"
    ok "Хост: ${GCLOUD_HOST_REMARK}"
    ok "Патч: $(gcloud_target_profiles_display) / ${GCLOUD_TARGET_OUTBOUND_TAG}"
    ok "IP: ${ip}"
    ok "Время: $(format_duration "$duration")"
}

install_haproxy() {
    header
    require_whitelist_mode
    need_root
    local backend_ip
    backend_ip="$(ask_ipv4 "Введите выходной IP")"

    stage "Настраиваю HAProxy"
    must "apt update" apt_update_quiet
    must "Установка HAProxy" apt_install_quiet haproxy

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
# FRONTEND : 8443
# -------------------------
frontend vless_in
    bind *:443
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

    labels+=("Полная оптимизация")
    actions+=("optimize")

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
    labels+=("Speedtest")
    actions+=("speedtest")
    labels+=("Проверка IP (IP.Check.Place)")
    actions+=("ipcheck-place")
    labels+=("Проверка IP (Region Check)")
    actions+=("ipcheck-region")

    if [[ "$MACHINE_MODE" == "node" && "$NODE_PROFILE" == "hysteria2" ]]; then
        labels+=("Сгенерировать SSL-сертификат")
        actions+=("ssl")
    elif [[ "$MACHINE_MODE" == "whitelist" ]]; then
        labels+=("HAProxy")
        actions+=("haproxy")
    fi

    labels+=("Настройки")
    actions+=("settings")
    if [[ "$MACHINE_MODE" == "node" && "$NODE_PROFILE" == "reality" ]]; then
        labels+=("Google Cloud")
        actions+=("google-cloud")
    fi

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
        speedtest) install_speedtest ;;
        ipcheck-place) ipcheck_place ;;
        ipcheck-region) ipcheck_region ;;
        ssl) issue_ssl_certificate ;;
        haproxy) install_haproxy ;;
        settings) settings_menu ;;
        google-cloud) install_google_cloud_stack ;;
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
        google-cloud|gcloud) install_google_cloud_stack ;;
        *) menu ;;
    esac
}

main "$@"
