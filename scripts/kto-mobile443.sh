#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

MOBILE443_BUILD="v245"
MOBILE443_DIR="/opt/mobile443"
MOBILE443_CONFIG="${MOBILE443_DIR}/config.conf"
MOBILE443_CHAIN="FILTER_MOBILE_443"
MOBILE443_IPSET="allowed_mobile_443"
# This root-level third-party installer is pinned and checksum-verified.
MOBILE443_REF="${KTO_MOBILE443_REF:-43d0065e983d1d518421b781298f8130125738b4}"
MOBILE443_ASN_URL="${KTO_MOBILE443_ASN_URL:-https://raw.githubusercontent.com/wh3r3ar3you/mobile443-filter/${MOBILE443_REF}/asn.sh}"
MOBILE443_ASN_SHA256="${KTO_MOBILE443_ASN_SHA256:-505184e6e859871d64a379a05954ccba648bae97ba672f2e6c7575ba969befaf}"
LOG_FILE="/var/log/kto-mobile443.log"

print_ok() {
    printf '[OK] %s\n' "$*"
}

print_error() {
    printf '[ОШИБКА] %s\n' "$*" >&2
}

require_root() {
    if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
        print_error "Запусти менеджер mobile443 от root"
        exit 1
    fi
    if ! mkdir -p "$(dirname "$LOG_FILE")" ||
        ! touch "$LOG_FILE" ||
        ! chown root:root "$LOG_FILE" ||
        ! chmod 0600 "$LOG_FILE"; then
        print_error "Не удалось подготовить лог: ${LOG_FILE}"
        exit 1
    fi
    if ! printf '===== kto-mobile443 %s %s =====\n' "$MOBILE443_BUILD" "$(date -Is)" >> "$LOG_FILE"; then
        print_error "Не удалось открыть лог: ${LOG_FILE}"
        exit 1
    fi
}

normalize_ports() {
    local raw="${1//,/ }" port numeric_port
    local -a input_ports=() valid_ports=()
    local IFS=' '
    read -r -a input_ports <<< "$raw"
    for port in "${input_ports[@]}"; do
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        (( ${#port} <= 5 )) || continue
        numeric_port=$((10#$port))
        (( numeric_port >= 1 && numeric_port <= 65535 )) || continue
        valid_ports+=("$numeric_port")
    done
    (( ${#valid_ports[@]} > 0 )) || return 1
    printf '%s\n' "${valid_ports[@]}" | sort -n -u | paste -sd ' ' -
}

ports_include() {
    local ports="$1" wanted="$2"
    [[ " $ports " == *" $wanted "* ]]
}

detect_ssh_port() {
    local port=""
    if command -v sshd >/dev/null 2>&1; then
        port="$(sshd -T 2>/dev/null | awk '/^port / { print $2; exit }' || true)"
    fi
    [[ "$port" =~ ^[0-9]+$ ]] || port=22
    printf '%s\n' "$port"
}

config_enabled() {
    [[ -s "$MOBILE443_CONFIG" ]] &&
        grep -Eq '^ENABLE_MOBILE_ALLOW=(true|"true")$' "$MOBILE443_CONFIG" 2>/dev/null
}

config_ports() {
    local raw
    raw="$(awk -F= '
        $1 == "PORTS" {
            value = substr($0, index($0, "=") + 1)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            if (value ~ /^".*"$/) value = substr(value, 2, length(value) - 2)
            print value
            exit
        }
    ' "$MOBILE443_CONFIG" 2>/dev/null || true)"
    normalize_ports "$raw"
}

write_config() {
    local ports="$1" enabled="$2" tmp
    ports="$(normalize_ports "$ports")" || return 1
    [[ "$enabled" == "true" || "$enabled" == "false" ]] || return 1
    tmp="$(mktemp)"
    cat > "$tmp" <<EOF
INSTALL_PROFILE="full"
PORTS="${ports}"
ENABLE_TRAF_GUARD="false"
ENABLE_TRAF_GUARD_GOVERNMENT="false"
ENABLE_TRAF_GUARD_ANTISCANNER="false"
ENABLE_MOBILE_ALLOW="${enabled}"
ENABLE_TELEGRAM="false"
TG_ENABLED="false"
TG_BOT_TOKEN=""
TG_ADMIN_ID=""
XRAY_ACCESS_LOG=""
REMNAWAVE_API_URL=""
REMNAWAVE_API_TOKEN=""
TG_ID_SOURCE=""
TG_CUSTOM_MESSAGE=''
TG_USERNAME_SEPARATOR=''
EOF
    if ! mkdir -p "$MOBILE443_DIR" >> "$LOG_FILE" 2>&1 ||
        ! install -m 0600 "$tmp" "$MOBILE443_CONFIG" >> "$LOG_FILE" 2>&1; then
        rm -f "$tmp"
        print_error "Не удалось сохранить конфиг mobile443"
        return 1
    fi
    rm -f "$tmp"
}

ensure_download_tools() {
    if command -v curl >/dev/null 2>&1 && command -v sha256sum >/dev/null 2>&1; then
        return 0
    fi
    if ! command -v apt-get >/dev/null 2>&1; then
        print_error "Нужны curl и sha256sum"
        return 1
    fi
    DEBIAN_FRONTEND=noninteractive apt-get update -y >> "$LOG_FILE" 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates coreutils >> "$LOG_FILE" 2>&1
}

download_upstream() {
    local destination="$1" actual_hash
    [[ "$MOBILE443_ASN_URL" =~ ^https:// ]] || {
        print_error "mobile443 разрешено скачивать только по HTTPS"
        return 1
    }
    if ! curl -fsSL "$MOBILE443_ASN_URL" -o "$destination" >> "$LOG_FILE" 2>&1; then
        print_error "Не удалось скачать mobile443-filter"
        return 1
    fi
    actual_hash="$(sha256sum "$destination" 2>/dev/null | awk '{ print tolower($1) }')"
    if [[ -z "$actual_hash" || "$actual_hash" != "${MOBILE443_ASN_SHA256,,}" ]]; then
        print_error "Контрольная сумма mobile443-filter не совпала"
        return 1
    fi
    if ! bash -n "$destination" >> "$LOG_FILE" 2>&1; then
        print_error "Скачанный mobile443-filter содержит ошибку синтаксиса"
        return 1
    fi
    chmod 0700 "$destination"
}

remove_jumps() {
    local chain proto port
    command -v iptables >/dev/null 2>&1 || return 0
    for chain in INPUT FORWARD DOCKER-USER; do
        iptables -nL "$chain" >/dev/null 2>&1 || continue
        while IFS=$'\t' read -r proto port; do
            [[ "$proto" == "tcp" || "$proto" == "udp" ]] || continue
            [[ "$port" =~ ^[0-9]+$ ]] || continue
            while iptables -C "$chain" -p "$proto" --dport "$port" -j "$MOBILE443_CHAIN" >/dev/null 2>&1; do
                iptables -D "$chain" -p "$proto" --dport "$port" -j "$MOBILE443_CHAIN" >> "$LOG_FILE" 2>&1 || break
            done
        done < <(iptables -S "$chain" 2>/dev/null | awk -v target="$MOBILE443_CHAIN" '
            {
                proto = ""
                port = ""
                jump = ""
                for (i = 1; i <= NF; i++) {
                    if ($i == "-p" && i < NF) proto = $(i + 1)
                    if ($i == "--dport" && i < NF) port = $(i + 1)
                    if ($i == "-j" && i < NF) jump = $(i + 1)
                }
                if (jump == target && proto != "" && port != "") print proto "\t" port
            }
        ')
    done
}

prefix_count() {
    ipset list "$MOBILE443_IPSET" 2>/dev/null |
        awk '/^Number of entries:/ { print $4; exit }'
}

healthy() {
    local ports="$1" count port
    local -a port_list=()
    local IFS=' '
    count="$(prefix_count || true)"
    [[ "$count" =~ ^[0-9]+$ ]] && (( count >= 500 )) || return 1
    read -r -a port_list <<< "$ports"
    for port in "${port_list[@]}"; do
        iptables -C INPUT -p tcp --dport "$port" -j "$MOBILE443_CHAIN" >/dev/null 2>&1 || return 1
        iptables -C INPUT -p udp --dport "$port" -j "$MOBILE443_CHAIN" >/dev/null 2>&1 || return 1
    done
}

fail_open() {
    local ports="$1"
    systemctl stop mobile443-update.service mobile443-apply.service >/dev/null 2>&1 || true
    systemctl disable --now mobile443-update.timer mobile443-monitor.service >/dev/null 2>&1 || true
    systemctl disable mobile443-apply.service >/dev/null 2>&1 || true
    remove_jumps
    write_config "$ports" false >/dev/null 2>&1 || true
}

enable_lte() {
    local ports ssh_port script count
    ports="$(normalize_ports "${1:-}")" || {
        print_error "Не переданы корректные HAProxy-порты"
        return 1
    }
    ssh_port="$(detect_ssh_port)"
    if ports_include "$ports" "$ssh_port"; then
        print_error "Порт ${ssh_port} занят SSH. LTE-фильтр не включён, чтобы не потерять доступ к серверу."
        return 1
    fi

    ensure_download_tools
    script="$(mktemp)"
    if ! download_upstream "$script"; then
        rm -f "$script"
        return 1
    fi

    printf '[..] Включаю режим "Только LTE" на портах: %s\n' "$ports"
    printf '[..] Загрузка мобильных ASN обычно занимает 2-5 минут.\n'
    systemctl stop mobile443-update.timer mobile443-update.service mobile443-apply.service >/dev/null 2>&1 || true
    remove_jumps
    if ! write_config "$ports" true; then
        rm -f "$script"
        fail_open "$ports"
        return 1
    fi
    if ! env HOME=/root DEBIAN_FRONTEND=noninteractive bash "$script" update full >> "$LOG_FILE" 2>&1; then
        rm -f "$script"
        fail_open "$ports"
        print_error "mobile443-filter не установился. Правила сняты, трафик оставлен открытым."
        tail -n 25 "$LOG_FILE" >&2 || true
        return 1
    fi
    rm -f "$script"

    systemctl disable --now mobile443-monitor.service >> "$LOG_FILE" 2>&1 || true
    if ! healthy "$ports"; then
        fail_open "$ports"
        print_error "Мобильный allowlist не прошёл проверку. Правила сняты, трафик оставлен открытым."
        return 1
    fi

    count="$(prefix_count)"
    print_ok "Режим \"Только LTE\" включён"
    print_ok "Порты TCP/UDP: ${ports}"
    print_ok "Мобильных IPv4-сетей: ${count}"
    print_ok "Telegram и traffic-guard отключены"
}

disable_lte() {
    local ports
    ports="$(config_ports 2>/dev/null || echo 443)"
    systemctl stop mobile443-update.service mobile443-apply.service >/dev/null 2>&1 || true
    systemctl disable --now mobile443-update.timer mobile443-monitor.service >/dev/null 2>&1 || true
    systemctl disable mobile443-apply.service >/dev/null 2>&1 || true
    remove_jumps
    write_config "$ports" false
    print_ok "Режим \"Только LTE\" выключен"
    print_ok "HAProxy и его порты не изменялись"
}

show_status() {
    local ports count filter_status timer_status
    ports="$(config_ports 2>/dev/null || echo 443)"
    count="$(prefix_count || true)"
    [[ "$count" =~ ^[0-9]+$ ]] || count=0
    if config_enabled; then
        if healthy "$ports"; then
            filter_status="активен"
        else
            filter_status="ошибка"
        fi
    else
        filter_status="выключен"
    fi
    timer_status="$(systemctl is-active mobile443-update.timer 2>/dev/null || true)"
    [[ -n "$timer_status" ]] || timer_status="inactive"

    printf '[ ТОЛЬКО LTE ]\n'
    printf 'Фильтр: %s\n' "$filter_status"
    printf 'Порты TCP/UDP: %s\n' "$ports"
    printf 'Мобильных IPv4-сетей: %s\n' "$count"
    printf 'Автообновление: %s\n' "$timer_status"
    printf 'Фильтрация идёт по мобильным ASN РФ, а не по типу радиосети телефона.\n'
}

require_root
case "${1:-status}" in
    enable) enable_lte "${2:-}" ;;
    disable) disable_lte ;;
    status) show_status ;;
    configured) config_enabled ;;
    *)
        print_error "Использование: kto-mobile443 {enable <порты>|disable|status|configured}"
        exit 2
        ;;
esac
