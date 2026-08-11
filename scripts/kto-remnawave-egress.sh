#!/usr/bin/env bash
# shellcheck shell=bash

set -Eeuo pipefail
IFS=$'\n\t'

REMNA_EGRESS_BUILD="v301"
API_URL="${KTO_REMNA_API_URL:-}"
API_TOKEN="${KTO_REMNA_API_TOKEN:-}"
API_INSECURE="${KTO_REMNA_API_INSECURE:-0}"
NODE_PROFILE="${KTO_NODE_PROFILE:-reality}"
STATE_DIR="${KTO_REMNA_EGRESS_STATE_DIR:-/var/lib/kto-remnawave-egress}"
LOG_FILE="${KTO_REMNA_EGRESS_LOG_FILE:-/var/log/kto-remnawave-egress.log}"
ASSUME_YES="${KTO_REMNA_EGRESS_ASSUME_YES:-0}"

WORK_DIR=""
NODES_FILE=""
NODE_FILE=""
PROFILE_FILE=""
NODE_UUID=""
NODE_NAME=""
PROFILE_UUID=""
PROFILE_NAME=""

info() { printf '[..] %s\n' "$*"; }
ok() { printf '[OK] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
fail() { printf '[ОШИБКА] %s\n' "$*" >&2; }

cleanup() {
    if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
        rm -rf -- "$WORK_DIR"
    fi
    return 0
}

init_runtime() {
    local log_dir
    log_dir="$(dirname "$LOG_FILE")"
    mkdir -p "$log_dir" "$STATE_DIR"
    chmod 0700 "$STATE_DIR" 2>/dev/null || true
    touch "$LOG_FILE"
    chmod 0600 "$LOG_FILE" 2>/dev/null || true
    printf '===== kto-remnawave-egress %s %s =====\n' "$REMNA_EGRESS_BUILD" "$(date -Is)" >> "$LOG_FILE"

    WORK_DIR="$(mktemp -d)"
    NODES_FILE="$WORK_DIR/nodes.json"
    NODE_FILE="$WORK_DIR/node.json"
    PROFILE_FILE="$WORK_DIR/profile.json"
    trap cleanup EXIT
}

require_root() {
    if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
        fail "Запусти через sudo или от root."
        return 1
    fi
}

require_commands() {
    local command_name missing=()
    for command_name in curl jq ip getent; do
        command -v "$command_name" >/dev/null 2>&1 || missing+=("$command_name")
    done
    if (( ${#missing[@]} > 0 )); then
        fail "Не найдены команды: ${missing[*]}"
        return 1
    fi
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

api_call() {
    local method="$1" path="$2" payload_file="${3:-}"
    local response_file code url
    local -a tls_args=()
    response_file="$(mktemp "$WORK_DIR/api.XXXXXX")"
    url="${API_URL%/}${path}"
    if [[ "$API_INSECURE" == "1" ]]; then
        tls_args=(-k)
    fi

    if [[ -n "$payload_file" ]]; then
        code="$(curl "${tls_args[@]}" -sS -L --connect-timeout 8 --max-time 45 \
            -X "$method" \
            -H "Authorization: Bearer ${API_TOKEN}" \
            -H 'Accept: application/json' \
            -H 'Content-Type: application/json' \
            --data-binary "@${payload_file}" \
            -o "$response_file" -w '%{http_code}' "$url" 2>> "$LOG_FILE" || true)"
    else
        code="$(curl "${tls_args[@]}" -sS -L --connect-timeout 8 --max-time 45 \
            -X "$method" \
            -H "Authorization: Bearer ${API_TOKEN}" \
            -H 'Accept: application/json' \
            -o "$response_file" -w '%{http_code}' "$url" 2>> "$LOG_FILE" || true)"
    fi

    if [[ "$code" =~ ^2[0-9][0-9]$ ]] && jq -e . "$response_file" >/dev/null 2>&1; then
        cat "$response_file"
        return 0
    fi

    fail "Remnawave API ${method} ${path}: HTTP ${code:-curl}"
    head -c 700 "$response_file" >&2 || true
    printf '\n' >&2
    return 1
}

local_ipv4s() {
    local ip_address
    ip -4 -o address show scope global 2>/dev/null |
        awk '{print $4}' |
        cut -d/ -f1 |
        awk '!seen[$0]++'

    ip_address="$(curl -q -4 -fsS --noproxy '*' --connect-timeout 4 --max-time 8 https://api.ipify.org 2>/dev/null || true)"
    if validate_ipv4 "$ip_address"; then
        printf '%s\n' "$ip_address"
    fi
    return 0
}

address_is_local() {
    local address="$1" local_ips="$2" resolved
    if grep -Fqx "$address" <<< "$local_ips"; then
        return 0
    fi
    while read -r resolved; do
        [[ -n "$resolved" ]] || continue
        grep -Fqx "$resolved" <<< "$local_ips" && return 0
    done < <(getent ahostsv4 "$address" 2>/dev/null | awk '{print $1}' | awk '!seen[$0]++')
    return 1
}

select_node() {
    local local_ips row uuid node_id name address choice index
    local -a rows=() matches=()
    local_ips="$(local_ipv4s | awk 'NF && !seen[$0]++')"
    mapfile -t rows < <(jq -r '.response[]? | [.uuid, (.id // "-" | tostring), .name, .address] | @tsv' "$NODES_FILE")

    for row in "${rows[@]}"; do
        IFS=$'\t' read -r uuid node_id name address <<< "$row"
        if address_is_local "$address" "$local_ips"; then
            matches+=("$row")
        fi
    done

    if (( ${#matches[@]} == 1 )); then
        IFS=$'\t' read -r uuid node_id name address <<< "${matches[0]}"
        printf '[OK] Нода определена: %s (%s)\n' "$name" "$address" >&2
        printf '%s\n' "$uuid"
        return 0
    fi

    if (( ${#rows[@]} == 0 )); then
        fail "Панель не вернула ни одной Remnawave-ноды."
        return 1
    fi

    if (( ${#matches[@]} > 1 )); then
        warn "По локальным IP найдено несколько нод. Выбери нужную."
    else
        warn "Не смог однозначно сопоставить IP сервера с нодой в панели."
    fi
    printf 'Выбери Remnawave-ноду:\n' >&2
    for index in "${!rows[@]}"; do
        IFS=$'\t' read -r uuid node_id name address <<< "${rows[$index]}"
        printf ' %d) ID %s | %s | %s\n' "$(( index + 1 ))" "$node_id" "$name" "$address" >&2
    done
    while true; do
        printf '> ' >&2
        read -r choice
        if [[ "$choice" =~ ^[0-9]+$ ]]; then
            choice=$(( 10#$choice ))
            if (( choice >= 1 && choice <= ${#rows[@]} )); then
                IFS=$'\t' read -r uuid _ _ _ <<< "${rows[$(( choice - 1 ))]}"
                printf '%s\n' "$uuid"
                return 0
            fi
        fi
        fail "Неверный выбор"
    done
}

load_context() {
    api_call GET /api/nodes > "$NODES_FILE"
    NODE_UUID="$(select_node)"
    jq -e --arg uuid "$NODE_UUID" '.response[]? | select(.uuid == $uuid)' "$NODES_FILE" > "$NODE_FILE"
    NODE_NAME="$(jq -r '.name' "$NODE_FILE")"
    PROFILE_UUID="$(jq -r '.configProfile.activeConfigProfileUuid // .activeConfigProfileUuid // empty' "$NODE_FILE")"
    if [[ -z "$PROFILE_UUID" ]]; then
        fail "У ноды ${NODE_NAME} не выбран активный Config Profile."
        return 1
    fi
    refresh_profile
}

refresh_profile() {
    api_call GET "/api/config-profiles/${PROFILE_UUID}" > "$PROFILE_FILE"
    PROFILE_NAME="$(jq -r '.response.name // "-"' "$PROFILE_FILE")"
    if ! jq -e '.response.config | type == "object"' "$PROFILE_FILE" >/dev/null; then
        fail "Remnawave не вернула Xray-конфиг профиля ${PROFILE_NAME}."
        return 1
    fi
}

profile_nodes_count() {
    jq -r --arg uuid "$PROFILE_UUID" '
        [.response[]? |
            select((.configProfile.activeConfigProfileUuid // .activeConfigProfileUuid // "") == $uuid)] |
        length
    ' "$NODES_FILE"
}

profile_nodes_list() {
    jq -r --arg uuid "$PROFILE_UUID" '
        .response[]? |
        select((.configProfile.activeConfigProfileUuid // .activeConfigProfileUuid // "") == $uuid) |
        "- \(.name) (\(.address))"
    ' "$NODES_FILE"
}

freedom_outbounds() {
    jq -r '
        .response.config.outbounds // [] |
        to_entries[] |
        select(.value.protocol == "freedom") |
        [.key, (.value.tag // "(без тега)"), (.value.sendThrough // "default")] |
        @tsv
    ' "$PROFILE_FILE"
}

select_freedom_outbound() {
    local row index tag current choice direct_index=""
    local -a rows=()
    mapfile -t rows < <(freedom_outbounds)
    if (( ${#rows[@]} == 0 )); then
        fail "В профиле ${PROFILE_NAME} нет outbound с protocol=freedom."
        return 1
    fi

    for row in "${rows[@]}"; do
        IFS=$'\t' read -r index tag current <<< "$row"
        if [[ "$tag" == "DIRECT" ]]; then
            direct_index="$index"
            break
        fi
    done
    if [[ -n "$direct_index" ]]; then
        printf '%s\n' "$direct_index"
        return 0
    fi
    if (( ${#rows[@]} == 1 )); then
        IFS=$'\t' read -r index _ _ <<< "${rows[0]}"
        printf '%s\n' "$index"
        return 0
    fi

    printf 'Выбери direct outbound:\n' >&2
    for index in "${!rows[@]}"; do
        IFS=$'\t' read -r _ tag current <<< "${rows[$index]}"
        printf ' %d) %s | sendThrough: %s\n' "$(( index + 1 ))" "$tag" "$current" >&2
    done
    while true; do
        printf '> ' >&2
        read -r choice
        if [[ "$choice" =~ ^[0-9]+$ ]]; then
            choice=$(( 10#$choice ))
            if (( choice >= 1 && choice <= ${#rows[@]} )); then
                IFS=$'\t' read -r index _ _ <<< "${rows[$(( choice - 1 ))]}"
                printf '%s\n' "$index"
                return 0
            fi
        fi
        fail "Неверный выбор"
    done
}

outbound_label() {
    local index="$1"
    jq -r --argjson index "$index" '.response.config.outbounds[$index].tag // "(без тега)"' "$PROFILE_FILE"
}

outbound_send_through() {
    local index="$1"
    jq -r --argjson index "$index" '.response.config.outbounds[$index].sendThrough // "default"' "$PROFILE_FILE"
}

primary_route_ip() {
    ip -4 route get 1.1.1.1 2>/dev/null |
        awk '{for (i=1; i<=NF; i++) if ($i == "src") {print $(i+1); exit}}' || true
}

primary_route_interface() {
    ip -4 route get 1.1.1.1 2>/dev/null |
        awk '{for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}' || true
}

list_routable_source_ips() {
    local primary_ip primary_interface line interface cidr source_ip route route_interface kind
    primary_ip="$(primary_route_ip)"
    primary_interface="$(primary_route_interface)"

    while read -r line; do
        interface="$(awk '{print $2}' <<< "$line")"
        interface="${interface%%@*}"
        cidr="$(awk '{print $4}' <<< "$line")"
        source_ip="${cidr%%/*}"
        case "$interface" in
            lo|docker*|veth*|br-*|virbr*) continue ;;
        esac
        validate_ipv4 "$source_ip" || continue
        route="$(ip -4 route get 1.1.1.1 from "$source_ip" 2>/dev/null || true)"
        route_interface="$(awk '{for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}' <<< "$route")"
        [[ "$route_interface" == "$interface" ]] || continue
        kind="additional"
        if [[ "$source_ip" == "$primary_ip" && "$interface" == "$primary_interface" ]]; then
            kind="default"
        fi
        printf '%s\t%s\t%s\n' "$source_ip" "$interface" "$kind"
    done < <(ip -4 -o address show scope global 2>/dev/null || true) |
        sort -t $'\t' -k3,3r -k2,2V -k1,1V |
        awk -F '\t' '!seen[$1]++'
}

select_source_ip() {
    local row source_ip interface kind choice index
    local -a rows=()
    mapfile -t rows < <(list_routable_source_ips)
    if (( ${#rows[@]} == 0 )); then
        fail "Не найдено ни одного рабочего исходящего IPv4."
        return 1
    fi

    printf 'Доступные исходящие IP:\n' >&2
    for index in "${!rows[@]}"; do
        IFS=$'\t' read -r source_ip interface kind <<< "${rows[$index]}"
        if [[ "$kind" == "default" ]]; then
            kind="системный default"
        else
            kind="дополнительный"
        fi
        printf ' %d) %s | %s | %s\n' "$(( index + 1 ))" "$source_ip" "$interface" "$kind" >&2
    done
    while true; do
        printf '> ' >&2
        read -r choice
        if [[ "$choice" =~ ^[0-9]+$ ]]; then
            choice=$(( 10#$choice ))
            if (( choice >= 1 && choice <= ${#rows[@]} )); then
                IFS=$'\t' read -r source_ip _ _ <<< "${rows[$(( choice - 1 ))]}"
                printf '%s\n' "$source_ip"
                return 0
            fi
        fi
        fail "Неверный выбор"
    done
}

probe_source_ip() {
    local source_ip="$1" external_ip
    if [[ "${KTO_REMNA_EGRESS_SKIP_PROBE:-0}" == "1" ]]; then
        return 0
    fi
    external_ip="$(curl -q -4 -fsS --noproxy '*' --interface "$source_ip" \
        --connect-timeout 6 --max-time 15 https://api.ipify.org 2>> "$LOG_FILE" || true)"
    if ! validate_ipv4 "$external_ip"; then
        fail "IP ${source_ip} не прошёл прямую HTTPS-проверку. Сначала запусти настройку дополнительных IP."
        return 1
    fi
    if [[ "$external_ip" != "$source_ip" ]]; then
        warn "Провайдер делает NAT: локальный ${source_ip}, внешний ${external_ip}."
    else
        ok "Прямой выход подтверждён: ${source_ip}"
    fi
}

rewrite_profile_config() {
    local profile_file="$1" outbound_index="$2" send_through="$3" output_file="$4"
    if [[ "$send_through" == "default" ]]; then
        jq --argjson index "$outbound_index" '
            .response.config |
            del(.outbounds[$index].sendThrough)
        ' "$profile_file" > "$output_file"
    else
        jq --argjson index "$outbound_index" --arg send_through "$send_through" '
            .response.config |
            .outbounds[$index].sendThrough = $send_through
        ' "$profile_file" > "$output_file"
    fi
}

confirm_profile_restart() {
    local node_count="$1" answer
    printf '\nПрофиль используется нодами:\n'
    profile_nodes_list
    warn "После сохранения Remnawave перезапустит Xray на ${node_count} нод(е/ах) этого профиля."
    if [[ "$ASSUME_YES" == "1" ]]; then
        return 0
    fi
    printf 'Для применения введи yes: '
    read -r answer
    [[ "${answer,,}" == "yes" ]]
}

save_state() {
    local outbound_index="$1" mode="$2" value="$3" backup_file="$4"
    local state_file temporary
    state_file="${STATE_DIR}/${NODE_UUID}.json"
    temporary="$(mktemp "$WORK_DIR/state.XXXXXX")"
    jq -n \
        --arg build "$REMNA_EGRESS_BUILD" \
        --arg nodeUuid "$NODE_UUID" \
        --arg nodeName "$NODE_NAME" \
        --arg profileUuid "$PROFILE_UUID" \
        --arg profileName "$PROFILE_NAME" \
        --argjson outboundIndex "$outbound_index" \
        --arg outboundTag "$(outbound_label "$outbound_index")" \
        --arg mode "$mode" \
        --arg value "$value" \
        --arg backup "$backup_file" \
        --arg updatedAt "$(date -Is)" \
        '{build:$build,nodeUuid:$nodeUuid,nodeName:$nodeName,profileUuid:$profileUuid,profileName:$profileName,outboundIndex:$outboundIndex,outboundTag:$outboundTag,mode:$mode,value:$value,backup:$backup,updatedAt:$updatedAt}' \
        > "$temporary"
    install -m 0600 "$temporary" "$state_file"
}

apply_send_through() {
    local outbound_index="$1" send_through="$2" mode="$3"
    local current outbound_tag node_count timestamp backup_file config_file payload_file response_file verified
    current="$(outbound_send_through "$outbound_index")"
    outbound_tag="$(outbound_label "$outbound_index")"
    node_count="$(profile_nodes_count)"

    if [[ "$current" == "$send_through" ]]; then
        ok "Уже настроено: ${outbound_tag} -> ${send_through}"
        return 0
    fi
    if [[ "$mode" == "fixed" && "$node_count" -gt 1 ]]; then
        fail "Фиксированный локальный IP нельзя записать в общий профиль ${PROFILE_NAME}."
        profile_nodes_list >&2
        warn "Используй режим origin или отдельный Config Profile только для этой ноды."
        return 1
    fi

    printf '\nНода: %s\n' "$NODE_NAME"
    printf 'Профиль: %s\n' "$PROFILE_NAME"
    printf 'Outbound: %s\n' "$outbound_tag"
    printf 'Изменение: %s -> %s\n' "$current" "$send_through"
    if ! confirm_profile_restart "$node_count"; then
        warn "Изменение отменено."
        return 0
    fi

    timestamp="$(date +%Y%m%d-%H%M%S)"
    backup_file="${STATE_DIR}/profile-${PROFILE_UUID}-${timestamp}.json"
    config_file="$WORK_DIR/config-new.json"
    payload_file="$WORK_DIR/profile-patch.json"
    response_file="$WORK_DIR/profile-patch-response.json"

    jq '.response.config' "$PROFILE_FILE" > "$backup_file"
    chmod 0600 "$backup_file"
    rewrite_profile_config "$PROFILE_FILE" "$outbound_index" "$send_through" "$config_file"
    if ! jq -e --argjson index "$outbound_index" '.outbounds[$index].protocol == "freedom"' "$config_file" >/dev/null; then
        fail "Не удалось безопасно собрать новый Xray-конфиг."
        return 1
    fi
    jq -n --arg uuid "$PROFILE_UUID" --slurpfile config "$config_file" \
        '{uuid:$uuid,config:$config[0]}' > "$payload_file"

    info "Сохраняю Config Profile через Remnawave API"
    api_call PATCH /api/config-profiles "$payload_file" > "$response_file"
    refresh_profile
    verified="$(outbound_send_through "$outbound_index")"
    if [[ "$verified" != "$send_through" ]]; then
        fail "Панель приняла запрос, но sendThrough не совпал: ${verified}."
        return 1
    fi
    save_state "$outbound_index" "$mode" "$send_through" "$backup_file"
    ok "Применено: ${outbound_tag} -> ${send_through}"
    ok "Резервная копия: ${backup_file}"
}

show_active_inbounds() {
    local active_tags
    active_tags="$(jq -c '[((.configProfile.activeInbounds // .activeInbounds // [])[]?) | (.tag // .)]' "$NODE_FILE")"
    jq -r --argjson tags "$active_tags" '
        .response.config.inbounds[]? |
        select(.tag as $tag | $tags | index($tag)) |
        "- \(.tag): \(.protocol // "-") | listen \(.listen // "0.0.0.0") | port \(.port // "-")"
    ' "$PROFILE_FILE"
}

show_status() {
    local outbound_index outbound_tag send_through mode node_count active
    refresh_profile
    outbound_index="$(select_freedom_outbound)"
    outbound_tag="$(outbound_label "$outbound_index")"
    send_through="$(outbound_send_through "$outbound_index")"
    node_count="$(profile_nodes_count)"
    case "$send_through" in
        default) mode="системный маршрут по умолчанию" ;;
        origin) mode="входной IP = выходной IP (Reality/TCP)" ;;
        *) mode="фиксированный IP" ;;
    esac

    printf '\n[ REMNAWAVE EGRESS ]\n'
    printf 'Нода: %s\n' "$NODE_NAME"
    printf 'Профиль: %s\n' "$PROFILE_NAME"
    printf 'Профиль используют: %s нод(ы)\n' "$node_count"
    printf 'Outbound: %s\n' "$outbound_tag"
    printf 'Режим: %s\n' "$mode"
    printf 'sendThrough: %s\n' "$send_through"
    printf '\nАктивные inbound:\n'
    active="$(show_active_inbounds)"
    printf '%s\n' "${active:-- не определены}"

    if [[ "$send_through" == "origin" ]]; then
        warn "Для подключения через дополнительный IP inbound должен слушать 0.0.0.0 или ::."
        if [[ "$NODE_PROFILE" == "reality_hysteria2" ]]; then
            warn "origin работает для Reality/TCP. Для Hysteria2/UDP нужен фиксированный IP и отдельный профиль ноды."
        fi
    fi
}

configure_origin() {
    local outbound_index
    outbound_index="$(select_freedom_outbound)"
    apply_send_through "$outbound_index" origin origin
    if [[ "$NODE_PROFILE" == "reality_hysteria2" ]]; then
        warn "Reality будет выходить через IP подключения. Hysteria2/UDP продолжит использовать системный маршрут."
    fi
}

configure_fixed() {
    local outbound_index source_ip
    outbound_index="$(select_freedom_outbound)"
    source_ip="$(select_source_ip)"
    probe_source_ip "$source_ip"
    apply_send_through "$outbound_index" "$source_ip" fixed
}

configure_default() {
    local outbound_index
    outbound_index="$(select_freedom_outbound)"
    apply_send_through "$outbound_index" default default
}

menu() {
    local choice
    load_context
    while true; do
        refresh_profile
        printf '\n[ ИСХОДЯЩИЙ IP REMNAWAVE ]\n'
        printf 'Нода: %s\n' "$NODE_NAME"
        printf 'Профиль: %s\n\n' "$PROFILE_NAME"
        printf '1) Входной IP = выходной IP (Reality)\n'
        printf '2) Фиксированный выходной IP\n'
        printf '3) Вернуть системный выход по умолчанию\n'
        printf '4) Статус\n'
        printf '0) Назад\n'
        printf '> '
        read -r choice
        case "$choice" in
            1) configure_origin || true ;;
            2) configure_fixed || true ;;
            3) configure_default || true ;;
            4) show_status || true ;;
            0) return 0 ;;
            *) fail "Неверный выбор" ;;
        esac
    done
}

main() {
    require_root
    require_commands
    if [[ -z "$API_URL" || -z "$API_TOKEN" ]]; then
        fail "Нужны KTO_REMNA_API_URL и KTO_REMNA_API_TOKEN."
        return 1
    fi
    init_runtime
    case "${1:-menu}" in
        menu) menu ;;
        status)
            load_context
            show_status
            ;;
        origin)
            load_context
            configure_origin
            ;;
        fixed)
            load_context
            configure_fixed
            ;;
        default|reset)
            load_context
            configure_default
            ;;
        *)
            fail "Использование: $0 menu|status|origin|fixed|default"
            return 1
            ;;
    esac
}

main "$@"
