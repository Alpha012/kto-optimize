#!/usr/bin/env bash
# shellcheck shell=bash

set -Eeuo pipefail
IFS=$'\n\t'

HAPROXY_BANDWIDTH_BUILD="v292"
LIMITS_CONFIG="${KTO_HAPROXY_BANDWIDTH_CONFIG:-/etc/kto-haproxy-bandwidth.conf}"
HAPROXY_CONFIG="${KTO_HAPROXY_CONFIG:-/etc/haproxy/haproxy.cfg}"
STATE_FILE="${KTO_HAPROXY_BANDWIDTH_STATE:-/run/kto-haproxy-bandwidth.state}"
PENDING_STATE="${KTO_HAPROXY_BANDWIDTH_PENDING_STATE:-${STATE_FILE}.pending}"
LOCK_FILE="${KTO_HAPROXY_BANDWIDTH_LOCK:-/run/kto-haproxy-bandwidth.lock}"
LOG_FILE="${KTO_HAPROXY_BANDWIDTH_LOG:-/var/log/kto-haproxy-bandwidth.log}"
ACTION_BASE="${KTO_HAPROXY_BANDWIDTH_ACTION_BASE:-3900000}"
PREF_BASE="${KTO_HAPROXY_BANDWIDTH_PREF_BASE:-42000}"

ok() { printf '[OK] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
fail() { printf '[ОШИБКА] %s\n' "$*" >&2; }

TC_LAST_ERROR=""

init_log() {
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    chmod 0644 "$LOG_FILE" 2>/dev/null || true
    printf '===== kto-haproxy-bandwidth %s %s =====\n' \
        "$HAPROXY_BANDWIDTH_BUILD" "$(date -Is)" >> "$LOG_FILE"
}

require_root() {
    if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
        fail "Запусти менеджер лимитов HAProxy от root"
        return 1
    fi
}

require_commands() {
    local command_name
    for command_name in awk flock grep install ip sort tc; do
        if ! command -v "$command_name" >/dev/null 2>&1; then
            fail "Не найдена команда: ${command_name}"
            return 1
        fi
    done
}

acquire_lock() {
    mkdir -p "$(dirname "$LOCK_FILE")"
    exec 9> "$LOCK_FILE"
    if ! flock -w 15 9; then
        fail "Другой процесс уже меняет лимиты HAProxy"
        return 1
    fi
}

validate_ipv4() {
    local ip="$1" octet
    local -a octets=()
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS=. read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
        (( 10#$octet >= 0 && 10#$octet <= 255 )) || return 1
    done
}

validate_rate_mbit() {
    local rate="${1:-}"
    [[ "$rate" =~ ^[0-9]+$ ]] || return 1
    (( ${#rate} <= 6 )) || return 1
    rate=$((10#$rate))
    (( rate >= 1 && rate <= 100000 ))
}

interface_for_ipv4() {
    local wanted="$1"
    ip -4 -o address show scope global 2>/dev/null | awk -v wanted="$wanted" '
        {
            split($4, cidr, "/")
            if (cidr[1] == wanted) {
                interface = $2
                sub(/@.*/, "", interface)
                print interface
                exit
            }
        }
    '
}

haproxy_ports() {
    [[ -s "$HAPROXY_CONFIG" ]] || return 1
    awk '
        $1 == "frontend" { section = "frontend"; next }
        $1 == "backend" || $1 == "global" || $1 == "defaults" || $1 == "listen" {
            section = $1
            next
        }
        section == "frontend" && $1 == "bind" {
            count = split($2, addresses, ",")
            for (i = 1; i <= count; i++) {
                address = addresses[i]
                sub(/^.*:/, "", address)
                sub(/[^0-9].*$/, "", address)
                port = address + 0
                if (address ~ /^[0-9]+$/ && port >= 1 && port <= 65535) print port
            }
        }
    ' "$HAPROXY_CONFIG" | sort -n -u
}

load_limits() {
    local line_number=0 ip rate extra
    local -A seen=()

    [[ -s "$LIMITS_CONFIG" ]] || return 0
    while IFS=$'\t' read -r ip rate extra; do
        line_number=$(( line_number + 1 ))
        ip="${ip//$'\r'/}"
        rate="${rate//$'\r'/}"
        [[ -n "$ip" && "${ip:0:1}" != "#" ]] || continue
        if [[ -n "${extra:-}" ]] || ! validate_ipv4 "$ip" || ! validate_rate_mbit "$rate"; then
            fail "Некорректная строка ${line_number} в ${LIMITS_CONFIG}"
            return 1
        fi
        rate=$((10#$rate))
        if [[ -n "${seen[$ip]+x}" && "${seen[$ip]}" != "$rate" ]]; then
            fail "Для ${ip} указано несколько разных лимитов"
            return 1
        fi
        seen[$ip]="$rate"
    done < "$LIMITS_CONFIG"

    for ip in "${!seen[@]}"; do
        printf '%s\t%s\n' "$ip" "${seen[$ip]}"
    done | sort -t $'\t' -k1,1V
}

burst_bytes_for_rate() {
    local rate_mbit="$1" burst
    burst=$(( rate_mbit * 6250 ))
    (( burst >= 262144 )) || burst=262144
    (( burst <= 67108864 )) || burst=67108864
    printf '%s\n' "$burst"
}

ensure_clsact() {
    local interface="$1" qdiscs
    qdiscs="$(tc qdisc show dev "$interface" 2>/dev/null || true)"
    if grep -Eq '^qdisc clsact ' <<< "$qdiscs"; then
        return 0
    fi
    if grep -Eq '^qdisc ingress ' <<< "$qdiscs"; then
        fail "На ${interface} уже есть отдельный ingress qdisc; автоматически заменять его опасно"
        return 1
    fi
    tc qdisc add dev "$interface" clsact >> "$LOG_FILE" 2>&1
}

tc_logged() {
    local output rc=0 argument
    output="$(tc "$@" 2>&1)" || rc=$?
    {
        printf '$ tc'
        for argument in "$@"; do
            printf ' %q' "$argument"
        done
        printf '\n'
        [[ -z "$output" ]] || printf '%s\n' "$output"
    } >> "$LOG_FILE"
    TC_LAST_ERROR="$output"
    return "$rc"
}

tc_error_summary() {
    local summary="${TC_LAST_ERROR//$'\n'/; }"
    [[ -n "$summary" ]] || summary="tc завершился с ошибкой без пояснения"
    printf '%.500s\n' "$summary"
}

delete_filter_quiet() {
    local interface="$1" direction="$2" pref="$3"
    tc filter delete dev "$interface" "$direction" protocol ip pref "$pref" \
        >> "$LOG_FILE" 2>&1 || true
}

delete_police_action_quiet() {
    local action_index="$1"
    tc actions delete action police index "$action_index" >> "$LOG_FILE" 2>&1 || true
}

add_police_filter() {
    local interface="$1" direction="$2" pref="$3" ip="$4" port="$5"
    local action_index="$6" rate="$7" burst="$8" define_action="$9"
    local flower_error u32_error
    local -a flower_match=() u32_match=() action_args=()

    if [[ "$direction" == "ingress" ]]; then
        flower_match=(dst_ip "$ip" dst_port "$port")
        u32_match=(match ip dst "${ip}/32" match ip dport "$port" 0xffff)
    else
        flower_match=(src_ip "$ip" src_port "$port")
        u32_match=(match ip src "${ip}/32" match ip sport "$port" 0xffff)
    fi
    if (( define_action == 1 )); then
        action_args=(
            action police rate "${rate}mbit" burst "$burst" mtu 64kb
            conform-exceed drop/ok index "$action_index"
        )
    else
        action_args=(action police index "$action_index")
    fi

    if tc_logged filter add dev "$interface" "$direction" protocol ip pref "$pref" \
        flower skip_hw ip_proto tcp "${flower_match[@]}" "${action_args[@]}"; then
        return 0
    fi
    flower_error="$(tc_error_summary)"
    delete_filter_quiet "$interface" "$direction" "$pref"
    if (( define_action == 1 )); then
        delete_police_action_quiet "$action_index"
    fi

    # cls_flower is optional on some minimal Ubuntu kernels. u32 provides the
    # same exact IPv4/TCP match without requiring that module.
    if tc_logged filter add dev "$interface" "$direction" protocol ip pref "$pref" \
        u32 match ip protocol 6 0xff "${u32_match[@]}" "${action_args[@]}"; then
        TC_FILTER_FALLBACK_USED=1
        return 0
    fi
    u32_error="$(tc_error_summary)"
    delete_filter_quiet "$interface" "$direction" "$pref"
    if (( define_action == 1 )); then
        delete_police_action_quiet "$action_index"
    fi
    TC_LAST_ERROR="flower: ${flower_error}; u32: ${u32_error}"
    return 1
}

cleanup_state_file() {
    local state_file="$1" kind interface direction pref action_index
    [[ -s "$state_file" ]] || return 0

    while IFS=$'\t' read -r kind interface direction pref action_index; do
        [[ "$kind" == "F" ]] || continue
        tc filter delete dev "$interface" "$direction" protocol ip pref "$pref" \
            >> "$LOG_FILE" 2>&1 || true
    done < "$state_file"
    while IFS=$'\t' read -r kind action_index _; do
        [[ "$kind" == "A" && "$action_index" =~ ^[0-9]+$ ]] || continue
        tc actions delete action police index "$action_index" >> "$LOG_FILE" 2>&1 || true
    done < "$state_file"
}

clear_limits() {
    cleanup_state_file "$STATE_FILE"
    cleanup_state_file "$PENDING_STATE"
    rm -f "$STATE_FILE" "$PENDING_STATE"
    ok "Kernel-лимиты входных IP HAProxy очищены"
}

apply_limits() {
    (
    local limits_file ports_file next_state
    local ip rate interface port action_index ingress_action_index egress_action_index burst pref
    local filter_count=0 limit_count=0 committed=0
    local ingress_action_bound=0 egress_action_bound=0
    local TC_FILTER_FALLBACK_USED=0
    local -a interfaces=()
    local -A seen_interfaces=()

    limits_file="$(mktemp)"
    ports_file="$(mktemp)"
    next_state="$PENDING_STATE"
    cleanup_state_file "$next_state"
    rm -f "$next_state"
    : > "$next_state"
    chmod 0600 "$next_state" 2>/dev/null || true
    trap 'rc=$?; trap - EXIT; if (( committed == 0 )); then cleanup_state_file "$next_state"; fi; rm -f "$limits_file" "$ports_file" "$next_state"; exit "$rc"' EXIT

    load_limits > "$limits_file" || return 1
    if [[ ! -s "$limits_file" ]]; then
        clear_limits
        return 0
    fi
    if ! haproxy_ports > "$ports_file" || [[ ! -s "$ports_file" ]]; then
        fail "Не удалось получить frontend-порты из ${HAPROXY_CONFIG}"
        return 1
    fi

    while IFS=$'\t' read -r ip rate; do
        interface="$(interface_for_ipv4 "$ip")"
        if [[ -z "$interface" ]]; then
            fail "Входной IP ${ip} не найден на локальных интерфейсах"
            return 1
        fi
        if [[ -z "${seen_interfaces[$interface]+x}" ]]; then
            seen_interfaces[$interface]=1
            interfaces+=("$interface")
        fi
        limit_count=$(( limit_count + 1 ))
    done < "$limits_file"

    for interface in "${interfaces[@]}"; do
        ensure_clsact "$interface" || return 1
    done

    cleanup_state_file "$STATE_FILE"
    action_index="$ACTION_BASE"
    pref="$PREF_BASE"
    while IFS=$'\t' read -r ip rate; do
        interface="$(interface_for_ipv4 "$ip")"
        ingress_action_index=$(( action_index + 1 ))
        egress_action_index=$(( action_index + 2 ))
        action_index="$egress_action_index"
        burst="$(burst_bytes_for_rate "$rate")"
        ingress_action_bound=0
        egress_action_bound=0

        # Each direction gets its own shared action, so the configured rate is
        # available independently to RX and TX across every HAProxy port.
        while read -r port; do
            [[ "$port" =~ ^[0-9]+$ ]] || continue
            pref=$(( pref + 1 ))
            if (( pref > 65000 )); then
                fail "Слишком много HAProxy-фильтров"
                cleanup_state_file "$next_state"
                return 1
            fi
            if ! add_police_filter "$interface" ingress "$pref" "$ip" "$port" \
                "$ingress_action_index" "$rate" "$burst" \
                "$(( ingress_action_bound == 0 ? 1 : 0 ))"; then
                fail "Не удалось ограничить вход ${ip}:${port}: $(tc_error_summary)"
                cleanup_state_file "$next_state"
                return 1
            fi
            if (( ingress_action_bound == 0 )); then
                printf 'A\t%s\n' "$ingress_action_index" >> "$next_state"
                ingress_action_bound=1
            fi
            printf 'F\t%s\tingress\t%s\t%s\n' \
                "$interface" "$pref" "$ingress_action_index" >> "$next_state"

            pref=$(( pref + 1 ))
            if ! add_police_filter "$interface" egress "$pref" "$ip" "$port" \
                "$egress_action_index" "$rate" "$burst" \
                "$(( egress_action_bound == 0 ? 1 : 0 ))"; then
                fail "Не удалось ограничить выход ${ip}:${port}: $(tc_error_summary)"
                cleanup_state_file "$next_state"
                return 1
            fi
            if (( egress_action_bound == 0 )); then
                printf 'A\t%s\n' "$egress_action_index" >> "$next_state"
                egress_action_bound=1
            fi
            printf 'F\t%s\tegress\t%s\t%s\n' \
                "$interface" "$pref" "$egress_action_index" >> "$next_state"
            filter_count=$(( filter_count + 2 ))
        done < "$ports_file"
    done < "$limits_file"

    install -m 0600 "$next_state" "$STATE_FILE"
    committed=1
    ok "Лимитов входных IP: ${limit_count}"
    ok "HAProxy tc-фильтров: ${filter_count}"
    ok "Для каждого IP: отдельный лимит RX и отдельный лимит TX"
    if (( TC_FILTER_FALLBACK_USED == 1 )); then
        warn "На этой системе применён совместимый classifier u32 вместо flower"
    fi
    )
}

active_filter_count() {
    local kind interface direction pref action_index output count=0
    [[ -s "$STATE_FILE" ]] || {
        printf '0\n'
        return 0
    }
    while IFS=$'\t' read -r kind interface direction pref action_index; do
        [[ "$kind" == "F" && "$pref" =~ ^[0-9]+$ ]] || continue
        output="$(tc filter show dev "$interface" "$direction" protocol ip pref "$pref" 2>/dev/null || true)"
        [[ -n "$output" ]] && count=$(( count + 1 ))
    done < "$STATE_FILE"
    printf '%s\n' "$count"
}

show_status() {
    (
    local limits_file ip rate interface action_index ingress_action_index egress_action_index
    local ingress_active egress_active filters expected ports_count limit_count overall="РАБОТАЕТ"
    limits_file="$(mktemp)"
    trap 'rm -f "$limits_file"' EXIT
    load_limits > "$limits_file" || return 1

    printf '[ ЛИМИТЫ ВХОДНЫХ IP HAPROXY ]\n'
    printf 'Build: %s\n' "$HAPROXY_BANDWIDTH_BUILD"
    if [[ ! -s "$limits_file" ]]; then
        printf 'Итог: ВЫКЛЮЧЕНО\n'
        printf 'Настроенных IP нет.\n'
        return 0
    fi

    ports_count="$(haproxy_ports 2>/dev/null | wc -l | tr -d '[:space:]')"
    [[ "$ports_count" =~ ^[0-9]+$ ]] || ports_count=0
    action_index="$ACTION_BASE"
    while IFS=$'\t' read -r ip rate; do
        ingress_action_index=$(( action_index + 1 ))
        egress_action_index=$(( action_index + 2 ))
        action_index="$egress_action_index"
        interface="$(interface_for_ipv4 "$ip")"
        ingress_active="НЕТ"
        egress_active="НЕТ"
        if [[ -n "$interface" ]] && \
            tc actions get action police index "$ingress_action_index" >/dev/null 2>&1; then
            ingress_active="OK"
        else
            overall="ОШИБКА"
        fi
        if [[ -n "$interface" ]] && \
            tc actions get action police index "$egress_action_index" >/dev/null 2>&1; then
            egress_active="OK"
        else
            overall="ОШИБКА"
        fi
        printf '%s (%s): %s Mbit/s на каждое направление\n' \
            "$ip" "${interface:-нет интерфейса}" "$rate"
        printf '  Вход (RX): %s\n' "$ingress_active"
        if [[ "$ingress_active" == "OK" ]]; then
            tc -s actions get action police index "$ingress_action_index" 2>/dev/null |
                awk '/Sent / { sub(/^[[:space:]]+/, ""); print "    " $0; exit }'
        fi
        printf '  Выход (TX): %s\n' "$egress_active"
        if [[ "$egress_active" == "OK" ]]; then
            tc -s actions get action police index "$egress_action_index" 2>/dev/null |
                awk '/Sent / { sub(/^[[:space:]]+/, ""); print "    " $0; exit }'
        fi
    done < "$limits_file"

    filters="$(active_filter_count)"
    [[ "$filters" =~ ^[0-9]+$ ]] || filters=0
    limit_count="$(wc -l < "$limits_file" | tr -d '[:space:]')"
    [[ "$limit_count" =~ ^[0-9]+$ ]] || limit_count=0
    expected=$(( ports_count * 2 * limit_count ))
    if (( filters != expected )); then
        overall="ОШИБКА"
    fi
    printf 'HAProxy-портов: %s\n' "$ports_count"
    printf 'Фильтров: %s/%s\n' "$filters" "$expected"
    printf 'Итог: %s\n' "$overall"
    printf 'RX и TX ограничиваются независимо; каждому доступен полный указанный лимит.\n'
    )
}

main() {
    require_root
    init_log
    require_commands
    acquire_lock
    case "${1:-status}" in
        apply) apply_limits ;;
        clear) clear_limits ;;
        status) show_status ;;
        *)
            fail "Использование: kto-haproxy-bandwidth {apply|clear|status}"
            return 2
            ;;
    esac
}

main "$@"
