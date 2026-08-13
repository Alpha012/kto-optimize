#!/usr/bin/env bash
# shellcheck shell=bash

set -Eeuo pipefail
IFS=$'\n\t'

HAPROXY_BANDWIDTH_BUILD="v317"
LIMITS_CONFIG="${KTO_HAPROXY_BANDWIDTH_CONFIG:-/etc/kto-haproxy-bandwidth.conf}"
HAPROXY_CONFIG="${KTO_HAPROXY_CONFIG:-/etc/haproxy/haproxy.cfg}"
STATE_FILE="${KTO_HAPROXY_BANDWIDTH_STATE:-/run/kto-haproxy-bandwidth.state}"
PENDING_STATE="${KTO_HAPROXY_BANDWIDTH_PENDING_STATE:-${STATE_FILE}.pending}"
READY_FILE="${KTO_HAPROXY_BANDWIDTH_READY:-${STATE_FILE}.ready}"
LOCK_FILE="${KTO_HAPROXY_BANDWIDTH_LOCK:-/run/kto-haproxy-bandwidth.lock}"
LOG_FILE="${KTO_HAPROXY_BANDWIDTH_LOG:-/var/log/kto-haproxy-bandwidth.log}"
PREF_BASE="${KTO_HAPROXY_BANDWIDTH_PREF_BASE:-42000}"
LEGACY_ACTION_BASE="${KTO_HAPROXY_BANDWIDTH_ACTION_BASE:-3900000}"
ROOT_MAJOR="${KTO_HAPROXY_BANDWIDTH_ROOT_MAJOR:-7a00}"
IFB_ROOT_MAJOR="${KTO_HAPROXY_BANDWIDTH_IFB_MAJOR:-7b00}"
ROOT_DEFAULT_LEAF_MAJOR="${KTO_HAPROXY_BANDWIDTH_DEFAULT_LEAF_MAJOR:-7aff}"
IFB_LEAF_MAJOR="${KTO_HAPROXY_BANDWIDTH_IFB_LEAF_MAJOR:-7b10}"
SHAPER_CAPACITY_MBIT="${KTO_HAPROXY_BANDWIDTH_CAPACITY_MBIT:-100000}"
STATE_SCHEMA="3"

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
    for command_name in awk flock grep install ip sha256sum sort tc; do
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

haproxy_endpoints() {
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
                if (address ~ /^[0-9]+$/) {
                    listen_ip = "*"
                    port = address + 0
                } else {
                    port_text = address
                    sub(/^.*:/, "", port_text)
                    sub(/[^0-9].*$/, "", port_text)
                    port = port_text + 0
                    listen_ip = address
                    sub(/:[^:]*$/, "", listen_ip)
                    gsub(/^\[/, "", listen_ip)
                    gsub(/\]$/, "", listen_ip)
                    if (listen_ip == "" || listen_ip == "0.0.0.0" || listen_ip == "::") listen_ip = "*"
                }
                if (port >= 1 && port <= 65535 && (listen_ip == "*" || listen_ip ~ /^[0-9.]+$/)) {
                    print listen_ip "\t" port
                }
            }
        }
    ' "$HAPROXY_CONFIG" | sort -t $'\t' -k1,1V -k2,2n -u
}

ports_for_ip() {
    local endpoints_file="$1" wanted="$2"
    awk -F '\t' -v wanted="$wanted" \
        '($1 == "*" || $1 == wanted) && !seen[$2]++ { print $2 }' "$endpoints_file" | sort -n
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

ifb_name_for_ip() {
    local ip="$1" digest
    digest="$(printf '%s' "$ip" | sha256sum | awk '{ print substr($1, 1, 8) }')"
    printf 'ktoifb%s\n' "$digest"
}

burst_bytes_for_rate() {
    local rate_mbit="$1" burst
    # Ten milliseconds of traffic keeps high-rate HTB classes accurate without
    # allowing the large bursts that made the old policer erratic.
    burst=$(( rate_mbit * 1250 ))
    (( burst >= 262144 )) || burst=262144
    (( burst <= 16777216 )) || burst=16777216
    printf '%s\n' "$burst"
}

desired_state_signature() {
    local limits_file="$1" endpoints_file="$2" mappings_file="$3"
    {
        printf 'schema=%s\n' "$STATE_SCHEMA"
        printf 'root=%s ifb=%s capacity=%s limited_leaf=fq_codel default_leaf=fq\n' \
            "$ROOT_MAJOR" "$IFB_ROOT_MAJOR" "$SHAPER_CAPACITY_MBIT"
        printf '[limits]\n'
        cat "$limits_file"
        printf '[endpoints]\n'
        cat "$endpoints_file"
        printf '[mappings]\n'
        cat "$mappings_file"
    } | sha256sum | awk '{ print $1 }'
}

saved_state_signature() {
    local state_file="$1"
    awk -F '\t' '$1 == "S" { print $2; exit }' "$state_file" 2>/dev/null || true
}

saved_state_schema() {
    local state_file="$1"
    awk -F '\t' '$1 == "V" { print $2; exit }' "$state_file" 2>/dev/null || true
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

current_root_qdisc() {
    local interface="$1"
    tc qdisc show dev "$interface" 2>/dev/null | awk '
        /(^|[[:space:]])root([[:space:]]|$)/ { print $2 "\t" $3; exit }
    '
}

root_qdisc_is_ours() {
    local interface="$1" kind handle
    IFS=$'\t' read -r kind handle < <(current_root_qdisc "$interface")
    [[ "$kind" == "htb" && "$handle" == "${ROOT_MAJOR}:" ]]
}

root_qdisc_is_replaceable() {
    local interface="$1" kind handle
    IFS=$'\t' read -r kind handle < <(current_root_qdisc "$interface")
    if [[ "$kind" == "htb" && "$handle" == "${ROOT_MAJOR}:" ]]; then
        return 0
    fi
    case "$kind" in
        ""|noqueue|mq|fq|fq_codel|pfifo_fast) return 0 ;;
        *)
            fail "На ${interface} уже настроен сторонний root qdisc ${kind} ${handle}; автоматически заменять его опасно"
            return 1
            ;;
    esac
}

restore_root_qdisc() {
    local interface="$1" original_kind="${2:-none}" current_kind current_handle
    if root_qdisc_is_ours "$interface"; then
        tc qdisc delete dev "$interface" root >> "$LOG_FILE" 2>&1 || true
    fi
    case "$original_kind" in
        ""|none|noqueue) return 0 ;;
        mq|fq|fq_codel|pfifo_fast)
            IFS=$'\t' read -r current_kind current_handle < <(current_root_qdisc "$interface")
            [[ "$current_kind" == "$original_kind" ]] && return 0
            tc qdisc replace dev "$interface" root "$original_kind" >> "$LOG_FILE" 2>&1 || \
                warn "Не удалось вернуть ${original_kind} на ${interface}; интерфейс оставлен с системным qdisc"
            ;;
    esac
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
    tc_logged qdisc add dev "$interface" clsact
}

interface_mtu() {
    local interface="$1" mtu
    mtu="$(cat "/sys/class/net/${interface}/mtu" 2>/dev/null || true)"
    [[ "$mtu" =~ ^[0-9]+$ ]] || mtu=1500
    printf '%s\n' "$mtu"
}

ensure_ifb() {
    local ifb="$1" source_interface="$2" mtu created=0
    if ip link show dev "$ifb" >/dev/null 2>&1; then
        if ! ip -d link show dev "$ifb" 2>/dev/null | grep -qw ifb; then
            fail "Интерфейс ${ifb} уже существует и не является IFB"
            return 1
        fi
    else
        if command -v modprobe >/dev/null 2>&1; then
            modprobe ifb >> "$LOG_FILE" 2>&1 || true
        fi
        ip link add name "$ifb" type ifb >> "$LOG_FILE" 2>&1 || {
            fail "Не удалось создать IFB ${ifb}"
            return 1
        }
        created=1
    fi
    mtu="$(interface_mtu "$source_interface")"
    ip link set dev "$ifb" mtu "$mtu" txqueuelen 10000 up >> "$LOG_FILE" 2>&1 || {
        (( created == 0 )) || ip link delete dev "$ifb" >> "$LOG_FILE" 2>&1 || true
        fail "Не удалось поднять IFB ${ifb}"
        return 1
    }
}

add_fq_codel() {
    local interface="$1" parent="$2" handle="$3"
    tc_logged qdisc replace dev "$interface" parent "$parent" handle "$handle" \
        fq_codel limit 10240 flows 4096 target 5ms interval 100ms quantum 1514
}

add_fq() {
    local interface="$1" parent="$2" handle="$3"
    tc_logged qdisc replace dev "$interface" parent "$parent" handle "$handle" fq
}

setup_ifb_shaper() {
    local ifb="$1" rate="$2" burst
    burst="$(burst_bytes_for_rate "$rate")"
    tc_logged qdisc replace dev "$ifb" root handle "${IFB_ROOT_MAJOR}:" htb default 10 r2q 100
    tc_logged class replace dev "$ifb" parent "${IFB_ROOT_MAJOR}:" \
        classid "${IFB_ROOT_MAJOR}:10" htb rate "${rate}mbit" ceil "${rate}mbit" \
        burst "${burst}b" cburst "${burst}b" quantum 65536
    add_fq_codel "$ifb" "${IFB_ROOT_MAJOR}:10" "${IFB_LEAF_MAJOR}:"
}

setup_egress_root() {
    local interface="$1" state_file="$2" original_kind original_handle capacity_burst
    IFS=$'\t' read -r original_kind original_handle < <(current_root_qdisc "$interface")
    [[ -n "$original_kind" ]] || original_kind=none
    capacity_burst="$(burst_bytes_for_rate "$SHAPER_CAPACITY_MBIT")"

    tc_logged qdisc replace dev "$interface" root handle "${ROOT_MAJOR}:" htb default fff r2q 100
    printf 'R\t%s\t%s\n' "$interface" "$original_kind" >> "$state_file"
    tc_logged class replace dev "$interface" parent "${ROOT_MAJOR}:" \
        classid "${ROOT_MAJOR}:1" htb rate "${SHAPER_CAPACITY_MBIT}mbit" \
        ceil "${SHAPER_CAPACITY_MBIT}mbit" burst "${capacity_burst}b" \
        cburst "${capacity_burst}b" quantum 65536
    tc_logged class replace dev "$interface" parent "${ROOT_MAJOR}:1" \
        classid "${ROOT_MAJOR}:fff" htb rate 1mbit ceil "${SHAPER_CAPACITY_MBIT}mbit" \
        burst 262144b cburst "${capacity_burst}b" prio 7 quantum 65536
    add_fq "$interface" "${ROOT_MAJOR}:fff" "${ROOT_DEFAULT_LEAF_MAJOR}:"
}

setup_egress_class() {
    local interface="$1" classid="$2" leaf_handle="$3" rate="$4" burst
    burst="$(burst_bytes_for_rate "$rate")"
    tc_logged class replace dev "$interface" parent "${ROOT_MAJOR}:1" classid "$classid" \
        htb rate "${rate}mbit" ceil "${rate}mbit" burst "${burst}b" cburst "${burst}b" \
        prio 1 quantum 65536
    add_fq_codel "$interface" "$classid" "$leaf_handle"
}

delete_filter_quiet() {
    local interface="$1" direction="$2" pref="$3"
    case "$direction" in
        root)
            tc filter delete dev "$interface" parent "${ROOT_MAJOR}:" protocol ip pref "$pref" \
                >> "$LOG_FILE" 2>&1 || true
            ;;
        ingress|egress)
            tc filter delete dev "$interface" "$direction" protocol ip pref "$pref" \
                >> "$LOG_FILE" 2>&1 || true
            ;;
    esac
}

add_ingress_redirect_filter() {
    local interface="$1" pref="$2" ip="$3" port="$4" ifb="$5" flower_error u32_error
    if [[ "${TC_FILTER_MODE:-}" != "u32" ]]; then
        if tc_logged filter add dev "$interface" ingress protocol ip pref "$pref" \
            flower skip_hw ip_proto tcp dst_ip "$ip" dst_port "$port" \
            action mirred egress redirect dev "$ifb"; then
            TC_FILTER_MODE="flower"
            return 0
        fi
        flower_error="$(tc_error_summary)"
        TC_FILTER_MODE="u32"
        delete_filter_quiet "$interface" ingress "$pref"
    else
        flower_error="пропущен после предыдущей ошибки flower"
    fi
    if tc_logged filter add dev "$interface" ingress protocol ip pref "$pref" u32 \
        match ip protocol 6 0xff match ip dst "${ip}/32" match ip dport "$port" 0xffff \
        action mirred egress redirect dev "$ifb"; then
        TC_FILTER_FALLBACK_USED=1
        return 0
    fi
    u32_error="$(tc_error_summary)"
    delete_filter_quiet "$interface" ingress "$pref"
    TC_LAST_ERROR="flower: ${flower_error}; u32: ${u32_error}"
    return 1
}

add_egress_class_filter() {
    local interface="$1" pref="$2" ip="$3" port="$4" classid="$5" flower_error u32_error
    if [[ "${TC_FILTER_MODE:-}" != "u32" ]]; then
        if tc_logged filter add dev "$interface" parent "${ROOT_MAJOR}:" protocol ip pref "$pref" \
            flower skip_hw ip_proto tcp src_ip "$ip" src_port "$port" classid "$classid"; then
            TC_FILTER_MODE="flower"
            return 0
        fi
        flower_error="$(tc_error_summary)"
        TC_FILTER_MODE="u32"
        delete_filter_quiet "$interface" root "$pref"
    else
        flower_error="пропущен после предыдущей ошибки flower"
    fi
    if tc_logged filter add dev "$interface" parent "${ROOT_MAJOR}:" protocol ip pref "$pref" u32 \
        match ip protocol 6 0xff match ip src "${ip}/32" match ip sport "$port" 0xffff \
        flowid "$classid"; then
        TC_FILTER_FALLBACK_USED=1
        return 0
    fi
    u32_error="$(tc_error_summary)"
    delete_filter_quiet "$interface" root "$pref"
    TC_LAST_ERROR="flower: ${flower_error}; u32: ${u32_error}"
    return 1
}

cleanup_state_file() {
    local state_file="$1" kind interface direction pref extra original_kind ifb action_index
    [[ -s "$state_file" ]] || return 0

    while IFS=$'\t' read -r kind interface direction pref extra; do
        [[ "$kind" == "F" ]] || continue
        delete_filter_quiet "$interface" "$direction" "$pref"
    done < "$state_file"
    while IFS=$'\t' read -r kind action_index _; do
        [[ "$kind" == "A" && "$action_index" =~ ^[0-9]+$ ]] || continue
        tc actions delete action police index "$action_index" >> "$LOG_FILE" 2>&1 || true
    done < "$state_file"
    while IFS=$'\t' read -r kind interface original_kind _; do
        [[ "$kind" == "R" ]] || continue
        restore_root_qdisc "$interface" "$original_kind"
    done < "$state_file"
    while IFS=$'\t' read -r kind ifb _; do
        [[ "$kind" == "I" ]] || continue
        tc qdisc delete dev "$ifb" root >> "$LOG_FILE" 2>&1 || true
        ip link delete dev "$ifb" >> "$LOG_FILE" 2>&1 || true
    done < "$state_file"
}

cleanup_orphaned_legacy_tc() {
    local interface direction pref action_index
    local -A seen_interfaces=()

    for interface in "$@"; do
        [[ -n "$interface" && -z "${seen_interfaces[$interface]+x}" ]] || continue
        seen_interfaces[$interface]=1
        for direction in ingress egress; do
            while read -r pref; do
                [[ "$pref" =~ ^[0-9]+$ ]] || continue
                if (( pref > PREF_BASE && pref <= 65000 )); then
                    delete_filter_quiet "$interface" "$direction" "$pref"
                fi
            done < <(tc filter show dev "$interface" "$direction" protocol ip 2>/dev/null | \
                awk '{ for (i = 1; i <= NF; i++) if ($i == "pref") print $(i + 1) }' | sort -nu)
        done
    done
    while read -r action_index; do
        [[ "$action_index" =~ ^[0-9]+$ ]] || continue
        if (( action_index > LEGACY_ACTION_BASE && action_index < LEGACY_ACTION_BASE + 100000 )); then
            tc actions delete action police index "$action_index" >> "$LOG_FILE" 2>&1 || true
        fi
    done < <(tc actions ls action police 2>/dev/null | \
        awk '{ for (i = 1; i <= NF; i++) if ($i == "index") print $(i + 1) }' | sort -nu)
}

cleanup_orphaned_managed_shapers() {
    local interface ifb
    local -A seen_interfaces=()
    for interface in "$@"; do
        [[ -n "$interface" && -z "${seen_interfaces[$interface]+x}" ]] || continue
        seen_interfaces[$interface]=1
        if root_qdisc_is_ours "$interface"; then
            tc qdisc delete dev "$interface" root >> "$LOG_FILE" 2>&1 || true
        fi
    done
    while read -r ifb; do
        [[ "$ifb" =~ ^ktoifb[0-9a-f]{8}$ ]] || continue
        tc qdisc delete dev "$ifb" root >> "$LOG_FILE" 2>&1 || true
        ip link delete dev "$ifb" >> "$LOG_FILE" 2>&1 || true
    done < <(ip -o link show type ifb 2>/dev/null | awk -F ': ' '{ name=$2; sub(/@.*/, "", name); print name }')
}

preflight_shaper() {
    local probe_ifb attempt rc=0
    for attempt in 0 1 2 3 4; do
        probe_ifb="ktotc$(( ($$ + attempt) % 100000000 ))"
        probe_ifb="${probe_ifb:0:15}"
        ip link show dev "$probe_ifb" >/dev/null 2>&1 || break
        probe_ifb=""
    done
    [[ -n "$probe_ifb" ]] || {
        fail "Не удалось подобрать свободное имя для IFB preflight"
        return 1
    }
    command -v modprobe >/dev/null 2>&1 && modprobe ifb >> "$LOG_FILE" 2>&1 || true
    ip link add name "$probe_ifb" type ifb >> "$LOG_FILE" 2>&1 || rc=1
    if (( rc == 0 )); then
        ip link set dev "$probe_ifb" up >> "$LOG_FILE" 2>&1 || rc=1
    fi
    if (( rc == 0 )); then
        tc qdisc add dev "$probe_ifb" root handle "${IFB_ROOT_MAJOR}:" htb default 10 >> "$LOG_FILE" 2>&1 || rc=1
        tc class add dev "$probe_ifb" parent "${IFB_ROOT_MAJOR}:" classid "${IFB_ROOT_MAJOR}:10" \
            htb rate 10mbit ceil 10mbit >> "$LOG_FILE" 2>&1 || rc=1
        tc qdisc add dev "$probe_ifb" parent "${IFB_ROOT_MAJOR}:10" handle "${IFB_LEAF_MAJOR}:" \
            fq_codel >> "$LOG_FILE" 2>&1 || rc=1
    fi
    tc qdisc delete dev "$probe_ifb" root >> "$LOG_FILE" 2>&1 || true
    ip link delete dev "$probe_ifb" >> "$LOG_FILE" 2>&1 || true
    if (( rc != 0 )); then
        fail "Kernel не поддерживает требуемую связку IFB + HTB + fq_codel"
        return 1
    fi
}

state_filter_snapshot() {
    local interface="$1" direction="$2"
    case "$direction" in
        root) tc filter show dev "$interface" parent "${ROOT_MAJOR}:" protocol ip 2>/dev/null || true ;;
        ingress|egress) tc filter show dev "$interface" "$direction" protocol ip 2>/dev/null || true ;;
    esac
}

active_filter_count() {
    (
    local kind interface direction pref extra key snapshot_file count=0 snapshot_index=0
    local snapshot_dir
    local -A snapshot_files=()
    [[ -s "$STATE_FILE" ]] || {
        printf '0\n'
        return 0
    }
    snapshot_dir="$(mktemp -d)"
    trap 'rm -rf "$snapshot_dir"' EXIT
    while IFS=$'\t' read -r kind interface direction pref extra; do
        [[ "$kind" == "F" && "$pref" =~ ^[0-9]+$ ]] || continue
        key="${interface}|${direction}"
        snapshot_file="${snapshot_files[$key]:-}"
        if [[ -z "$snapshot_file" ]]; then
            snapshot_index=$(( snapshot_index + 1 ))
            snapshot_file="${snapshot_dir}/${snapshot_index}"
            state_filter_snapshot "$interface" "$direction" > "$snapshot_file"
            snapshot_files[$key]="$snapshot_file"
        fi
        if grep -Eq "(^|[[:space:]])pref ${pref}([[:space:]]|$)" "$snapshot_file"; then
            count=$(( count + 1 ))
        fi
    done < "$STATE_FILE"
    printf '%s\n' "$count"
    )
}

state_layout_active() {
    local kind ip rate interface ifb classid ports_csv original_kind extra
    while IFS=$'\t' read -r kind interface original_kind extra; do
        [[ "$kind" == "R" ]] || continue
        root_qdisc_is_ours "$interface" || return 1
    done < "$STATE_FILE"
    while IFS=$'\t' read -r kind ifb extra; do
        [[ "$kind" == "I" ]] || continue
        ip link show dev "$ifb" >/dev/null 2>&1 || return 1
        tc qdisc show dev "$ifb" 2>/dev/null | \
            grep -Eq "^qdisc htb ${IFB_ROOT_MAJOR}: root" || return 1
    done < "$STATE_FILE"
    while IFS=$'\t' read -r kind ip rate interface ifb classid ports_csv; do
        [[ "$kind" == "L" ]] || continue
        tc class show dev "$ifb" 2>/dev/null | \
            grep -Eq "class htb ${IFB_ROOT_MAJOR}:10([[:space:]]|$)" || return 1
        tc class show dev "$interface" 2>/dev/null | \
            grep -Eq "class htb ${classid}([[:space:]]|$)" || return 1
    done < "$STATE_FILE"
    local filters expected
    filters="$(active_filter_count)"
    expected="$(awk -F '\t' '$1 == "F" { count++ } END { print count + 0 }' "$STATE_FILE")"
    [[ "$filters" == "$expected" ]]
}

clear_limits() {
    local -a interfaces=()
    cleanup_state_file "$PENDING_STATE"
    cleanup_state_file "$STATE_FILE"
    mapfile -t interfaces < <(ip -4 -o address show scope global 2>/dev/null | \
        awk '{ interface=$2; sub(/@.*/, "", interface); if (!seen[interface]++) print interface }')
    cleanup_orphaned_legacy_tc "${interfaces[@]}"
    cleanup_orphaned_managed_shapers "${interfaces[@]}"
    rm -f "$STATE_FILE" "$PENDING_STATE" "$READY_FILE" "${READY_FILE}.pending"
    ok "Kernel-shaper входных IP HAProxy очищен"
}

apply_limits() {
    (
    local limits_file endpoints_file mappings_file next_state ready_tmp
    local ip rate interface ifb ports_csv class_minor classid leaf_major leaf_handle port
    local desired_signature current_signature ready_signature state_filters expected_filters
    local limit_count=0 filter_count=0 pref="$PREF_BASE" committed=0 index=0
    local TC_FILTER_FALLBACK_USED=0 TC_FILTER_MODE=""
    local -a interfaces=() ports=()
    local -A seen_interfaces=()

    limits_file="$(mktemp)"
    endpoints_file="$(mktemp)"
    mappings_file="$(mktemp)"
    next_state="$PENDING_STATE"
    ready_tmp="${READY_FILE}.pending"
    trap 'rc=$?; trap - EXIT; if (( committed == 0 )); then cleanup_state_file "$next_state"; fi; rm -f "$limits_file" "$endpoints_file" "$mappings_file" "$next_state" "$ready_tmp"; exit "$rc"' EXIT

    load_limits > "$limits_file" || return 1
    if [[ ! -s "$limits_file" ]]; then
        clear_limits
        return 0
    fi
    if ! haproxy_endpoints > "$endpoints_file" || [[ ! -s "$endpoints_file" ]]; then
        fail "Не удалось получить frontend IP:порты из ${HAPROXY_CONFIG}"
        return 1
    fi
    if ! validate_rate_mbit "$SHAPER_CAPACITY_MBIT"; then
        fail "Некорректный внутренний предел shaper: ${SHAPER_CAPACITY_MBIT} Mbit/s"
        return 1
    fi

    while IFS=$'\t' read -r ip rate; do
        interface="$(interface_for_ipv4 "$ip")"
        if [[ -z "$interface" ]]; then
            fail "Входной IP ${ip} не найден на локальных интерфейсах"
            return 1
        fi
        mapfile -t ports < <(ports_for_ip "$endpoints_file" "$ip")
        if (( ${#ports[@]} == 0 )); then
            fail "Для ${ip} нет точного или wildcard HAProxy listener"
            return 1
        fi
        ifb="$(ifb_name_for_ip "$ip")"
        index=$(( index + 1 ))
        class_minor="$(printf '%x' "$(( 0x100 + index ))")"
        classid="${ROOT_MAJOR}:${class_minor}"
        leaf_major="$(printf '%x' "$(( 0x8000 + index ))")"
        leaf_handle="${leaf_major}:"
        ports_csv="$(printf '%s\n' "${ports[@]}" | paste -sd, -)"
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$ip" "$rate" "$interface" "$ifb" "$classid" "$leaf_handle" "$ports_csv" >> "$mappings_file"
        if [[ -z "${seen_interfaces[$interface]+x}" ]]; then
            seen_interfaces[$interface]=1
            interfaces+=("$interface")
        fi
        limit_count=$(( limit_count + 1 ))
    done < "$limits_file"

    desired_signature="$(desired_state_signature "$limits_file" "$endpoints_file" "$mappings_file")"
    current_signature="$(saved_state_signature "$STATE_FILE")"
    ready_signature="$(cat "$READY_FILE" 2>/dev/null || true)"
    state_filters="$(awk -F '\t' '$1 == "F" { count++ } END { print count + 0 }' "$STATE_FILE" 2>/dev/null || printf '0')"
    expected_filters=0
    while IFS=$'\t' read -r ip rate interface ifb classid leaf_handle ports_csv; do
        IFS=',' read -r -a ports <<< "$ports_csv"
        expected_filters=$(( expected_filters + ${#ports[@]} * 2 ))
    done < "$mappings_file"
    if [[ "$(saved_state_schema "$STATE_FILE")" == "$STATE_SCHEMA" &&
          -n "$desired_signature" && "$current_signature" == "$desired_signature" &&
          "$ready_signature" == "$desired_signature" && "$state_filters" == "$expected_filters" ]] &&
        state_layout_active; then
        committed=1
        ok "Shaper HAProxy уже актуален: ${limit_count} IP, ${expected_filters} точных фильтров"
        return 0
    fi

    preflight_shaper || return 1
    for interface in "${interfaces[@]}"; do
        root_qdisc_is_replaceable "$interface" || return 1
        ensure_clsact "$interface" || return 1
    done

    cleanup_state_file "$next_state"
    cleanup_state_file "$STATE_FILE"
    rm -f "$next_state" "$READY_FILE" "$ready_tmp"
    cleanup_orphaned_legacy_tc "${interfaces[@]}"
    cleanup_orphaned_managed_shapers "${interfaces[@]}"
    : > "$next_state"
    chmod 0600 "$next_state" 2>/dev/null || true
    printf 'S\t%s\nV\t%s\n' "$desired_signature" "$STATE_SCHEMA" >> "$next_state"

    # Prepare every IFB before redirecting a single live packet into it.
    while IFS=$'\t' read -r ip rate interface ifb classid leaf_handle ports_csv; do
        ensure_ifb "$ifb" "$interface" || return 1
        printf 'I\t%s\n' "$ifb" >> "$next_state"
        setup_ifb_shaper "$ifb" "$rate" || {
            fail "Не удалось подготовить RX shaper ${ip} через ${ifb}: $(tc_error_summary)"
            return 1
        }
    done < "$mappings_file"

    for interface in "${interfaces[@]}"; do
        setup_egress_root "$interface" "$next_state" || {
            fail "Не удалось подготовить TX shaper на ${interface}: $(tc_error_summary)"
            return 1
        }
    done
    while IFS=$'\t' read -r ip rate interface ifb classid leaf_handle ports_csv; do
        setup_egress_class "$interface" "$classid" "$leaf_handle" "$rate" || {
            fail "Не удалось подготовить TX-класс ${ip}: $(tc_error_summary)"
            return 1
        }
        printf 'L\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$ip" "$rate" "$interface" "$ifb" "$classid" "$ports_csv" >> "$next_state"
    done < "$mappings_file"

    while IFS=$'\t' read -r ip rate interface ifb classid leaf_handle ports_csv; do
        IFS=',' read -r -a ports <<< "$ports_csv"
        for port in "${ports[@]}"; do
            pref=$(( pref + 1 ))
            (( pref <= 65000 )) || {
                fail "Слишком много HAProxy-фильтров"
                return 1
            }
            if ! add_ingress_redirect_filter "$interface" "$pref" "$ip" "$port" "$ifb"; then
                fail "Не удалось включить плавный RX-лимит ${ip}:${port}: $(tc_error_summary)"
                return 1
            fi
            printf 'F\t%s\tingress\t%s\n' "$interface" "$pref" >> "$next_state"

            pref=$(( pref + 1 ))
            if ! add_egress_class_filter "$interface" "$pref" "$ip" "$port" "$classid"; then
                fail "Не удалось включить плавный TX-лимит ${ip}:${port}: $(tc_error_summary)"
                return 1
            fi
            printf 'F\t%s\troot\t%s\n' "$interface" "$pref" >> "$next_state"
            filter_count=$(( filter_count + 2 ))
        done
    done < "$mappings_file"

    install -m 0600 "$next_state" "$STATE_FILE"
    printf '%s\n' "$desired_signature" > "$ready_tmp"
    install -m 0600 "$ready_tmp" "$READY_FILE"
    committed=1
    ok "Плавных лимитов HAProxy: ${limit_count} IP"
    ok "Точных IP:порт фильтров: ${filter_count}"
    ok "RX: IFB + HTB + fq_codel; TX: HTB + fq_codel"
    ok "Для каждого IP доступны отдельные полные лимиты RX и TX"
    if (( TC_FILTER_FALLBACK_USED == 1 )); then
        warn "На этой системе применён совместимый classifier u32 вместо flower"
    fi
    )
}

show_status() {
    (
    local limits_file ip rate interface ifb classid ports_csv kind saved_schema filters expected overall="РАБОТАЕТ"
    local rx_status tx_status
    limits_file="$(mktemp)"
    trap 'rm -f "$limits_file"' EXIT
    load_limits > "$limits_file" || return 1

    printf '[ ПЛАВНЫЕ ЛИМИТЫ ВХОДНЫХ IP HAPROXY ]\n'
    printf 'Build: %s\n' "$HAPROXY_BANDWIDTH_BUILD"
    printf 'Режим: RX IFB/HTB/fq_codel; TX HTB/fq_codel\n'
    if [[ ! -s "$limits_file" ]]; then
        printf 'Итог: ВЫКЛЮЧЕНО\n'
        printf 'Настроенных IP нет.\n'
        return 0
    fi
    if [[ ! -s "$STATE_FILE" ]]; then
        while IFS=$'\t' read -r ip rate; do
            interface="$(interface_for_ipv4 "$ip")"
            printf '%s (%s): настроено %s Mbit/s RX + TX, но kernel-state отсутствует\n' \
                "$ip" "${interface:-нет интерфейса}" "$rate"
        done < "$limits_file"
        printf 'Итог: ТРЕБУЕТ ПЕРЕПРИМЕНЕНИЯ\n'
        return 0
    fi
    saved_schema="$(saved_state_schema "$STATE_FILE")"
    if [[ "$saved_schema" != "$STATE_SCHEMA" ]]; then
        overall="ТРЕБУЕТ ПЕРЕПРИМЕНЕНИЯ"
    fi

    while IFS=$'\t' read -r kind ip rate interface ifb classid ports_csv; do
        [[ "$kind" == "L" ]] || continue
        rx_status="НЕТ"
        tx_status="НЕТ"
        if ip link show dev "$ifb" >/dev/null 2>&1 &&
            tc qdisc show dev "$ifb" 2>/dev/null | grep -Eq "^qdisc htb ${IFB_ROOT_MAJOR}: root"; then
            rx_status="OK"
        else
            overall="ОШИБКА"
        fi
        if root_qdisc_is_ours "$interface" &&
            tc class show dev "$interface" 2>/dev/null | grep -Eq "class htb ${classid}([[:space:]]|$)"; then
            tx_status="OK"
        else
            overall="ОШИБКА"
        fi
        printf '%s (%s): %s Mbit/s RX + %s Mbit/s TX\n' "$ip" "$interface" "$rate" "$rate"
        printf '  Порты: %s\n' "$ports_csv"
        printf '  RX очередь: %s (%s)\n' "$rx_status" "$ifb"
        printf '  TX очередь: %s (%s)\n' "$tx_status" "$classid"
        if [[ "$rx_status" == "OK" ]]; then
            tc -s qdisc show dev "$ifb" 2>/dev/null | awk '/^qdisc fq_codel / { print "    " $0; getline; print "    " $0; exit }'
        fi
        if [[ "$tx_status" == "OK" ]]; then
            tc -s class show dev "$interface" classid "$classid" 2>/dev/null | awk '/^class htb / { print "    " $0; getline; print "    " $0; exit }'
        fi
    done < "$STATE_FILE"

    filters="$(active_filter_count)"
    expected="$(awk -F '\t' '$1 == "F" { count++ } END { print count + 0 }' "$STATE_FILE" 2>/dev/null || printf '0')"
    if (( filters != expected )); then
        overall="ОШИБКА"
    fi
    printf 'Фильтров: %s/%s\n' "$filters" "$expected"
    printf 'Итог: %s\n' "$overall"
    printf 'Превышение скорости ставится в управляемую очередь; старый police/drop не используется.\n'
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
