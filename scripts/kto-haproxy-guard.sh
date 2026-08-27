#!/usr/bin/env bash
# shellcheck shell=bash

set -Eeuo pipefail
IFS=$'\n\t'

HAPROXY_GUARD_BUILD="v343"
CONFIG="${KTO_HAPROXY_CONFIG:-/etc/haproxy/haproxy.cfg}"
SERVICE="${KTO_HAPROXY_SERVICE:-haproxy.service}"
TIMER="${KTO_HAPROXY_GUARD_TIMER:-kto-haproxy-guard.timer}"
FIREWALL_MANAGER="${KTO_HAPROXY_FIREWALL_MANAGER:-/usr/local/sbin/kto-haproxy-firewall}"
BACKUP_DIR="${KTO_HAPROXY_BACKUP_DIR:-/var/backups/kto-haproxy}"
ADDITIONAL_ROUTE_SERVICE="${KTO_ADDITIONAL_IP_ROUTE_SERVICE:-kto-additional-ip-routes.service}"
STATE_DIR="${KTO_HAPROXY_GUARD_STATE_DIR:-/run/kto-haproxy-guard}"
LOCK_FILE="${KTO_HAPROXY_GUARD_LOCK_FILE:-/run/lock/kto-haproxy-guard.lock}"
CONFIG_GRACE_SEC="${KTO_HAPROXY_GUARD_CONFIG_GRACE_SEC:-20}"
REPAIR_COOLDOWN_SEC="${KTO_HAPROXY_GUARD_COOLDOWN_SEC:-120}"
FIREWALL_INTERVAL_SEC="${KTO_HAPROXY_GUARD_FIREWALL_INTERVAL_SEC:-300}"
ROUTE_REPAIR_INTERVAL_SEC="${KTO_HAPROXY_GUARD_ROUTE_REPAIR_INTERVAL_SEC:-60}"
INVALID_THRESHOLD="${KTO_HAPROXY_GUARD_INVALID_THRESHOLD:-2}"
LISTENER_THRESHOLD="${KTO_HAPROXY_GUARD_LISTENER_THRESHOLD:-2}"

CHECK_OUTPUT=""

log() {
    printf '[kto-haproxy-guard] %s %s\n' "$(date -Is)" "$*"
}

normalize_number() {
    local value="$1" fallback="$2" minimum="$3" maximum="$4"
    [[ "$value" =~ ^[0-9]+$ ]] || value="$fallback"
    value=$((10#$value))
    (( value >= minimum && value <= maximum )) || value="$fallback"
    printf '%s\n' "$value"
}

prepare_runtime() {
    local action="${1:-repair}"
    [[ ${EUID:-$(id -u)} -eq 0 ]] || {
        echo "kto-haproxy-guard: run as root" >&2
        return 1
    }
    mkdir -p "$STATE_DIR" "$(dirname "$LOCK_FILE")"
    chmod 0700 "$STATE_DIR" 2>/dev/null || true
    [[ "$action" == "repair" || "$action" == "heal" || "$action" == "run" ]] || return 0
    exec 9>"$LOCK_FILE"
    if command -v flock >/dev/null 2>&1; then
        flock -n 9 || exit 0
    fi
}

state_number() {
    local name="$1" value="0"
    [[ -r "${STATE_DIR}/${name}" ]] && read -r value < "${STATE_DIR}/${name}" || true
    [[ "$value" =~ ^[0-9]+$ ]] || value=0
    printf '%s\n' "$value"
}

set_state_number() {
    local name="$1" value="$2" temporary
    temporary="$(mktemp "${STATE_DIR}/.${name}.XXXXXX")"
    printf '%s\n' "$value" > "$temporary"
    mv -f "$temporary" "${STATE_DIR}/${name}"
}

set_state_text() {
    local name="$1" value="$2" temporary
    temporary="$(mktemp "${STATE_DIR}/.${name}.XXXXXX")"
    printf '%s\n' "$value" > "$temporary"
    mv -f "$temporary" "${STATE_DIR}/${name}"
}

record_action() {
    local message="$1"
    set_state_number last_repair "$(date +%s)"
    set_state_text last_action "$(date -Is) | ${message}"
    log "$message"
}

configured_endpoints() {
    awk '
        function emit(endpoint, port, host) {
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
            if (host == "" || host == "0.0.0.0" || host == "::") host = "*"
            if (port ~ /^[0-9]+$/ && port + 0 >= 1 && port + 0 <= 65535) {
                print host "|" port + 0
            }
        }
        $1 == "frontend" { section = "frontend"; next }
        $1 == "global" || $1 == "defaults" || $1 == "backend" || $1 == "listen" {
            section = $1
            next
        }
        (section == "frontend" || section == "listen") && $1 == "bind" {
            count = split($2, endpoints, ",")
            for (i = 1; i <= count; i++) emit(endpoints[i])
        }
    ' "$CONFIG" 2>/dev/null | LC_ALL=C sort -u
}

configured_source_ips() {
    awk '
        $1 == "backend" { section = "backend"; next }
        $1 == "global" || $1 == "defaults" || $1 == "frontend" || $1 == "listen" {
            section = $1
            next
        }
        (section == "backend" || section == "listen") && $1 == "server" {
            for (i = 1; i < NF; i++) {
                if ($i == "source" && $(i + 1) ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
                    print $(i + 1)
                }
            }
        }
    ' "$CONFIG" 2>/dev/null | LC_ALL=C sort -u
}

configured_required_ips() {
    {
        configured_endpoints | awk -F '|' '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { print $1 }'
        configured_source_ips
    } | LC_ALL=C sort -u
}

local_ipv4s() {
    ip -4 -o address show scope global 2>/dev/null |
        awk '{split($4, value, "/"); print value[1]}' | LC_ALL=C sort -u
}

missing_required_ips() {
    local local_file
    local_file="$(mktemp)"
    local_ipv4s > "$local_file"
    configured_required_ips | while IFS= read -r address; do
        [[ -n "$address" ]] || continue
        grep -Fqx "$address" "$local_file" || printf '%s\n' "$address"
    done
    rm -f "$local_file"
}

active_listener_endpoints() {
    ss -H -ltnp 2>/dev/null | awk '
        $0 !~ /haproxy/ { next }
        {
            endpoint = $4
            port = endpoint
            sub(/^.*:/, "", port)
            host = endpoint
            sub(/:[^:]*$/, "", host)
            gsub(/^\[/, "", host)
            gsub(/\]$/, "", host)
            if (host == "" || host == "0.0.0.0" || host == "::") host = "*"
            if (port ~ /^[0-9]+$/) print host "|" port + 0
        }
    ' | LC_ALL=C sort -u
}

missing_listeners() {
    local active_file
    active_file="$(mktemp)"
    active_listener_endpoints > "$active_file"
    configured_endpoints | while IFS= read -r endpoint; do
        [[ -n "$endpoint" ]] || continue
        grep -Fqx "$endpoint" "$active_file" || printf '%s\n' "${endpoint/|/:}"
    done
    rm -f "$active_file"
}

service_active() {
    timeout 5 systemctl is-active --quiet "$SERVICE" 2>/dev/null
}

config_valid() {
    local output rc=0
    output="$(mktemp)"
    if timeout 10 haproxy -c -f "$CONFIG" > "$output" 2>&1; then
        CHECK_OUTPUT="Configuration file is valid"
        rm -f "$output"
        return 0
    else
        rc=$?
    fi
    CHECK_OUTPUT="$(tail -n 8 "$output" 2>/dev/null || true)"
    rm -f "$output"
    return "$rc"
}

config_is_recent() {
    local modified now age
    modified="$(stat -c %Y "$CONFIG" 2>/dev/null || printf '0')"
    [[ "$modified" =~ ^[0-9]+$ ]] || return 1
    now="$(date +%s)"
    age=$(( now - modified ))
    (( age >= 0 && age < CONFIG_GRACE_SEC ))
}

cooldown_ready() {
    local last now
    last="$(state_number last_repair)"
    now="$(date +%s)"
    (( now - last >= REPAIR_COOLDOWN_SEC ))
}

ensure_nonlocal_bind() {
    [[ "$(sysctl -n net.ipv4.ip_nonlocal_bind 2>/dev/null || true)" == "1" ]] && return 0
    sysctl -w net.ipv4.ip_nonlocal_bind=1 >/dev/null
    log "enabled net.ipv4.ip_nonlocal_bind=1"
}

trigger_additional_route_repair() {
    local last now
    systemctl cat "$ADDITIONAL_ROUTE_SERVICE" >/dev/null 2>&1 || return 0
    last="$(state_number last_route_repair)"
    now="$(date +%s)"
    (( now - last >= ROUTE_REPAIR_INTERVAL_SEC )) || return 0
    set_state_number last_route_repair "$now"
    timeout 5 systemctl start --no-block "$ADDITIONAL_ROUTE_SERVICE" >/dev/null 2>&1 || true
}

valid_backup() {
    local backup="$1" checksum="${1}.sha256" expected actual
    [[ -s "$backup" && -s "$checksum" ]] || return 1
    expected="$(awk 'NR == 1 { print $1; exit }' "$checksum" 2>/dev/null || true)"
    actual="$(sha256sum "$backup" 2>/dev/null | awk '{print $1}' || true)"
    [[ "$expected" =~ ^[a-fA-F0-9]{64}$ && "$actual" == "$expected" ]] || return 1
    timeout 10 haproxy -c -f "$backup" >/dev/null 2>&1
}

restore_latest_valid_backup() {
    local backup failed_copy timestamp
    [[ -d "$BACKUP_DIR" ]] || return 1
    while IFS= read -r backup; do
        [[ -n "$backup" ]] || continue
        valid_backup "$backup" || continue
        timestamp="$(date -u +%Y%m%d-%H%M%S)"
        failed_copy="${CONFIG}.guard-failed-${timestamp}"
        cp -a "$CONFIG" "$failed_copy" 2>/dev/null || true
        install -m 0644 "$backup" "$CONFIG"
        timeout 10 haproxy -c -f "$CONFIG" >/dev/null 2>&1 || return 1
        record_action "restored verified config backup $(basename "$backup"); failed config: ${failed_copy}"
        return 0
    done < <(
        find "$BACKUP_DIR" -maxdepth 1 -type f -name 'haproxy-*.cfg' \
            -printf '%T@\t%p\n' 2>/dev/null | sort -t $'\t' -k1,1nr | cut -f2-
    )
    return 1
}

start_or_restart_service() {
    local action="$1" missing output rc=0
    timeout 8 systemctl reset-failed "$SERVICE" >/dev/null 2>&1 || true
    output="$(timeout 20 systemctl "$action" "$SERVICE" 2>&1)" || rc=$?
    if (( rc != 0 )); then
        record_failure "${action} failed with rc=${rc}" "$output"
        return 1
    fi
    sleep 1
    if ! service_active; then
        record_failure "${action} returned success, but service is not active" "$output"
        return 1
    fi
    missing="$(missing_listeners)"
    if [[ -n "$missing" ]]; then
        record_failure "${action} left missing listeners: ${missing//$'\n'/, }" "$output"
        return 1
    fi
    rm -f "${STATE_DIR}/last_error"
    record_action "HAProxy recovered via ${action}"
}

configured_listener_owners() {
    local ports_file line endpoint port
    ports_file="$(mktemp)"
    configured_endpoints | awk -F '|' '{ print $2 }' | LC_ALL=C sort -nu > "$ports_file"
    while IFS= read -r line; do
        endpoint="$(awk '{ print $4 }' <<< "$line")"
        port="${endpoint##*:}"
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        grep -Fqx "$port" "$ports_file" || continue
        printf '%s\n' "$line"
    done < <(ss -H -ltnp 2>/dev/null || true)
    rm -f "$ports_file"
}

record_failure() {
    local message="$1" command_output="${2:-}" context
    context="$({
        printf '%s\n' "$message"
        [[ -z "$command_output" ]] || printf '%s\n' "$command_output"
        printf '%s\n' '-- configured listener owners --'
        configured_listener_owners || true
        if command -v journalctl >/dev/null 2>&1; then
            printf '%s\n' '-- recent HAProxy journal --'
            timeout 6 journalctl -u "$SERVICE" -n 12 --no-pager -o cat 2>/dev/null || true
        fi
    } | tail -n 32)"
    set_state_text last_error "$(date -Is) | ${context}"
    record_action "$message"
}

repair_firewall_if_due() {
    local last now output rc=0
    [[ -x "$FIREWALL_MANAGER" ]] || return 0
    last="$(state_number last_firewall_check)"
    now="$(date +%s)"
    (( now - last >= FIREWALL_INTERVAL_SEC )) || return 0
    output="$(timeout 20 "$FIREWALL_MANAGER" 2>&1)" || rc=$?
    set_state_number last_firewall_check "$now"
    if [[ -n "$output" ]]; then
        log "firewall: ${output//$'\n'/; }"
    fi
    (( rc == 0 )) || log "firewall repair failed with rc=${rc}"
    return 0
}

report_status() {
    local config_status service_status missing_ips missing_ips_label missing missing_count timer_status nonlocal last_action last_error
    if [[ ! -s "$CONFIG" ]]; then
        config_status="missing"
    elif config_valid; then
        config_status="valid"
    else
        config_status="invalid"
    fi
    if service_active; then service_status="active"; else service_status="inactive"; fi
    missing_ips="$(missing_required_ips 2>/dev/null || true)"
    missing_ips_label="${missing_ips//$'\n'/, }"
    [[ -n "$missing_ips_label" ]] || missing_ips_label="-"
    missing="$(missing_listeners 2>/dev/null || true)"
    missing_count="$(awk 'NF { count++ } END { print count + 0 }' <<< "$missing")"
    timer_status="$(systemctl is-active "$TIMER" 2>/dev/null || true)"
    nonlocal="$(sysctl -n net.ipv4.ip_nonlocal_bind 2>/dev/null || printf '?')"
    last_action="$(cat "${STATE_DIR}/last_action" 2>/dev/null || printf '-')"
    last_error="$(cat "${STATE_DIR}/last_error" 2>/dev/null || true)"

    printf 'kto HAProxy guard %s\n' "$HAPROXY_GUARD_BUILD"
    printf 'Config: %s\n' "$config_status"
    printf 'Service: %s\n' "$service_status"
    printf 'Timer: %s\n' "${timer_status:-inactive}"
    printf 'ip_nonlocal_bind: %s\n' "$nonlocal"
    printf 'Missing route IPs: %s\n' "$missing_ips_label"
    printf 'Missing listeners: %s\n' "$missing_count"
    [[ -z "$missing" ]] || printf '  %s\n' "${missing//$'\n'/$'\n  '}"
    printf 'Last action: %s\n' "$last_action"
    if [[ -n "$last_error" ]]; then
        printf 'Last failure:\n  %s\n' "${last_error//$'\n'/$'\n  '}"
    fi
}

check_health() {
    local failed=0
    [[ -s "$CONFIG" ]] || return 1
    config_valid || failed=1
    service_active || failed=1
    [[ -z "$(missing_listeners)" ]] || failed=1
    report_status
    return "$failed"
}

repair_health() {
    local invalid_count listener_count missing_ips missing previous_missing

    [[ -s "$CONFIG" ]] || return 0
    config_is_recent && return 0

    if ! config_valid; then
        invalid_count=$(( $(state_number invalid_config_count) + 1 ))
        set_state_number invalid_config_count "$invalid_count"
        if service_active; then
            log "config invalid, but loaded service is active; automatic rollback skipped"
            return 0
        fi
        if (( invalid_count < INVALID_THRESHOLD )) || ! cooldown_ready; then
            log "config invalid (${invalid_count}/${INVALID_THRESHOLD}); waiting before rollback"
            return 0
        fi
        if ! restore_latest_valid_backup; then
            log "config invalid and no verified backup can be restored: ${CHECK_OUTPUT//$'\n'/; }"
            return 0
        fi
        set_state_number invalid_config_count 0
        set_state_number last_repair 0
    else
        set_state_number invalid_config_count 0
    fi

    ensure_nonlocal_bind || {
        log "failed to enable net.ipv4.ip_nonlocal_bind"
        return 0
    }

    missing_ips="$(missing_required_ips 2>/dev/null || true)"
    previous_missing="$(cat "${STATE_DIR}/missing_ips" 2>/dev/null || true)"
    if [[ "$missing_ips" != "$previous_missing" ]]; then
        set_state_text missing_ips "$missing_ips"
        if [[ -n "$missing_ips" ]]; then
            log "configured IPs are absent: ${missing_ips//$'\n'/, }; routes kept intact"
        elif [[ -n "$previous_missing" ]]; then
            log "all configured HAProxy IPs are present again"
        fi
    fi
    [[ -z "$missing_ips" ]] || trigger_additional_route_repair

    if ! service_active; then
        cooldown_ready || return 0
        if start_or_restart_service start; then
            repair_firewall_if_due
        fi
        return 0
    fi

    missing="$(missing_listeners)"
    if [[ -z "$missing" ]]; then
        set_state_number listener_failure_count 0
        rm -f "${STATE_DIR}/last_error"
        repair_firewall_if_due
        return 0
    fi

    listener_count=$(( $(state_number listener_failure_count) + 1 ))
    set_state_number listener_failure_count "$listener_count"
    if (( listener_count < LISTENER_THRESHOLD )); then
        log "missing listeners (${listener_count}/${LISTENER_THRESHOLD}): ${missing//$'\n'/, }"
        return 0
    fi
    cooldown_ready || return 0
    if start_or_restart_service reload; then
        set_state_number listener_failure_count 0
        repair_firewall_if_due
    fi
    return 0
}

main() {
    local action="${1:-repair}"
    CONFIG_GRACE_SEC="$(normalize_number "$CONFIG_GRACE_SEC" 20 5 300)"
    REPAIR_COOLDOWN_SEC="$(normalize_number "$REPAIR_COOLDOWN_SEC" 120 30 3600)"
    FIREWALL_INTERVAL_SEC="$(normalize_number "$FIREWALL_INTERVAL_SEC" 300 30 3600)"
    ROUTE_REPAIR_INTERVAL_SEC="$(normalize_number "$ROUTE_REPAIR_INTERVAL_SEC" 60 30 600)"
    INVALID_THRESHOLD="$(normalize_number "$INVALID_THRESHOLD" 2 2 10)"
    LISTENER_THRESHOLD="$(normalize_number "$LISTENER_THRESHOLD" 2 2 10)"
    prepare_runtime "$action"

    case "$action" in
        repair|heal|run) repair_health ;;
        check) check_health ;;
        status) report_status ;;
        *)
            echo "Usage: $0 repair|check|status" >&2
            return 2
            ;;
    esac
}

main "$@"
