#!/usr/bin/env bash
set -Eeuo pipefail

PUSH_BUILD="v178"
CONFIG="${KTO_STATS_PUSH_CONFIG:-/etc/kto-stats-push.conf}"
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

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

KTO_IP_LIMIT_ENABLED="${KTO_IP_LIMIT_ENABLED:-0}"
KTO_IP_LIMIT_LOG_FILE="${KTO_IP_LIMIT_LOG_FILE:-}"
KTO_IP_LIMIT_DOCKER_CONTAINER="${KTO_IP_LIMIT_DOCKER_CONTAINER:-}"
KTO_IP_LIMIT_USER_REGEX="${KTO_IP_LIMIT_USER_REGEX:-}"
KTO_IP_LIMIT_IP_REGEX="${KTO_IP_LIMIT_IP_REGEX:-}"
KTO_IP_LIMIT_SCAN_SEC="${KTO_IP_LIMIT_SCAN_SEC:-120}"
KTO_IP_LIMIT_TAIL_LINES="${KTO_IP_LIMIT_TAIL_LINES:-5000}"
KTO_IP_LIMIT_MAX_EVENTS="${KTO_IP_LIMIT_MAX_EVENTS:-5000}"
KTO_IP_LIMIT_XRAY_LOGS="${KTO_IP_LIMIT_XRAY_LOGS:-1}"
KTO_IP_LIMIT_BLOCK_STATE="${KTO_IP_LIMIT_BLOCK_STATE:-/run/kto-ip-limit-blocks.tsv}"

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
scan_wrong_sni_total=0
scan_wrong_sni_sources=0
scan_wrong_sni_top='[]'
scan_wrong_sni_names='[]'
haproxy_allowed_sni='[]'
ip_limit_events='[]'
ip_limit_events_count=0

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

validate_ipv4() {
    local ip="$1" octet
    local octets=()
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS=. read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
        (( 10#$octet >= 0 && 10#$octet <= 255 )) || return 1
    done
}

detect_ssh_port() {
    local port=""
    if command -v sshd >/dev/null 2>&1; then
        port="$(sshd -T 2>/dev/null | awk '/^port / {print $2; exit}' || true)"
    fi
    if [[ -z "$port" && -r /etc/ssh/sshd_config ]]; then
        port="$(awk 'tolower($1)=="port" && $1 !~ /^#/ {print $2; exit}' /etc/ssh/sshd_config 2>/dev/null || true)"
    fi
    echo "${port:-22}"
}

ufw_active() {
    command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"
}

ufw_ssh_rule_exists() {
    local rule="$1"
    local ip="$2"
    ufw status 2>/dev/null | awk -v rule="$rule" -v ip="$ip" '$0 ~ /ALLOW/ && $1 == rule && $3 == ip {found=1} END{exit found ? 0 : 1}'
}

apply_collector_ssh_ips() {
    local response="$1"
    local ssh_port rule ip applied=0

    command -v jq >/dev/null 2>&1 || return 0
    ufw_active || return 0

    ssh_port="$(detect_ssh_port)"
    rule="${ssh_port}/tcp"
    while read -r ip; do
        [[ -n "$ip" ]] || continue
        validate_ipv4 "$ip" || continue
        if ! ufw_ssh_rule_exists "$rule" "$ip"; then
            ufw allow proto tcp from "$ip" to any port "$ssh_port" comment 'kto-ssh' >/dev/null 2>&1 || true
            applied=$(( applied + 1 ))
        fi
    done < <(printf '%s' "$response" | jq -r '.ssh_allowed_ips[]? // empty' 2>/dev/null || true)

    if (( applied > 0 )); then
        echo "push ${PUSH_BUILD}: applied ssh ip rules=${applied}"
    fi
}

normalize_sni_value() {
    local value="${1:-}" label
    local labels=()

    value="${value,,}"
    value="${value%.}"
    [[ -n "$value" && ${#value} -le 253 ]] || return 1
    if [[ "$value" == \*.* ]]; then
        value="${value#*.}"
        [[ -n "$value" ]] || return 1
        printf '*.'
    fi
    [[ "$value" == *.* ]] || return 1
    IFS=. read -r -a labels <<< "$value"
    for label in "${labels[@]}"; do
        [[ "$label" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || return 1
    done
    printf '%s\n' "$value"
}

read_haproxy_allowed_sni() {
    local values

    haproxy_allowed_sni='[]'
    command -v jq >/dev/null 2>&1 || return 0
    [[ -r /etc/haproxy/haproxy.cfg ]] || return 0

    values="$(awk '
        $1 == "acl" && $2 == "allowed_sni" && $3 == "req.ssl_sni" {
            for (i = 1; i <= NF; i++) {
                if ($i == "-i") {
                    for (j = i + 1; j <= NF; j++) print $j
                    exit
                }
            }
        }
    ' /etc/haproxy/haproxy.cfg 2>/dev/null || true)"
    [[ -n "$values" ]] || return 0

    haproxy_allowed_sni="$(while read -r value; do
        [[ -n "$value" ]] || continue
        normalize_sni_value "$value" || true
    done <<< "$values" | awk '!seen[$0]++' | jq -R -s '[split("\n")[] | select(length > 0)]' 2>/dev/null || echo '[]')"
}

apply_collector_allowed_sni() {
    local response="$1"
    local desired_file tmp_cfg desired_line current_line applied=0

    command -v jq >/dev/null 2>&1 || return 0
    command -v haproxy >/dev/null 2>&1 || return 0
    [[ -r /etc/haproxy/haproxy.cfg && -w /etc/haproxy/haproxy.cfg ]] || return 0
    printf '%s' "$response" | jq -e 'has("allowed_sni") and (.allowed_sni | type == "array")' >/dev/null 2>&1 || return 0

    desired_file="$(mktemp)"
    tmp_cfg="$(mktemp)"
    printf '%s' "$response" | jq -r '.allowed_sni[]? // empty' 2>/dev/null | while read -r value; do
        [[ -n "$value" ]] || continue
        normalize_sni_value "$value" || true
    done | awk '!seen[$0]++' > "$desired_file"

    if [[ ! -s "$desired_file" ]]; then
        rm -f "$desired_file" "$tmp_cfg"
        return 0
    fi

    desired_line="    acl allowed_sni req.ssl_sni -i $(paste -sd ' ' "$desired_file")"
    current_line="$(awk '
        $1 == "acl" && $2 == "allowed_sni" && $3 == "req.ssl_sni" {
            print
            exit
        }
    ' /etc/haproxy/haproxy.cfg 2>/dev/null || true)"
    if [[ "$current_line" == "$desired_line" ]]; then
        rm -f "$desired_file" "$tmp_cfg"
        return 0
    fi

    if ! awk -v replacement="$desired_line" '
        $1 == "acl" && $2 == "allowed_sni" && $3 == "req.ssl_sni" && replaced == 0 {
            print replacement
            replaced = 1
            next
        }
        { print }
        END { if (replaced == 0) exit 2 }
    ' /etc/haproxy/haproxy.cfg > "$tmp_cfg"; then
        rm -f "$desired_file" "$tmp_cfg"
        return 0
    fi
    if ! haproxy -c -f "$tmp_cfg" >/dev/null 2>&1; then
        echo "push ${PUSH_BUILD}: allowed_sni skipped, haproxy config check failed" >&2
        rm -f "$desired_file" "$tmp_cfg"
        return 0
    fi
    if cp "$tmp_cfg" /etc/haproxy/haproxy.cfg 2>/dev/null; then
        if systemctl reload haproxy >/dev/null 2>&1 || systemctl restart haproxy >/dev/null 2>&1; then
            applied=1
        fi
    fi
    rm -f "$desired_file" "$tmp_cfg"

    if (( applied == 1 )); then
        echo "push ${PUSH_BUILD}: allowed_sni applied"
    fi
}

ip_limit_block_chains() {
    command -v iptables >/dev/null 2>&1 || return 0
    printf '%s\n' INPUT FORWARD
    if iptables -S DOCKER-USER >/dev/null 2>&1; then
        printf '%s\n' DOCKER-USER
    fi
}

ip_limit_drop_exists() {
    local chain="$1" ip="$2"
    iptables -C "$chain" -s "$ip" -m comment --comment "kto-ip-limit" -j DROP >/dev/null 2>&1
}

ip_limit_add_drop() {
    local chain="$1" ip="$2"
    ip_limit_drop_exists "$chain" "$ip" && return 0
    iptables -I "$chain" 1 -s "$ip" -m comment --comment "kto-ip-limit" -j DROP >/dev/null 2>&1 || true
}

ip_limit_del_drop() {
    local chain="$1" ip="$2"
    while iptables -D "$chain" -s "$ip" -m comment --comment "kto-ip-limit" -j DROP >/dev/null 2>&1; do
        :
    done
}

ip_limit_kill_conntrack() {
    local ip="$1"
    command -v conntrack >/dev/null 2>&1 || return 0
    conntrack -D -s "$ip" >/dev/null 2>&1 || true
    conntrack -D -d "$ip" >/dev/null 2>&1 || true
}

apply_ip_limit_blocks() {
    local response="$1"
    local now state_dir desired_file merged_file active_file previous_file ip expires user chain applied=0 removed=0

    command -v jq >/dev/null 2>&1 || return 0
    command -v iptables >/dev/null 2>&1 || return 0

    now="$(date +%s)"
    state_dir="$(dirname "$KTO_IP_LIMIT_BLOCK_STATE")"
    mkdir -p "$state_dir" >/dev/null 2>&1 || true
    desired_file="$(mktemp)"
    merged_file="$(mktemp)"
    active_file="$(mktemp)"
    previous_file="$(mktemp)"

    printf '%s' "$response" | jq -r --argjson now "$now" '
        .ip_limit_blocks[]? |
        select((.expires_at // 0 | tonumber) > $now) |
        [.ip, (.expires_at // 0 | tostring), (.user // "")] | @tsv
    ' 2>/dev/null > "$desired_file" || true

    if [[ -r "$KTO_IP_LIMIT_BLOCK_STATE" ]]; then
        cp "$KTO_IP_LIMIT_BLOCK_STATE" "$previous_file" 2>/dev/null || true
        cat "$KTO_IP_LIMIT_BLOCK_STATE" >> "$merged_file" 2>/dev/null || true
    fi
    cat "$desired_file" >> "$merged_file" 2>/dev/null || true

    awk -F '\t' -v now="$now" '
        function valid(ip) { return ip ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/ }
        valid($1) && ($2 + 0) > now {
            key = $1
            if (($2 + 0) > expires[key]) {
                expires[key] = $2 + 0
                user[key] = $3
            }
        }
        END {
            for (ip in expires) {
                print ip "\t" expires[ip] "\t" user[ip]
            }
        }
    ' "$merged_file" | sort -t $'\t' -k1,1 > "$active_file"

    while IFS=$'\t' read -r ip expires user; do
        [[ -n "$ip" ]] || continue
        validate_ipv4 "$ip" || continue
        while read -r chain; do
            [[ -n "$chain" ]] || continue
            if ! ip_limit_drop_exists "$chain" "$ip"; then
                ip_limit_add_drop "$chain" "$ip"
                applied=$(( applied + 1 ))
            fi
        done < <(ip_limit_block_chains)
        ip_limit_kill_conntrack "$ip"
    done < "$active_file"

    while IFS=$'\t' read -r ip expires user; do
        [[ -n "$ip" ]] || continue
        validate_ipv4 "$ip" || continue
        if ! awk -F '\t' -v ip="$ip" '$1 == ip {found=1} END {exit found ? 0 : 1}' "$active_file"; then
            while read -r chain; do
                [[ -n "$chain" ]] || continue
                ip_limit_del_drop "$chain" "$ip"
                removed=$(( removed + 1 ))
            done < <(ip_limit_block_chains)
        fi
    done < "$previous_file"

    if [[ -s "$active_file" ]]; then
        cp "$active_file" "$KTO_IP_LIMIT_BLOCK_STATE" 2>/dev/null || true
    else
        rm -f "$KTO_IP_LIMIT_BLOCK_STATE" 2>/dev/null || true
    fi
    rm -f "$desired_file" "$merged_file" "$active_file" "$previous_file"

    if (( applied > 0 || removed > 0 )); then
        echo "push ${PUSH_BUILD}: ip blocks applied=${applied} removed=${removed}"
    fi
}

config_bool_value() {
    case "${1:-0}" in
        1|yes|true|on|enabled) echo 1 ;;
        *) echo 0 ;;
    esac
}

set_push_config_value() {
    local key="$1" value="$2" tmp
    [[ -n "$key" ]] || return 0
    tmp="$(mktemp)"
    if [[ -r "$CONFIG" ]]; then
        awk -v key="$key" -v line="${key}=\"${value}\"" '
            BEGIN { done = 0 }
            $0 ~ "^" key "=" {
                if (!done) {
                    print line
                    done = 1
                }
                next
            }
            { print }
            END {
                if (!done) print line
            }
        ' "$CONFIG" > "$tmp"
    else
        printf '%s="%s"\n' "$key" "$value" > "$tmp"
    fi
    if cp "$tmp" "$CONFIG" 2>/dev/null; then
        chmod 600 "$CONFIG" 2>/dev/null || true
        rm -f "$tmp"
        return 0
    fi
    rm -f "$tmp"
    return 1
}

apply_collector_ip_limit_config() {
    local response="$1" desired current
    command -v jq >/dev/null 2>&1 || return 0
    desired="$(printf '%s' "$response" | jq -r 'if has("ip_limit_enabled") then (if .ip_limit_enabled then "1" else "0" end) else "" end' 2>/dev/null || true)"
    [[ "$desired" == "0" || "$desired" == "1" ]] || return 0
    current="$(config_bool_value "$KTO_IP_LIMIT_ENABLED")"
    [[ "$current" != "$desired" ]] || return 0
    if set_push_config_value "KTO_IP_LIMIT_ENABLED" "$desired"; then
        echo "push ${PUSH_BUILD}: ip limit enabled=${desired} (next run)"
    else
        echo "push ${PUSH_BUILD}: ip limit config write failed" >&2
    fi
}

read_haproxy_scan_stats() {
    local socket="/run/haproxy/admin.sock"
    local raw entries sni_raw sni_entries

    scan_wrong_sni_total=0
    scan_wrong_sni_sources=0
    scan_wrong_sni_top='[]'
    scan_wrong_sni_names='[]'

    command -v socat >/dev/null 2>&1 || return 0
    command -v jq >/dev/null 2>&1 || return 0
    [[ -S "$socket" ]] || return 0

    raw="$(printf 'show table vless_in\n' | socat -t 2 - UNIX-CONNECT:"$socket" 2>/dev/null || true)"
    [[ -n "$raw" ]] || return 0

    entries="$(awk '
        /key=/ {
            ip = ""
            gpc = 0
            rate = 0
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^key=/) {
                    split($i, value, "=")
                    ip = value[2]
                } else if ($i ~ /^gpc0=/) {
                    split($i, value, "=")
                    gpc = value[2] + 0
                } else if ($i ~ /^conn_rate\([0-9]+\)=/) {
                    split($i, value, "=")
                    rate = value[2] + 0
                }
            }
            if (ip != "" && gpc > 0) {
                print ip, gpc, rate
            }
        }
    ' <<< "$raw" || true)"
    [[ -n "$entries" ]] || return 0

    scan_wrong_sni_total="$(awk '{sum += $2} END {print sum + 0}' <<< "$entries")"
    scan_wrong_sni_sources="$(awk 'END {print NR + 0}' <<< "$entries")"
    scan_wrong_sni_top="$(printf '%s\n' "$entries" \
        | sort -k2,2nr \
        | head -n 10 \
        | jq -R -s '[split("\n")[] | select(length > 0) | split(" ") | {ip: .[0], count: (.[1] | tonumber), rate: (.[2] | tonumber)}]' 2>/dev/null || echo '[]')"

    sni_raw="$(printf 'show table wrong_sni_names\n' | socat -t 2 - UNIX-CONNECT:"$socket" 2>/dev/null || true)"
    [[ -n "$sni_raw" ]] || return 0
    sni_entries="$(awk '
        /key=/ {
            sni = ""
            gpc = 0
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^key=/) {
                    sub(/^key=/, "", $i)
                    sni = $i
                } else if ($i ~ /^gpc0=/) {
                    split($i, value, "=")
                    gpc = value[2] + 0
                }
            }
            if (sni != "" && gpc > 0) {
                print sni, gpc
            }
        }
    ' <<< "$sni_raw" || true)"
    [[ -n "$sni_entries" ]] || return 0
    scan_wrong_sni_names="$(printf '%s\n' "$sni_entries" \
        | sort -k2,2nr \
        | head -n 10 \
        | jq -R -s '[split("\n")[] | select(length > 0) | split(" ") | {sni: .[0], count: (.[1] | tonumber)}]' 2>/dev/null || echo '[]')"
}

ip_limit_enabled() {
    case "${KTO_IP_LIMIT_ENABLED}" in
        1|yes|true|on|enabled) return 0 ;;
        *) return 1 ;;
    esac
}

ip_limit_xray_logs_enabled() {
    case "${KTO_IP_LIMIT_XRAY_LOGS}" in
        1|yes|true|on|enabled) return 0 ;;
        *) return 1 ;;
    esac
}

ip_limit_user_from_line() {
    local line="$1" candidate
    local regex

    if [[ -n "$KTO_IP_LIMIT_USER_REGEX" && "$line" =~ $KTO_IP_LIMIT_USER_REGEX ]]; then
        [[ -n "${BASH_REMATCH[1]-}" ]] || return 1
        printf '%s\n' "${BASH_REMATCH[1]}"
        return 0
    fi

    for regex in \
        '"email"[[:space:]]*:[[:space:]]*"([^"]+)"' \
        'email:[[:space:]]*([^[:space:]]+)' \
        'user:[[:space:]]*([^[:space:]]+)' \
        'uuid:[[:space:]]*([0-9a-fA-F-]{32,36})' \
        'client:[[:space:]]*([^[:space:]]+)'; do
        if [[ "$line" =~ $regex ]]; then
            printf '%s\n' "${BASH_REMATCH[1]}"
            return 0
        fi
    done

    for regex in \
        '\[([^][]+)[[:space:]]*->[[:space:]]*[^][]+\]' \
        '\[([^][]+)[[:space:]]*>>[[:space:]]*[^][]+\]' \
        '\[([^][]+)[[:space:]]*<-[[:space:]]*[^][]+\]'; do
        if [[ "$line" =~ $regex ]]; then
            candidate="${BASH_REMATCH[1]}"
            candidate="${candidate#"${candidate%%[![:space:]]*}"}"
            candidate="${candidate%"${candidate##*[![:space:]]}"}"
            if [[ -n "$candidate" && "$candidate" != tcp:* && "$candidate" != udp:* ]]; then
                printf '%s\n' "$candidate"
                return 0
            fi
        fi
    done

    if [[ "$line" =~ ([A-Za-z0-9._%+-]+@[A-Za-z0-9._-]+) ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}"
        return 0
    fi

    return 1
}

ip_limit_ip_from_line() {
    local line="$1"
    local regex

    if [[ -n "$KTO_IP_LIMIT_IP_REGEX" && "$line" =~ $KTO_IP_LIMIT_IP_REGEX ]]; then
        [[ -n "${BASH_REMATCH[1]-}" ]] || return 1
        printf '%s\n' "${BASH_REMATCH[1]}"
        return 0
    fi
    if [[ "$line" =~ from[[:space:]]+(tcp:|udp:)?(::ffff:)?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) ]]; then
        printf '%s\n' "${BASH_REMATCH[3]}"
        return 0
    fi
    if [[ "$line" =~ ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}"
        return 0
    fi

    return 1
}

ip_limit_seen_at_from_line() {
    local line="$1"
    local stamp

    if [[ "$line" =~ ^([0-9]{4})/([0-9]{2})/([0-9]{2})[[:space:]]+([0-9]{2}):([0-9]{2}):([0-9]{2}) ]]; then
        stamp="${BASH_REMATCH[1]}-${BASH_REMATCH[2]}-${BASH_REMATCH[3]} ${BASH_REMATCH[4]}:${BASH_REMATCH[5]}:${BASH_REMATCH[6]}"
        date -d "$stamp" +%s 2>/dev/null && return 0
    fi
    if [[ "$line" =~ ^([0-9]{4})-([0-9]{2})-([0-9]{2})[T[:space:]]([0-9]{2}):([0-9]{2}):([0-9]{2}) ]]; then
        stamp="${BASH_REMATCH[1]}-${BASH_REMATCH[2]}-${BASH_REMATCH[3]} ${BASH_REMATCH[4]}:${BASH_REMATCH[5]}:${BASH_REMATCH[6]}"
        date -d "$stamp" +%s 2>/dev/null && return 0
    fi
    return 1
}

read_ip_limit_source_lines() {
    local output_file="$1"
    local scan_sec="$KTO_IP_LIMIT_SCAN_SEC"
    local tail_lines="$KTO_IP_LIMIT_TAIL_LINES"

    if [[ -n "$KTO_IP_LIMIT_DOCKER_CONTAINER" ]] && command -v docker >/dev/null 2>&1; then
        docker logs --since "${scan_sec}s" "$KTO_IP_LIMIT_DOCKER_CONTAINER" 2>/dev/null | awk '{print "recent\t" $0}' >> "$output_file" || true
        if ip_limit_xray_logs_enabled; then
            docker exec "$KTO_IP_LIMIT_DOCKER_CONTAINER" sh -c '
                lines="$1"
                case "$lines" in
                    ""|*[!0-9]*) lines=500 ;;
                esac
                for path in \
                    /var/log/supervisor/xray.out.log \
                    /var/log/supervisor/xray.err.log \
                    /var/log/xray/access.log \
                    /usr/local/etc/xray/access.log; do
                    [ -r "$path" ] && tail -n "$lines" "$path"
                done
            ' sh "$tail_lines" 2>/dev/null | awk '{print "file\t" $0}' >> "$output_file" || true
        fi
    fi
    if [[ -n "$KTO_IP_LIMIT_LOG_FILE" && -r "$KTO_IP_LIMIT_LOG_FILE" ]]; then
        tail -n "$tail_lines" "$KTO_IP_LIMIT_LOG_FILE" 2>/dev/null | awk '{print "file\t" $0}' >> "$output_file" || true
    fi
}

read_ip_limit_events() {
    local lines_file events_file dedup_file source line user ip seen_at parsed_seen_at scan_sec cutoff max_events

    ip_limit_events='[]'
    ip_limit_enabled || return 0
    command -v jq >/dev/null 2>&1 || return 0

    lines_file="$(mktemp)"
    events_file="$(mktemp)"
    dedup_file="$(mktemp)"
    read_ip_limit_source_lines "$lines_file"
    case "$KTO_IP_LIMIT_SCAN_SEC" in
        ""|*[!0-9]*) scan_sec=120 ;;
        *) scan_sec="$KTO_IP_LIMIT_SCAN_SEC" ;;
    esac
    case "$KTO_IP_LIMIT_MAX_EVENTS" in
        ""|*[!0-9]*) max_events=5000 ;;
        *) max_events="$KTO_IP_LIMIT_MAX_EVENTS" ;;
    esac
    if (( max_events < 100 )); then
        max_events=100
    fi
    cutoff=$(( updated_at - scan_sec - 5 ))

    while IFS=$'\t' read -r source line; do
        if [[ "$source" != "recent" && "$source" != "file" ]]; then
            line="${source}${line:+ ${line}}"
            source="recent"
        fi
        [[ -n "$line" ]] || continue
        user="$(ip_limit_user_from_line "$line" || true)"
        [[ -n "$user" ]] || continue
        ip="$(ip_limit_ip_from_line "$line" || true)"
        validate_ipv4 "$ip" || continue
        seen_at="$updated_at"
        parsed_seen_at="$(ip_limit_seen_at_from_line "$line" || true)"
        if [[ -n "$parsed_seen_at" ]]; then
            seen_at="$parsed_seen_at"
        elif [[ "$source" == "file" ]]; then
            continue
        fi
        (( seen_at >= cutoff && seen_at <= updated_at + 300 )) || continue
        printf '%s\t%s\t%s\t%s\n' "$user" "$ip" "$KTO_PUSH_NODE_NAME" "$seen_at" >> "$events_file"
    done < "$lines_file"

    if [[ -s "$events_file" ]]; then
        awk -F '\t' 'NF >= 4 {
            key = $1 SUBSEP $2 SUBSEP $3
            user[key] = $1
            ip[key] = $2
            node[key] = $3
            seen[key] = $4
        }
        END {
            for (key in seen) {
                print user[key] "\t" ip[key] "\t" node[key] "\t" seen[key]
            }
        }' "$events_file" | sort -t "$(printf '\t')" -k4,4n | tail -n "$max_events" > "$dedup_file"
        ip_limit_events="$(jq -R -s '
            [split("\n")[] | select(length > 0) | split("\t") |
                {user: .[0], ip: .[1], node: .[2], seen_at: (.[3] | tonumber)}
            ]
        ' "$dedup_file" 2>/dev/null || echo '[]')"
    fi
    ip_limit_events_count="$(printf '%s' "$ip_limit_events" | jq -r 'length' 2>/dev/null || echo 0)"

    rm -f "$lines_file" "$events_file" "$dedup_file"
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
read_haproxy_scan_stats
read_haproxy_allowed_sni
read_ip_limit_events

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
    --argjson scan_wrong_sni_total "$scan_wrong_sni_total" \
    --argjson scan_wrong_sni_sources "$scan_wrong_sni_sources" \
    --argjson scan_wrong_sni_top "$scan_wrong_sni_top" \
    --argjson scan_wrong_sni_names "$scan_wrong_sni_names" \
    --argjson haproxy_allowed_sni "$haproxy_allowed_sni" \
    --argjson ip_limit_events "$ip_limit_events" \
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
        scan_wrong_sni_total: $scan_wrong_sni_total,
        scan_wrong_sni_sources: $scan_wrong_sni_sources,
        scan_wrong_sni_top: $scan_wrong_sni_top,
        scan_wrong_sni_names: $scan_wrong_sni_names,
        haproxy_allowed_sni: $haproxy_allowed_sni,
        ip_limit_events: $ip_limit_events,
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
    ip_limit_extra=""
    if ip_limit_enabled; then
        ip_limit_extra=" ip_events=${ip_limit_events_count}"
    fi
    apply_collector_ssh_ips "$response"
    apply_collector_allowed_sni "$response"
    apply_collector_ip_limit_config "$response"
    apply_ip_limit_blocks "$response"
    echo "push ${PUSH_BUILD}: ok node=${KTO_PUSH_NODE_NAME} ram=${ram_percent}% cpu=${cpu_percent}% uptime=${uptime_sec}s${ip_limit_extra}"
else
    echo "push ${PUSH_BUILD}: bad response: ${response}" >&2
    exit 1
fi
