#!/usr/bin/env bash
set -Eeuo pipefail

PUSH_BUILD="v158"
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
KTO_IP_LIMIT_TAIL_LINES="${KTO_IP_LIMIT_TAIL_LINES:-500}"
KTO_IP_LIMIT_XRAY_LOGS="${KTO_IP_LIMIT_XRAY_LOGS:-1}"

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

read_haproxy_scan_stats() {
    local socket="/run/haproxy/admin.sock"
    local raw entries

    scan_wrong_sni_total=0
    scan_wrong_sni_sources=0
    scan_wrong_sni_top='[]'

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
        'email:[[:space:]]*([^[:space:]]+)' \
        'user:[[:space:]]*([^[:space:]]+)' \
        'uuid:[[:space:]]*([0-9a-fA-F-]{32,36})' \
        'client:[[:space:]]*([^[:space:]]+)'; do
        if [[ "$line" =~ $regex ]]; then
            printf '%s\n' "${BASH_REMATCH[1]}"
            return 0
        fi
    done

    if [[ "$line" =~ \[([^][]+)\] ]]; then
        candidate="${BASH_REMATCH[1]}"
        candidate="${candidate%% ->*}"
        candidate="${candidate%% >>*}"
        candidate="${candidate%% <-*}"
        candidate="${candidate%% *}"
        if [[ -n "$candidate" && "$candidate" != tcp:* && "$candidate" != udp:* ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    fi
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

read_ip_limit_source_lines() {
    local output_file="$1"
    local scan_sec="$KTO_IP_LIMIT_SCAN_SEC"
    local tail_lines="$KTO_IP_LIMIT_TAIL_LINES"

    if [[ -n "$KTO_IP_LIMIT_DOCKER_CONTAINER" ]] && command -v docker >/dev/null 2>&1; then
        docker logs --since "${scan_sec}s" "$KTO_IP_LIMIT_DOCKER_CONTAINER" >> "$output_file" 2>/dev/null || true
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
            ' sh "$tail_lines" >> "$output_file" 2>/dev/null || true
        fi
    fi
    if [[ -n "$KTO_IP_LIMIT_LOG_FILE" && -r "$KTO_IP_LIMIT_LOG_FILE" ]]; then
        tail -n "$tail_lines" "$KTO_IP_LIMIT_LOG_FILE" >> "$output_file" 2>/dev/null || true
    fi
}

read_ip_limit_events() {
    local lines_file events_file line user ip

    ip_limit_events='[]'
    ip_limit_enabled || return 0
    command -v jq >/dev/null 2>&1 || return 0

    lines_file="$(mktemp)"
    events_file="$(mktemp)"
    read_ip_limit_source_lines "$lines_file"

    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        user="$(ip_limit_user_from_line "$line" || true)"
        [[ -n "$user" ]] || continue
        ip="$(ip_limit_ip_from_line "$line" || true)"
        validate_ipv4 "$ip" || continue
        printf '%s\t%s\t%s\t%s\n' "$user" "$ip" "$KTO_PUSH_NODE_NAME" "$updated_at" >> "$events_file"
    done < "$lines_file"

    if [[ -s "$events_file" ]]; then
        ip_limit_events="$(sort -u "$events_file" | awk 'NR <= 200' | jq -R -s '
            [split("\n")[] | select(length > 0) | split("\t") |
                {user: .[0], ip: .[1], node: .[2], seen_at: (.[3] | tonumber)}
            ]
        ' 2>/dev/null || echo '[]')"
    fi
    ip_limit_events_count="$(printf '%s' "$ip_limit_events" | jq -r 'length' 2>/dev/null || echo 0)"

    rm -f "$lines_file" "$events_file"
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
    echo "push ${PUSH_BUILD}: ok node=${KTO_PUSH_NODE_NAME} ram=${ram_percent}% cpu=${cpu_percent}% uptime=${uptime_sec}s${ip_limit_extra}"
else
    echo "push ${PUSH_BUILD}: bad response: ${response}" >&2
    exit 1
fi
