#!/usr/bin/env bash
set -Eeuo pipefail

PUSH_BUILD="v231"
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
KTO_PUSH_INTERVAL="${KTO_PUSH_INTERVAL:-15}"
KTO_REMNA_LOG_ENABLED="${KTO_REMNA_LOG_ENABLED:-1}"
KTO_REMNA_DOCKER_CONTAINER="${KTO_REMNA_DOCKER_CONTAINER:-${KTO_IP_LIMIT_DOCKER_CONTAINER:-remnanode}}"
KTO_REMNA_LOG_SCAN_SEC="${KTO_REMNA_LOG_SCAN_SEC:-300}"
KTO_REMNA_DIAG_CACHE_SEC="${KTO_REMNA_DIAG_CACHE_SEC:-15}"
KTO_REMNA_DIAG_CACHE="${KTO_REMNA_DIAG_CACHE:-/run/kto-stats-push-remna.json}"
KTO_PUSH_UPDATE_STATE="${KTO_PUSH_UPDATE_STATE:-/var/lib/kto-stats-push/update_state.json}"
KTO_UPDATE_RAW_BASE="${KTO_UPDATE_RAW_BASE:-https://raw.githubusercontent.com/Alpha012/kto-optimize/main}"
KTO_PUSH_NODE_UUID="${KTO_PUSH_NODE_UUID:-}"
KTO_PUSH_NODE_KIND="${KTO_PUSH_NODE_KIND:-}"
KTO_PUSH_REQUIRE_SIGNED_RESPONSE="${KTO_PUSH_REQUIRE_SIGNED_RESPONSE:-0}"
KTO_ALLOW_INSECURE_UPDATE_URL="${KTO_ALLOW_INSECURE_UPDATE_URL:-0}"
KTO_PUSH_CPU_STATE="${KTO_PUSH_CPU_STATE:-/run/kto-stats-push-cpu.state}"
KTO_TUNING_SYSCTL_CONF="${KTO_TUNING_SYSCTL_CONF:-/etc/sysctl.d/99-kto-tuning.conf}"
KTO_LIMITS_CONF="${KTO_LIMITS_CONF:-/etc/security/limits.d/99-kto-limits.conf}"
KTO_SYSTEMD_LIMITS_CONF="${KTO_SYSTEMD_LIMITS_CONF:-/etc/systemd/system.conf.d/99-kto-limits.conf}"
KTO_USER_LIMITS_CONF="${KTO_USER_LIMITS_CONF:-/etc/systemd/user.conf.d/99-kto-limits.conf}"

if command -v flock >/dev/null 2>&1; then
    exec 9>/run/kto-stats-push.lock
    if ! flock -n 9; then
        echo "push ${PUSH_BUILD}: previous run is still active"
        exit 0
    fi
fi

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
haproxy_backend_target=''
ip_limit_events='[]'
ip_limit_events_count=0
update_result='{}'
remna_status=''
remna_restarts=0
remna_error_count=0
remna_last_error=''
remna_compose_dir=''

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
    local previous_total=0 previous_idle=0 current_total=0 current_idle=0 total_delta idle_delta tmp
    read -r current_total current_idle < <(read_cpu_totals)
    if [[ -r "$KTO_PUSH_CPU_STATE" ]]; then
        read -r previous_total previous_idle < "$KTO_PUSH_CPU_STATE" || true
    fi
    [[ "$previous_total" =~ ^[0-9]+$ ]] || previous_total=0
    [[ "$previous_idle" =~ ^[0-9]+$ ]] || previous_idle=0
    [[ "$current_total" =~ ^[0-9]+$ ]] || current_total=0
    [[ "$current_idle" =~ ^[0-9]+$ ]] || current_idle=0
    tmp="${KTO_PUSH_CPU_STATE}.$$"
    if printf '%s %s\n' "$current_total" "$current_idle" > "$tmp" 2>/dev/null; then
        mv -f "$tmp" "$KTO_PUSH_CPU_STATE" 2>/dev/null || rm -f "$tmp"
    else
        rm -f "$tmp" 2>/dev/null || true
    fi
    total_delta=$(( ${current_total:-0} - ${previous_total:-0} ))
    idle_delta=$(( ${current_idle:-0} - ${previous_idle:-0} ))
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

read_haproxy_backend_target() {
    local target

    haproxy_backend_target=''
    [[ -r /etc/haproxy/haproxy.cfg ]] || return 0

    target="$(awk '
        $1 == "server" && $2 == "xray1" {
            print $3
            exit
        }
    ' /etc/haproxy/haproxy.cfg 2>/dev/null || true)"
    haproxy_backend_target="$(normalize_haproxy_target "$target" 2>/dev/null || true)"
}

config_enabled_value() {
    case "${1:-}" in
        1|yes|true|on|enabled) return 0 ;;
        *) return 1 ;;
    esac
}

remna_container_name() {
    if [[ -n "${KTO_REMNA_DOCKER_CONTAINER:-}" ]]; then
        printf '%s\n' "$KTO_REMNA_DOCKER_CONTAINER"
    elif [[ -n "${KTO_IP_LIMIT_DOCKER_CONTAINER:-}" ]]; then
        printf '%s\n' "$KTO_IP_LIMIT_DOCKER_CONTAINER"
    else
        printf '%s\n' remnanode
    fi
}

dir_has_compose_file() {
    local dir="$1"
    [[ -d "$dir" ]] || return 1
    [[ -f "$dir/docker-compose.yml" || -f "$dir/docker-compose.yaml" || -f "$dir/compose.yml" || -f "$dir/compose.yaml" ]]
}

detect_remna_compose_dir() {
    local container="$1" label_dir inspect_file candidate

    if [[ -n "$container" ]] && command -v docker >/dev/null 2>&1; then
        label_dir="$(docker inspect -f '{{ index .Config.Labels "com.docker.compose.project.working_dir" }}' "$container" 2>/dev/null || true)"
        if dir_has_compose_file "$label_dir"; then
            printf '%s\n' "$label_dir"
            return 0
        fi
        inspect_file="$(docker inspect -f '{{ index .Config.Labels "com.docker.compose.project.config_files" }}' "$container" 2>/dev/null || true)"
        if [[ -n "$inspect_file" ]]; then
            candidate="$(dirname "${inspect_file%%,*}" 2>/dev/null || true)"
            if dir_has_compose_file "$candidate"; then
                printf '%s\n' "$candidate"
                return 0
            fi
        fi
    fi

    for candidate in /opt/remnawave /opt/remnanode; do
        if dir_has_compose_file "$candidate"; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

read_remna_diagnostics() {
    local container logs scan_sec cache_sec cache_mtime cache_age tmp

    remna_status=''
    remna_restarts=0
    remna_error_count=0
    remna_last_error=''
    remna_compose_dir=''

    config_enabled_value "$KTO_REMNA_LOG_ENABLED" || return 0
    command -v docker >/dev/null 2>&1 || return 0
    cache_sec="$(int_or_zero "$KTO_REMNA_DIAG_CACHE_SEC")"
    if (( cache_sec > 0 )) && [[ -r "$KTO_REMNA_DIAG_CACHE" ]]; then
        cache_mtime="$(stat -c %Y "$KTO_REMNA_DIAG_CACHE" 2>/dev/null || echo 0)"
        cache_age=$(( $(date +%s) - ${cache_mtime:-0} ))
        if (( cache_age >= 0 && cache_age < cache_sec )); then
            if IFS=$'\t' read -r remna_status remna_restarts remna_error_count remna_last_error remna_compose_dir \
                < <(jq -r '[.status // "", .restarts // 0, .error_count // 0, .last_error // "", .compose_dir // ""] | @tsv' "$KTO_REMNA_DIAG_CACHE" 2>/dev/null); then
                remna_restarts="$(int_or_zero "$remna_restarts")"
                remna_error_count="$(int_or_zero "$remna_error_count")"
                return 0
            fi
            rm -f "$KTO_REMNA_DIAG_CACHE" 2>/dev/null || true
        fi
    fi

    container="$(remna_container_name)"
    [[ -n "$container" ]] || return 0
    if docker inspect "$container" >/dev/null 2>&1; then
        remna_status="$(docker inspect -f '{{.State.Status}}' "$container" 2>/dev/null || true)"
        remna_restarts="$(docker inspect -f '{{.RestartCount}}' "$container" 2>/dev/null || echo 0)"
        remna_restarts="$(int_or_zero "$remna_restarts")"
    fi
    remna_compose_dir="$(detect_remna_compose_dir "$container" 2>/dev/null || true)"
    if [[ -z "$remna_status" && -n "$remna_compose_dir" ]]; then
        remna_status='not found'
    fi
    [[ -n "$remna_status" || -n "$remna_compose_dir" ]] || return 0

    case "$KTO_REMNA_LOG_SCAN_SEC" in
        ""|*[!0-9]*) scan_sec=300 ;;
        *) scan_sec="$KTO_REMNA_LOG_SCAN_SEC" ;;
    esac
    logs="$(docker logs --since "${scan_sec}s" "$container" 2>&1 \
        | grep -Eai 'error|failed|panic|fatal|exception|traceback|timeout|refused|denied|invalid|warn' \
        | tail -n 20 || true)"
    if [[ -n "$logs" ]]; then
        remna_error_count="$(printf '%s\n' "$logs" | awk 'NF {count++} END {print count + 0}')"
        remna_last_error="$(printf '%s\n' "$logs" | tail -n 1 | tr -d '\r' | cut -c1-500)"
    fi
    tmp="${KTO_REMNA_DIAG_CACHE}.$$"
    if jq -n \
        --arg status "$remna_status" \
        --argjson restarts "$remna_restarts" \
        --argjson error_count "$remna_error_count" \
        --arg last_error "$remna_last_error" \
        --arg compose_dir "$remna_compose_dir" \
        '{status: $status, restarts: $restarts, error_count: $error_count, last_error: $last_error, compose_dir: $compose_dir}' > "$tmp" 2>/dev/null; then
        mv -f "$tmp" "$KTO_REMNA_DIAG_CACHE" 2>/dev/null || rm -f "$tmp"
    else
        rm -f "$tmp" 2>/dev/null || true
    fi
}

apply_collector_haproxy_config() {
    local response="$1"
    local desired_file tmp_cfg next_cfg desired_sni_line current_sni_line
    local desired_target current_target current_target_raw applied=0 changed=0 has_sni=0 has_target=0

    command -v jq >/dev/null 2>&1 || return 0
    command -v haproxy >/dev/null 2>&1 || return 0
    [[ -r /etc/haproxy/haproxy.cfg && -w /etc/haproxy/haproxy.cfg ]] || return 0

    desired_file="$(mktemp)"
    tmp_cfg="$(mktemp)"
    next_cfg="$(mktemp)"

    if ! cp /etc/haproxy/haproxy.cfg "$tmp_cfg" 2>/dev/null; then
        rm -f "$desired_file" "$tmp_cfg" "$next_cfg"
        return 0
    fi

    desired_target="$(printf '%s' "$response" | jq -r '.haproxy_target // empty' 2>/dev/null || true)"
    if [[ -n "$desired_target" ]]; then
        if desired_target="$(normalize_haproxy_target "$desired_target" 2>/dev/null)"; then
            current_target_raw="$(awk '
                $1 == "server" && $2 == "xray1" {
                    print $3
                    exit
                }
            ' "$tmp_cfg" 2>/dev/null || true)"
            current_target="$(normalize_haproxy_target "$current_target_raw" 2>/dev/null || true)"
            if [[ -n "$current_target_raw" && "$current_target" != "$desired_target" ]]; then
                if awk -v target="$desired_target" '
                    $1 == "server" && $2 == "xray1" && replaced == 0 {
                        print "    server xray1 " target " check weight 10"
                        replaced = 1
                        next
                    }
                    { print }
                    END { if (replaced == 0) exit 2 }
                ' "$tmp_cfg" > "$next_cfg"; then
                    mv "$next_cfg" "$tmp_cfg"
                    changed=1
                    has_target=1
                else
                    rm -f "$desired_file" "$tmp_cfg" "$next_cfg"
                    return 0
                fi
            elif [[ -z "$current_target_raw" ]]; then
                echo "push ${PUSH_BUILD}: haproxy target skipped, xray1 backend not found" >&2
            fi
        else
            echo "push ${PUSH_BUILD}: haproxy target skipped, bad target from collector" >&2
            desired_target=""
        fi
    fi

    if printf '%s' "$response" | jq -e 'has("allowed_sni") and (.allowed_sni | type == "array")' >/dev/null 2>&1; then
        printf '%s' "$response" | jq -r '.allowed_sni[]? // empty' 2>/dev/null | while read -r value; do
            [[ -n "$value" ]] || continue
            normalize_sni_value "$value" || true
        done | awk '!seen[$0]++' > "$desired_file"

        if [[ -s "$desired_file" ]]; then
            has_sni=1
            desired_sni_line="    acl allowed_sni req.ssl_sni -i $(paste -sd ' ' "$desired_file")"
            current_sni_line="$(awk '
                $1 == "acl" && $2 == "allowed_sni" && $3 == "req.ssl_sni" {
                    print
                    exit
                }
            ' "$tmp_cfg" 2>/dev/null || true)"
            if [[ "$current_sni_line" != "$desired_sni_line" ]]; then
                if awk -v replacement="$desired_sni_line" '
                    $1 == "acl" && $2 == "allowed_sni" && $3 == "req.ssl_sni" && replaced == 0 {
                        print replacement
                        replaced = 1
                        next
                    }
                    { print }
                    END { if (replaced == 0) exit 2 }
                ' "$tmp_cfg" > "$next_cfg"; then
                    mv "$next_cfg" "$tmp_cfg"
                    changed=1
                else
                    rm -f "$desired_file" "$tmp_cfg" "$next_cfg"
                    return 0
                fi
            fi
        elif [[ -n "$desired_target" ]]; then
            :
        else
            rm -f "$desired_file" "$tmp_cfg" "$next_cfg"
            return 0
        fi
    fi

    if (( changed == 0 )); then
        rm -f "$desired_file" "$tmp_cfg" "$next_cfg"
        return 0
    fi

    if ! haproxy -c -f "$tmp_cfg" >/dev/null 2>&1; then
        echo "push ${PUSH_BUILD}: haproxy config skipped, config check failed" >&2
        rm -f "$desired_file" "$tmp_cfg" "$next_cfg"
        return 0
    fi
    if cp "$tmp_cfg" /etc/haproxy/haproxy.cfg 2>/dev/null; then
        if systemctl reload haproxy >/dev/null 2>&1 || systemctl restart haproxy >/dev/null 2>&1; then
            applied=1
        fi
    fi
    rm -f "$desired_file" "$tmp_cfg" "$next_cfg"

    if (( applied == 1 )); then
        if (( has_sni == 1 && has_target == 1 )); then
            echo "push ${PUSH_BUILD}: haproxy target+sni applied"
        elif (( has_target == 1 )); then
            echo "push ${PUSH_BUILD}: haproxy target applied"
        else
            echo "push ${PUSH_BUILD}: allowed_sni applied"
        fi
    fi
}

write_update_result() {
    local job_id="$1" status="$2" message="${3:-}" build="${4:-$PUSH_BUILD}" details="${5:-{}}" details_text="${6:-}" state_dir tmp
    state_dir="$(dirname "$KTO_PUSH_UPDATE_STATE")"
    mkdir -p "$state_dir" 2>/dev/null || true
    message="${message//$'\n'/ }"
    message="${message:0:240}"
    details_text="${details_text:0:4000}"
    if ! printf '%s' "$details" | jq -e 'type == "object"' >/dev/null 2>&1; then
        details='{}'
    fi
    tmp="$(mktemp)"
    if jq -n \
        --arg id "$job_id" \
        --arg status "$status" \
        --arg build "$build" \
        --arg message "$message" \
        --arg details_text "$details_text" \
        --argjson details "$details" \
        --argjson updated_at "$(date +%s)" \
        '{id: $id, status: $status, build: $build, message: $message, updated_at: $updated_at}
        + (if ($details | length) > 0 then {details: $details} else {} end)
        + (if ($details_text | length) > 0 then {details_text: $details_text} else {} end)' > "$tmp" 2>/dev/null; then
        mv "$tmp" "$KTO_PUSH_UPDATE_STATE" 2>/dev/null || rm -f "$tmp"
    else
        rm -f "$tmp"
    fi
}

read_update_result() {
    update_result='{}'
    command -v jq >/dev/null 2>&1 || return 0
    [[ -r "$KTO_PUSH_UPDATE_STATE" ]] || return 0
    update_result="$(jq -c '{
        id: (.id // ""),
        status: (.status // ""),
        build: (.build // ""),
        message: (.message // ""),
        updated_at: (.updated_at // 0),
        details_text: (.details_text // ""),
        details: (.details // {})
    }' "$KTO_PUSH_UPDATE_STATE" 2>/dev/null || echo '{}')"
}

escape_double_quoted_config_value() {
    local value="${1:-}"
    value="${value//$'\r'/}"
    value="${value//$'\n'/}"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//\$/\\\$}"
    value="${value//\`/\\\`}"
    printf '%s' "$value"
}

set_push_config_value() {
    local key="$1" value="$2" escaped tmp line found=0
    [[ -n "$key" && -w "$CONFIG" ]] || return 1
    tmp="$(mktemp)" || return 1
    escaped="$(escape_double_quoted_config_value "$value")"
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" == "${key}="* ]]; then
            if (( found == 0 )); then
                printf '%s="%s"\n' "$key" "$escaped" >> "$tmp"
                found=1
            fi
        else
            printf '%s\n' "$line" >> "$tmp"
        fi
    done < "$CONFIG"
    if (( found == 0 )); then
        printf '%s="%s"\n' "$key" "$escaped" >> "$tmp"
    fi
    if [[ -s "$tmp" ]]; then
        install -m 0600 "$tmp" "$CONFIG"
        rm -f "$tmp"
        return 0
    fi
    rm -f "$tmp"
    return 1
}

generate_node_uuid() {
    local value=""
    if [[ -r /proc/sys/kernel/random/uuid ]]; then
        read -r value < /proc/sys/kernel/random/uuid || true
    elif command -v uuidgen >/dev/null 2>&1; then
        value="$(uuidgen 2>/dev/null || true)"
    fi
    printf '%s' "${value,,}"
}

ensure_node_identity() {
    local inferred_kind lowered_name machine_mode=""
    KTO_PUSH_NODE_UUID="${KTO_PUSH_NODE_UUID,,}"
    if [[ ! "$KTO_PUSH_NODE_UUID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]]; then
        KTO_PUSH_NODE_UUID="$(generate_node_uuid)"
        if [[ ! "$KTO_PUSH_NODE_UUID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]]; then
            echo "push ${PUSH_BUILD}: failed to generate node UUID" >&2
            exit 1
        fi
        if ! set_push_config_value KTO_PUSH_NODE_UUID "$KTO_PUSH_NODE_UUID"; then
            echo "push ${PUSH_BUILD}: failed to persist node UUID" >&2
            exit 1
        fi
    fi
    if [[ "$KTO_PUSH_NODE_KIND" != "wl" && "$KTO_PUSH_NODE_KIND" != "bl" ]]; then
        lowered_name="${KTO_PUSH_NODE_NAME,,}"
        inferred_kind="bl"
        if [[ -r /etc/kto-cfg.conf ]]; then
            machine_mode="$(awk -F= '$1 == "MACHINE_MODE" {gsub(/^"|"$/, "", $2); print tolower($2); exit}' /etc/kto-cfg.conf 2>/dev/null || true)"
        fi
        if [[ "$machine_mode" == "whitelist" ]] || [[ -r /etc/haproxy/haproxy.cfg ]]; then
            inferred_kind="wl"
        elif [[ "$machine_mode" != "node" ]]; then
            case "$lowered_name" in
                *"обход"*|*whitelist*|*haproxy*) inferred_kind="wl" ;;
            esac
        fi
        KTO_PUSH_NODE_KIND="$inferred_kind"
        set_push_config_value KTO_PUSH_NODE_KIND "$KTO_PUSH_NODE_KIND" || true
    fi
}

sha256_text() {
    sha256sum | awk '{print tolower($1)}'
}

hmac_sha256_text() {
    local secret="$1"
    openssl dgst -sha256 -hmac "$secret" 2>/dev/null | awk '{print tolower($NF)}'
}

response_header_value() {
    local file="$1" key="$2"
    awk -F':' -v wanted="$key" '
        tolower($1) == tolower(wanted) {
            sub(/^[^:]*:[[:space:]]*/, "", $0)
            sub(/\r$/, "", $0)
            value = $0
        }
        END { print value }
    ' "$file" 2>/dev/null
}

ensure_node_identity

write_push_timer_interval() {
    local interval="$1" tmp
    [[ "$interval" =~ ^[0-9]+$ ]] || return 1
    tmp="$(mktemp)" || return 1
    cat >"$tmp" <<EOF
[Unit]
Description=kto stats push timer

[Timer]
OnBootSec=20
OnUnitActiveSec=${interval}s
AccuracySec=1s
Unit=kto-stats-push.service

[Install]
WantedBy=timers.target
EOF
    if install -m 0644 "$tmp" /etc/systemd/system/kto-stats-push.timer; then
        rm -f "$tmp"
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl enable --now kto-stats-push.timer >/dev/null 2>&1 || true
        systemctl restart kto-stats-push.timer >/dev/null 2>&1 || true
        return 0
    fi
    rm -f "$tmp"
    return 1
}

apply_collector_push_interval() {
    local response="$1" desired current
    command -v jq >/dev/null 2>&1 || return 0
    desired="$(printf '%s' "$response" | jq -r '.push_interval_sec // empty' 2>/dev/null || true)"
    [[ "$desired" =~ ^[0-9]+$ ]] || return 0
    if (( desired < 1 || desired > 3600 )); then
        return 0
    fi
    current="$(int_or_zero "${KTO_PUSH_INTERVAL:-0}")"
    if [[ "$current" == "$desired" ]]; then
        return 0
    fi
    if set_push_config_value "KTO_PUSH_INTERVAL" "$desired" && write_push_timer_interval "$desired"; then
        KTO_PUSH_INTERVAL="$desired"
        echo "push ${PUSH_BUILD}: interval updated ${current}s -> ${desired}s"
    else
        echo "push ${PUSH_BUILD}: interval update failed ${current}s -> ${desired}s" >&2
    fi
}

update_task_already_finished() {
    local job_id="$1" current_id current_status
    command -v jq >/dev/null 2>&1 || return 1
    [[ -r "$KTO_PUSH_UPDATE_STATE" ]] || return 1
    current_id="$(jq -r '.id // empty' "$KTO_PUSH_UPDATE_STATE" 2>/dev/null || true)"
    current_status="$(jq -r '.status // empty' "$KTO_PUSH_UPDATE_STATE" 2>/dev/null || true)"
    [[ "$current_id" == "$job_id" && ( "$current_status" == "ok" || "$current_status" == "error" ) ]]
}

opt_field() {
    local value="${1:-}"
    value="${value//$'\t'/ }"
    value="${value//$'\r'/ }"
    value="${value//$'\n'/ }"
    printf '%s' "$value"
}

append_optimize_row() {
    local file="$1" id="$2" name="$3" status="$4" current="$5" desired="$6"
    printf '%s\t%s\t%s\t%s\t%s\n' \
        "$(opt_field "$id")" \
        "$(opt_field "$name")" \
        "$(opt_field "$status")" \
        "$(opt_field "$current")" \
        "$(opt_field "$desired")" >> "$file"
}

opt_root_file_has_line() {
    local file="$1" line="$2"
    [[ -r "$file" ]] && grep -Fqx -- "$line" "$file" 2>/dev/null
}

opt_service_active() {
    local service="$1"
    command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$service" >/dev/null 2>&1
}

opt_hostname_hosts_configured() {
    local host short
    [[ -r /etc/hosts ]] || return 1
    host="$(hostname -f 2>/dev/null || hostname 2>/dev/null || true)"
    short="$(hostname -s 2>/dev/null || hostname 2>/dev/null || true)"
    [[ -n "$host$short" ]] || return 1
    awk -v host="$host" -v short="$short" '
        $1 ~ /^#/ { next }
        {
            for (i = 2; i <= NF; i++) {
                if (($i == host && host != "") || ($i == short && short != "")) {
                    found = 1
                }
            }
        }
        END { exit found ? 0 : 1 }
    ' /etc/hosts
}

optimize_check_json() {
    local rows_file cc qdisc sysctl_file_ok limits_ok missing=() service_current host_value
    rows_file="$(mktemp)"

    host_value="$(hostname 2>/dev/null || echo "-")"
    if opt_hostname_hosts_configured; then
        append_optimize_row "$rows_file" "hostname" "hostname" "ok" "$host_value" "/etc/hosts entry"
    else
        append_optimize_row "$rows_file" "hostname" "hostname" "miss" "$host_value" "/etc/hosts entry"
    fi

    cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "-")"
    qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "-")"
    if [[ "$cc" == "bbr" && "$qdisc" == "fq" ]]; then
        append_optimize_row "$rows_file" "bbr_fq" "BBR + FQ" "ok" "${cc} + ${qdisc}" "bbr + fq"
    else
        append_optimize_row "$rows_file" "bbr_fq" "BBR + FQ" "miss" "${cc} + ${qdisc}" "bbr + fq"
    fi

    sysctl_file_ok=1
    opt_root_file_has_line "$KTO_TUNING_SYSCTL_CONF" "net.ipv4.tcp_congestion_control = bbr" || sysctl_file_ok=0
    opt_root_file_has_line "$KTO_TUNING_SYSCTL_CONF" "net.core.default_qdisc = fq" || sysctl_file_ok=0
    opt_root_file_has_line "$KTO_TUNING_SYSCTL_CONF" "fs.file-max = 2097152" || sysctl_file_ok=0
    opt_root_file_has_line "$KTO_TUNING_SYSCTL_CONF" "vm.swappiness = 1" || sysctl_file_ok=0
    if [[ "$sysctl_file_ok" == "1" ]]; then
        append_optimize_row "$rows_file" "sysctl_file" "sysctl file" "ok" "$KTO_TUNING_SYSCTL_CONF" "kto tuning profile"
    else
        append_optimize_row "$rows_file" "sysctl_file" "sysctl file" "miss" "нет или неполный" "$KTO_TUNING_SYSCTL_CONF"
    fi

    limits_ok=1
    opt_root_file_has_line "$KTO_LIMITS_CONF" "* soft nofile 1048576" || limits_ok=0
    opt_root_file_has_line "$KTO_LIMITS_CONF" "* hard nofile 1048576" || limits_ok=0
    opt_root_file_has_line "$KTO_SYSTEMD_LIMITS_CONF" "DefaultLimitNOFILE=1048576" || limits_ok=0
    opt_root_file_has_line "$KTO_USER_LIMITS_CONF" "DefaultLimitNOFILE=1048576" || limits_ok=0
    if [[ "$limits_ok" == "1" ]]; then
        append_optimize_row "$rows_file" "limits" "limits" "ok" "nofile 1048576" "nofile 1048576"
    else
        append_optimize_row "$rows_file" "limits" "limits" "miss" "нет или неполный" "nofile/systemd limits"
    fi

    if command -v systemctl >/dev/null 2>&1; then
        missing=()
        opt_service_active chrony || missing+=("chrony")
        opt_root_file_has_line /etc/default/cpufrequtils 'GOVERNOR="performance"' || missing+=("performance")
        if (( ${#missing[@]} == 0 )); then
            append_optimize_row "$rows_file" "node_services" "node services" "ok" "chrony, performance" "chrony, performance"
        else
            service_current="$(IFS=', '; echo "${missing[*]}")"
            append_optimize_row "$rows_file" "node_services" "node services" "miss" "нет: ${service_current}" "chrony, performance"
        fi
    else
        append_optimize_row "$rows_file" "node_services" "node services" "skip" "systemctl нет" "chrony, performance"
    fi

    jq -R -s -c '
        split("\n")
        | map(select(length > 0) | split("\t") | {
            id: (.[0] // ""),
            name: (.[1] // ""),
            status: (.[2] // "miss"),
            current: (.[3] // "-"),
            desired: (.[4] // "-")
        })
    ' "$rows_file" 2>/dev/null || echo '[]'
    rm -f "$rows_file"
}

optimize_missing_count() {
    printf '%s' "${1:-[]}" | jq '[.[] | select(.status == "miss")] | length' 2>/dev/null || echo 0
}

optimize_status_label() {
    case "${1:-}" in
        ok) printf 'OK' ;;
        skip) printf 'SKIP' ;;
        error) printf 'ERROR' ;;
        *) printf 'NO' ;;
    esac
}

optimize_fit_cell() {
    local value="${1:-}" width="$2"
    value="$(opt_field "$value")"
    if (( ${#value} > width )); then
        value="${value:0:width-1}~"
    fi
    printf "%-${width}s" "$value"
}

optimize_table_text_json() {
    local rows="${1:-[]}" line name status current desired
    {
        printf '%s %s %s %s\n' \
            "$(optimize_fit_cell 'Check' 18)" \
            "$(optimize_fit_cell 'Status' 6)" \
            "$(optimize_fit_cell 'Current' 24)" \
            "Desired"
        printf '%s %s %s %s\n' \
            "------------------" \
            "------" \
            "------------------------" \
            "------------------------"
        printf '%s' "$rows" | jq -r '.[] | [.name, .status, .current, .desired] | @tsv' 2>/dev/null |
            while IFS=$'\t' read -r name status current desired; do
                status="$(optimize_status_label "$status")"
                printf '%s %s %s %s\n' \
                    "$(optimize_fit_cell "$name" 18)" \
                    "$(optimize_fit_cell "$status" 6)" \
                    "$(optimize_fit_cell "$current" 24)" \
                    "$(opt_field "$desired")"
            done
    } | sed '/^[[:space:]]*$/d'
}

status_bool() {
    if [[ "${1:-0}" == "1" || "${1:-}" == "active" || "${1:-}" == "running" ]]; then
        printf 'ok'
    else
        printf 'fail'
    fi
}

status_field() {
    opt_field "$1"
}

append_status_panel_row() {
    local file="$1" section="$2" name="$3" value="$4" status="${5:-info}"
    printf '%s\t%s\t%s\t%s\n' \
        "$(status_field "$section")" \
        "$(status_field "$name")" \
        "$(status_field "$value")" \
        "$(status_field "$status")" >> "$file"
}

kto_cfg_get() {
    local key="$1" file="${2:-/etc/kto-cfg.conf}"
    [[ -r "$file" ]] || return 0
    awk -v key="$key" -F= '
        $1 == key {
            value = $0
            sub(/^[^=]*=/, "", value)
            gsub(/^"/, "", value)
            gsub(/"$/, "", value)
            print value
            exit
        }
    ' "$file" 2>/dev/null || true
}

bytes_to_human() {
    local bytes="${1:-0}"
    [[ "$bytes" =~ ^[0-9]+$ ]] || bytes=0
    awk -v bytes="$bytes" 'BEGIN {
        split("B KB MB GB TB", units, " ")
        value = bytes + 0
        unit = 1
        while (value >= 1024 && unit < 5) {
            value /= 1024
            unit++
        }
        if (unit == 1) {
            printf "%d %s", value, units[unit]
        } else {
            printf "%.1f %s", value, units[unit]
        }
    }'
}

swap_total_bytes() {
    awk '$1 == "SwapTotal:" { print int($2 * 1024); found=1 } END { if (!found) print 0 }' /proc/meminfo 2>/dev/null || echo 0
}

zram_swap_active() {
    awk 'NR > 1 && $1 ~ /zram/ { found=1 } END { exit found ? 0 : 1 }' /proc/swaps 2>/dev/null
}

zram_swap_summary() {
    awk 'NR > 1 && $1 ~ /zram/ { size += $3; used += $4; found=1 } END {
        if (found) {
            printf "%.1f MB / %.1f MB", used / 1024, size / 1024
        }
    }' /proc/swaps 2>/dev/null || true
}

service_active_status() {
    local service="$1"
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$service" >/dev/null 2>&1; then
        printf 'ok'
    else
        printf 'fail'
    fi
}

ufw_allowed_ports_panel() {
    command -v ufw >/dev/null 2>&1 || { printf '-'; return 0; }
    ufw status 2>/dev/null |
        awk '$0 ~ /ALLOW/ && $1 !~ /\[/ { print $1 }' |
        sed 's#/tcp##; s#/udp##' |
        awk '!seen[$0]++' |
        paste -sd ', ' - 2>/dev/null |
        awk 'NF {print; found=1} END {if (!found) print "-"}'
}

antiscanner_rules_count_panel() {
    command -v ufw >/dev/null 2>&1 || { printf '0'; return 0; }
    ufw status 2>/dev/null | grep -c 'AntiScanner-Block' 2>/dev/null || echo 0
}

status_panel_rows_json() {
    local rows_file section cc qdisc mode profile ram_used_b ram_total_b ram_percent available_b swap_b zram_summary kernel cpus
    local docker_status container node_status antiscanner_count
    rows_file="$(mktemp)"

    mode="$(kto_cfg_get MACHINE_MODE)"
    mode="${mode:-node}"
    profile="$(kto_cfg_get NODE_PROFILE)"
    profile="${profile:-reality}"
    cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "-")"
    qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "-")"

    section="СЕТЬ"
    append_status_panel_row "$rows_file" "$section" "mode" "$mode" "info"
    if [[ "$mode" == "node" ]]; then
        append_status_panel_row "$rows_file" "$section" "profile" "$profile" "info"
    fi
    append_status_panel_row "$rows_file" "$section" "BBR + FQ" "${cc} + ${qdisc}" "$([[ "$cc" == "bbr" && "$qdisc" == "fq" ]] && echo ok || echo fail)"
    append_status_panel_row "$rows_file" "$section" "ports" "$(ufw_allowed_ports_panel)" "info"

    read -r ram_used_b ram_total_b ram_percent < <(memory_stats)
    ram_used_b="$(int_or_zero "$ram_used_b")"
    ram_total_b="$(int_or_zero "$ram_total_b")"
    available_b=$(( ram_total_b > ram_used_b ? ram_total_b - ram_used_b : 0 ))
    swap_b="$(swap_total_bytes)"
    swap_b="$(int_or_zero "$swap_b")"
    section="ПАМЯТЬ"
    append_status_panel_row "$rows_file" "$section" "RAM" "$(bytes_to_human "$available_b") / $(bytes_to_human "$ram_total_b")" "info"
    if zram_swap_active; then
        zram_summary="$(zram_swap_summary)"
        append_status_panel_row "$rows_file" "$section" "zram" "${zram_summary:-active}" "ok"
    elif (( swap_b > 0 )); then
        append_status_panel_row "$rows_file" "$section" "swap" "$(bytes_to_human "$swap_b")" "ok"
    else
        append_status_panel_row "$rows_file" "$section" "swap/zram" "none" "fail"
    fi

    section="СЛУЖБЫ"
    append_status_panel_row "$rows_file" "$section" "ufw" "firewall" "$(service_active_status ufw)"
    antiscanner_count="$(antiscanner_rules_count_panel)"
    append_status_panel_row "$rows_file" "$section" "antiscanner" "${antiscanner_count} rules" "$([[ "$antiscanner_count" =~ ^[1-9][0-9]*$ ]] && echo ok || echo fail)"
    if command -v haproxy >/dev/null 2>&1; then
        append_status_panel_row "$rows_file" "$section" "haproxy" "proxy" "$(service_active_status haproxy)"
    fi
    append_status_panel_row "$rows_file" "$section" "fail2ban" "ssh guard" "$(service_active_status fail2ban)"
    append_status_panel_row "$rows_file" "$section" "chrony" "time sync" "$(service_active_status chrony)"
    cpus="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"
    cpus="$(int_or_zero "$cpus")"
    if (( cpus > 1 )); then
        append_status_panel_row "$rows_file" "$section" "irqbalance" "irq" "$(service_active_status irqbalance)"
    else
        append_status_panel_row "$rows_file" "$section" "irqbalance" "single CPU, skip" "info"
    fi

    section="REMNAWAVE"
    if command -v docker >/dev/null 2>&1; then
        docker_status="$(service_active_status docker)"
        append_status_panel_row "$rows_file" "$section" "docker" "engine" "$docker_status"
        container="$(remna_container_name)"
        node_status="$(docker inspect -f '{{.State.Status}}' "$container" 2>/dev/null || echo "not found")"
        append_status_panel_row "$rows_file" "$section" "remnanode" "$node_status" "$([[ "$node_status" == "running" ]] && echo ok || echo fail)"
    else
        append_status_panel_row "$rows_file" "$section" "docker" "not installed" "fail"
        append_status_panel_row "$rows_file" "$section" "remnanode" "not found" "fail"
    fi

    section="ЯДРО"
    kernel="$(uname -r 2>/dev/null || echo "-")"
    append_status_panel_row "$rows_file" "$section" "kernel" "$kernel" "$([[ "$kernel" == *liquorix* ]] && echo ok || echo fail)"

    jq -R -s -c '
        split("\n")
        | map(select(length > 0) | split("\t") | {
            section: (.[0] // ""),
            name: (.[1] // ""),
            value: (.[2] // "-"),
            status: (.[3] // "info")
        })
    ' "$rows_file" 2>/dev/null || echo '[]'
    rm -f "$rows_file"
}

status_panel_fail_count() {
    printf '%s' "${1:-[]}" | jq '[.[] | select(.status == "fail")] | length' 2>/dev/null || echo 0
}

status_panel_table_text_json() {
    local rows="${1:-[]}" section name value status
    {
        printf '%s %s %s %s\n' \
            "$(optimize_fit_cell 'Section' 12)" \
            "$(optimize_fit_cell 'Check' 18)" \
            "$(optimize_fit_cell 'Status' 6)" \
            "Value"
        printf '%s %s %s %s\n' \
            "------------" \
            "------------------" \
            "------" \
            "------------------------"
        printf '%s' "$rows" | jq -r '.[] | [.section, .name, .value, .status] | @tsv' 2>/dev/null |
            while IFS=$'\t' read -r section name value status; do
                case "$status" in
                    ok) status="OK" ;;
                    fail) status="FAIL" ;;
                    warn) status="WARN" ;;
                    *) status="-" ;;
                esac
                printf '%s %s %s %s\n' \
                    "$(optimize_fit_cell "$section" 12)" \
                    "$(optimize_fit_cell "$name" 18)" \
                    "$(optimize_fit_cell "$status" 6)" \
                    "$(opt_field "$value")"
            done
    } | sed '/^[[:space:]]*$/d'
}

optimize_details_json() {
    local mode="$1" before="$2" after="$3"
    jq -n -c \
        --arg mode "$mode" \
        --argjson before "$before" \
        --argjson after "$after" \
        '($before | map(select(.status == "miss"))) as $missing_before |
        ($after | map(select(.status == "miss"))) as $missing_after |
        {
            kind: "optimize",
            mode: $mode,
            before: $before,
            after: $after,
            missing_before: ($missing_before | map(.name)),
            fixed_count: (($missing_before | length) - ($missing_after | length)),
            remaining_count: ($missing_after | length)
        }' 2>/dev/null || echo '{}'
}

optimize_details_fallback_json() {
    local mode="$1" before="$2" after="$3"
    jq -n -c \
        --arg mode "$mode" \
        --argjson before "${before:-[]}" \
        --argjson after "${after:-[]}" \
        '{
            kind: "optimize",
            mode: $mode,
            before: $before,
            after: $after,
            missing_before: ($before | map(select(.status == "miss")) | map(.name)),
            fixed_count: 0,
            remaining_count: ($after | map(select(.status == "miss")) | length)
        }' 2>/dev/null || echo '{}'
}

optimize_status_panel_details_json() {
    local mode="$1" rows="$2"
    jq -n -c \
        --arg mode "$mode" \
        --argjson rows "${rows:-[]}" \
        '{
            kind: "optimize",
            mode: $mode,
            source: "kto_status_panel",
            status_rows: $rows,
            status_fail_count: ($rows | map(select(.status == "fail")) | length)
        }' 2>/dev/null || echo '{}'
}

write_status_panel_result() {
    local job_id="$1" mode="$2" rows="$3" fails="$4" message="$5" details_text tmp state_dir
    details_text="$(status_panel_table_text_json "$rows")"
    state_dir="$(dirname "$KTO_PUSH_UPDATE_STATE")"
    mkdir -p "$state_dir" 2>/dev/null || true
    message="${message//$'\n'/ }"
    message="${message:0:240}"
    details_text="${details_text:0:4000}"
    tmp="$(mktemp)"
    if jq -n \
        --arg id "$job_id" \
        --arg status "ok" \
        --arg build "$PUSH_BUILD" \
        --arg message "$message" \
        --arg mode "$mode" \
        --arg details_text "$details_text" \
        --argjson rows "${rows:-[]}" \
        --argjson fails "$(int_or_zero "$fails")" \
        --argjson updated_at "$(date +%s)" \
        '{
            id: $id,
            status: $status,
            build: $build,
            message: $message,
            updated_at: $updated_at,
            details_text: $details_text,
            status_rows: $rows,
            details: {
                kind: "optimize",
                mode: $mode,
                source: "kto_status_panel",
                status_rows: $rows,
                status_fail_count: $fails
            }
        }' > "$tmp" 2>/dev/null; then
        mv "$tmp" "$KTO_PUSH_UPDATE_STATE" 2>/dev/null || rm -f "$tmp"
        return 0
    fi
    rm -f "$tmp"
    write_update_result "$job_id" "ok" "$message" "$PUSH_BUILD" "{}" "$details_text"
}

optimize_ensure_hostname_hosts() {
    local host short tmp
    opt_hostname_hosts_configured && return 0
    host="$(hostname -f 2>/dev/null || hostname 2>/dev/null || true)"
    short="$(hostname -s 2>/dev/null || hostname 2>/dev/null || true)"
    [[ -n "$host$short" ]] || return 0
    tmp="$(mktemp)"
    if [[ -r /etc/hosts ]]; then
        cat /etc/hosts > "$tmp" 2>/dev/null || true
    fi
    printf '127.0.1.1 %s %s\n' "${host:-$short}" "${short:-$host}" >> "$tmp"
    install -m 0644 "$tmp" /etc/hosts 2>/dev/null || true
    rm -f "$tmp"
}

optimize_apply_system() {
    local tmp
    [[ "${EUID:-$(id -u)}" == "0" ]] || return 1

    optimize_ensure_hostname_hosts
    modprobe tcp_bbr >/dev/null 2>&1 || true
    mkdir -p /etc/sysctl.d /etc/security/limits.d /etc/systemd/system.conf.d /etc/systemd/user.conf.d 2>/dev/null || true

    tmp="$(mktemp)"
    cat >"$tmp" <<'EOF'
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
    install -m 0644 "$tmp" "$KTO_TUNING_SYSCTL_CONF" 2>/dev/null || true
    rm -f "$tmp"
    sysctl --system >/dev/null 2>&1 || true

    tmp="$(mktemp)"
    cat >"$tmp" <<'EOF'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF
    install -m 0644 "$tmp" "$KTO_LIMITS_CONF" 2>/dev/null || true
    rm -f "$tmp"

    tmp="$(mktemp)"
    cat >"$tmp" <<'EOF'
[Manager]
DefaultLimitNOFILE=1048576
EOF
    install -m 0644 "$tmp" "$KTO_SYSTEMD_LIMITS_CONF" 2>/dev/null || true
    install -m 0644 "$tmp" "$KTO_USER_LIMITS_CONF" 2>/dev/null || true
    rm -f "$tmp"

    if command -v apt-get >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y chrony cpufrequtils >/dev/null 2>&1 || true
    fi
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl enable --now chrony >/dev/null 2>&1 || true
        tmp="$(mktemp)"
        printf '%s\n' 'GOVERNOR="performance"' > "$tmp"
        install -m 0644 "$tmp" /etc/default/cpufrequtils 2>/dev/null || true
        rm -f "$tmp"
        systemctl restart cpufrequtils >/dev/null 2>&1 || true
    fi
    return 0
}

apply_optimize_task() {
    local job_id="$1" mode="$2" before after before_missing remaining details details_text status message panel_rows panel_fails
    mode="${mode:-status}"
    write_update_result "$job_id" "running" "optimize ${mode} started"

    if [[ "$mode" == "status" ]]; then
        panel_rows="$(status_panel_rows_json)"
        panel_fails="$(status_panel_fail_count "$panel_rows")"
        message="status panel, fail=${panel_fails}"
        write_status_panel_result "$job_id" "$mode" "$panel_rows" "$panel_fails" "$message"
        echo "push ${PUSH_BUILD}: optimize ${mode} status=ok panel_fails=${panel_fails}"
        return 0
    fi

    before="$(optimize_check_json)"
    before_missing="$(optimize_missing_count "$before")"
    if [[ "$mode" == "apply" && "$before_missing" =~ ^[0-9]+$ && "$before_missing" -gt 0 ]]; then
        optimize_apply_system || true
    fi
    after="$(optimize_check_json)"
    remaining="$(optimize_missing_count "$after")"
    details="$(optimize_details_json "$mode" "$before" "$after")"
    if ! printf '%s' "$details" | jq -e '.kind == "optimize" and (.after | type == "array") and (.after | length > 0)' >/dev/null 2>&1; then
        details="$(optimize_details_fallback_json "$mode" "$before" "$after")"
    fi
    details_text="$(optimize_table_text_json "$after")"
    panel_rows="$(status_panel_rows_json)"
    if printf '%s' "$panel_rows" | jq -e 'type == "array" and length > 0' >/dev/null 2>&1; then
        details="$(jq -n -c --argjson details "$details" --argjson rows "$panel_rows" '$details + {source: "kto_status_panel", status_rows: $rows, status_fail_count: ($rows | map(select(.status == "fail")) | length)}' 2>/dev/null || printf '%s' "$details")"
    fi

    status="ok"
    if [[ "$mode" == "apply" ]]; then
        if [[ "$remaining" =~ ^[0-9]+$ && "$remaining" -gt 0 ]]; then
            status="error"
            message="optimize applied, remaining=${remaining}"
        elif [[ "$before_missing" =~ ^[0-9]+$ && "$before_missing" -gt 0 ]]; then
            message="optimize applied, fixed=${before_missing}"
        else
            message="already optimized"
        fi
    else
        if [[ "$remaining" =~ ^[0-9]+$ && "$remaining" -gt 0 ]]; then
            message="missing=${remaining}"
        else
            message="all ok"
        fi
    fi

    write_update_result "$job_id" "$status" "$message" "$PUSH_BUILD" "$details" "$details_text"
    echo "push ${PUSH_BUILD}: optimize ${mode} status=${status} before=${before_missing} remaining=${remaining}"
}

apply_collector_update_task() {
    local response="$1"
    local job_id action raw_base tmp err_file message new_build script_size backup

    command -v jq >/dev/null 2>&1 || return 0
    printf '%s' "$response" | jq -e 'has("update_task") and (.update_task | type == "object")' >/dev/null 2>&1 || return 0

    job_id="$(printf '%s' "$response" | jq -r '.update_task.id // empty' 2>/dev/null || true)"
    action="$(printf '%s' "$response" | jq -r '.update_task.action // empty' 2>/dev/null || true)"
    [[ -n "$job_id" ]] || return 0
    if update_task_already_finished "$job_id"; then
        return 0
    fi

    if [[ "$action" == "node_update" ]]; then
        apply_node_update_task "$job_id"
        return 0
    fi

    if [[ "$action" == "push_delete" ]]; then
        apply_push_delete_task "$job_id"
        return 0
    fi

    if [[ "$action" == "optimize" ]]; then
        apply_optimize_task "$job_id" "apply"
        return 0
    fi

    if [[ "$action" == "optimize_status" ]]; then
        apply_optimize_task "$job_id" "status"
        return 0
    fi

    [[ "$action" == "push_update" ]] || return 0
    command -v curl >/dev/null 2>&1 || return 0
    command -v bash >/dev/null 2>&1 || return 0
    # The collector may request an action, but the node chooses its trusted update source.
    raw_base="$KTO_UPDATE_RAW_BASE"
    raw_base="${raw_base%/}"
    if [[ ! "$raw_base" =~ ^https:// ]] && [[ "$KTO_ALLOW_INSECURE_UPDATE_URL" != "1" ]]; then
        write_update_result "$job_id" "error" "insecure update URL rejected"
        echo "push ${PUSH_BUILD}: insecure update URL rejected: ${raw_base}" >&2
        return 0
    fi

    write_update_result "$job_id" "running" "push update started"
    tmp="$(mktemp)"
    err_file="$(mktemp)"
    if ! curl -fsSL "${raw_base}/scripts/kto-stats-push.sh" -o "$tmp" 2>"$err_file"; then
        message="curl failed: $(tr '\n' ' ' <"$err_file" 2>/dev/null || true)"
        rm -f "$tmp" "$err_file"
        write_update_result "$job_id" "error" "$message"
        echo "push ${PUSH_BUILD}: update failed: ${message}" >&2
        return 0
    fi
    rm -f "$err_file"

    script_size="$(wc -c < "$tmp" 2>/dev/null || echo 0)"
    if [[ ! "$script_size" =~ ^[0-9]+$ ]] || (( script_size < 10000 || script_size > 1048576 )); then
        rm -f "$tmp"
        write_update_result "$job_id" "error" "downloaded push script has invalid size"
        echo "push ${PUSH_BUILD}: update failed: invalid script size ${script_size}" >&2
        return 0
    fi
    if [[ "$(head -n 1 "$tmp" 2>/dev/null || true)" != "#!/usr/bin/env bash" ]]; then
        rm -f "$tmp"
        write_update_result "$job_id" "error" "downloaded push script has invalid header"
        echo "push ${PUSH_BUILD}: update failed: invalid script header" >&2
        return 0
    fi
    if ! bash -n "$tmp" >/dev/null 2>&1; then
        rm -f "$tmp"
        write_update_result "$job_id" "error" "downloaded push script failed bash -n"
        echo "push ${PUSH_BUILD}: update failed: downloaded push script failed bash -n" >&2
        return 0
    fi
    new_build="$(awk -F= '$1 == "PUSH_BUILD" { gsub(/"/, "", $2); print $2; exit }' "$tmp" 2>/dev/null || true)"
    if [[ ! "$new_build" =~ ^v[0-9]+$ ]]; then
        rm -f "$tmp"
        write_update_result "$job_id" "error" "downloaded push script has invalid build"
        echo "push ${PUSH_BUILD}: update failed: invalid build marker" >&2
        return 0
    fi
    backup="/usr/local/bin/kto-stats-push.prev"
    if [[ -f /usr/local/bin/kto-stats-push ]]; then
        cp -f /usr/local/bin/kto-stats-push "$backup" 2>/dev/null || true
    fi
    if install -m 0755 "$tmp" /usr/local/bin/kto-stats-push 2>/dev/null; then
        rm -f "$tmp"
        write_update_result "$job_id" "ok" "push script updated" "$new_build"
        echo "push ${PUSH_BUILD}: push script updated job=${job_id}"
    else
        rm -f "$tmp"
        write_update_result "$job_id" "error" "install /usr/local/bin/kto-stats-push failed"
        echo "push ${PUSH_BUILD}: update failed: install /usr/local/bin/kto-stats-push failed" >&2
    fi
}

apply_push_delete_task() {
    local job_id="$1"
    write_update_result "$job_id" "ok" "push deleted" "$PUSH_BUILD"
    echo "push ${PUSH_BUILD}: deleting push service by collector request"
    systemctl disable --now kto-stats-push.timer >/dev/null 2>&1 || true
    systemctl disable kto-stats-push.service >/dev/null 2>&1 || true
    rm -f \
        /etc/kto-stats-push.conf \
        /etc/systemd/system/kto-stats-push.timer \
        /etc/systemd/system/kto-stats-push.service \
        /usr/local/bin/kto-stats-push
    rm -rf /var/lib/kto-stats-push
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl reset-failed kto-stats-push.timer kto-stats-push.service >/dev/null 2>&1 || true
}

apply_node_update_task() {
    local job_id="$1" container compose_dir err_file message

    command -v docker >/dev/null 2>&1 || {
        write_update_result "$job_id" "error" "docker not found"
        return 0
    }
    if ! docker compose version >/dev/null 2>&1; then
        write_update_result "$job_id" "error" "docker compose not found"
        return 0
    fi

    container="$(remna_container_name)"
    compose_dir="$(detect_remna_compose_dir "$container" 2>/dev/null || true)"
    if [[ -z "$compose_dir" ]]; then
        write_update_result "$job_id" "error" "compose dir not found"
        return 0
    fi

    write_update_result "$job_id" "running" "node update started"
    err_file="$(mktemp)"
    if (
        cd "$compose_dir" &&
        docker compose pull &&
        docker compose up -d --remove-orphans &&
        docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null | grep -qx true
    ) >"$err_file" 2>&1; then
        rm -f "$err_file"
        write_update_result "$job_id" "ok" "node updated"
        echo "push ${PUSH_BUILD}: node updated dir=${compose_dir}"
    else
        message="$(tail -n 20 "$err_file" 2>/dev/null | tr '\n' ' ' | cut -c1-220)"
        rm -f "$err_file"
        write_update_result "$job_id" "error" "${message:-node update failed}"
        echo "push ${PUSH_BUILD}: node update failed: ${message:-unknown}" >&2
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
    local now state_dir desired_file merged_file active_file previous_file ip _expires _user chain applied=0 removed=0

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

    while IFS=$'\t' read -r ip _expires _user; do
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

    while IFS=$'\t' read -r ip _expires _user; do
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

normalize_node_name_from_collector() {
    local value="${1:-}"
    value="${value//$'\r'/ }"
    value="${value//$'\n'/ }"
    value="$(printf '%s' "$value" | awk '{$1=$1; print}' 2>/dev/null || true)"
    [[ -n "$value" && ${#value} -le 120 ]] || return 1
    [[ "$value" != *\"* && "$value" != *\\* && "$value" != *'$'* && "$value" != *'`'* ]] || return 1
    printf '%s\n' "$value"
}

apply_collector_node_name_config() {
    local response="$1" desired changed=0
    command -v jq >/dev/null 2>&1 || return 0
    desired="$(printf '%s' "$response" | jq -r '.node_name // empty' 2>/dev/null || true)"
    [[ -n "$desired" ]] || return 0
    desired="$(normalize_node_name_from_collector "$desired" 2>/dev/null || true)"
    [[ -n "$desired" ]] || return 0
    [[ "$desired" != "$KTO_PUSH_NODE_NAME" ]] || return 0
    if [[ "$desired" != "$KTO_PUSH_NODE_NAME" ]]; then
        if set_push_config_value "KTO_PUSH_NODE_NAME" "$desired"; then
            changed=1
        else
            echo "push ${PUSH_BUILD}: node name config write failed" >&2
        fi
    fi
    if (( changed == 1 )); then
        echo "push ${PUSH_BUILD}: node name=${desired} (next run)"
    fi
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
read_haproxy_backend_target
read_remna_diagnostics
read_ip_limit_events
read_update_result

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
    --arg node_uuid "$KTO_PUSH_NODE_UUID" \
    --arg node_kind "$KTO_PUSH_NODE_KIND" \
    --arg push_build "$PUSH_BUILD" \
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
    --argjson push_interval_sec "$(int_or_zero "$KTO_PUSH_INTERVAL")" \
    --argjson scan_wrong_sni_total "$scan_wrong_sni_total" \
    --argjson scan_wrong_sni_sources "$scan_wrong_sni_sources" \
    --argjson scan_wrong_sni_top "$scan_wrong_sni_top" \
    --argjson scan_wrong_sni_names "$scan_wrong_sni_names" \
    --argjson haproxy_allowed_sni "$haproxy_allowed_sni" \
    --arg haproxy_backend_target "$haproxy_backend_target" \
    --arg remna_status "$remna_status" \
    --argjson remna_restarts "$remna_restarts" \
    --argjson remna_error_count "$remna_error_count" \
    --arg remna_last_error "$remna_last_error" \
    --arg remna_compose_dir "$remna_compose_dir" \
    --argjson ip_limit_events "$ip_limit_events" \
    --argjson update_result "$update_result" \
    --argjson updated_at "$updated_at" \
    '{
        id: $id,
        name: $name,
        node_uuid: $node_uuid,
        node_kind: $node_kind,
        push_build: $push_build,
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
        push_interval_sec: $push_interval_sec,
        scan_wrong_sni_total: $scan_wrong_sni_total,
        scan_wrong_sni_sources: $scan_wrong_sni_sources,
        scan_wrong_sni_top: $scan_wrong_sni_top,
        scan_wrong_sni_names: $scan_wrong_sni_names,
        haproxy_allowed_sni: $haproxy_allowed_sni,
        haproxy_backend_target: $haproxy_backend_target,
        remna: {
            status: $remna_status,
            restarts: $remna_restarts,
            error_count: $remna_error_count,
            last_error: $remna_last_error,
            compose_dir: $remna_compose_dir
        },
        ip_limit_events: $ip_limit_events,
        update_result: $update_result,
        error: $error,
        updated_at: $updated_at
    }' 2>&1)"; then
    echo "push ${PUSH_BUILD}: jq payload failed: ${payload}" >&2
    exit 1
fi

curl_errors="$(mktemp)"
response_headers="$(mktemp)"
request_timestamp="$(date +%s)"
request_nonce=""
request_signature=""
request_signed=0
curl_headers=(-H "Content-Type: application/json")
if command -v openssl >/dev/null 2>&1 && command -v sha256sum >/dev/null 2>&1; then
    request_nonce="$(tr -d '-' < /proc/sys/kernel/random/uuid 2>/dev/null || true)"
    if [[ "$request_nonce" =~ ^[0-9a-fA-F]{16,64}$ ]]; then
        payload_hash="$(printf '%s' "$payload" | sha256_text)"
        request_signature="$(printf 'kto-v2\n%s\n%s\n%s' "$request_timestamp" "$request_nonce" "$payload_hash" | hmac_sha256_text "$KTO_PUSH_SECRET" || true)"
        if [[ "$request_signature" =~ ^[0-9a-f]{64}$ ]]; then
            request_signed=1
            curl_headers+=(
                -H "X-KTO-Timestamp: ${request_timestamp}"
                -H "X-KTO-Nonce: ${request_nonce}"
                -H "X-KTO-Signature: ${request_signature}"
            )
        fi
    fi
fi
if (( request_signed == 0 )) && [[ "$KTO_PUSH_REQUIRE_SIGNED_RESPONSE" == "1" ]]; then
    echo "push ${PUSH_BUILD}: signed transport unavailable" >&2
    rm -f "$curl_errors" "$response_headers"
    exit 1
fi
if [[ "$KTO_PUSH_REQUIRE_SIGNED_RESPONSE" != "1" ]]; then
    curl_headers+=(-H "Authorization: Bearer ${KTO_PUSH_SECRET}")
fi

if response="$(curl -4 -fsS --connect-timeout 8 --max-time 20 \
    -X POST "$collector_url" \
    -D "$response_headers" \
    "${curl_headers[@]}" \
    --data-binary "$payload" 2>"$curl_errors")"; then
    :
else
    rc=$?
    echo "push ${PUSH_BUILD}: curl failed rc=${rc}: $(tr '\n' ' ' < "$curl_errors")" >&2
    rm -f "$curl_errors" "$response_headers"
    exit "$rc"
fi
rm -f "$curl_errors"

response_signature="$(response_header_value "$response_headers" X-KTO-Response-Signature)"
response_nonce="$(response_header_value "$response_headers" X-KTO-Nonce)"
if [[ -n "$response_signature" ]]; then
    response_hash="$(printf '%s' "$response" | sha256_text)"
    expected_response_signature="$(printf 'kto-v2\n%s\n%s' "$request_nonce" "$response_hash" | hmac_sha256_text "$KTO_PUSH_SECRET" || true)"
    if (( request_signed == 0 )) || [[ "$response_nonce" != "$request_nonce" ]] || [[ ! "$response_signature" =~ ^[0-9a-fA-F]{64}$ ]] || [[ "${response_signature,,}" != "$expected_response_signature" ]]; then
        echo "push ${PUSH_BUILD}: collector response signature is invalid" >&2
        rm -f "$response_headers"
        exit 1
    fi
    if [[ "$KTO_PUSH_REQUIRE_SIGNED_RESPONSE" != "1" ]]; then
        if set_push_config_value KTO_PUSH_REQUIRE_SIGNED_RESPONSE 1; then
            KTO_PUSH_REQUIRE_SIGNED_RESPONSE=1
        else
            echo "push ${PUSH_BUILD}: signed response verified, but pinning failed" >&2
        fi
    fi
elif [[ "$KTO_PUSH_REQUIRE_SIGNED_RESPONSE" == "1" ]]; then
    echo "push ${PUSH_BUILD}: collector returned an unsigned response" >&2
    rm -f "$response_headers"
    exit 1
fi
rm -f "$response_headers"

if printf '%s' "$response" | jq -e '.ok == true' >/dev/null 2>&1; then
    ip_limit_extra=""
    if ip_limit_enabled; then
        ip_limit_extra=" ip_events=${ip_limit_events_count}"
    fi
    apply_collector_ssh_ips "$response"
    apply_collector_haproxy_config "$response"
    apply_collector_node_name_config "$response"
    apply_collector_ip_limit_config "$response"
    apply_collector_push_interval "$response"
    apply_ip_limit_blocks "$response"
    apply_collector_update_task "$response"
    echo "push ${PUSH_BUILD}: ok node=${KTO_PUSH_NODE_NAME} ram=${ram_percent}% cpu=${cpu_percent}% uptime=${uptime_sec}s${ip_limit_extra}"
else
    echo "push ${PUSH_BUILD}: bad response: ${response}" >&2
    exit 1
fi
