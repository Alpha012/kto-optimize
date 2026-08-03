#!/usr/bin/env bash
# shellcheck shell=bash

set -Eeuo pipefail
IFS=$'\n\t'

ADDITIONAL_IP_BUILD="v254"
MANAGED_NETPLAN_FILE="${KTO_ADDITIONAL_IP_NETPLAN_FILE:-/etc/netplan/90-kto-extra-nics.yaml}"
LEGACY_ALIAS_NETPLAN_FILE="${KTO_ADDITIONAL_IP_LEGACY_NETPLAN_FILE:-/etc/netplan/90-kto-extra-ips.yaml}"
MANAGED_SYSCTL_FILE="${KTO_ADDITIONAL_IP_SYSCTL_FILE:-/etc/sysctl.d/99-z-kto-multiwan.conf}"
METADATA_URL="${KTO_OPENSTACK_METADATA_URL:-http://169.254.169.254/openstack/latest/network_data.json}"
LOG_FILE="${KTO_ADDITIONAL_IP_LOG_FILE:-/var/log/kto-additional-ips.log}"
DHCP_WAIT_SEC="${KTO_ADDITIONAL_IP_DHCP_WAIT_SEC:-45}"

info() { printf '[..] %s\n' "$*"; }
ok() { printf '[OK] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
fail() { printf '[ОШИБКА] %s\n' "$*" >&2; }

init_log() {
    local directory
    directory="$(dirname "$LOG_FILE")"
    mkdir -p "$directory"
    touch "$LOG_FILE"
    chmod 0644 "$LOG_FILE" 2>/dev/null || true
    printf '===== kto-additional-ips %s %s =====\n' "$ADDITIONAL_IP_BUILD" "$(date -Is)" >> "$LOG_FILE"
}

require_root() {
    if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
        fail "Запусти через sudo или от root."
        return 1
    fi
}

require_commands() {
    local command_name missing=()
    for command_name in curl python3 ip netplan sysctl; do
        command -v "$command_name" >/dev/null 2>&1 || missing+=("$command_name")
    done
    if (( ${#missing[@]} > 0 )); then
        fail "Не найдены команды: ${missing[*]}"
        return 1
    fi
}

primary_interface() {
    ip -4 route get 1.1.1.1 2>/dev/null |
        awk '{for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}' || true
}

primary_ipv4() {
    ip -4 route get 1.1.1.1 2>/dev/null |
        awk '{for (i=1; i<=NF; i++) if ($i == "src") {print $(i+1); exit}}' || true
}

primary_route_metric() {
    local interface="$1"
    ip -4 route show default dev "$interface" 2>/dev/null |
        awk 'NR == 1 {for (i=1; i<=NF; i++) if ($i == "metric") {print $(i+1); exit}}' || true
}

interface_mac() {
    local interface="$1"
    tr '[:upper:]' '[:lower:]' < "/sys/class/net/${interface}/address" 2>/dev/null || true
}

interface_for_mac() {
    local wanted="${1,,}" path current
    for path in /sys/class/net/*/address; do
        [[ -r "$path" ]] || continue
        read -r current < "$path" || continue
        if [[ "${current,,}" == "$wanted" ]]; then
            basename "$(dirname "$path")"
            return 0
        fi
    done
    return 1
}

fetch_openstack_metadata() {
    local output="$1" temporary url
    local urls=(
        "$METADATA_URL"
        "http://169.254.169.254/openstack/2018-08-27/network_data.json"
    )
    temporary="$(mktemp)"

    for url in "${urls[@]}"; do
        if curl -fsS --noproxy '*' --connect-timeout 5 --max-time 12 "$url" -o "$temporary" >> "$LOG_FILE" 2>&1 &&
            python3 - "$temporary" >> "$LOG_FILE" 2>&1 <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    data = json.load(source)
if not isinstance(data.get("links"), list) or not isinstance(data.get("networks"), list):
    raise SystemExit(1)
PY
        then
            mv "$temporary" "$output"
            return 0
        fi
    done

    rm -f "$temporary"
    return 1
}

openstack_ipv4_port_macs() {
    local metadata_file="$1"
    python3 - "$metadata_file" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    data = json.load(source)

links = {
    item.get("id"): str(item.get("ethernet_mac_address", "")).lower()
    for item in data.get("links", [])
}
seen = set()
for network in data.get("networks", []):
    if network.get("type") != "ipv4_dhcp":
        continue
    mac = links.get(network.get("link"), "")
    if not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", mac):
        continue
    if mac not in seen:
        seen.add(mac)
        print(mac)
PY
}

rescan_network_links() {
    if [[ -w /sys/bus/pci/rescan ]]; then
        printf '1\n' > /sys/bus/pci/rescan 2>> "$LOG_FILE" || true
    fi
    command -v udevadm >/dev/null 2>&1 && udevadm settle >> "$LOG_FILE" 2>&1 || true
}

render_netplan() {
    local state_file="$1" output_file="$2"
    local name mac metric ip_cidr gateway network_cidr table priority source_ip

    {
        cat <<'EOF'
# Managed by kto-additional-ips. Re-run the kto menu to refresh it.
network:
  version: 2
  ethernets:
EOF
        while IFS='|' read -r name mac metric ip_cidr gateway network_cidr table priority; do
            [[ -n "$name" && -n "$mac" && -n "$metric" ]] || continue
            cat <<EOF
    ${name}:
      match:
        macaddress: "${mac}"
      set-name: ${name}
      dhcp4: true
      dhcp6: false
      optional: true
      dhcp4-overrides:
        route-metric: ${metric}
        use-dns: false
EOF
            if [[ -n "$ip_cidr" && -n "$gateway" && -n "$network_cidr" && -n "$table" && -n "$priority" ]]; then
                source_ip="${ip_cidr%%/*}"
                cat <<EOF
      routes:
        - to: ${network_cidr}
          scope: link
          table: ${table}
        - to: 0.0.0.0/0
          via: ${gateway}
          on-link: true
          table: ${table}
      routing-policy:
        - from: ${source_ip}/32
          table: ${table}
          priority: ${priority}
EOF
            fi
        done < "$state_file"
    } > "$output_file"
}

main_route_healthy() {
    local expected_interface="$1" expected_ip="$2" route
    route="$(ip -4 route get 1.1.1.1 2>/dev/null || true)"
    [[ " $route " == *" dev ${expected_interface} "* && " $route " == *" src ${expected_ip} "* ]]
}

restore_managed_netplan() {
    local backup_file="$1" had_previous="$2"
    if (( had_previous == 1 )); then
        install -m 0600 "$backup_file" "$MANAGED_NETPLAN_FILE"
    else
        rm -f "$MANAGED_NETPLAN_FILE"
    fi
    netplan generate >> "$LOG_FILE" 2>&1 || true
    netplan apply >> "$LOG_FILE" 2>&1 || true
}

apply_managed_netplan() {
    local candidate="$1" expected_interface="$2" expected_ip="$3"
    local backup_file had_previous=0
    backup_file="$(mktemp)"

    mkdir -p "$(dirname "$MANAGED_NETPLAN_FILE")"
    if [[ -f "$MANAGED_NETPLAN_FILE" ]]; then
        had_previous=1
        cp -a "$MANAGED_NETPLAN_FILE" "$backup_file"
        cp -a "$MANAGED_NETPLAN_FILE" "${MANAGED_NETPLAN_FILE}.kto.bak" 2>> "$LOG_FILE" || true
    fi
    install -m 0600 "$candidate" "$MANAGED_NETPLAN_FILE"

    if ! netplan generate >> "$LOG_FILE" 2>&1; then
        fail "Netplan не принял сгенерированный конфиг. Возвращаю предыдущий."
        restore_managed_netplan "$backup_file" "$had_previous"
        rm -f "$backup_file"
        return 1
    fi
    if ! netplan apply >> "$LOG_FILE" 2>&1; then
        fail "Netplan не применился. Возвращаю предыдущий конфиг."
        restore_managed_netplan "$backup_file" "$had_previous"
        rm -f "$backup_file"
        return 1
    fi

    sleep 2
    if ! main_route_healthy "$expected_interface" "$expected_ip"; then
        fail "Основной маршрут изменился. Конфиг автоматически откачен."
        restore_managed_netplan "$backup_file" "$had_previous"
        rm -f "$backup_file"
        return 1
    fi

    rm -f "$backup_file"
    return 0
}

renew_interfaces() {
    local interface
    for interface in "$@"; do
        ip link show "$interface" >/dev/null 2>&1 || continue
        ip link set dev "$interface" up >> "$LOG_FILE" 2>&1 || true
        if command -v networkctl >/dev/null 2>&1; then
            networkctl reconfigure "$interface" >> "$LOG_FILE" 2>&1 || true
            networkctl renew "$interface" >> "$LOG_FILE" 2>&1 || true
        fi
    done
}

interface_ipv4_cidr() {
    local interface="$1"
    ip -4 -o address show dev "$interface" scope global 2>/dev/null |
        awk 'NR == 1 {print $4}' || true
}

interface_gateway() {
    local interface="$1"
    ip -4 route show default dev "$interface" 2>/dev/null |
        awk 'NR == 1 {print $3}' || true
}

network_for_cidr() {
    local cidr="$1"
    python3 -c 'import ipaddress,sys; print(ipaddress.ip_interface(sys.argv[1]).network)' "$cidr"
}

wait_for_dhcp() {
    local attempt interface ready
    local -a interfaces=("$@")

    for (( attempt=1; attempt<=DHCP_WAIT_SEC; attempt++ )); do
        ready=1
        for interface in "${interfaces[@]}"; do
            if [[ -z "$(interface_ipv4_cidr "$interface")" || -z "$(interface_gateway "$interface")" ]]; then
                ready=0
                break
            fi
        done
        (( ready == 1 )) && return 0
        if (( attempt % 10 == 0 )); then
            renew_interfaces "${interfaces[@]}"
        fi
        sleep 1
    done
    return 1
}

write_multiwan_sysctl() {
    local temporary
    temporary="$(mktemp)"
    cat > "$temporary" <<'EOF'
# Managed by kto-additional-ips.
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
net.ipv4.conf.all.arp_filter=1
net.ipv4.conf.default.arp_filter=1
net.ipv4.conf.all.arp_ignore=1
net.ipv4.conf.default.arp_ignore=1
net.ipv4.conf.all.arp_announce=2
net.ipv4.conf.default.arp_announce=2
EOF
    install -m 0644 "$temporary" "$MANAGED_SYSCTL_FILE"
    rm -f "$temporary"
    sysctl -p "$MANAGED_SYSCTL_FILE" >> "$LOG_FILE" 2>&1
}

disable_legacy_alias_file() {
    local state_file="$1" result_variable="$2" ip_cidr ip backup found=0
    [[ -f "$LEGACY_ALIAS_NETPLAN_FILE" ]] || return 1

    while IFS='|' read -r _ _ _ ip_cidr _; do
        [[ -n "$ip_cidr" ]] || continue
        ip="${ip_cidr%%/*}"
        if grep -Fq "$ip" "$LEGACY_ALIAS_NETPLAN_FILE"; then
            found=1
            break
        fi
    done < "$state_file"

    if (( found == 1 )); then
        backup="${LEGACY_ALIAS_NETPLAN_FILE}.kto-disabled"
        if [[ -e "$backup" ]]; then
            backup="${backup}.$(date +%s)"
        fi
        mv "$LEGACY_ALIAS_NETPLAN_FILE" "$backup"
        printf -v "$result_variable" '%s' "$backup"
        warn "Отключён старый конфиг с IP-алиасами: ${LEGACY_ALIAS_NETPLAN_FILE}"
        return 0
    fi
    return 1
}

restore_legacy_alias_file() {
    local backup="$1"
    [[ -n "$backup" && -f "$backup" ]] || return 0
    mv "$backup" "$LEGACY_ALIAS_NETPLAN_FILE"
    netplan generate >> "$LOG_FILE" 2>&1 || true
    netplan apply >> "$LOG_FILE" 2>&1 || true
    warn "Старый конфиг IP-алиасов возвращён после неудачного применения Netplan."
}

remove_duplicate_primary_addresses() {
    local primary="$1" state_file="$2" ip_cidr ip duplicate
    while IFS='|' read -r _ _ _ ip_cidr _; do
        [[ -n "$ip_cidr" ]] || continue
        ip="${ip_cidr%%/*}"
        while read -r duplicate; do
            [[ -n "$duplicate" ]] || continue
            ip address del "$duplicate" dev "$primary" >> "$LOG_FILE" 2>&1 || true
            warn "Убран дубликат ${duplicate} с основного интерфейса ${primary}"
        done < <(ip -4 -o address show dev "$primary" 2>/dev/null |
            awk -v wanted="$ip" '{split($4, value, "/"); if (value[1] == wanted) print $4}')
    done < "$state_file"
}

bound_public_ip() {
    local source_ip="$1" url output
    local urls=(
        "https://api.ipify.org"
        "https://ifconfig.me/ip"
        "https://icanhazip.com"
    )
    for url in "${urls[@]}"; do
        output="$(curl -q -4 --noproxy '*' --interface "$source_ip" -fsS --connect-timeout 8 --max-time 12 "$url" 2>> "$LOG_FILE" || true)"
        output="${output//$'\r'/}"
        output="${output//$'\n'/}"
        if [[ "$output" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            printf '%s\n' "$output"
            return 0
        fi
    done
    return 1
}

print_result_table() {
    local primary_interface_name="$1" primary_ip="$2" state_file="$3"
    local name mac metric ip_cidr gateway network_cidr table priority ip route external status
    local total=0 working=0 direct=0 nat=0

    printf '\n%-8s %-16s %-16s %-7s %-16s %s\n' "Интерф." "IP" "Шлюз" "Таблица" "Внешний IP" "Статус"
    printf '%-8s %-16s %-16s %-7s %-16s %s\n' "--------" "----------------" "----------------" "-------" "----------------" "------"
    external="$(bound_public_ip "$primary_ip" || true)"
    if [[ "$external" == "$primary_ip" ]]; then
        status="OK"
    elif [[ -n "$external" ]]; then
        status="NAT"
    else
        status="FAIL"
    fi
    printf '%-8s %-16s %-16s %-7s %-16s %s\n' "$primary_interface_name" "$primary_ip" "main" "main" "${external:--}" "$status"

    while IFS='|' read -r name mac metric ip_cidr gateway network_cidr table priority; do
        total=$(( total + 1 ))
        ip="${ip_cidr%%/*}"
        if [[ -z "$ip_cidr" || -z "$gateway" ]]; then
            printf '%-8s %-16s %-16s %-7s %-16s %s\n' "$name" "-" "-" "-" "-" "NO DHCP"
            continue
        fi
        route="$(ip -4 route get 1.1.1.1 from "$ip" 2>/dev/null || true)"
        external="$(bound_public_ip "$ip" || true)"
        if [[ " $route " != *" dev ${name} "* ]]; then
            status="ROUTE"
        elif [[ -z "$external" ]]; then
            status="FAIL"
        elif [[ "$external" == "$ip" ]]; then
            status="OK"
            working=$(( working + 1 ))
            direct=$(( direct + 1 ))
        else
            status="NAT"
            working=$(( working + 1 ))
            nat=$(( nat + 1 ))
        fi
        printf '%-8s %-16s %-16s %-7s %-16s %s\n' "$name" "$ip" "$gateway" "$table" "${external:--}" "$status"
    done < "$state_file"

    printf '\n'
    if (( total > 0 && working == total )); then
        ok "Дополнительные IP имеют доступ в интернет: ${working}/${total}"
        if (( nat > 0 )); then
            warn "Без подмены адреса: ${direct}; через NAT/прокси: ${nat}. Статус NAT показывает фактический внешний IP."
        fi
        ok "Основной SSH-маршрут сохранён: ${primary_ip} через ${primary_interface_name}"
        return 0
    fi
    fail "Имеют доступ в интернет не все дополнительные IP: ${working}/${total}"
    return 1
}

setup_additional_ips() {
    local metadata_file initial_state final_state initial_netplan final_netplan
    local primary_interface_name primary_ip primary_mac mac interface name
    local idx suffix existing_suffix metric metric_base primary_metric table priority ip_cidr gateway network_cidr successful=0
    local legacy_backup=""
    local -a metadata_macs=() extra_macs=() names=()
    local -A reserved_names=() assigned_names=()

    require_root
    require_commands
    init_log
    [[ "$DHCP_WAIT_SEC" =~ ^[0-9]+$ ]] || DHCP_WAIT_SEC=45
    (( DHCP_WAIT_SEC >= 5 && DHCP_WAIT_SEC <= 300 )) || DHCP_WAIT_SEC=45

    primary_interface_name="$(primary_interface)"
    primary_ip="$(primary_ipv4)"
    primary_mac="$(interface_mac "$primary_interface_name")"
    if [[ -z "$primary_interface_name" || -z "$primary_ip" || -z "$primary_mac" ]]; then
        fail "Не смог определить основной интерфейс, IP или MAC. Ничего не изменено."
        return 1
    fi
    primary_metric="$(primary_route_metric "$primary_interface_name")"
    [[ "$primary_metric" =~ ^[0-9]+$ ]] || primary_metric=100
    metric_base=$(( 10#$primary_metric + 398 ))

    metadata_file="$(mktemp)"
    initial_state="$(mktemp)"
    final_state="$(mktemp)"
    initial_netplan="$(mktemp)"
    final_netplan="$(mktemp)"
    trap 'rm -f "$metadata_file" "$initial_state" "$final_state" "$initial_netplan" "$final_netplan"' RETURN

    info "Читаю OpenStack network metadata"
    if ! fetch_openstack_metadata "$metadata_file"; then
        fail "OpenStack metadata недоступны. Автоматическая настройка не поддерживается на этой машине."
        return 1
    fi
    mapfile -t metadata_macs < <(openstack_ipv4_port_macs "$metadata_file")
    for mac in "${metadata_macs[@]}"; do
        [[ "${mac,,}" == "${primary_mac,,}" ]] && continue
        extra_macs+=("${mac,,}")
    done
    if (( ${#extra_macs[@]} == 0 )); then
        ok "Дополнительных IPv4 DHCP-портов в OpenStack не найдено."
        return 0
    fi
    ok "Найдено дополнительных OpenStack-портов: ${#extra_macs[@]}"

    rescan_network_links
    for interface in /sys/class/net/*; do
        reserved_names["$(basename "$interface")"]=1
    done
    for mac in "${extra_macs[@]}"; do
        interface="$(interface_for_mac "$mac" 2>/dev/null || true)"
        if [[ "$interface" =~ ^wan([0-9]+)$ ]]; then
            existing_suffix="${BASH_REMATCH[1]}"
            if (( 10#$existing_suffix >= 2 )); then
                assigned_names["$mac"]="$interface"
            fi
        fi
    done

    suffix=2
    for mac in "${extra_macs[@]}"; do
        name="${assigned_names[$mac]:-}"
        if [[ -z "$name" ]]; then
            while [[ -n "${reserved_names[wan${suffix}]+x}" ]]; do
                suffix=$(( suffix + 1 ))
            done
            name="wan${suffix}"
            suffix=$(( suffix + 1 ))
        fi
        reserved_names["$name"]=1
        names+=("$name")
    done

    for idx in "${!extra_macs[@]}"; do
        suffix="${names[$idx]#wan}"
        metric=$(( metric_base + 10#$suffix ))
        table=$(( 100 + 10#$suffix ))
        priority=$(( table * 100 ))
        printf '%s|%s|%d||||%d|%d\n' \
            "${names[$idx]}" "${extra_macs[$idx]}" "$metric" "$table" "$priority" >> "$initial_state"
    done
    render_netplan "$initial_state" "$initial_netplan"

    info "Поднимаю дополнительные интерфейсы через DHCP"
    if ! apply_managed_netplan "$initial_netplan" "$primary_interface_name" "$primary_ip"; then
        return 1
    fi
    rescan_network_links
    renew_interfaces "${names[@]}"
    if ! wait_for_dhcp "${names[@]}"; then
        warn "Не все интерфейсы получили DHCP за ${DHCP_WAIT_SEC}s. Настрою те, которые ответили."
    fi

    for idx in "${!extra_macs[@]}"; do
        name="${names[$idx]}"
        suffix="${name#wan}"
        metric=$(( metric_base + 10#$suffix ))
        table=$(( 100 + 10#$suffix ))
        priority=$(( table * 100 ))
        ip_cidr="$(interface_ipv4_cidr "$name")"
        gateway="$(interface_gateway "$name")"
        network_cidr=""
        if [[ -n "$ip_cidr" && -n "$gateway" ]]; then
            network_cidr="$(network_for_cidr "$ip_cidr" 2>> "$LOG_FILE" || true)"
        fi
        if [[ -n "$ip_cidr" && -n "$gateway" && -n "$network_cidr" ]]; then
            successful=$(( successful + 1 ))
        else
            warn "${name} (${extra_macs[$idx]}): DHCP не выдал полный IP/шлюз"
        fi
        printf '%s|%s|%d|%s|%s|%s|%d|%d\n' \
            "$name" "${extra_macs[$idx]}" "$metric" "$ip_cidr" "$gateway" "$network_cidr" "$table" "$priority" >> "$final_state"
    done
    if (( successful == 0 )); then
        fail "Ни один дополнительный порт не получил DHCP. Конфиг оставлен для повторной попытки или перезагрузки."
        return 1
    fi

    disable_legacy_alias_file "$final_state" legacy_backup || true
    remove_duplicate_primary_addresses "$primary_interface_name" "$final_state"
    render_netplan "$final_state" "$final_netplan"

    info "Создаю отдельный source-route для каждого IP"
    if ! apply_managed_netplan "$final_netplan" "$primary_interface_name" "$primary_ip"; then
        restore_legacy_alias_file "$legacy_backup"
        return 1
    fi
    write_multiwan_sysctl
    renew_interfaces "${names[@]}"
    sleep 3

    print_result_table "$primary_interface_name" "$primary_ip" "$final_state"
}

show_status() {
    local primary_interface_name primary_ip
    primary_interface_name="$(primary_interface)"
    primary_ip="$(primary_ipv4)"
    printf 'kto additional IP %s\n' "$ADDITIONAL_IP_BUILD"
    printf 'Основной: %s %s\n' "${primary_interface_name:--}" "${primary_ip:--}"
    printf 'Netplan: %s\n' "$([[ -f "$MANAGED_NETPLAN_FILE" ]] && echo OK || echo '-')"
    printf 'Sysctl: %s\n' "$([[ -f "$MANAGED_SYSCTL_FILE" ]] && echo OK || echo '-')"
    echo
    ip -br -4 address
    echo
    ip -4 rule
}

main() {
    case "${1:-setup}" in
        setup|apply|install) setup_additional_ips ;;
        status|check) show_status ;;
        *)
            echo "Использование: $0 setup|status"
            return 1
            ;;
    esac
}

main "$@"
