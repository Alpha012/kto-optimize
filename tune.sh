#!/bin/bash

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
PURPLE='\033[38;5;93m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

# Жесткая очистка консоли
printf '\033c'

echo -e "${PURPLE}==========================================${NC}"
echo -e "${BOLD}${GREEN}    kto VPN: Ультимативное говно          ${NC}"
echo -e "${PURPLE}==========================================${NC}"
echo -e "1) Полная оптимизация"
echo -e "2) Установка ноды Remnawave"
echo -e "3) Установка SelfSteal"
echo -e "4) Установка WARP Native"
echo -e "5) Проверка говна"
echo -e "6) Speedtest"
echo -e "0) Выход"
echo -e "${PURPLE}==========================================${NC}"

echo -ne "${PURPLE}❯${NC} ${BOLD}Выберите действие (0-6):${NC} "
read choice

case $choice in
    1)
        echo -e "\n${YELLOW}[INFO]${NC} Запуск оптимизации и самолечения..."
        SSH_PORT=$(grep -E "^Port " /etc/ssh/sshd_config | grep -v "^#" | awk '{print $2}' | head -n 1)
        SSH_PORT=${SSH_PORT:-22}
        
        echo -e "${PURPLE}[..]${NC} Лечим APT..."
        sudo rm -f /etc/apt/sources.list.d/ookla_speedtest-cli.list
        sudo rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock
        sudo dpkg --configure -a > /dev/null 2>&1
        
        sudo systemctl disable --now snapd.socket snapd.service > /dev/null 2>&1
        sudo apt-get purge snapd -y > /dev/null 2>&1
        
        echo -e "${PURPLE}[..]${NC} Обновление и установка утилит..."
        sudo apt-get update > /dev/null
        sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y curl wget gnupg2 chrony ufw cpufrequtils irqbalance software-properties-common > /dev/null
        
        echo -e "${PURPLE}[..]${NC} Установка ядра Liquorix..."
        sudo add-apt-repository ppa:damentz/liquorix -y > /dev/null
        sudo apt-get update > /dev/null
        sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y linux-image-liquorix-amd64 linux-headers-liquorix-amd64 > /dev/null
        
        echo -e "${PURPLE}[..]${NC} Тюнинг ядра и сети (Pro-Level)..."
        echo 'GOVERNOR="performance"' | sudo tee /etc/default/cpufrequtils > /dev/null
        sudo systemctl restart cpufrequtils > /dev/null 2>&1 || true
        sudo systemctl enable --now irqbalance > /dev/null 2>&1 || true
        
        sudo tee /etc/sysctl.d/99-vpn-tuning.conf > /dev/null <<EOF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.somaxconn = 65535
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_max_syn_backlog = 3240000
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_syncookies = 1
net.core.rmem_default = 1048576
net.core.rmem_max = 16777216
net.core.wmem_default = 1048576
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 1048576 2097152
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
vm.swappiness = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.core.optmem_max = 65536
EOF
        sudo sysctl --system > /dev/null
        
        sudo tee /etc/security/limits.d/99-vpn-limits.conf > /dev/null <<EOF
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF
        sudo sed -i 's/#DefaultLimitNOFILE=/DefaultLimitNOFILE=1048576/g' /etc/systemd/system.conf > /dev/null
        sudo sed -i 's/#DefaultLimitNOFILE=/DefaultLimitNOFILE=1048576/g' /etc/systemd/user.conf > /dev/null
        sudo systemctl daemon-reload > /dev/null
        
        echo -e "${PURPLE}[..]${NC} Настройка Firewall (UFW)..."
        sudo ufw --force reset > /dev/null
        sudo ufw default deny incoming > /dev/null
        sudo ufw default allow outgoing > /dev/null
        sudo ufw allow $SSH_PORT/tcp > /dev/null
        sudo ufw allow 443 > /dev/null
        sudo ufw allow 1488 > /dev/null
        sudo ufw --force enable > /dev/null
        sudo systemctl enable --now chronyd > /dev/null
        
        echo -e "\n${GREEN}[OK]${NC} Оптимизация завершена. Не забудь: ${BOLD}${PURPLE}sudo reboot${NC}"
        ;;

    2)
        echo -e "\n${YELLOW}[..]${NC} Подготовка к установке Remnawave..."
        echo -ne "${PURPLE}❯${NC} ${BOLD}Введите SECRET_KEY для ноды:${NC} "
        read SECRET_KEY
        [ -z "$SECRET_KEY" ] && { echo -e "\n${RED}[ОШИБКА] Ключ пуст!${NC}"; exit 1; }

        if ! command -v docker &> /dev/null; then
            curl -fsSL https://get.docker.com | sudo sh > /dev/null
        fi

        sudo mkdir -p /opt/remnawave/
        cd /opt/remnawave/ || exit
        
        cat <<EOF | sudo tee docker-compose.yml > /dev/null
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
      - SECRET_KEY="$SECRET_KEY"
EOF

        if [ -x "$(command -v docker-compose)" ]; then
            sudo docker-compose up -d
        else
            sudo docker compose up -d
        fi
        echo -e "${GREEN}[OK]${NC} Нода запущена!"
        ;;

    3)
        curl -sL "https://github.com/DigneZzZ/remnawave-scripts/raw/main/selfsteal.sh" -o /tmp/selfsteal.sh
        sudo bash /tmp/selfsteal.sh @ install < /dev/tty
        rm -f /tmp/selfsteal.sh
        ;;

    4)
        curl -sL "https://raw.githubusercontent.com/distillium/warp-native/main/install.sh" -o /tmp/warp.sh
        sudo bash /tmp/warp.sh < /dev/tty
        rm -f /tmp/warp.sh
        ;;

    5)
        printf '\033c'
        echo -e "${PURPLE}┌──────────────────────────────────────────┐${NC}"
        echo -e "${PURPLE}│${NC}        ${BOLD}${YELLOW}КТО VPN: STATUS DASHBOARD${NC}         ${PURPLE}│${NC}"
        echo -e "${PURPLE}└──────────────────────────────────────────┘${NC}"

        # Функция отрисовки строки статуса
        render_line() {
            local label=$1
            local status=$2
            local value=$3
            printf "${PURPLE}│${NC} %-20s " "$label"
            if [ "$status" == "OK" ]; then
                printf "${GREEN}● OK${NC}"
            else
                printf "${RED}○ BAD${NC}"
            fi
            printf " ${PURPLE}│${NC}\n"
        }

        echo -e "${PURPLE}┌──────────────────────────────────────────┐${NC}"
        render_line "Ядро Liquorix" "$(uname -r | grep -q liquorix && echo OK || echo BAD)"
        render_line "BBR + FQ" "$( [ "$(sysctl -n net.ipv4.tcp_congestion_control)" == "bbr" ] && echo OK || echo BAD )"
        render_line "TCP Fast Open" "$( [ "$(sysctl -n net.ipv4.tcp_fastopen)" == "3" ] && echo OK || echo BAD )"
        render_line "Keepalive (10m)" "$( [ "$(sysctl -n net.ipv4.tcp_keepalive_time)" == "600" ] && echo OK || echo BAD )"
        render_line "Snapd Удален" "$( ! command -v snap &> /dev/null && echo OK || echo BAD )"
        echo -e "${PURPLE}├──────────────────────────────────────────┤${NC}"
        
        # Статус служб одной строкой
        echo -ne "${PURPLE}│${NC} Службы: "
        for svc in chronyd ufw irqbalance; do
            systemctl is-active --quiet $svc && echo -ne "${GREEN} $svc " || echo -ne "${RED} $svc "
        done
        printf "             ${PURPLE}│${NC}\n"
        
        echo -e "${PURPLE}└──────────────────────────────────────────┘${NC}"
        
        # Порты
        echo -e "${PURPLE}┌──────────────────────────────────────────┐${NC}"
        echo -e "${PURPLE}│${NC} ${BOLD}Порты:${NC} $(sudo ufw status | grep ALLOW | awk '{print $1}' | xargs | sed 's/ /, /g')     ${PURPLE}│${NC}"
        echo -e "${PURPLE}└──────────────────────────────────────────┘${NC}"
        ;;

    6)
        if ! command -v speedtest &> /dev/null; then
            wget -qO- https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-x86_64.tgz | sudo tar xvz -C /usr/local/bin/ speedtest > /dev/null 2>&1
        fi
        speedtest --accept-license --accept-gdpr
        ;;

    0)
        exit 0
        ;;
    *)
        echo -e "${RED}Ошибка!${NC}"
        ;;
esac
