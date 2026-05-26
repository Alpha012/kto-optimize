#!/bin/bash

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}==========================================${NC}"
echo -e "${GREEN}    kto VPN: Ультимативное говно          ${NC}"
echo -e "${CYAN}==========================================${NC}"
echo "1) Полная оптимизация системы"
echo "2) Установка/обновление ноды Remnawave"
echo "3) Установка SelfSteal (от DigneZzZ)"
echo "4) Установка WARP Native"
echo "5) Проверка состояния ноды (Чекер)"
echo "0) Выход"
echo -e "${CYAN}==========================================${NC}"
read -p "Выберите действие (0-5): " choice

case $choice in
    1)
        echo -e "\n${YELLOW}[INFO]${NC} Запуск тихой оптимизации. Пожалуйста, подождите..."
        SSH_PORT=$(grep -E "^Port " /etc/ssh/sshd_config | grep -v "^#" | awk '{print $2}' | head -n 1)
        SSH_PORT=${SSH_PORT:-22}
        
        sudo systemctl disable --now snapd.socket snapd.service > /dev/null 2>&1
        sudo apt-get purge snapd -y > /dev/null 2>&1
        sudo apt-get update > /dev/null 2>&1
        sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y wget gnupg2 chrony ufw cpufrequtils irqbalance software-properties-common > /dev/null 2>&1
        
        sudo add-apt-repository ppa:damentz/liquorix -y > /dev/null 2>&1
        sudo apt-get update > /dev/null 2>&1
        sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y linux-image-liquorix-amd64 linux-headers-liquorix-amd64 > /dev/null 2>&1
        
        echo 'GOVERNOR="performance"' | sudo tee /etc/default/cpufrequtils > /dev/null 2>&1
        sudo systemctl restart cpufrequtils > /dev/null 2>&1 || true
        sudo systemctl enable --now irqbalance > /dev/null 2>&1 || true
        
        sudo tee /etc/sysctl.d/99-vpn-tuning.conf > /dev/null 2>&1 <<EOF
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
EOF
        sudo sysctl --system > /dev/null 2>&1
        
        sudo tee /etc/security/limits.d/99-vpn-limits.conf > /dev/null 2>&1 <<EOF
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF
        sudo sed -i 's/#DefaultLimitNOFILE=/DefaultLimitNOFILE=1048576/g' /etc/systemd/system.conf > /dev/null 2>&1
        sudo sed -i 's/#DefaultLimitNOFILE=/DefaultLimitNOFILE=1048576/g' /etc/systemd/user.conf > /dev/null 2>&1
        sudo systemctl daemon-reload > /dev/null 2>&1
        
        sudo ufw --force reset > /dev/null 2>&1
        sudo ufw default deny incoming > /dev/null 2>&1
        sudo ufw default allow outgoing > /dev/null 2>&1
        sudo ufw allow $SSH_PORT/tcp > /dev/null 2>&1
        sudo ufw allow 443 > /dev/null 2>&1
        sudo ufw allow 1488 > /dev/null 2>&1
        sudo ufw --force enable > /dev/null 2>&1
        sudo systemctl enable --now chronyd > /dev/null 2>&1
        
        echo -e "${GREEN}[OK]${NC} Оптимизация завершена. Обязательно выполни: ${CYAN}sudo reboot${NC}"
        ;;

    2)
        echo -e "\n${YELLOW}[..]${NC} Подготовка к установке Remnawave..."
        
        read -p "Введите SECRET_KEY для ноды: " SECRET_KEY
        [ -z "$SECRET_KEY" ] && { echo -e "${RED}Ошибка: Ключ не может быть пустым!${NC}"; exit 1; }

        if ! command -v docker &> /dev/null; then
            echo -e "${YELLOW}[..]${NC} Docker не найден, устанавливаем..."
            curl -fsSL https://get.docker.com | sh > /dev/null 2>&1
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

        echo -e "${YELLOW}[..]${NC} Запуск контейнера..."
        if command -v docker compose &> /dev/null; then
            sudo docker compose up -d
        else
            sudo docker-compose up -d
        fi
        
        echo -e "${GREEN}[OK]${NC} Нода успешно запущена!"
        echo -e "Для просмотра логов введи: ${CYAN}docker logs -f remnanode${NC}"
        ;;

    3)
        echo -e "\n${YELLOW}[INFO]${NC} Запуск скрипта SelfSteal..."
        bash <(curl -Ls https://github.com/DigneZzZ/remnawave-scripts/raw/main/selfsteal.sh) @ install
        echo -e "\n${GREEN}[OK]${NC} Скрипт SelfSteal завершил работу!"
        ;;

    4)
        echo -e "\n${YELLOW}[INFO]${NC} Запуск установки WARP Native..."
        bash <(curl -fsSL https://raw.githubusercontent.com/distillium/warp-native/main/install.sh)
        echo -e "\n${GREEN}[OK]${NC} Установка WARP Native завершена!"
        ;;

    5)
        echo -e "\n${CYAN}==========================================${NC}"
        echo -e "${YELLOW}         kto VPN: Проверка говна          ${NC}"
        echo -e "${CYAN}==========================================${NC}\n"

        KERNEL=$(uname -r)
        if echo "$KERNEL" | grep -q "liquorix"; then
            echo -e "1. Ядро ОС: ${GREEN}Liquorix активно ($KERNEL)${NC}"
        else
            echo -e "1. Ядро ОС: ${RED}Стоковое ($KERNEL). Нужен reboot!${NC}"
        fi

        BBR=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
        FQ=$(sysctl -n net.core.default_qdisc 2>/dev/null)
        if [ "$BBR" == "bbr" ] && [ "$FQ" == "fq" ]; then
            echo -e "2. Сеть: ${GREEN}BBR + FQ включены${NC}"
        else
            echo -e "2. Сеть: ${RED}Ошибка ($BBR, $FQ)${NC}"
        fi

        CPU_GOV=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null)
        if [ "$CPU_GOV" == "performance" ]; then
            echo -e "3. CPU: ${GREEN}Performance (Максимальная мощь)${NC}"
        elif [ -z "$CPU_GOV" ]; then
            echo -e "3. CPU: ${YELLOW}Заблокирован хостером (Норма)${NC}"
        else
            echo -e "3. CPU: ${RED}Не performance ($CPU_GOV)${NC}"
        fi

        SWAP=$(sysctl -n vm.swappiness 2>/dev/null)
        if [ "$SWAP" == "1" ]; then
            echo -e "4. Swap: ${GREEN}Настроен (1)${NC}"
        else
            echo -e "4. Swap: ${RED}Не настроен ($SWAP)${NC}"
        fi

        if ! command -v snap &> /dev/null; then
            echo -e "5. Snapd: ${GREEN}Успешно удален${NC}"
        else
            echo -e "5. Snapd: ${RED}Установлен!${NC}"
        fi

        LIMIT=$(systemctl show -p DefaultLimitNOFILE | cut -d= -f2)
        if [ "$LIMIT" == "1048576" ] || [ "$LIMIT" == "infinity" ] || [ "$LIMIT" -ge 500000 ] 2>/dev/null; then
            echo -e "6. Лимиты: ${GREEN}Расширены ($LIMIT)${NC}"
        else
            echo -e "6. Лимиты: ${RED}Стандартные ($LIMIT)${NC}"
        fi

        echo -e "\n${CYAN}=== СТАТУС СЛУЖБ ===${NC}"
        CORES=$(nproc)
        for svc in chronyd ufw irqbalance; do
            if systemctl is-active --quiet $svc; then
                echo -e "[$svc]: ${GREEN}Работает${NC}"
            else
                if [ "$svc" == "irqbalance" ] && [ "$CORES" -eq 1 ]; then
                    echo -e "[$svc]: ${YELLOW}Выключена (1 ядро)${NC}"
                else
                    echo -e "[$svc]: ${RED}НЕ РАБОТАЕТ${NC}"
                fi
            fi
        done

        echo -e "\n${CYAN}=== ОТКРЫТЫЕ ПОРТЫ ===${NC}"
        if sudo ufw status | grep -q "ALLOW"; then
            sudo ufw status | grep ALLOW
        else
            echo -e "${RED}Файрвол выключен или правила не заданы!${NC}"
        fi
        echo -e "${CYAN}==========================================${NC}"
        ;;

    0)
        echo -e "${CYAN}Выход.${NC}"
        exit 0
        ;;
    *)
        echo -e "${RED}Ошибка: Неверный выбор!${NC}"
        ;;
esac
