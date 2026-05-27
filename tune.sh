#!/bin/bash

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
PURPLE='\033[38;5;93m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

# Жесткая очистка консоли через системный сброс
printf '\033c'

echo -e "${PURPLE}==========================================${NC}"
echo -e "${BOLD}${GREEN}    kto VPN: Ультимативное говно          ${NC}"
echo -e "${PURPLE}==========================================${NC}"
echo -e "1) Полная оптимизация системы"
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
        echo -e "\n${YELLOW}[INFO]${NC} Запуск оптимизации. Пожалуйста, подождите..."
        SSH_PORT=$(grep -E "^Port " /etc/ssh/sshd_config | grep -v "^#" | awk '{print $2}' | head -n 1)
        SSH_PORT=${SSH_PORT:-22}
        
        sudo systemctl disable --now snapd.socket snapd.service > /dev/null 2>&1
        sudo apt-get purge snapd -y > /dev/null 2>&1
        
        echo -e "${PURPLE}[..]${NC} Обновление пакетов и установка базовых утилит..."
        sudo apt-get update > /dev/null
        sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y curl wget gnupg2 chrony ufw cpufrequtils irqbalance software-properties-common > /dev/null
        
        echo -e "${PURPLE}[..]${NC} Установка ядра Liquorix..."
        sudo add-apt-repository ppa:damentz/liquorix -y > /dev/null
        sudo apt-get update > /dev/null
        sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y linux-image-liquorix-amd64 linux-headers-liquorix-amd64 > /dev/null
        
        echo -e "${PURPLE}[..]${NC} Тюнинг процессора и сети..."
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
        
        echo -e "\n${GREEN}[OK]${NC} Оптимизация завершена. Если не было красных ошибок, пиши: ${BOLD}${PURPLE}sudo reboot${NC}"
        ;;

    2)
        echo -e "\n${YELLOW}[..]${NC} Подготовка к установке Remnawave..."
        
        echo -ne "${PURPLE}❯${NC} ${BOLD}Введите SECRET_KEY для ноды:${NC} "
        read SECRET_KEY
        [ -z "$SECRET_KEY" ] && { echo -e "\n${RED}[ОШИБКА] Ключ не может быть пустым!${NC}"; exit 1; }

        if ! command -v docker &> /dev/null; then
            echo -e "${YELLOW}[..]${NC} Docker не найден, устанавливаем..."
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

        echo -e "${YELLOW}[..]${NC} Запуск контейнера..."
        if command -v docker compose &> /dev/null; then
            DOCKER_CMD="sudo docker compose"
        else
            DOCKER_CMD="sudo docker-compose"
        fi
        
        if $DOCKER_CMD up -d; then
            echo -e "${GREEN}[OK]${NC} Нода успешно запущена!"
            echo -e "Для просмотра логов введи: ${BOLD}${PURPLE}sudo docker logs -f remnanode${NC}"
        else
            echo -e "\n${RED}[ОШИБКА] Docker не смог запустить ноду! Ищи причину в тексте выше.${NC}"
        fi
        ;;

    3)
        echo -e "\n${YELLOW}[INFO]${NC} Запуск скрипта SelfSteal..."
        # Физически скачиваем файл во временную папку
        curl -sL "https://github.com/DigneZzZ/remnawave-scripts/raw/main/selfsteal.sh" -o /tmp/selfsteal.sh
        
        # Запускаем от рута как обычный скрипт (чтобы инпуты работали)
        if sudo bash /tmp/selfsteal.sh @ install; then
            echo -e "\n${GREEN}[OK]${NC} Скрипт SelfSteal успешно завершил работу!"
        else
            echo -e "\n${RED}[ОШИБКА] Скрипт SelfSteal прервался с ошибкой!${NC}"
        fi
        
        # Удаляем мусор за собой
        rm -f /tmp/selfsteal.sh
        ;;

    4)
        echo -e "\n${YELLOW}[INFO]${NC} Запуск установки WARP Native..."
        # Аналогичный безопасный запуск для WARP
        curl -sL "https://raw.githubusercontent.com/distillium/warp-native/main/install.sh" -o /tmp/warp.sh
        
        if sudo bash /tmp/warp.sh; then
            echo -e "\n${GREEN}[OK]${NC} Установка WARP Native успешно завершена!"
        else
            echo -e "\n${RED}[ОШИБКА] Установка WARP Native прервалась с ошибкой!${NC}"
        fi
        
        rm -f /tmp/warp.sh
        ;;

    5)
        printf '\033c'
        echo -e "${PURPLE}==========================================${NC}"
        echo -e "${BOLD}${YELLOW}    kto VPN: Проверка говна               ${NC}"
        echo -e "${PURPLE}==========================================${NC}\n"

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

        echo -e "\n${PURPLE}=== СТАТУС СЛУЖБ ===${NC}"
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

        echo -e "\n${PURPLE}=== ОТКРЫТЫЕ ПОРТЫ ===${NC}"
        if sudo ufw status | grep -q "ALLOW"; then
            sudo ufw status | grep ALLOW
        else
            echo -e "${RED}Файрвол выключен или правила не заданы!${NC}"
        fi
        echo -e "${PURPLE}==========================================${NC}"
        ;;

    6)
        echo -e "\n${YELLOW}[INFO]${NC} Подготовка к замеру скорости..."
        
        if ! command -v speedtest &> /dev/null; then
            echo -e "${PURPLE}[..]${NC} Прямое скачивание бинарника Speedtest (Ookla)..."
            wget -qO- https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-x86_64.tgz | sudo tar xvz -C /usr/local/bin/ speedtest > /dev/null 2>&1
        fi
        
        if command -v speedtest &> /dev/null; then
            echo -e "${PURPLE}[..]${NC} Запуск теста...\n"
            speedtest --accept-license --accept-gdpr
            echo -e "\n${GREEN}[OK]${NC} Тест завершен!"
        else
            echo -e "\n${RED}[ОШИБКА] Не удалось скачать Speedtest. Проверь интернет на сервере.${NC}"
        fi
        ;;

    0)
        echo -e "${PURPLE}Выход.${NC}"
        exit 0
        ;;
    *)
        echo -e "${RED}Ошибка: Неверный выбор!${NC}"
        ;;
esac
