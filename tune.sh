#!/bin/bash

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
PURPLE='\033[38;5;93m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

printf '\033c'

echo -e "${PURPLE}==========================================${NC}"
echo -e "${BOLD}${GREEN}                 kto VPN                  ${NC}"
echo -e "${PURPLE}==========================================${NC}"
echo -e "1) Полная оптимизация"
echo -e "2) Установка ноды Remnawave"
echo -e "3) Установка SelfSteal"
echo -e "4) Установка WARP Native"
echo -e "5) Панель состояния"
echo -e "6) Speedtest"
echo -e "7) Проверка IP (IP.Check.Place)"
echo -e "8) Проверка IP (Region Check)"
echo -e "9) Сгенерировать SSL-сертификат"
echo -e "0) Выход"
echo -e "${PURPLE}==========================================${NC}"

echo -ne "${PURPLE}❯${NC} ${BOLD}Выберите действие (0-9):${NC} "
read choice

case $choice in
    1)
        echo -e "\n${YELLOW}[INFO]${NC} Запуск оптимизации..."
        SSH_PORT=$(grep -E "^Port " /etc/ssh/sshd_config | grep -v "^#" | awk '{print $2}' | head -n 1)
        SSH_PORT=${SSH_PORT:-22}
        
        echo -e "${PURPLE}[..]${NC} Очистка процессов..."
        sudo systemctl stop unattended-upgrades > /dev/null 2>&1
        sudo killall apt apt-get > /dev/null 2>&1
        sudo rm -f /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock*
        sudo dpkg --configure -a > /dev/null 2>&1
        
        echo -e "${PURPLE}[..]${NC} Подготовка системы..."
        sudo rm -f /etc/apt/sources.list.d/ookla_speedtest-cli.list > /dev/null 2>&1
        sudo systemctl disable --now snapd.socket snapd.service > /dev/null 2>&1
        sudo apt-get purge snapd -y > /dev/null 2>&1
        
        export NEEDRESTART_MODE=a
        export NEEDRESTART_SUSPEND=1
        
        echo -e "${PURPLE}[..]${NC} Установка утилит..."
        sudo apt-get update > /dev/null 2>&1
        sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" curl wget gnupg2 chrony ufw cpufrequtils irqbalance software-properties-common > /dev/null 2>&1
        
        echo -e "${PURPLE}[..]${NC} Установка ядра Liquorix..."
        sudo add-apt-repository ppa:damentz/liquorix -y > /dev/null 2>&1
        sudo apt-get update > /dev/null 2>&1
        
        for i in {1..3}; do
            sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" linux-image-liquorix-amd64 linux-headers-liquorix-amd64 > /dev/null 2>&1
            if dpkg -l | grep -q linux-image-liquorix; then
                break
            fi
            sleep 2
        done
        
        echo -e "${PURPLE}[..]${NC} Применение сетевых настроек..."
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
        sudo sysctl --system > /dev/null 2>&1
        
        sudo tee /etc/security/limits.d/99-vpn-limits.conf > /dev/null <<EOF
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF
        sudo sed -i 's/#DefaultLimitNOFILE=/DefaultLimitNOFILE=1048576/g' /etc/systemd/system.conf > /dev/null
        sudo sed -i 's/#DefaultLimitNOFILE=/DefaultLimitNOFILE=1048576/g' /etc/systemd/user.conf > /dev/null
        sudo systemctl daemon-reload > /dev/null 2>&1
        
        echo -e "${PURPLE}[..]${NC} Настройка Firewall (UFW)..."
        sudo ufw --force reset > /dev/null 2>&1
        sudo ufw default deny incoming > /dev/null 2>&1
        sudo ufw default allow outgoing > /dev/null 2>&1
        sudo ufw allow $SSH_PORT/tcp > /dev/null 2>&1
        sudo ufw allow 443 > /dev/null 2>&1
        sudo ufw allow 1488 > /dev/null 2>&1
        sudo ufw --force enable > /dev/null 2>&1
        
        sudo systemctl enable --now chrony > /dev/null 2>&1
        
        echo -e "\n${GREEN}[OK]${NC} Оптимизация завершена. Не забудь: ${BOLD}${PURPLE}sudo reboot${NC}"
        ;;

    2)
        echo -e "\n${YELLOW}[..]${NC} Подготовка к установке Remnawave..."
        
        echo -ne "${PURPLE}❯${NC} ${BOLD}Введите SECRET_KEY для ноды:${NC} "
        read SECRET_KEY
        [ -z "$SECRET_KEY" ] && { echo -e "\n${RED}[ОШИБКА] Ключ не может быть пустым!${NC}"; exit 1; }

        if ! command -v docker &> /dev/null; then
            curl -fsSL https://get.docker.com | sudo sh > /dev/null 2>&1
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

        if command -v docker compose &> /dev/null; then
            DOCKER_CMD="sudo docker compose"
        else
            DOCKER_CMD="sudo docker-compose"
        fi
        
        if $DOCKER_CMD up -d; then
            echo -e "${GREEN}[OK]${NC} Нода запущена!"
            echo -e "Для просмотра логов введи: ${BOLD}${PURPLE}sudo docker logs -f remnanode${NC}"
        else
            echo -e "\n${RED}[ОШИБКА] Docker не смог запустить ноду! Проверь лимиты.${NC}"
        fi
        ;;

    3)
        echo -e "\n${YELLOW}[INFO]${NC} Запуск установки SelfSteal..."
        curl -sL "https://github.com/DigneZzZ/remnawave-scripts/raw/main/selfsteal.sh" -o /tmp/selfsteal.sh
        
        if sudo bash /tmp/selfsteal.sh @ install < /dev/tty; then
            echo -e "\n${GREEN}[OK]${NC} SelfSteal установлен!"
        else
            echo -e "\n${RED}[ОШИБКА] Ошибка SelfSteal.${NC}"
        fi
        
        rm -f /tmp/selfsteal.sh
        ;;

    4)
        echo -e "\n${YELLOW}[INFO]${NC} Запуск установки WARP Native..."
        curl -sL "https://raw.githubusercontent.com/distillium/warp-native/main/install.sh" -o /tmp/warp.sh
        
        if echo -e "2\n1\n" | sudo bash /tmp/warp.sh; then
            echo -e "\n${GREEN}[OK]${NC} WARP успешно установлен!"
        else
            echo -e "\n${RED}[ОШИБКА] Ошибка WARP.${NC}"
        fi
        
        rm -f /tmp/warp.sh
        ;;

    5)
        printf '\033c'
        sudo sysctl -p /etc/sysctl.d/99-vpn-tuning.conf > /dev/null 2>&1
        
        echo -e "${PURPLE}══════════════════════════════════════════════════════${NC}"
        echo -e "${BOLD}${YELLOW}                       kto VPN                        ${NC}"
        echo -e "${PURPLE}══════════════════════════════════════════════════════${NC}"
        
        echo -e "${BOLD}${PURPLE}[ СИСТЕМА ]${NC}"
        
        print_stat() {
            local name=$1
            local val=$2
            local expected=$3
            
            echo -ne " $name "
            if [[ "$val" == *"$expected"* ]]; then
                echo -e "${GREEN}[ OK ]${NC}"
            else
                echo -e "${RED}[ FAIL ]${NC} ($val)"
            fi
        }

        KERNEL_VER=$(uname -r)
        print_stat "Ядро Liquorix   " "$KERNEL_VER" "liquorix"
        
        NET_CC=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
        NET_QDISC=$(sysctl -n net.core.default_qdisc 2>/dev/null)
        print_stat "BBR + FQ        " "${NET_CC}+${NET_QDISC}" "bbr+fq"
        
        TFO=$(sysctl -n net.ipv4.tcp_fastopen 2>/dev/null)
        print_stat "TCP Fast Open   " "$TFO" "3"
        
        KEEPALIVE=$(sysctl -n net.ipv4.tcp_keepalive_time 2>/dev/null)
        print_stat "Keepalive (10m) " "$KEEPALIVE" "600"
        
        SNAP_STATUS=$(command -v snap &> /dev/null && echo "found" || echo "clean")
        print_stat "Snapd удален    " "$SNAP_STATUS" "clean"

        echo -e "\n${BOLD}${PURPLE}[ СЛУЖБЫ ]${NC}"
        echo -ne " "
        for svc in chrony ufw irqbalance; do
            if systemctl is-active --quiet $svc; then
                echo -ne "${BOLD}$svc:${NC} ${GREEN}OK${NC}    "
            else
                echo -ne "${BOLD}$svc:${NC} ${RED}FAIL${NC}  "
            fi
        done
        echo ""

        echo -e "\n${BOLD}${PURPLE}[ ПОРТЫ ]${NC}"
        PORTS=$(sudo ufw status | grep ALLOW | awk '{print $1}' | sed 's/(v6)//g' | sort -u | xargs | sed 's/ /, /g')
        echo -e " Открыты:  ${YELLOW}${PORTS:-Файрвол не настроен}${NC}"
        echo -e "${PURPLE}══════════════════════════════════════════════════════${NC}"
        ;;

    6)
        echo -e "\n${YELLOW}[INFO]${NC} Подготовка Speedtest..."
        
        sudo apt-get remove -y speedtest-cli > /dev/null 2>&1
        sudo rm -f /usr/bin/speedtest /usr/local/bin/speedtest > /dev/null 2>&1
        
        wget -qO- https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-x86_64.tgz | sudo tar xvz -C /usr/local/bin/ speedtest > /dev/null 2>&1
        
        if [ -f "/usr/local/bin/speedtest" ]; then
            echo -e "${PURPLE}[..]${NC} Запуск теста...\n"
            /usr/local/bin/speedtest --accept-license --accept-gdpr
            echo -e "\n${GREEN}[OK]${NC} Тест завершен!"
        else
            echo -e "\n${RED}[ОШИБКА] Ошибка скачивания Speedtest.${NC}"
        fi
        ;;

    7)
        printf '\033c'
        echo -e "${YELLOW}[INFO]${NC} Выполнение IP Check (IP.Check.Place)...\n"
        bash <(curl -Ls https://IP.Check.Place) -l en
        echo -e "\n${GREEN}[OK]${NC} Проверка завершена!"
        ;;

    8)
        printf '\033c'
        echo -e "${YELLOW}[INFO]${NC} Выполнение IP Region Check...\n"
        bash <(wget -qO- https://github.com/Davoyan/ipregion/raw/main/ipregion.sh)
        echo -e "\n${GREEN}[OK]${NC} Проверка завершена!"
        ;;

    9)
        echo -e "\n${YELLOW}[INFO]${NC} Генерация SSL-сертификата..."
        echo -ne "${PURPLE}❯${NC} ${BOLD}Введите домен (например, vpn.domain.com):${NC} "
        read DOMAIN
        
        if [ -z "$DOMAIN" ]; then
            echo -e "${RED}[ОШИБКА] Домен не может быть пустым!${NC}"
        else
            echo -e "${PURPLE}[..]${NC} Подготовка окружения..."
            sudo apt-get update > /dev/null 2>&1
            sudo apt-get install cron socat -y > /dev/null 2>&1
            sudo systemctl enable --now cron > /dev/null 2>&1
            
            if [ ! -f "/root/.acme.sh/acme.sh" ]; then
                curl -s https://get.acme.sh | sh -s email=aaaaaa123456@gmail.com --force > /dev/null 2>&1
            fi
            
            echo -e "${PURPLE}[..]${NC} Настройка Let's Encrypt..."
            /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt > /dev/null 2>&1
            
            echo -e "${PURPLE}[..]${NC} Выпуск сертификата (ожидай около минуты)..."
            sudo ufw allow 80/tcp > /dev/null 2>&1
            sudo docker stop remnanode > /dev/null 2>&1
            sudo mkdir -p /opt/remnawave/
            
            if /root/.acme.sh/acme.sh --issue --standalone -d "$DOMAIN" --key-file /opt/remnawave/privkey.key --fullchain-file /opt/remnawave/fullchain.pem --force > /dev/null 2>&1; then
                echo -e "\n${GREEN}[OK]${NC} Сертификат успешно выпущен!"
                echo -e "${GREEN}[+]${NC} Cron настроен, автопродление активно."
                echo -e "Ключ:       ${BOLD}/opt/remnawave/privkey.key${NC}"
                echo -e "Fullchain:  ${BOLD}/opt/remnawave/fullchain.pem${NC}"
            else
                echo -e "\n${RED}[ОШИБКА] Ошибка выпуска. Убедись, что домен направлен на IP этого сервера!${NC}"
            fi
            
            sudo docker start remnanode > /dev/null 2>&1
            sudo ufw delete allow 80/tcp > /dev/null 2>&1
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
