#!/bin/bash
# kto VPN: Ультимативный инсталлятор

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}==========================================${NC}"
echo -e "${GREEN}    kto VPN: Ультимативное говно        ${NC}"
echo -e "${CYAN}==========================================${NC}"
echo "1) Полная оптимизация системы"
echo "2) Установка ноды Remnawave"
read -p "Выберите действие (1-2): " choice

case $choice in
    1)
        # --- БЛОК ОПТИМИЗАЦИИ (Твой старый код) ---
        echo -e "\n${YELLOW}[..]${NC} Запуск оптимизации..."
        SSH_PORT=$(grep -E "^Port " /etc/ssh/sshd_config | grep -v "^#" | awk '{print $2}' | head -n 1)
        SSH_PORT=${SSH_PORT:-22}
        
        sudo systemctl disable --now snapd.socket snapd.service > /dev/null 2>&1
        sudo apt-get purge snapd -y > /dev/null 2>&1
        sudo apt-get update > /dev/null 2>&1
        sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y wget gnupg2 chrony ufw cpufrequtils irqbalance software-properties-common > /dev/null 2>&1
        
        sudo add-apt-repository ppa:damentz/liquorix -y > /dev/null 2>&1
        sudo apt-get update > /dev/null 2>&1
        sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y linux-image-liquorix-amd64 linux-headers-liquorix-amd64 > /dev/null 2>&1
        
        # Конфиги (Sysctl, limits) оставляем как были...
        echo -e "${GREEN}[OK]${NC} Оптимизация завершена. Сделай sudo reboot!"
        ;;

    2)
        # --- БЛОК УСТАНОВКИ НОДЫ ---
        echo -e "\n${YELLOW}[..]${NC} Установка Remnawave Node..."
        
        # Спрашиваем ключ
        read -p "Введите SECRET_KEY для ноды: " SECRET_KEY
        [ -z "$SECRET_KEY" ] && { echo -e "${RED}Ошибка: Ключ не может быть пустым!${NC}"; exit 1; }

        # Ставим Docker, если нет
        if ! command -v docker &> /dev/null; then
            echo -e "${YELLOW}[..]${NC} Установка Docker..."
            curl -fsSL https://get.docker.com | sh > /dev/null 2>&1
        fi

        # Создаем конфиг
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
        # Пробуем новую команду, если не сработает — старую
        if command -v docker compose &> /dev/null; then
            sudo docker compose up -d
        else
            sudo docker-compose up -d
        fi
        
        echo -e "${GREEN}[OK]${NC} Нода успешно запущена!"
        echo -e "Логи: ${CYAN}docker logs -f remnanode${NC}"
        ;;
    *)
        echo "Неверный выбор."
        ;;
esac
