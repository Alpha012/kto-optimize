#!/bin/bash
# Скрипт автонастройки ноды kto VPN

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}==========================================${NC}"
echo -e "${GREEN}    kto VPN: Auto-Tuning Node Setup       ${NC}"
echo -e "${YELLOW}==========================================${NC}"
echo "Начинаем универсальный тюнинг сервера..."

# Автоопределение порта SSH (чтобы не заблокировать себя)
SSH_PORT=$(grep -E "^Port " /etc/ssh/sshd_config | grep -v "^#" | awk '{print $2}' | head -n 1)
if [ -z "$SSH_PORT" ]; then
    SSH_PORT=22
fi
echo "Обнаружен SSH порт: $SSH_PORT. Он будет добавлен в UFW."

# 1. Подготовка и удаление snapd
sudo systemctl disable --now snapd.socket snapd.service 2>/dev/null
sudo apt purge snapd -y
sudo apt autoremove -y

# 2. Установка утилит
sudo apt update && sudo apt install -y wget gnupg2 chrony ufw cpufrequtils irqbalance software-properties-common

# Устанавливаем ядро Liquorix
sudo add-apt-repository ppa:damentz/liquorix -y
sudo apt update
sudo apt install linux-image-liquorix-amd64 linux-headers-liquorix-amd64 -y

# 3. Настройка процессора и прерываний
echo 'GOVERNOR="performance"' | sudo tee /etc/default/cpufrequtils > /dev/null
sudo systemctl restart cpufrequtils 2>/dev/null || true
sudo systemctl enable --now irqbalance 2>/dev/null || true

# 4. Тюнинг сетевого стека (Sysctl)
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
sudo sysctl --system

# 5. Лимиты на файловые дескрипторы
sudo tee /etc/security/limits.d/99-vpn-limits.conf > /dev/null <<EOF
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF
sudo sed -i 's/#DefaultLimitNOFILE=/DefaultLimitNOFILE=1048576/g' /etc/systemd/system.conf
sudo sed -i 's/#DefaultLimitNOFILE=/DefaultLimitNOFILE=1048576/g' /etc/systemd/user.conf
sudo systemctl daemon-reload

# 6. Настройка UFW
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing

sudo ufw allow $SSH_PORT/tcp
sudo ufw allow 443     
sudo ufw allow 1488    
sudo ufw --force enable

# 7. Включаем точное время
sudo systemctl enable --now chronyd

echo -e "${GREEN}========================================================${NC}"
echo -e "${YELLOW}Тюнинг успешно завершен!${NC}"
echo -e "Твой SSH порт ($SSH_PORT) в безопасности."
echo -e "Для применения ядра Liquorix напиши: ${GREEN}sudo reboot${NC}"
echo -e "${GREEN}========================================================${NC}"
