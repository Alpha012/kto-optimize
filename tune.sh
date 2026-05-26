#!/bin/bash
# Скрипт автонастройки ноды kto VPN (Silent Mode)

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}==========================================${NC}"
echo -e "${GREEN}    kto VPN: Auto-Tuning Node Setup       ${NC}"
echo -e "${CYAN}==========================================${NC}"
echo "Начинаем тихую установку. Пожалуйста, подождите..."
echo ""

# Автоопределение порта SSH
SSH_PORT=$(grep -E "^Port " /etc/ssh/sshd_config | grep -v "^#" | awk '{print $2}' | head -n 1)
SSH_PORT=${SSH_PORT:-22}
echo -e "${GREEN}[INFO]${NC} Обнаружен SSH порт: $SSH_PORT. Он будет защищен."
echo ""

# 1. Мусор
echo -n -e "${YELLOW}[..]${NC} 1/7 Удаление мусора (snapd)... "
sudo systemctl disable --now snapd.socket snapd.service > /dev/null 2>&1
sudo apt-get purge snapd -y > /dev/null 2>&1
sudo apt-get autoremove -y > /dev/null 2>&1
echo -e "\r${GREEN}[OK]${NC} 1/7 Удаление мусора (snapd) завершено!     "

# 2. Утилиты
echo -n -e "${YELLOW}[..]${NC} 2/7 Установка базовых утилит... "
sudo apt-get update > /dev/null 2>&1
# Переменная DEBIAN_FRONTEND отключает розовые экраны с подтверждениями во время установки
sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y wget gnupg2 chrony ufw cpufrequtils irqbalance software-properties-common > /dev/null 2>&1
echo -e "\r${GREEN}[OK]${NC} 2/7 Базовые утилиты установлены!           "

# 3. Liquorix
echo -n -e "${YELLOW}[..]${NC} 3/7 Установка ядра Liquorix (занимает 1-2 мин)... "
sudo add-apt-repository ppa:damentz/liquorix -y > /dev/null 2>&1
sudo apt-get update > /dev/null 2>&1
sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y linux-image-liquorix-amd64 linux-headers-liquorix-amd64 > /dev/null 2>&1
echo -e "\r${GREEN}[OK]${NC} 3/7 Ядро Liquorix успешно установлено!                       "

# 4. Процессор
echo -n -e "${YELLOW}[..]${NC} 4/7 Настройка процессора и прерываний... "
echo 'GOVERNOR="performance"' | sudo tee /etc/default/cpufrequtils > /dev/null 2>&1
sudo systemctl restart cpufrequtils > /dev/null 2>&1 || true
sudo systemctl enable --now irqbalance > /dev/null 2>&1 || true
echo -e "\r${GREEN}[OK]${NC} 4/7 Процессор настроен!                          "

# 5. Sysctl
echo -n -e "${YELLOW}[..]${NC} 5/7 Оптимизация сети (Sysctl, BBR, FQ)... "
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
echo -e "\r${GREEN}[OK]${NC} 5/7 Оптимизация сети завершена!                   "

# 6. Лимиты
echo -n -e "${YELLOW}[..]${NC} 6/7 Снятие лимитов на дескрипторы... "
sudo tee /etc/security/limits.d/99-vpn-limits.conf > /dev/null 2>&1 <<EOF
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF
sudo sed -i 's/#DefaultLimitNOFILE=/DefaultLimitNOFILE=1048576/g' /etc/systemd/system.conf > /dev/null 2>&1
sudo sed -i 's/#DefaultLimitNOFILE=/DefaultLimitNOFILE=1048576/g' /etc/systemd/user.conf > /dev/null 2>&1
sudo systemctl daemon-reload > /dev/null 2>&1
echo -e "\r${GREEN}[OK]${NC} 6/7 Лимиты системы расширены!              "

# 7. UFW и Chrony
echo -n -e "${YELLOW}[..]${NC} 7/7 Настройка файрвола (UFW) и времени... "
sudo ufw --force reset > /dev/null 2>&1
sudo ufw default deny incoming > /dev/null 2>&1
sudo ufw default allow outgoing > /dev/null 2>&1
sudo ufw allow $SSH_PORT/tcp > /dev/null 2>&1
sudo ufw allow 443 > /dev/null 2>&1
sudo ufw allow 1488 > /dev/null 2>&1
sudo ufw --force enable > /dev/null 2>&1
sudo systemctl enable --now chronyd > /dev/null 2>&1
echo -e "\r${GREEN}[OK]${NC} 7/7 Файрвол и время готовы!                     "

echo ""
echo -e "${CYAN}========================================================${NC}"
echo -e "${GREEN}Тюнинг успешно завершен без единого лога!${NC}"
echo -e "Для применения ядра Liquorix напиши: ${GREEN}sudo reboot${NC}"
echo -e "${CYAN}========================================================${NC}"
