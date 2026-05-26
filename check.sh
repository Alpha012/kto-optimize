#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}==========================================${NC}"
echo -e "${YELLOW} kto VPN: Проверка ультимативного говна ${NC}"
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
