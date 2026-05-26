#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}=== УНИВЕРСАЛЬНАЯ ПРОВЕРКА ТЮНИНГА СЕРВЕРА ===${NC}\n"

# 1. Проверка ядра
KERNEL=$(uname -r)
if echo "$KERNEL" | grep -q "liquorix"; then
    echo -e "1. Ядро ОС: ${GREEN}Liquorix активно ($KERNEL)${NC}"
else
    echo -e "1. Ядро ОС: ${RED}Стоковое ($KERNEL). Нужен reboot!${NC}"
fi

# 2. Проверка алгоритмов (BBR + FQ)
BBR=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
FQ=$(sysctl -n net.core.default_qdisc 2>/dev/null)
if [ "$BBR" == "bbr" ] && [ "$FQ" == "fq" ]; then
    echo -e "2. Алгоритм сети: ${GREEN}BBR + FQ включены${NC}"
else
    echo -e "2. Алгоритм сети: ${RED}Ошибка ($BBR, $FQ)${NC}"
fi

# 3. Проверка режима CPU (Умная)
CPU_GOV=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null)
if [ "$CPU_GOV" == "performance" ]; then
    echo -e "3. Режим CPU: ${GREEN}Performance (Максимальная мощь)${NC}"
elif [ -z "$CPU_GOV" ]; then
    echo -e "3. Режим CPU: ${YELLOW}Заблокирован хостером (Норма для виртуалок)${NC}"
else
    echo -e "3. Режим CPU: ${RED}Не performance ($CPU_GOV)${NC}"
fi

# 4. Проверка Swap
SWAP=$(sysctl -n vm.swappiness 2>/dev/null)
if [ "$SWAP" == "1" ]; then
    echo -e "4. Swap (swappiness): ${GREEN}Настроен (1)${NC}"
else
    echo -e "4. Swap (swappiness): ${RED}Не настроен ($SWAP)${NC}"
fi

# 5. Проверка удаления мусора (snapd)
if ! command -v snap &> /dev/null; then
    echo -e "5. Мусор (snapd): ${GREEN}Успешно удален${NC}"
else
    echo -e "5. Мусор (snapd): ${RED}Всё еще установлен!${NC}"
fi

# 6. Проверка лимитов (systemd)
LIMIT=$(systemctl show -p DefaultLimitNOFILE | cut -d= -f2)
if [ "$LIMIT" == "1048576" ] || [ "$LIMIT" == "infinity" ] || [ "$LIMIT" -ge 500000 ] 2>/dev/null; then
    echo -e "6. Лимиты соединений: ${GREEN}Расширены ($LIMIT) — Отлично!${NC}"
else
    echo -e "6. Лимиты соединений: ${RED}Стандартные ($LIMIT)${NC}"
fi

# 7. Проверка служб (Умная проверка irqbalance)
echo -e "\n${YELLOW}=== СТАТУС СЛУЖБ ===${NC}"
CORES=$(nproc)
for svc in chronyd ufw irqbalance; do
    if systemctl is-active --quiet $svc; then
        echo -e "Служба $svc: ${GREEN}Работает${NC}"
    else
        if [ "$svc" == "irqbalance" ] && [ "$CORES" -eq 1 ]; then
            echo -e "Служба $svc: ${YELLOW}Выключена (У сервера 1 ядро, балансировка не нужна)${NC}"
        else
            echo -e "Служба $svc: ${RED}НЕ РАБОТАЕТ${NC}"
        fi
    fi
done

# 8. Проверка файрвола (UFW)
echo -e "\n${YELLOW}=== ОТКРЫТЫЕ ПОРТЫ (UFW) ===${NC}"
if sudo ufw status | grep -q "ALLOW"; then
    sudo ufw status | grep ALLOW
else
    echo -e "${RED}Файрвол выключен или правила не заданы!${NC}"
fi
echo -e "${YELLOW}==============================================${NC}"
