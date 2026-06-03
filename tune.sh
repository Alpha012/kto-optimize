#!/usr/bin/env bash
# shellcheck shell=bash

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_NAME="kto VPN"
SCRIPT_VERSION="2.1.1"

DRY_RUN=0
ASSUME_YES="${KTO_ASSUME_YES:-1}"
NO_COLOR="${NO_COLOR:-0}"
ACTION="${KTO_ACTION:-optimize}"
PROFILE="${KTO_PROFILE:-throughput}"
DEFAULT_NODE_PORT="${KTO_NODE_PORT:-1488}"

SYSCTL_FILE="/etc/sysctl.d/99-kto-vpn.conf"
LIMITS_FILE="/etc/security/limits.d/99-kto-vpn-limits.conf"
SYSTEMD_SYSTEM_DROPIN="/etc/systemd/system.conf.d/99-kto-vpn.conf"
SYSTEMD_USER_DROPIN="/etc/systemd/user.conf.d/99-kto-vpn.conf"
JOURNALD_DROPIN="/etc/systemd/journald.conf.d/99-kto-vpn.conf"
BACKUP_ROOT="/var/backups/kto-vpn"
REMNA_DIR="/opt/remnanode"
REMNA_CONTAINER="remnanode"

if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
    LOG_FILE="${KTO_LOG_FILE:-/var/log/kto-vpn-tune.log}"
else
    LOG_FILE="${KTO_LOG_FILE:-/tmp/kto-vpn-tune.log}"
fi

SUDO=()
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    SUDO=(sudo)
fi

if [[ -t 1 && "$NO_COLOR" != "1" ]]; then
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    PURPLE='\033[38;5;93m'
    RED='\033[0;31m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    DIM='\033[2m'
    NC='\033[0m'
else
    GREEN=''
    YELLOW=''
    PURPLE=''
    RED=''
    BLUE=''
    BOLD=''
    DIM=''
    NC=''
fi

cleanup_files=()

cleanup() {
    local file
    for file in "${cleanup_files[@]:-}"; do
        [[ -z "$file" ]] && continue
        if [[ -d "$file" ]]; then
            rm -rf "$file"
        elif [[ -f "$file" ]]; then
            rm -f "$file"
        fi
    done
}

on_error() {
    local exit_code=$?
    local line_no=${1:-unknown}
    local cmd=${2:-unknown}
    echo -e "\n${RED}[ERROR]${NC} Команда упала на строке ${line_no}: ${cmd}" >&2
    echo -e "${YELLOW}[LOG]${NC} ${LOG_FILE}" >&2
    exit "$exit_code"
}

trap cleanup EXIT
trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR

print_header() {
    printf '\033c'
    echo -e "${PURPLE}==========================================${NC}"
    echo -e "${BOLD}${GREEN}                 ${SCRIPT_NAME}                  ${NC}"
    echo -e "${DIM}                  v${SCRIPT_VERSION}${NC}"
    echo -e "${PURPLE}==========================================${NC}"
}

info() { echo -e "${YELLOW}[INFO]${NC} $*"; }
step() { echo -e "${PURPLE}[..]${NC} $*"; }
ok() { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
fail() { echo -e "${RED}[FAIL]${NC} $*" >&2; }

pause() {
    [[ -t 0 ]] || return 0
    echo
    read -r -p "Нажми Enter, чтобы продолжить..." _
}

usage() {
    cat <<EOF
${SCRIPT_NAME} v${SCRIPT_VERSION}

Использование:
  ./tune.sh                         Полная оптимизация без вопросов
  ./tune.sh menu                    Интерактивное меню
  ./tune.sh optimize                Полная оптимизация
  ./tune.sh install-node            Установка Remnawave Node
  ./tune.sh status                  Панель состояния
  ./tune.sh ssl                     Выпуск SSL-сертификата
  ./tune.sh speedtest               Speedtest
  ./tune.sh ipcheck-place           Проверка IP.Check.Place
  ./tune.sh ipcheck-region          Проверка региона IP
  ./tune.sh selfsteal               Установка SelfSteal
  ./tune.sh warp                    Установка WARP Native
  ./tune.sh rollback                Откат последнего бэкапа

Опции:
  --profile balanced|throughput|low-memory
  --yes                             Автоответ "да" на подтверждения
  --ask                             Включить ручные вопросы
  --dry-run                         Показать действия без изменений
  --no-color                        Без цветов
  --log PATH                        Путь к лог-файлу
  -h, --help                        Помощь

Примеры:
  ./tune.sh
  ./tune.sh optimize --profile throughput
  ./tune.sh menu --ask
  REMNA_SSL_CERT='...' ./tune.sh install-node
  ./tune.sh status --no-color

Переменные для автоматизации:
  KTO_PROFILE=throughput|balanced|low-memory
  KTO_NODE_PORT=1488
  REMNA_MODE=modern|legacy
  REMNA_SSL_CERT=...                 Для modern Remnawave Node
  REMNA_SECRET_KEY=...               Для legacy Remnawave Node
  REMNA_IMAGE_TAG=latest
  REMNA_PANEL_IP=1.2.3.4
  SSL_DOMAIN=vpn.domain.com
  ACME_EMAIL=admin@domain.com
  CERT_DIR=/opt/remnawave/nginx
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            menu|optimize|install-node|status|ssl|speedtest|ipcheck-place|ipcheck-region|selfsteal|warp|rollback)
                ACTION="$1"
                shift
                ;;
            --profile)
                PROFILE="${2:-}"
                shift 2
                ;;
            --profile=*)
                PROFILE="${1#*=}"
                shift
                ;;
            --yes|-y)
                ASSUME_YES=1
                shift
                ;;
            --ask)
                ASSUME_YES=0
                shift
                ;;
            --dry-run)
                DRY_RUN=1
                shift
                ;;
            --no-color)
                NO_COLOR=1
                shift
                ;;
            --log)
                LOG_FILE="${2:-}"
                shift 2
                ;;
            --log=*)
                LOG_FILE="${1#*=}"
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                fail "Неизвестный аргумент: $1"
                usage
                exit 2
                ;;
        esac
    done
