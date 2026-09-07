#!/usr/bin/env bash
# Установка демона LaLune/CSQTT на роутер с OpenWrt.
# Запускается НЕ на роутере, а на машине в той же сети (ноутбук/ПК).
#
#   ./install.sh root@192.168.1.1 ./csqtt-daemon-arm64 ./csqtt-client-arm64
#
# Третий аргумент (ядро csqtt-client под вашу архитектуру) необязателен:
# если его не передать, скрипт поставит только демон, а ядро вы положите
# в /usr/bin/csqtt-client позже сами.

set -euo pipefail

ROUTER="${1:-}"
DAEMON_BIN="${2:-}"
CORE_BIN="${3:-}"

if [ -z "$ROUTER" ] || [ -z "$DAEMON_BIN" ]; then
	echo "Использование: $0 root@<ip-роутера> <путь-к-csqtt-daemon-arm64> [путь-к-csqtt-client]" >&2
	exit 1
fi

if [ ! -f "$DAEMON_BIN" ]; then
	echo "Не найден бинарник демона: $DAEMON_BIN" >&2
	exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FILES_DIR="$SCRIPT_DIR/OpenWRT/files"

echo "==> Проверяю роутер"
ARCH="$(ssh "$ROUTER" 'uname -m')"
echo "    Архитектура: $ARCH"
if [ "$ARCH" != "aarch64" ]; then
	echo "    ВНИМАНИЕ: ожидался aarch64 (Cudy TR3000 = MT7981). Убедитесь, что бинарники собраны под $ARCH." >&2
fi

if ! ssh "$ROUTER" 'command -v fw4 >/dev/null 2>&1'; then
	echo "    ВНИМАНИЕ: fw4 не найден — демон рассчитан на firewall4 (nftables)." >&2
	echo "    На старых сборках с fw3 правила firewall придётся добавить вручную." >&2
fi

echo "==> Копирую файлы"
ssh "$ROUTER" 'mkdir -p /etc/csqtt'
scp "$DAEMON_BIN" "$ROUTER:/usr/sbin/csqtt-daemon"
scp "$FILES_DIR/csqtt.init" "$ROUTER:/etc/init.d/csqtt"

if [ -n "$CORE_BIN" ]; then
	if [ ! -f "$CORE_BIN" ]; then
		echo "Не найден бинарник ядра: $CORE_BIN" >&2
		exit 1
	fi
	scp "$CORE_BIN" "$ROUTER:/usr/bin/csqtt-client"
	ssh "$ROUTER" 'chmod +x /usr/bin/csqtt-client'
fi

# Конфиг не перезаписываем, если он уже есть — иначе затрём ключи подключения.
if ssh "$ROUTER" '[ -f /etc/csqtt/csqtt.conf ]'; then
	echo "    /etc/csqtt/csqtt.conf уже существует — оставляю как есть"
else
	scp "$FILES_DIR/csqtt.conf.example" "$ROUTER:/etc/csqtt/csqtt.conf"
	ssh "$ROUTER" 'chmod 600 /etc/csqtt/csqtt.conf'
fi

echo "==> Включаю сервис"
ssh "$ROUTER" 'chmod +x /usr/sbin/csqtt-daemon /etc/init.d/csqtt && /etc/init.d/csqtt enable && /etc/init.d/csqtt restart'

sleep 2
echo "==> Статус"
ssh "$ROUTER" 'curl -s http://127.0.0.1:8080/api/status || echo "(API ещё не отвечает — проверьте logread | grep csqtt)"'
echo

cat <<EOF

Готово. Дальше:

  1. Заполните ключи подключения:
       ssh $ROUTER vi /etc/csqtt/csqtt.conf
     (PEER=HOST:PORT, PASSWORD, VK — см. README.md, раздел про csqtt:// ссылку)

  2. Перезапустите и подключитесь:
       ssh $ROUTER '/etc/init.d/csqtt restart'
       ssh $ROUTER 'curl -s -X POST http://127.0.0.1:8080/api/connect'

  3. Смотрите лог:
       ssh $ROUTER 'curl -s http://127.0.0.1:8080/api/logs | tail -n 40'

     Успех выглядит как строка: [TUN] Туннель поднят: csqtt0 ...
EOF
