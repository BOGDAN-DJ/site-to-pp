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

# У OpenWrt в базовой поставке нет /usr/libexec/sftp-server, а scp начиная с
# OpenSSH 9.0 по умолчанию ходит по SFTP и падает с "Connection closed".
# -O возвращает legacy-протокол scp; на клиентах старше OpenSSH 8.6 флага нет,
# поэтому подставляем его только если он поддерживается.
if scp -O 2>&1 | grep -q 'unknown option'; then
	SCP="scp"
else
	SCP="scp -O"
fi

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

# Без /dev/net/tun демон не сможет создать интерфейс (ioctl TUNSETIFF) и
# Connect() упадёт на setupTunDevice. В образе OpenWrt для filogic kmod-tun
# по умолчанию не установлен, поэтому ставим его сами.
if ! ssh "$ROUTER" '[ -c /dev/net/tun ]'; then
	echo "    /dev/net/tun отсутствует — ставлю kmod-tun"
	ssh "$ROUTER" '(apk add kmod-tun || opkg update && opkg install kmod-tun) && modprobe tun'
	if ! ssh "$ROUTER" '[ -c /dev/net/tun ]'; then
		echo "    ОШИБКА: не удалось получить /dev/net/tun — демон не сможет поднять туннель." >&2
		exit 1
	fi
fi

echo "==> Копирую файлы"
# Демон надо остановить до копирования: пишем поверх работающего бинарника,
# и ядро отвечает ETXTBSY ("Text file busy"). Заодно это заставляет демон
# поймать SIGTERM и откатить маршруты/firewall/TUN, если туннель был поднят.
ssh "$ROUTER" '[ -x /etc/init.d/csqtt ] && /etc/init.d/csqtt stop 2>/dev/null; mkdir -p /etc/csqtt'
$SCP "$DAEMON_BIN" "$ROUTER:/usr/sbin/csqtt-daemon"
$SCP "$FILES_DIR/csqtt.init" "$ROUTER:/etc/init.d/csqtt"

# Обработчик кнопки "mode" (BTN_0). Кнопку reset не трогаем — она нужна
# для failsafe.
$SCP "$FILES_DIR/csqtt.button" "$ROUTER:/etc/rc.button/BTN_0"
ssh "$ROUTER" 'chmod +x /etc/rc.button/BTN_0'

if [ -n "$CORE_BIN" ]; then
	if [ ! -f "$CORE_BIN" ]; then
		echo "Не найден бинарник ядра: $CORE_BIN" >&2
		exit 1
	fi
	$SCP "$CORE_BIN" "$ROUTER:/usr/bin/csqtt-client"
	ssh "$ROUTER" 'chmod +x /usr/bin/csqtt-client'
fi

# Конфиг не перезаписываем, если он уже есть — иначе затрём ключи подключения.
if ssh "$ROUTER" '[ -f /etc/csqtt/csqtt.conf ]'; then
	echo "    /etc/csqtt/csqtt.conf уже существует — оставляю как есть"
else
	$SCP "$FILES_DIR/csqtt.conf.example" "$ROUTER:/etc/csqtt/csqtt.conf"
	ssh "$ROUTER" 'chmod 600 /etc/csqtt/csqtt.conf'
fi

echo "==> Включаю сервис"
ssh "$ROUTER" 'chmod +x /usr/sbin/csqtt-daemon /etc/init.d/csqtt && /etc/init.d/csqtt enable && /etc/init.d/csqtt restart'

sleep 2
echo "==> Статус"
# curl в базовой поставке OpenWrt нет — там uclient-fetch, притворяющийся wget.
ssh "$ROUTER" 'if command -v curl >/dev/null 2>&1; then curl -s http://127.0.0.1:8080/api/status; else wget -qO- http://127.0.0.1:8080/api/status; fi || echo "(API ещё не отвечает — проверьте logread | grep csqtt)"'
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
