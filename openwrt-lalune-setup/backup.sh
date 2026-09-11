#!/usr/bin/env bash
# Полный бэкап роутера с OpenWrt.
#
#   ./backup.sh root@192.168.1.1 [каталог]
#
# Кладёт в каталог (по умолчанию ./backups) набор из четырёх файлов с общей
# меткой времени. Восстанавливается скриптом restore.sh рядом.
#
# ВНИМАНИЕ, ВНУТРИ СЕКРЕТЫ. В бэкап попадают пароль VPN
# (/etc/csqtt/csqtt.conf), пароли Wi-Fi (/etc/config/wireless), приватные
# host-ключи SSH (/etc/dropbear/) и authorized_keys. Храните архив так же,
# как хранили бы эти файлы по отдельности: не в публичном репозитории и не
# в общей папке.
#
# Почему не хватает штатного `sysupgrade -b`
# ------------------------------------------
# Он сохраняет только список из /etc/sysupgrade.conf плюс базовый набор —
# на этом роутере это 35 файлов, среди которых НЕТ ни демона
# (/usr/sbin/csqtt-daemon), ни его конфига (/etc/csqtt/), ни обработчика
# переключателя (/etc/rc.button/BTN_0), ни ядра с glibc-прослойкой (/opt).
# Поэтому основной архив здесь — весь overlay целиком.

set -euo pipefail

ROUTER="${1:-}"
OUTDIR="${2:-./backups}"

if [ -z "$ROUTER" ]; then
	echo "Использование: $0 root@<ip-роутера> [каталог]" >&2
	exit 1
fi

# Порт ssh задаётся переменной SSH_PORT. Роутер бывает доступен не на 22:
# например со стороны WAN, по проброшенному порту — именно этим путём до
# него получается достучаться, когда машина не в его локальной сети.
#
#   SSH_PORT=45123 ./backup.sh root@192.168.31.179 ~/backups
SSH="ssh"
if scp -O 2>&1 | grep -q 'unknown option'; then SCP="scp"; else SCP="scp -O"; fi
if [ -n "${SSH_PORT:-}" ]; then
	SSH="ssh -p $SSH_PORT"
	# У scp флаг порта пишется заглавной буквой, в отличие от ssh.
	SCP="$SCP -P $SSH_PORT"
fi

STAMP="$(date +%Y%m%d-%H%M%S)"
DEST="$OUTDIR/$STAMP"
mkdir -p "$DEST"

echo "==> Собираю сведения о роутере"
$SSH "$ROUTER" 'sh -s' > "$DEST/info.txt" <<'REMOTE'
echo "=== Дата бэкапа: $(date) ==="
echo
echo "--- Плата ---"
cat /tmp/sysinfo/model 2>/dev/null
cat /tmp/sysinfo/board_name 2>/dev/null
echo
echo "--- Прошивка ---"
cat /etc/openwrt_release
echo
echo "--- Ядро ---"
uname -a
echo
echo "--- Разделы ---"
df -h
echo
echo "--- Сеть ---"
ip -4 addr show | grep -E "^[0-9]+: |inet "
echo
echo "--- Маршруты ---"
ip -4 route show
echo
echo "--- Состояние CSQTT ---"
curl -s --max-time 5 http://127.0.0.1:8080/api/status 2>/dev/null || echo "(демон не отвечает)"
REMOTE
echo "    $(grep -c '' "$DEST/info.txt") строк"

echo "==> Список установленных пакетов"
$SSH "$ROUTER" '(apk list -I 2>/dev/null || opkg list-installed 2>/dev/null)' \
	| sort > "$DEST/packages.txt"
echo "    $(grep -c '' "$DEST/packages.txt") пакетов"

echo "==> Штатный конфиг-бэкап (sysupgrade -b)"
# Пригодится, если роутер придётся прошивать начисто: этот архив
# восстанавливается штатным `sysupgrade -r` и не тащит за собой бинарники.
$SSH "$ROUTER" 'sysupgrade -b - 2>/dev/null' </dev/null > "$DEST/config.tar.gz"
echo "    $(du -h "$DEST/config.tar.gz" | cut -f1)"

echo "==> Overlay целиком (это и есть полный бэкап)"
# /overlay/upper — всё, что отличается от заводского образа: доустановленные
# пакеты, наши бинарники, конфиги, ключи. Именно он восстанавливает систему
# в текущее состояние.
#
# Исключаем только заведомо временное: сокеты и кэш apk. Сокеты в tar всё
# равно не переносятся, а от apk-кэша при восстановлении толку нет.
# tar здесь busybox-овский: у него нет --exclude, вместо этого -X с файлом
# шаблонов. Ошибки чтения глушим — в overlay попадаются сокеты и файлы,
# исчезающие прямо во время архивации, и падать из-за них не нужно.
$SSH "$ROUTER" 'sh -s' > "$DEST/overlay.tar.gz" <<'REMOTE'
cat > /tmp/backup-exclude <<'EXC'
./tmp/*
./var/*
./lib/apk/db/lock
EXC
tar -czf - -C /overlay/upper -X /tmp/backup-exclude . 2>/dev/null
rm -f /tmp/backup-exclude
REMOTE
echo "    $(du -h "$DEST/overlay.tar.gz" | cut -f1)"

# Ссылка на образ ровно той версии, что стоит сейчас: если роутер придётся
# восстанавливать с нуля, прошивать надо именно её, иначе overlay от другой
# версии может не подойти (например, kmod-* жёстко привязаны к версии ядра).
RELEASE="$(sed -n "s/^DISTRIB_RELEASE='\(.*\)'/\1/p" "$DEST/info.txt")"
TARGET="$(sed -n "s/^DISTRIB_TARGET='\(.*\)'/\1/p" "$DEST/info.txt")"
BOARD="$(sed -n 's/^cudy,/cudy_/p;s/,/_/g' "$DEST/info.txt" | head -1)"

cat > "$DEST/RESTORE.txt" <<EOF
Как восстановить этот бэкап
===========================

Снят: $STAMP
Прошивка: OpenWrt $RELEASE, таргет $TARGET, плата $BOARD

--- Вариант 1: роутер загружается, надо откатить состояние ---

    ./restore.sh root@192.168.1.1 $DEST/overlay.tar.gz

Скрипт остановит сервисы, распакует overlay поверх текущего и перезагрузит
роутер. Занимает около минуты.

--- Вариант 2: роутер прошит начисто или заменён ---

1. Прошейте РОВНО ту же версию OpenWrt. Overlay от другой версии может не
   подойти: пакеты kmod-* жёстко привязаны к версии ядра.

   https://downloads.openwrt.org/releases/$RELEASE/targets/$TARGET/openwrt-$RELEASE-${TARGET//\//-}-$BOARD-squashfs-sysupgrade.bin

2. Дайте роутеру загрузиться, убедитесь, что доступен по ssh.

3. Восстановите overlay:

    ./restore.sh root@192.168.1.1 $DEST/overlay.tar.gz

--- Вариант 3: только настройки, без бинарников ---

Если нужен лишь штатный набор конфигов (/etc/config/*, ключи ssh и т.п.):

    scp -O $DEST/config.tar.gz root@192.168.1.1:/tmp/
    ssh root@192.168.1.1 'sysupgrade -r /tmp/config.tar.gz && reboot'

Это НЕ вернёт демон CSQTT, ядро и /opt/glibc — только настройки.

--- Что лежит в этом каталоге ---

overlay.tar.gz  полный слепок /overlay/upper: пакеты, бинарники, конфиги
config.tar.gz   штатный sysupgrade -b, только список из /etc/sysupgrade.conf
packages.txt    список установленных пакетов (на случай ручной пересборки)
info.txt        версия прошивки, разделы, сеть, состояние туннеля на момент снятия

ВНИМАНИЕ: overlay.tar.gz и config.tar.gz содержат пароль VPN, пароли Wi-Fi
и приватные ssh-ключи роутера. Храните соответственно.
EOF

echo
echo "=== Готово: $DEST ==="
ls -la "$DEST"
echo
echo "Инструкция по восстановлению: $DEST/RESTORE.txt"
echo
echo "ВНИМАНИЕ: в архивах лежат пароль VPN, пароли Wi-Fi и приватные"
echo "ssh-ключи роутера. Не кладите их в git и в общие папки."
