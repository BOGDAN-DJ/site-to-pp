#!/usr/bin/env bash
# Восстановление роутера из бэкапа, снятого backup.sh.
#
#   ./restore.sh root@192.168.1.1 backups/20260908-021500/overlay.tar.gz
#
# Распаковывает слепок /overlay/upper поверх текущего состояния и
# перезагружает роутер.
#
# Про безопасность операции
# -------------------------
# Пишем прямо в /overlay/upper смонтированной overlayfs. Строго говоря,
# менять upper-каталог живой overlayfs не рекомендуется: ядро не ожидает
# правок «снизу» и часть уже открытых файлов останется в кэше со старым
# содержимым. Поэтому здесь: сначала останавливаем сервисы, затем
# распаковываем, затем СРАЗУ перезагружаем — до перезагрузки система
# считается в неопределённом состоянии, и трогать её не надо.
#
# Если роутер прошит начисто, версия прошивки должна совпадать с той, из
# которой снят бэкап: пакеты kmod-* жёстко привязаны к версии ядра, и от
# другой версии они просто не загрузятся. Версия записана в info.txt рядом
# с архивом.

set -euo pipefail

ROUTER="${1:-}"
ARCHIVE="${2:-}"

if [ -z "$ROUTER" ] || [ -z "$ARCHIVE" ]; then
	echo "Использование: $0 root@<ip-роутера> <путь-к-overlay.tar.gz>" >&2
	exit 1
fi

if [ ! -f "$ARCHIVE" ]; then
	echo "Не найден архив: $ARCHIVE" >&2
	exit 1
fi

# Порт ssh задаётся переменной SSH_PORT — см. комментарий в backup.sh.
# Восстанавливать бэкап приходится как раз тогда, когда роутер доступен не
# самым обычным путём, так что возможность указать порт тут не роскошь.
SSH="ssh"
if scp -O 2>&1 | grep -q 'unknown option'; then SCP="scp"; else SCP="scp -O"; fi
if [ -n "${SSH_PORT:-}" ]; then
	SSH="ssh -p $SSH_PORT"
	SCP="$SCP -P $SSH_PORT"
fi

SIZE="$(du -h "$ARCHIVE" | cut -f1)"

echo "==> Проверяю совместимость"
REMOTE_REL="$($SSH "$ROUTER" "sed -n \"s/^DISTRIB_RELEASE='\(.*\)'/\1/p\" /etc/openwrt_release")"
INFO="$(dirname "$ARCHIVE")/info.txt"
if [ -f "$INFO" ]; then
	BACKUP_REL="$(sed -n "s/^DISTRIB_RELEASE='\(.*\)'/\1/p" "$INFO")"
	echo "    прошивка на роутере: $REMOTE_REL"
	echo "    прошивка в бэкапе:   $BACKUP_REL"
	if [ "$REMOTE_REL" != "$BACKUP_REL" ]; then
		echo >&2
		echo "    ОСТАНОВЛЕНО: версии прошивки не совпадают." >&2
		echo "    Пакеты kmod-* привязаны к версии ядра и от другой версии не" >&2
		echo "    загрузятся. Прошейте $BACKUP_REL, либо, если понимаете риск," >&2
		echo "    запустите с FORCE=1." >&2
		[ "${FORCE:-0}" = "1" ] || exit 1
		echo "    FORCE=1 — продолжаю вопреки несовпадению." >&2
	fi
else
	echo "    (info.txt рядом с архивом нет, проверить версию не могу)"
fi

echo
echo "Роутер:  $ROUTER (сейчас $REMOTE_REL)"
echo "Архив:   $ARCHIVE ($SIZE)"
echo
echo "Будет распакован слепок overlay поверх текущего состояния, после чего"
echo "роутер уйдёт в перезагрузку. Текущие настройки будут заменены."
echo
printf "Продолжить? [y/N] "
read -r ANSWER
case "$ANSWER" in
	[yY]|[yY][eE][sS]) ;;
	*) echo "Отменено."; exit 0 ;;
esac

echo "==> Заливаю архив"
$SCP "$ARCHIVE" "$ROUTER:/tmp/restore-overlay.tar.gz"

echo "==> Останавливаю сервисы и распаковываю"
$SSH "$ROUTER" 'sh -s' <<'REMOTE'
set -e

# Демон сам снимает маршруты, firewall и TUN по SIGTERM — даём ему это
# сделать до того, как заменим под ним файлы.
if [ -x /etc/init.d/csqtt ]; then
	/etc/init.d/csqtt stop 2>/dev/null || true
	sleep 2
fi

echo "--- распаковка ---"
tar -xzf /tmp/restore-overlay.tar.gz -C /overlay/upper
rm -f /tmp/restore-overlay.tar.gz
sync

echo "--- перезагрузка ---"
# reboot в фоне, чтобы ssh успел корректно закрыть сессию и не оборвать
# нас на полуслове.
(sleep 2; reboot) >/dev/null 2>&1 &
REMOTE

echo
echo "=== Роутер перезагружается ==="
echo
echo "Через минуту-полторы проверьте:"
echo
echo "  ssh $ROUTER 'curl -s http://127.0.0.1:8080/api/status'"
echo
echo "или откройте панель в браузере."
