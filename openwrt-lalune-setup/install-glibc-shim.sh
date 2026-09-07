#!/usr/bin/env bash
# Ставит на OpenWrt-роутер минимальный glibc-рантайм в /opt/glibc и обёртку
# /usr/bin/csqtt-client, запускающую через него официальный релизный бинарник
# csqtt-core.
#
#   ./install-glibc-shim.sh root@192.168.1.1 [путь-к-client-linux-arm64]
#
# Зачем это нужно
# ---------------
# Релизы Endlad2/csqtt-core собираются под aarch64-unknown-linux-gnu:
#
#   $ file client-linux-arm64
#   ELF 64-bit LSB pie executable, ARM aarch64, dynamically linked,
#   interpreter /lib/ld-linux-aarch64.so.1, for GNU/Linux 3.7.0
#
# и требуют символов вплоть до GLIBC_2.38. Стоковый OpenWrt — musl, у него
# есть только /lib/ld-musl-aarch64.so.1, поэтому ядро не находит ELF-
# интерпретатор и запуск падает с "not found" (rc=127), хотя файл на месте и
# исполняемый.
#
# Entware как обходной путь здесь не работает: нужной версии glibc (2.38+)
# там нет. Правильное решение — пересобрать csqtt-core под
# aarch64-unknown-linux-musl; пока этого нет, кладём рядом собственный
# загрузчик и libc, ничего не подменяя в системных /lib и /usr/lib.
#
# Занимает ~3 МБ. Удаляется полностью: rm -rf /opt/glibc /opt/csqtt.

set -euo pipefail

ROUTER="${1:-}"
CORE_BIN="${2:-}"

if [ -z "$ROUTER" ]; then
	echo "Использование: $0 root@<ip-роутера> [путь-к-client-linux-arm64]" >&2
	exit 1
fi

GLIBC_DEB_URL="http://ftp.debian.org/debian/pool/main/g/glibc/libc6_2.41-12+deb13u4_arm64.deb"
LIBGCC_DEB_URL="http://ftp.debian.org/debian/pool/main/g/gcc-14/libgcc-s1_14.2.0-19_arm64.deb"
CORE_URL="https://github.com/Endlad2/csqtt-core/releases/latest/download/client-linux-arm64"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# .deb — это ar-архив. GNU tar его не читает, bsdtar читает. На Windows
# системный C:\Windows\System32\tar.exe как раз bsdtar, в отличие от tar
# из Git for Windows, который GNU.
unpack_deb() {
	local deb="$1" dest="$2"
	mkdir -p "$dest"
	if command -v bsdtar >/dev/null 2>&1; then
		bsdtar -xf "$deb" -C "$dest"
	elif [ -x /c/Windows/System32/tar.exe ]; then
		/c/Windows/System32/tar.exe -xf "$(cygpath -w "$deb")" -C "$(cygpath -w "$dest")"
	elif command -v ar >/dev/null 2>&1; then
		( cd "$dest" && ar x "$deb" )
	else
		echo "Нужен bsdtar или ar, чтобы распаковать .deb" >&2
		exit 1
	fi
	# Внутри — data.tar.xz, его уже понимает любой tar. Ошибки глушим: в
	# libgcc-s1 лежит символьная ссылка в usr/share/doc, которую GNU tar не
	# может создать на файловой системе Windows, а нужные нам .so при этом
	# распаковываются нормально. Что распаковалось действительно всё, что
	# требуется, проверяется ниже явным списком файлов.
	tar -xf "$dest"/data.tar.* -C "$dest" 2>/dev/null || true
}

echo "==> Скачиваю glibc-рантайм (Debian trixie, arm64)"
curl -fsSL -o "$WORK/libc6.deb"  "$GLIBC_DEB_URL"
curl -fsSL -o "$WORK/libgcc.deb" "$LIBGCC_DEB_URL"

echo "==> Распаковываю"
unpack_deb "$WORK/libc6.deb"  "$WORK/libc6"
unpack_deb "$WORK/libgcc.deb" "$WORK/libgcc"

LIBDIR_C="$WORK/libc6/usr/lib/aarch64-linux-gnu"
LIBDIR_G="$WORK/libgcc/usr/lib/aarch64-linux-gnu"

echo "==> Собираю минимальный набор"
mkdir -p "$WORK/payload"
# Загрузчик + то, что реально просит бинарник (libc/libm/libgcc_s), плюс
# NSS/resolv: getaddrinfo в glibc умеет подгружать их через dlopen, и без
# них у ядра может отвалиться разрешение имён.
for f in \
	ld-linux-aarch64.so.1 \
	libc.so.6 libm.so.6 \
	libdl.so.2 libpthread.so.0 librt.so.1 \
	libresolv.so.2 libnss_dns.so.2 libnss_files.so.2
do
	[ -f "$LIBDIR_C/$f" ] || { echo "В libc6.deb не оказалось $f" >&2; exit 1; }
	cp -a "$LIBDIR_C/$f" "$WORK/payload/"
done
[ -f "$LIBDIR_G/libgcc_s.so.1" ] || { echo "В libgcc-s1.deb не оказалось libgcc_s.so.1" >&2; exit 1; }
cp -a "$LIBDIR_G/libgcc_s.so.1" "$WORK/payload/"

if [ -n "$CORE_BIN" ]; then
	[ -f "$CORE_BIN" ] || { echo "Не найден бинарник ядра: $CORE_BIN" >&2; exit 1; }
	cp "$CORE_BIN" "$WORK/payload/csqtt-client-glibc"
else
	echo "==> Скачиваю csqtt-client из последнего релиза csqtt-core"
	curl -fsSL -o "$WORK/payload/csqtt-client-glibc" "$CORE_URL"
fi
chmod +x "$WORK/payload/csqtt-client-glibc"

# Обёртка лежит отдельным файлом рядом со скриптом: тот же самый файл берёт
# workflow сборки прошивки, и держать две копии одного shell-скрипта,
# которые обязаны совпадать, не стоит.
WRAPPER_SRC="$SCRIPT_DIR/OpenWRT/files/csqtt-client.wrapper"
[ -f "$WRAPPER_SRC" ] || { echo "Не найдена обёртка: $WRAPPER_SRC" >&2; exit 1; }
cp "$WRAPPER_SRC" "$WORK/payload/csqtt-client-wrapper"

tar -C "$WORK/payload" -czf "$WORK/payload.tar.gz" .

if scp -O 2>&1 | grep -q 'unknown option'; then SCP="scp"; else SCP="scp -O"; fi

echo "==> Заливаю на роутер ($(du -h "$WORK/payload.tar.gz" | cut -f1))"
$SCP "$WORK/payload.tar.gz" "$ROUTER:/tmp/glibc-shim.tar.gz"

ssh "$ROUTER" 'sh -s' <<'REMOTE'
set -e
mkdir -p /opt/glibc /opt/csqtt
tar -xzf /tmp/glibc-shim.tar.gz -C /opt/glibc
rm -f /tmp/glibc-shim.tar.gz

mv /opt/glibc/csqtt-client-glibc /opt/csqtt/csqtt-client-glibc
mv /opt/glibc/csqtt-client-wrapper /usr/bin/csqtt-client
chmod +x /usr/bin/csqtt-client /opt/csqtt/csqtt-client-glibc
# ld-linux вызывается как обычная программа, поэтому ему нужен бит
# исполнения. Права из .deb до сюда не доезжают: сборка идёт на машине
# разработчика, и на файловой системе Windows режим теряется.
chmod +x /opt/glibc/ld-linux-aarch64.so.1

# У glibc есть вкомпилированный дефолт, но без nsswitch.conf он в некоторых
# сборках резолвит только через файлы. Явный конфиг убирает эту неоднозначность.
[ -f /etc/nsswitch.conf ] || printf 'hosts: files dns\n' > /etc/nsswitch.conf

echo "--- проверка запуска ---"
/usr/bin/csqtt-client --help 2>&1 | head -20 || true
echo "rc=$?"
REMOTE
