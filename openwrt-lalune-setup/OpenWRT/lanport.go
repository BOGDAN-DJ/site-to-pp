package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Управление режимом согласования скорости на проводном порту LAN.
//
// Зачем это вообще понадобилось: связка «PHY роутера + конкретное устройство
// на 100 Мбит/с» иногда согласуется неустойчиво. Симптом — линк
// поднимается и падает по кругу, копятся CRC-ошибки, а клиент не успевает
// даже получить адрес по DHCP: пять DHCPDISCOVER подряд и ни одного ACK.
// На том же порту гигабитный ноутбук при этом работает без единой ошибки,
// то есть порт исправен, а проблема именно в паре.
//
// Лечится сужением набора скоростей, которые порт предлагает при
// автосогласовании. ВАЖНО: именно сужением, а не отключением autoneg.
// Если выключить автосогласование с одной стороны, вторая продолжит его
// пытаться, не получит ответа и по стандарту свалится в ПОЛУДУПЛЕКС —
// получится рассогласование дуплекса, коллизии и ошибки вместо решения.
// Поэтому autoneg остаётся включённым всегда, меняется только маска
// предлагаемых режимов.

const (
	// Маски ethtool для advertise.
	//
	//	0x001 10baseT/Half    0x002 10baseT/Full
	//	0x004 100baseT/Half   0x008 100baseT/Full
	//	0x020 1000baseT/Full
	advertiseAll     = "0x02f" // всё, что умеет типовой гигабитный порт
	advertise100Full = "0x008" // только 100 Мбит/с полный дуплекс

	lanModeAuto     = "auto"
	lanMode100Full  = "100full"
	sysClassNetPath = "/sys/class/net"
)

// lanPort определяет проводной порт в мосте LAN.
//
// Берём из моста первый интерфейс, не похожий на радио: точки доступа
// добавляются в тот же мост, но у них имена вида phy0-ap0. Если
// определить не вышло, возвращаем пустую строку — вызывающий код тогда
// просто ничего не делает, а не портит наугад чужой интерфейс.
func lanPort(configured string) string {
	if configured != "" {
		return configured
	}

	dev := "br-lan"
	if out, err := exec.Command("uci", "-q", "get", "network.lan.device").Output(); err == nil {
		if d := strings.TrimSpace(string(out)); d != "" {
			dev = d
		}
	}

	entries, err := os.ReadDir(filepath.Join(sysClassNetPath, dev, "brif"))
	if err != nil {
		return ""
	}

	var wired []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "phy") || strings.Contains(name, "-ap") ||
			strings.HasPrefix(name, "wlan") {
			continue
		}
		wired = append(wired, name)
	}
	if len(wired) == 0 {
		return ""
	}
	// Порядок чтения каталога не гарантирован, а имя порта попадает в
	// конфиг и в панель — пусть будет стабильным.
	sort.Strings(wired)
	return wired[0]
}

// applyLanLinkMode выставляет набор предлагаемых скоростей.
func applyLanLinkMode(dev, mode string) {
	if dev == "" {
		return
	}

	mask := advertiseAll
	if mode == lanMode100Full {
		mask = advertise100Full
	}

	// autoneg on обязателен: см. комментарий в начале файла.
	cmd := exec.Command("ethtool", "-s", dev, "autoneg", "on", "advertise", mask)
	if out, err := cmd.CombinedOutput(); err != nil {
		log("[LAN] Не удалось настроить %s: %v (%s)", dev, err, strings.TrimSpace(string(out)))
		return
	}

	if mode == lanMode100Full {
		log("[LAN] Порт %s: предлагаем только 100baseT/Full", dev)
		return
	}
	log("[LAN] Порт %s: обычное автосогласование", dev)
}

func readSysNet(dev, attr string) string {
	data, err := os.ReadFile(filepath.Join(sysClassNetPath, dev, attr))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readSysNetInt(dev, attr string) int {
	n, _ := strconv.Atoi(readSysNet(dev, attr))
	return n
}

// lanPortStatus собирает то, что показывает панель.
//
// Счётчики обрывов и CRC-ошибок здесь не для красоты: именно они
// отличают неисправный кабель или капризное согласование от проблемы
// уровнем выше. У здорового соединения оба стоят на месте.
func lanPortStatus(dev, mode string) map[string]interface{} {
	if dev == "" {
		return map[string]interface{}{"device": ""}
	}

	speed := readSysNet(dev, "speed")
	if speed == "-1" || speed == "" {
		speed = ""
	}

	return map[string]interface{}{
		"device":     dev,
		"link":       readSysNet(dev, "carrier") == "1",
		"speed":      speed,
		"duplex":     readSysNet(dev, "duplex"),
		"mode":       mode,
		"flaps":      readSysNetInt(dev, "carrier_down_count"),
		"crc_errors": readSysNetInt(dev, "statistics/rx_crc_errors"),
	}
}
