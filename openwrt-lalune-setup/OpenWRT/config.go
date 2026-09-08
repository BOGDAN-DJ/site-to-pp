package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Config - конфигурация подключения CSQTT, хранится в /etc/csqtt/csqtt.conf
// в формате простых пар KEY=VALUE (совместимо с /bin/sh, чтобы конфиг можно
// было при желании source-ить руками для отладки).
type Config struct {
	Peer        string
	Password    string
	VkHashes    string
	Workers     int
	Fingerprint string
	ClientIDs   string
	Obfs        string
	VkAuthMode  string
	DeviceID    string
	CaptchaMode string
	TurnHost    string
	TurnPort    string
	Tun         string
	// AutoConnect - что делать при старте демона (то есть и после
	// перезагрузки роутера):
	//
	//	"0"      ничего, ждать команды. Значение по умолчанию: пока туннель
	//	         не проверен, пусть ребут гарантированно возвращает роутер
	//	         в заведомо рабочее состояние.
	//	"1"      всегда подключаться.
	//	"switch" подключаться, только если аппаратный переключатель
	//	         (SwitchLabel) стоит в положении "включено".
	AutoConnect string
	// SwitchLabel - метка кнопки/переключателя в devicetree, положение
	// которой смотрит режим AUTOCONNECT='switch'.
	SwitchLabel string
	// Led - светодиод в /sys/class/leds, горящий при поднятом туннеле
	// (и мигающий во время подключения). Пустое значение отключает
	// индикацию.
	Led string
	// Listen - адрес, на котором висят панель и API.
	//
	// Пустое значение означает "определить LAN-адрес роутера сам" — см.
	// listenAddr(). Слушать ":8080" на всех интерфейсах по умолчанию было
	// бы неправильно: панель принимает и показывает параметры подключения,
	// а единственным, что отделяло бы её от WAN, оказалось бы правило
	// firewall. Полагаться на это не стоит.
	Listen string
	// LedIdle - светодиод, горящий когда туннеля нет. На Cudy TR3000 это
	// второй цвет того же физического индикатора: гасить его совсем было
	// бы плохо, роутер выглядел бы выключенным.
	LedIdle string
	// RebindDomains - домены, которые надо исключить из защиты dnsmasq от
	// DNS rebinding (см. dnsmasq.go). Через запятую или пробелы.
	RebindDomains string
	// LanSubnets - подсети через запятую, трафик которых заворачивается в
	// туннель. Пустое значение означает "определить автоматически по
	// адресам LAN-интерфейса из uci".
	LanSubnets string
}

func defaultConfig() Config {
	return Config{
		Workers:     18,
		Fingerprint: "chrome",
		Obfs:        "video",
		VkAuthMode:  "vkcalls",
		DeviceID:    "unknown",
		CaptchaMode: "auto",
		Tun:         "csqtt0",
		AutoConnect: "0",
		// Метка переключателя "mode" в devicetree Cudy TR3000.
		SwitchLabel: "mode",
		// Штатный индикатор Cudy TR3000, в обычной жизни горит ровно.
		Led:     "white:status",
		LedIdle: "red:power",
	}
}

func (a *App) loadConfig() {
	a.config = defaultConfig()

	data, err := os.ReadFile(a.configFile)
	if err != nil {
		log("[CONFIG] Файл %s не найден, использую значения по умолчанию: %v", a.configFile, err)
		return
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), "'\"")

		switch key {
		case "PEER":
			a.config.Peer = value
		case "PASSWORD":
			a.config.Password = value
		case "VK":
			a.config.VkHashes = value
		case "N":
			if n, err := strconv.Atoi(value); err == nil {
				a.config.Workers = n
			}
		case "FINGERPRINT":
			a.config.Fingerprint = value
		case "CLIENT_IDS":
			a.config.ClientIDs = value
		case "OBFS":
			a.config.Obfs = value
		case "VK_AUTH_MODE":
			a.config.VkAuthMode = value
		case "DEVICE_ID":
			a.config.DeviceID = value
		case "CAPTCHA_MODE":
			a.config.CaptchaMode = value
		case "TURN_HOST":
			a.config.TurnHost = value
		case "TURN_PORT":
			a.config.TurnPort = value
		case "TUN":
			if value != "" {
				a.config.Tun = value
			}
		case "AUTOCONNECT":
			a.config.AutoConnect = strings.ToLower(value)
		case "SWITCH_LABEL":
			if value != "" {
				a.config.SwitchLabel = value
			}
		case "LED":
			a.config.Led = value
		case "LED_IDLE":
			a.config.LedIdle = value
		case "LISTEN":
			if value != "" {
				a.config.Listen = value
			}
		case "LAN_SUBNETS":
			a.config.LanSubnets = value
		case "REBIND_DOMAINS":
			a.config.RebindDomains = value
		}
	}

	log("[CONFIG] Peer=%s Tun=%s Workers=%d Obfs=%s Fingerprint=%s",
		a.config.Peer, a.config.Tun, a.config.Workers, a.config.Obfs, a.config.Fingerprint)
}

func (a *App) saveConfig() error {
	if err := os.MkdirAll(filepath.Dir(a.configFile), 0755); err != nil {
		return err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "PEER='%s'\n", a.config.Peer)
	fmt.Fprintf(&b, "PASSWORD='%s'\n", a.config.Password)
	fmt.Fprintf(&b, "VK='%s'\n", a.config.VkHashes)
	fmt.Fprintf(&b, "N='%d'\n", a.config.Workers)
	fmt.Fprintf(&b, "FINGERPRINT='%s'\n", a.config.Fingerprint)
	fmt.Fprintf(&b, "CLIENT_IDS='%s'\n", a.config.ClientIDs)
	fmt.Fprintf(&b, "OBFS='%s'\n", a.config.Obfs)
	fmt.Fprintf(&b, "VK_AUTH_MODE='%s'\n", a.config.VkAuthMode)
	fmt.Fprintf(&b, "DEVICE_ID='%s'\n", a.config.DeviceID)
	fmt.Fprintf(&b, "CAPTCHA_MODE='%s'\n", a.config.CaptchaMode)
	fmt.Fprintf(&b, "TURN_HOST='%s'\n", a.config.TurnHost)
	fmt.Fprintf(&b, "TURN_PORT='%s'\n", a.config.TurnPort)
	fmt.Fprintf(&b, "TUN='%s'\n", a.config.Tun)
	fmt.Fprintf(&b, "AUTOCONNECT='%s'\n", a.config.AutoConnect)
	fmt.Fprintf(&b, "SWITCH_LABEL='%s'\n", a.config.SwitchLabel)
	fmt.Fprintf(&b, "LED='%s'\n", a.config.Led)
	fmt.Fprintf(&b, "LED_IDLE='%s'\n", a.config.LedIdle)
	fmt.Fprintf(&b, "LISTEN='%s'\n", a.config.Listen)
	fmt.Fprintf(&b, "LAN_SUBNETS='%s'\n", a.config.LanSubnets)
	fmt.Fprintf(&b, "REBIND_DOMAINS='%s'\n", a.config.RebindDomains)

	return os.WriteFile(a.configFile, []byte(b.String()), 0600)
}
