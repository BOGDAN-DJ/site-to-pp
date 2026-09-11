package main

import (
	_ "embed"
	"encoding/json"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

//go:embed panel.html
var panelHTML []byte

// Разбор строки статистики ядра:
//
//	[СТАТИСТИКА] Активных: 18 | Трафик: 2.18 МБ
//
// Панели нужны числа, а не текст, поэтому вытаскиваем их отдельно. Если
// формат строки в ядре когда-нибудь поменяется, поля просто окажутся
// нулевыми — панель это переживёт, а строку целиком она показывает рядом.
var (
	reStatsActive  = regexp.MustCompile(`Активных:\s*(\d+)`)
	reStatsTraffic = regexp.MustCompile(`Трафик:\s*([\d.]+)`)
)

// statusSnapshot - то, что отдаётся в /api/status и рисуется панелью.
type statusSnapshot struct {
	Connected bool   `json:"connected"`
	TunUp     bool   `json:"tun_up"`
	PID       int    `json:"pid"`
	CoreStats string `json:"core_stats"`

	Active  int     `json:"active"`
	Workers int     `json:"workers"`
	Traffic float64 `json:"traffic_mb"`
	Uptime  int     `json:"uptime_sec"`

	TunName  string `json:"tun_name"`
	TunIP    string `json:"tun_ip"`
	Underlay string `json:"underlay"`

	Peer string `json:"peer"`
	// Retrying и RetryIn показывают, что демон не сдался, а ждёт повтора.
	// Без этого панель рисовала бы просто «Выключен», и отличить «не смог и
	// перестал пытаться» от «сейчас попробует снова» было бы невозможно.
	Retrying bool `json:"retrying"`
	// CaptchaBlocked - последняя неудача была из-за антибот-проверки ВК.
	// Панель показывает это отдельно: причина не в связи, и ждать придётся
	// заметно дольше обычного.
	CaptchaBlocked bool   `json:"captcha_blocked"`
	RetryIn        int    `json:"retry_in_sec"`
	Configured     bool   `json:"configured"`
	AutoConnect    string `json:"autoconnect"`

	Version string `json:"version"`
}

func (a *App) snapshot() statusSnapshot {
	a.mu.Lock()
	s := statusSnapshot{
		Connected:      a.connected,
		TunUp:          a.tunUp,
		PID:            a.corePID,
		CoreStats:      a.coreStats,
		Workers:        a.config.Workers,
		TunName:        a.config.Tun,
		TunIP:          a.tunIP,
		Peer:           a.config.Peer,
		Retrying:       a.wantConnected && !a.connected && !a.nextRetry.IsZero(),
		CaptchaBlocked: a.captchaBlocked,
		AutoConnect:    a.config.AutoConnect,
		Version:        daemonVersion,
	}
	s.Configured = a.config.Peer != "" && a.config.Password != "" && a.config.VkHashes != ""
	if !a.connectedAt.IsZero() && a.connected {
		s.Uptime = int(time.Since(a.connectedAt).Seconds())
	}
	if s.Retrying {
		if left := time.Until(a.nextRetry); left > 0 {
			s.RetryIn = int(left.Seconds())
		}
	}
	stats := a.coreStats
	a.mu.Unlock()

	if m := reStatsActive.FindStringSubmatch(stats); m != nil {
		s.Active, _ = strconv.Atoi(m[1])
	}
	if m := reStatsTraffic.FindStringSubmatch(stats); m != nil {
		s.Traffic, _ = strconv.ParseFloat(m[1], 64)
	}
	// Канал перечитываем каждый раз, а не берём запомненный: при двух WAN
	// он меняется на ходу, и панель должна показывать текущий.
	if r := getDefaultRoute(s.TunName); r.has {
		s.Underlay = r.String()
	}

	return s
}

// handleLink принимает ссылку csqtt://connect?... и накладывает её на
// существующий конфиг. Именно накладывает: ссылка несёт только peer,
// password и хеши, а остальные настройки должны пережить её замену.
func (a *App) handleLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Link string `json:"link"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, map[string]interface{}{"success": false, "error": "не разобрать запрос"})
		return
	}

	peer, password, vk, err := parseCSQTTLink(body.Link)
	if err != nil {
		writeJSON(w, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}

	a.mu.Lock()
	a.config.Peer = peer
	a.config.Password = password
	a.config.VkHashes = vk
	a.mu.Unlock()

	if err := a.saveConfig(); err != nil {
		log("[CONFIG] Ошибка сохранения: %v", err)
		writeJSON(w, map[string]interface{}{"success": false, "error": "не сохранить конфиг"})
		return
	}

	// Пароль и хеши в лог не пишем — только адрес и число хешей.
	log("[CONFIG] Ссылка принята: peer=%s, хешей=%d", peer, len(strings.Split(vk, ",")))

	writeJSON(w, map[string]interface{}{
		"success": true,
		"peer":    peer,
		"hashes":  len(strings.Split(vk, ",")),
		"applied": !a.IsConnected(),
	})
}

func (a *App) handlePanel(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Панель самодостаточна: ни одного внешнего ресурса, потому что роутер
	// может быть без интернета ровно в тот момент, когда панель нужнее всего.
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
	w.Write(panelHTML)
}

// listenAddrs возвращает адреса, на которых поднимать панель и API.
//
// Loopback присутствует всегда: по 127.0.0.1:8080 ходят скрипт
// переключателя, install.sh и любая отладка через ssh — потерять этот
// адрес нельзя.
//
// Второй адрес — LAN-интерфейс роутера (или заданный в LISTEN). Слушать
// все интерфейсы (":8080") по умолчанию неправильно: панель отдаёт и
// принимает параметры подключения, а от WAN её отделял бы только firewall,
// и это слишком тонкая защита для таких данных.
//
// Если LAN-адрес определить не удалось, остаёмся на одном loopback: пусть
// панель будет доступна только через «ssh -L», чем случайно окажется
// открытой наружу.
func (a *App) listenAddrs() []string {
	const loopback = "127.0.0.1:8080"
	addrs := []string{loopback}

	if a.config.Listen != "" {
		if a.config.Listen != loopback {
			addrs = append(addrs, a.config.Listen)
		}
		return addrs
	}

	dev := "br-lan"
	if out, err := exec.Command("uci", "-q", "get", "network.lan.device").Output(); err == nil {
		if d := strings.TrimSpace(string(out)); d != "" {
			dev = d
		}
	}

	out, err := exec.Command("ip", "-4", "-o", "addr", "show", "dev", dev).Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			for i, f := range fields {
				if f != "inet" || i+1 >= len(fields) {
					continue
				}
				if ip, _, err := net.ParseCIDR(fields[i+1]); err == nil {
					return append(addrs, net.JoinHostPort(ip.String(), "8080"))
				}
			}
		}
	}

	log("[API] Не удалось определить адрес LAN (%s) — слушаю только loopback. "+
		"Задайте LISTEN в конфиге, если панель нужна из локальной сети.", dev)
	return addrs
}

// handleRebind читает и правит список доменов, исключённых из защиты
// dnsmasq от DNS rebinding.
//
// Живёт в конфиге демона, а не прямо в /etc/config/dhcp, чтобы у настройки
// был один владелец: applyRebindDomains приводит dnsmasq в соответствие с
// этим списком при каждом старте. Иначе панель показывала бы одно, а
// работало бы другое.
func (a *App) handleRebind(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		a.mu.Lock()
		list := a.config.RebindDomains
		a.mu.Unlock()
		writeJSON(w, map[string]interface{}{
			"domains": splitList(list),
			"active":  currentRebindDomains(),
		})
		return
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Domains []string `json:"domains"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, map[string]interface{}{"success": false, "error": "не разобрать запрос"})
		return
	}

	// Нормализуем и проверяем до записи: половина применённого списка хуже,
	// чем понятная ошибка.
	var clean []string
	seen := map[string]bool{}
	for _, d := range body.Domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" || seen[d] {
			continue
		}
		if !validDomain(d) {
			writeJSON(w, map[string]interface{}{
				"success": false,
				"error":   "не похоже на доменное имя: " + d,
			})
			return
		}
		seen[d] = true
		clean = append(clean, d)
	}

	a.mu.Lock()
	a.config.RebindDomains = strings.Join(clean, ",")
	list := a.config.RebindDomains
	a.mu.Unlock()

	if err := a.saveConfig(); err != nil {
		log("[CONFIG] Ошибка сохранения: %v", err)
		writeJSON(w, map[string]interface{}{"success": false, "error": "не сохранить конфиг"})
		return
	}

	applyRebindDomains(list)

	writeJSON(w, map[string]interface{}{
		"success": true,
		"domains": clean,
		"active":  currentRebindDomains(),
	})
}

// handleLanPort показывает состояние проводного порта LAN и переключает
// режим согласования скорости.
//
// Живой счётчик обрывов и CRC-ошибок здесь важнее кнопки: именно по ним
// видно, помогло переключение или нет. У здорового соединения оба стоят
// на месте, у капризного растут на глазах.
func (a *App) handleLanPort(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	dev := lanPort(a.config.LanPort)
	mode := a.config.LanLinkMode
	a.mu.Unlock()
	if mode == "" {
		mode = lanModeAuto
	}

	if r.Method == http.MethodGet {
		writeJSON(w, lanPortStatus(dev, mode))
		return
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, map[string]interface{}{"success": false, "error": "не разобрать запрос"})
		return
	}

	newMode := strings.ToLower(strings.TrimSpace(body.Mode))
	if newMode != lanModeAuto && newMode != lanMode100Full {
		writeJSON(w, map[string]interface{}{
			"success": false,
			"error":   "режим должен быть auto или 100full",
		})
		return
	}
	if dev == "" {
		writeJSON(w, map[string]interface{}{
			"success": false,
			"error":   "не удалось определить проводной порт LAN",
		})
		return
	}

	a.mu.Lock()
	a.config.LanLinkMode = newMode
	a.mu.Unlock()

	if err := a.saveConfig(); err != nil {
		log("[CONFIG] Ошибка сохранения: %v", err)
		writeJSON(w, map[string]interface{}{"success": false, "error": "не сохранить конфиг"})
		return
	}

	applyLanLinkMode(dev, newMode)

	resp := lanPortStatus(dev, newMode)
	resp["success"] = true
	writeJSON(w, resp)
}

// handleCaptcha отдаёт незакрытый запрос капчи и принимает решение.
//
// Демон капчу не решает — он только доставляет запрос человеку и передаёт
// ответ ядру. Токен приходит либо от юзерскрипта в браузере, либо руками
// из панели; подробности протокола — в captcha.go.
func (a *App) handleCaptcha(w http.ResponseWriter, r *http.Request) {
	// Юзерскрипт работает на странице VK, то есть с чужого источника.
	// Без этого заголовка браузер не даст ему отправить сюда токен.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method == http.MethodGet {
		req := a.pendingCaptcha()
		a.mu.Lock()
		seen := a.captchaSeen
		a.mu.Unlock()

		resp := map[string]interface{}{"pending": req != nil, "seen": seen}
		if req != nil {
			resp["mode"] = req.Mode
			resp["redirect_uri"] = req.RedirectURI
			resp["waiting_sec"] = req.WaitingSec
		}
		writeJSON(w, resp)
		return
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, map[string]interface{}{"success": false, "error": "не разобрать запрос"})
		return
	}

	if err := a.solveCaptcha(body.Token); err != nil {
		writeJSON(w, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]interface{}{"success": true})
}

//go:embed files/csqtt-captcha.user.js
var captchaUserScript string

// handleUserScript отдаёт юзерскрипт для возврата токена капчи.
//
// Отдаётся из панели, а не берётся из репозитория руками, по двум
// причинам. Во-первых, менеджеры юзерскриптов распознают ссылку,
// оканчивающуюся на .user.js, и предлагают установку в один клик. Во-вторых,
// адрес панели подставляется здесь же: иначе его пришлось бы править в
// файле вручную, а на роутере с нестандартным LAN-адресом про это легко
// забыть и потом гадать, почему токен не возвращается.
func (a *App) handleUserScript(w http.ResponseWriter, r *http.Request) {
	// Куда скрипту слать токен: тот адрес, по которому открыта панель.
	// r.Host уже содержит порт.
	endpoint := "http://" + r.Host + "/api/captcha"
	script := strings.Replace(captchaUserScript,
		"var PANEL = 'http://192.168.1.1:8080/api/captcha';",
		"var PANEL = '"+endpoint+"';", 1)

	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Write([]byte(script))
}
