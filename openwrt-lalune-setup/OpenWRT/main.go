// Демон LaLune/CSQTT для OpenWrt.
//
// В отличие от исходного демона из репозитория LaLune (Endlad2/LaLune,
// каталог OpenWRT/), этот вариант:
//   - не передаёт ядру csqtt-client несуществующий флаг --tun (текущий CLI
//     ядра поддерживает только -listen: сам процесс говорит по локальному
//     UDP и ничего не знает про kernel TUN);
//   - сам поднимает TUN-интерфейс (ioctl TUNSETIFF) и перекачивает пакеты
//     между ним и локальным UDP-портом ядра — это то, что на Desktop-версии
//     делает платформенный код моста (Wintun на Windows, аналогичный кусок
//     на Linux), но для OpenWRT никогда не было реализовано;
//   - заворачивает в туннель трафик из LAN правилами policy routing, не
//     трогая основную таблицу маршрутизации: иначе туда попадает и трафик
//     самого ядра, которому надо ходить на серверы авторизации VK, чтобы
//     туннель поднять или восстановить — и он уходит в тот самый туннель,
//     который чинит;
//   - интегрируется с firewall4 (nftables), давая туннелю masquerade и
//     форвардинг из lan, иначе клиенты в локальной сети не получат выход
//     в интернет через VPN.
package main

import (
	"encoding/json"
	"fmt"
	stdlog "log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/songgao/water"
)

const (
	corePath   = "/usr/bin/csqtt-client"
	logPath    = "/tmp/csqtt-client.log"
	configPath = "/etc/csqtt/csqtt.conf"
	tunMTU     = "1300"
	// Сколько ждём TUNCONF от ядра + первый признак трафика, прежде чем
	// считать попытку подключения неудавшейся.
	connectTimeout = 90 * time.Second
)

type App struct {
	mu sync.Mutex

	config     Config
	configFile string

	connected bool
	tunUp     bool

	coreCmd  *exec.Cmd
	coreDone <-chan struct{}
	corePID  int
	ifce     *water.Interface
	udpConn  *net.UDPConn
	bridgeCh chan struct{}

	// lanSubnets - подсети, трафик которых заворачивается в туннель
	// правилами ip rule. Запоминаются на время подключения, чтобы снять
	// ровно те правила, которые были добавлены.
	lanSubnets []string
	// lastActive - когда ядро последний раз сообщало о живых сессиях.
	// По нему детектируется зависший туннель, см. watchdog.
	lastActive time.Time

	// led - штатные светодиоды роутера, которыми показываем состояние
	// туннеля: активный мигает при подключении и ровно горит при поднятом
	// туннеле, простойный горит когда туннеля нет. Исходное состояние обоих
	// запоминается при старте и возвращается при выходе.
	led leds

	// coreStats - последняя строка статистики от ядра. Хранится отдельно
	// потому, что в лог такие строки попадают прорежёнными, а текущие
	// цифры хочется видеть сразу и целиком.
	coreStats string
	// noiseLogged - когда в последний раз пропускали в лог строку каждого
	// из повторяющихся классов (см. coreNoise).
	noiseLogged map[string]time.Time

	logs []string
}

var app *App

func main() {
	stdlog.SetFlags(stdlog.LstdFlags | stdlog.Lmicroseconds)
	log("=== LaLune OpenWrt daemon ===")

	app = &App{
		configFile:  configPath,
		noiseLogged: map[string]time.Time{},
	}
	app.loadConfig()
	app.led = captureLeds(app.config.Led, app.config.LedIdle)
	// Пока туннеля нет, показываем это сразу: индикатор должен отражать
	// состояние с первой секунды, а не только после первого действия.
	app.led.tunnelDown()

	// Зона csqtt могла пережить жёсткую перезагрузку — см. clearStaleFirewall.
	clearStaleFirewall()

	go app.watchdog()
	go app.startAPI()

	if app.shouldAutoConnect() {
		go app.autoConnect()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log("Завершение по сигналу...")
	app.Disconnect()
	// Снимаем за собой индикацию: без демона роутер должен выглядеть так
	// же, как до его установки.
	app.led.restore()
	os.Exit(0)
}

// log - глобальный помощник для логирования, которым пользуются все файлы
// пакета (main.go/process.go/tunnel.go/config.go). Пишет и в stdout
// (init.d/procd перехватит его в системный лог), и в кольцевой буфер,
// который отдаётся через /api/logs.
func log(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	stdlog.Println(msg)
	if app == nil {
		return
	}
	app.mu.Lock()
	app.logs = append(app.logs, msg)
	if len(app.logs) > 1000 {
		app.logs = app.logs[len(app.logs)-1000:]
	}
	app.mu.Unlock()
}

func (a *App) IsConnected() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.connected
}

func (a *App) Connect() error {
	a.mu.Lock()
	if a.connected {
		a.mu.Unlock()
		return fmt.Errorf("уже подключено")
	}
	cfg := a.config
	a.mu.Unlock()

	if cfg.Peer == "" || cfg.Password == "" || cfg.VkHashes == "" {
		return fmt.Errorf("конфигурация неполная: нужны PEER, PASSWORD и VK")
	}

	if underlay := getDefaultRoute(a.currentTunName()); underlay.has {
		log("[ROUTE] Канал в интернет: %s", underlay)
	} else {
		log("[WARN] Нет default route — ядру не через что достучаться до сервера")
	}

	subnets := lanSubnets(cfg.LanSubnets)
	if len(subnets) == 0 {
		return fmt.Errorf("не удалось определить подсети LAN: заворачивать в туннель нечего")
	}

	listenPort := freePort()
	args := buildCoreArgs(cfg, listenPort)
	log("[INFO] Запуск ядра: %s %s", corePath, safeArgsForLog(args))

	cmd, done, err := startCore(corePath, logPath, args)
	if err != nil {
		return fmt.Errorf("не удалось запустить ядро: %w", err)
	}

	a.mu.Lock()
	a.connected = true
	a.coreCmd = cmd
	a.coreDone = done
	a.corePID = cmd.Process.Pid
	a.lanSubnets = subnets
	// Считаем сессии живыми на момент запуска, иначе детектор зависания
	// сработает раньше, чем ядро успеет их поднять.
	a.lastActive = time.Now()
	a.mu.Unlock()

	log("[INFO] Ядро запущено (PID %d), слушаю порт %d", cmd.Process.Pid, listenPort)
	a.led.connecting()

	tunConfCh := make(chan tunConf, 1)
	trafficCh := make(chan struct{}, 1)

	watcher := &logWatcher{
		path:      logPath,
		onLine:    a.logCoreLine,
		onTunConf: tunConfCh,
		onTraffic: trafficCh,
	}
	watchCancel := make(chan struct{})
	go watcher.run(watchCancel)

	go a.finishConnect(cmd, listenPort, tunConfCh, trafficCh, watchCancel)

	return nil
}

// logCoreLine пишет строку из лога ядра в общий лог, прореживая те, что
// ядро повторяет постоянно (см. coreNoise в process.go). Последняя строка
// статистики при этом всегда сохраняется целиком и отдаётся в /api/status,
// так что текущие цифры доступны без выуживания их из лога.
func (a *App) logCoreLine(line string) {
	if coreNoise["stats"].MatchString(line) {
		// Отметка живых сессий нужна watchdog: по ней он отличает
		// работающий туннель от зависшего.
		active := activeSessions(line)
		a.mu.Lock()
		a.coreStats = line
		if active > 0 {
			a.lastActive = time.Now()
		}
		a.mu.Unlock()
	}

	if class := coreNoiseClass(line); class != "" {
		now := time.Now()
		a.mu.Lock()
		last, seen := a.noiseLogged[class]
		allow := !seen || now.Sub(last) >= coreNoiseInterval
		if allow {
			a.noiseLogged[class] = now
		}
		a.mu.Unlock()
		if !allow {
			return
		}
	}

	log("[CORE] %s", line)
}

// finishConnect ждёт TUNCONF + первый признак трафика от ядра и только
// после этого поднимает TUN, DNS, правила маршрутизации и firewall — ровно
// так же, как это делают Desktop-клиенты LaLune (см. app_windows.go).
func (a *App) finishConnect(cmd *exec.Cmd, listenPort int, tunConfCh <-chan tunConf, trafficCh <-chan struct{}, watchCancel chan struct{}) {
	var conf tunConf
	hasConf, hasTraffic := false, false
	deadline := time.After(connectTimeout)

	for !hasConf || !hasTraffic {
		select {
		case c := <-tunConfCh:
			conf = c
			hasConf = true
			log("[TUN] TUNCONF получен: IP=%s DNS=%s", c.ip, c.dns)
		case <-trafficCh:
			hasTraffic = true
			log("[TUN] Трафик обнаружен (Активных > 0)")
		case <-deadline:
			log("[TUN] Таймаут ожидания подключения — отключаюсь")
			a.Disconnect()
			return
		case <-watchCancel:
			return
		}
	}

	ifce, err := setupTunDevice(a.currentTunName(), conf.ip, tunMTU)
	if err != nil {
		log("[TUN] Ошибка настройки TUN: %v", err)
		a.Disconnect()
		return
	}

	udpConn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: listenPort})
	if err != nil {
		log("[TUN] Ошибка подключения к ядру по UDP: %v", err)
		ifce.Close()
		a.Disconnect()
		return
	}

	a.mu.Lock()
	subnets := a.lanSubnets
	a.mu.Unlock()

	appendResolvConf(conf.dns)
	setTunnelPolicyRoutes(ifce.Name(), subnets)
	firewallUp(ifce.Name())

	bridgeCh := make(chan struct{})

	a.mu.Lock()
	a.ifce = ifce
	a.udpConn = udpConn
	a.bridgeCh = bridgeCh
	a.tunUp = true
	a.mu.Unlock()

	log("[TUN] Туннель поднят: %s %s/32, в туннель идёт %v", ifce.Name(), conf.ip, subnets)
	a.led.tunnelUp()

	bridgeTunUDP(ifce, udpConn, bridgeCh)
	log("[TUN] Мост TUN<->UDP остановлен")
}

// shouldAutoConnect решает, поднимать ли туннель на старте демона.
//
// Режим "switch" существует потому, что обработчик /etc/rc.button/BTN_0
// вызывается только при СМЕНЕ положения переключателя. После перезагрузки
// смены не было, и без явной проверки демон не знал бы, куда переключатель
// выставлен физически — при AUTOCONNECT='1' он поднял бы туннель, даже
// если тумблер стоит в положении "выключено".
func (a *App) shouldAutoConnect() bool {
	switch a.config.AutoConnect {
	case "1", "true", "yes":
		log("[AUTO] AUTOCONNECT=%s, жду готовности сети", a.config.AutoConnect)
		return true

	case "switch":
		on, known := hwSwitchOn(a.config.SwitchLabel)
		if !known {
			log("[AUTO] AUTOCONNECT='switch', но положение переключателя %q определить не удалось — не подключаюсь", a.config.SwitchLabel)
			return false
		}
		if !on {
			log("[AUTO] Переключатель %q в положении «выключено» — не подключаюсь", a.config.SwitchLabel)
			return false
		}
		log("[AUTO] Переключатель %q в положении «включено», жду готовности сети", a.config.SwitchLabel)
		return true

	default:
		return false
	}
}

// autoConnect поднимает туннель при старте демона, если это включено в
// конфиге. Ждём появления default route: procd запускает нас на S95, но
// DHCP на WAN к этому моменту может быть ещё не отработан, а без маршрута
// до сервера подключаться бессмысленно.
func (a *App) autoConnect() {
	deadline := time.Now().Add(2 * time.Minute)

	for time.Now().Before(deadline) {
		if getDefaultRoute(a.currentTunName()).has {
			log("[AUTO] Сеть готова, подключаюсь")
			if err := a.Connect(); err != nil {
				log("[AUTO] Не удалось подключиться: %v", err)
			}
			return
		}
		time.Sleep(3 * time.Second)
	}

	log("[AUTO] За 2 минуты после старта интернет так и не появился — автоподключение отменено")
}

func (a *App) currentTunName() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.config.Tun == "" {
		return "csqtt0"
	}
	return a.config.Tun
}

func (a *App) Disconnect() bool {
	a.mu.Lock()
	if !a.connected {
		a.mu.Unlock()
		return false
	}
	cmd := a.coreCmd
	ifce := a.ifce
	udpConn := a.udpConn
	bridgeCh := a.bridgeCh
	subnets := a.lanSubnets
	tunUp := a.tunUp

	a.connected = false
	a.tunUp = false
	a.coreCmd = nil
	a.coreDone = nil
	a.corePID = 0
	a.ifce = nil
	a.udpConn = nil
	a.bridgeCh = nil
	a.lanSubnets = nil
	a.mu.Unlock()

	log("[INFO] Отключение...")

	if bridgeCh != nil {
		close(bridgeCh)
	}
	if udpConn != nil {
		udpConn.Close()
	}

	if tunUp {
		firewallDown()
		// Основную таблицу маршрутизации мы не трогали, поэтому
		// восстанавливать в ней нечего: достаточно снять свои правила.
		clearTunnelPolicyRoutes(subnets)
	}
	if ifce != nil {
		ifce.Close()
	}

	if cmd != nil && cmd.Process != nil {
		cmd.Process.Signal(syscall.SIGTERM)
		time.Sleep(500 * time.Millisecond)
		cmd.Process.Kill()
	}

	a.led.tunnelDown()
	log("[INFO] Отключено")
	return true
}

// Сколько ядро может держать "Активных: 0", прежде чем считать туннель
// зависшим. Полторы минуты с запасом перекрывают обычное переподключение
// сессий, но не заставляют ждать слишком долго.
const staleTunnelTimeout = 90 * time.Second

// watchdog перезапускает подключение в двух случаях:
//
//   - процесс ядра неожиданно завершился;
//   - ядро живо, но давно не сообщало ни об одной активной сессии.
//
// Второй случай пришлось добавить после того, как туннель на живом роутере
// молча умер и не поднялся: ядро осталось в памяти и бесконечно крутило
// попытки авторизации, а смерть процесса — единственное, что watchdog умел
// замечать раньше. Само по себе это не должно больше происходить (трафик
// ядра теперь не заворачивается в туннель, см. tunnel.go), но зависнуть
// туннель может и по другим причинам — сервер перезапустили, связь моргнула.
func (a *App) watchdog() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		a.mu.Lock()
		connected := a.connected
		done := a.coreDone
		tunUp := a.tunUp
		idle := time.Since(a.lastActive)
		a.mu.Unlock()

		if !connected || done == nil {
			continue
		}

		select {
		case <-done:
			a.reconnect("ядро завершилось")
			continue
		default:
		}

		// Пока туннель ещё поднимается, сессий закономерно нет — за этим
		// следит собственный таймаут finishConnect.
		if tunUp && idle > staleTunnelTimeout {
			a.reconnect(fmt.Sprintf("нет активных сессий уже %s", idle.Truncate(time.Second)))
		}
	}
}

func (a *App) reconnect(reason string) {
	log("[WATCHDOG] %s, переподключаюсь...", reason)
	a.Disconnect()
	time.Sleep(2 * time.Second)
	if err := a.Connect(); err != nil {
		log("[WATCHDOG] Переподключение не удалось: %v", err)
	}
}

func resolveHost(host string) []string {
	if ip := net.ParseIP(host); ip != nil {
		return []string{ip.String()}
	}
	ips, err := net.LookupHost(host)
	if err != nil {
		log("[DNS] Не удалось разрешить %s: %v", host, err)
		return nil
	}
	var v4 []string
	for _, ip := range ips {
		if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() != nil {
			v4 = append(v4, parsed.String())
		}
	}
	return v4
}

func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 52230
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// safeArgsForLog скрывает пароль/хеши в логе команды запуска.
func safeArgsForLog(args []string) string {
	out := make([]string, len(args))
	copy(out, args)
	for i, a := range out {
		if a == "-password" || a == "-vk" {
			if i+1 < len(out) {
				out[i+1] = "***"
			}
		}
	}
	joined := ""
	for _, a := range out {
		joined += a + " "
	}
	return joined
}

// ---- HTTP API (совместим по эндпоинтам с оригинальным демоном LaLune) ----

func (a *App) startAPI() {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		status := map[string]interface{}{
			"connected": a.connected,
			"tun_up":    a.tunUp,
			"pid":       a.corePID,
			// Статистика ядра приходит раз в секунду и в лог попадает
			// прорежённой — здесь всегда самая свежая.
			"core_stats": a.coreStats,
		}
		a.mu.Unlock()
		writeJSON(w, status)
	})

	mux.HandleFunc("/api/connect", func(w http.ResponseWriter, r *http.Request) {
		err := a.Connect()
		resp := map[string]interface{}{"success": err == nil}
		if err != nil {
			resp["error"] = err.Error()
		}
		writeJSON(w, resp)
	})

	mux.HandleFunc("/api/disconnect", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]bool{"success": a.Disconnect()})
	})

	// /api/toggle - для физической кнопки на роутере: решение о том, что
	// делать, принимается здесь под тем же мьютексом, что и само действие.
	// Если бы кнопка сначала спрашивала /api/status, а потом дёргала
	// connect или disconnect, между двумя запросами состояние могло бы
	// смениться (нажали дважды подряд, сработал watchdog).
	mux.HandleFunc("/api/toggle", func(w http.ResponseWriter, r *http.Request) {
		if a.IsConnected() {
			a.Disconnect()
			writeJSON(w, map[string]interface{}{"success": true, "action": "disconnected"})
			return
		}
		err := a.Connect()
		resp := map[string]interface{}{"success": err == nil, "action": "connected"}
		if err != nil {
			resp["action"] = "failed"
			resp["error"] = err.Error()
		}
		writeJSON(w, resp)
	})

	mux.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		logsCopy := append([]string{}, a.logs...)
		a.mu.Unlock()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		for _, line := range logsCopy {
			fmt.Fprintln(w, line)
		}
	})

	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		cfg := a.config
		a.mu.Unlock()
		safe := cfg
		safe.Password = ""
		writeJSON(w, safe)
	})

	mux.HandleFunc("/api/config/update", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var newCfg Config
		if err := json.NewDecoder(r.Body).Decode(&newCfg); err != nil {
			writeJSON(w, map[string]bool{"success": false})
			return
		}
		if newCfg.Tun == "" {
			newCfg.Tun = "csqtt0"
		}
		if newCfg.Workers <= 0 {
			newCfg.Workers = 18
		}

		a.mu.Lock()
		a.config = newCfg
		a.mu.Unlock()

		if err := a.saveConfig(); err != nil {
			log("[CONFIG] Ошибка сохранения: %v", err)
			writeJSON(w, map[string]bool{"success": false})
			return
		}
		writeJSON(w, map[string]bool{"success": true})
	})

	log("[API] Запущен на :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log("[API] Остановлен: %v", err)
	}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
