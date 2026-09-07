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
//   - прокладывает host-маршруты к peer/TURN-серверам через исходный шлюз
//     ДО переключения default route на туннель — иначе роутер после
//     "туннель поднялся" не сможет достучаться до самого VPN-сервера;
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

	origRoute   defaultRoute
	bypassAdded map[string]bool

	logs []string
}

var app *App

func main() {
	stdlog.SetFlags(stdlog.LstdFlags | stdlog.Lmicroseconds)
	log("=== LaLune OpenWrt daemon ===")

	app = &App{
		configFile:  configPath,
		bypassAdded: map[string]bool{},
	}
	app.loadConfig()

	go app.watchdog()
	go app.startAPI()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log("Завершение по сигналу...")
	app.Disconnect()
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

	origRoute := getDefaultRoute()
	if !origRoute.has {
		log("[WARN] Не удалось определить исходный default route — обходные маршруты к серверу не будут работать корректно")
	}

	bypassed := map[string]bool{}
	for _, ip := range resolveHost(peerHost(cfg.Peer)) {
		addBypassRoute(origRoute, ip)
		bypassed[ip] = true
	}
	if cfg.TurnHost != "" {
		for _, ip := range resolveHost(cfg.TurnHost) {
			addBypassRoute(origRoute, ip)
			bypassed[ip] = true
		}
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
	a.origRoute = origRoute
	a.bypassAdded = bypassed
	a.mu.Unlock()

	log("[INFO] Ядро запущено (PID %d), слушаю порт %d", cmd.Process.Pid, listenPort)

	tunConfCh := make(chan tunConf, 1)
	trafficCh := make(chan struct{}, 1)
	bypassIPCh := make(chan string, 16)

	watcher := &logWatcher{
		path:       logPath,
		onLine:     func(line string) { log("[CORE] %s", line) },
		onTunConf:  tunConfCh,
		onTraffic:  trafficCh,
		onBypassIP: bypassIPCh,
	}
	watchCancel := make(chan struct{})
	go watcher.run(watchCancel)

	go a.consumeBypassIPs(bypassIPCh, watchCancel)
	go a.finishConnect(cmd, listenPort, tunConfCh, trafficCh, watchCancel)

	return nil
}

func (a *App) consumeBypassIPs(ch <-chan string, cancel <-chan struct{}) {
	for {
		select {
		case <-cancel:
			return
		case ip := <-ch:
			a.mu.Lock()
			already := a.bypassAdded[ip]
			if !already {
				a.bypassAdded[ip] = true
			}
			orig := a.origRoute
			a.mu.Unlock()
			if !already {
				log("[ROUTE] Обходной маршрут для relay/TURN %s", ip)
				addBypassRoute(orig, ip)
			}
		}
	}
}

// finishConnect ждёт TUNCONF + первый признак трафика от ядра и только
// после этого поднимает TUN, DNS, default route и firewall — ровно так же,
// как это делают Desktop-клиенты LaLune (см. app_windows.go/app_linux.go).
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

	appendResolvConf(conf.dns)
	setDefaultViaTun(ifce.Name())
	firewallUp(ifce.Name())

	bridgeCh := make(chan struct{})

	a.mu.Lock()
	a.ifce = ifce
	a.udpConn = udpConn
	a.bridgeCh = bridgeCh
	a.tunUp = true
	a.mu.Unlock()

	log("[TUN] Туннель поднят: %s %s/32, default route -> %s", ifce.Name(), conf.ip, ifce.Name())

	bridgeTunUDP(ifce, udpConn, bridgeCh)
	log("[TUN] Мост TUN<->UDP остановлен")
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
	origRoute := a.origRoute
	bypassed := a.bypassAdded
	tunUp := a.tunUp

	a.connected = false
	a.tunUp = false
	a.coreCmd = nil
	a.coreDone = nil
	a.corePID = 0
	a.ifce = nil
	a.udpConn = nil
	a.bridgeCh = nil
	a.bypassAdded = map[string]bool{}
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
		restoreDefaultRoute(ifce.Name(), origRoute)
	}
	if ifce != nil {
		ifce.Close()
	}
	for ip := range bypassed {
		removeBypassRoute(ip)
	}

	if cmd != nil && cmd.Process != nil {
		cmd.Process.Signal(syscall.SIGTERM)
		time.Sleep(500 * time.Millisecond)
		cmd.Process.Kill()
	}

	log("[INFO] Отключено")
	return true
}

// watchdog перезапускает подключение, если процесс ядра неожиданно умер
// после того, как туннель уже был поднят (например, сервер разорвал сессию).
func (a *App) watchdog() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		a.mu.Lock()
		connected := a.connected
		done := a.coreDone
		a.mu.Unlock()

		if !connected || done == nil {
			continue
		}

		select {
		case <-done:
			log("[WATCHDOG] Ядро завершилось, переподключаюсь...")
			a.Disconnect()
			time.Sleep(2 * time.Second)
			if err := a.Connect(); err != nil {
				log("[WATCHDOG] Переподключение не удалось: %v", err)
			}
		default:
			// процесс жив, ничего не делаем
		}
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
