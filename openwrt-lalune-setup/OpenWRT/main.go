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
	"io"
	stdlog "log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/songgao/water"
)

// daemonVersion показывается в панели — по нему видно, тот ли бинарник
// реально запущен на роутере после обновления.
const daemonVersion = "1.0"

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

	// coreStdin - канал управления ядра. Через него уходит ответ на запрос
	// капчи, см. captcha.go.
	coreStdin io.WriteCloser
	// captcha - незакрытый запрос капчи, captchaSeen - счётчик за сессию.
	captcha     *captchaRequest
	captchaSeen int
	// captchaBlocked - ВК отклонила авторизацию как ботовую в текущей
	// попытке. Сбрасывается при каждом новом подключении.
	captchaBlocked bool

	// watchCancel закрывается при отключении и останавливает logWatcher и
	// finishConnect текущей сессии.
	//
	// Без этого они продолжали жить после Disconnect. Беда в том, что
	// startCore пересоздаёт /tmp/csqtt-client.log при каждом подключении:
	// осиротевший наблюдатель замечал, что файл стал короче, сбрасывал
	// смещение и начинал скармливать СТАРОЙ finishConnect вывод НОВОГО
	// ядра. Две горутины одновременно доходили до создания csqtt0, одна
	// получала "device or resource busy", вызывала Disconnect и сносила
	// туннель, который только что подняла другая.
	watchCancel chan struct{}
	// session - номер текущего подключения, см. sessionValid.
	session uint64

	// wantConnected - ЖЕЛАЕМОЕ состояние, в отличие от connected, который
	// описывает фактическое. Их обязательно надо различать: попытка
	// подключения может не удаться (например, канал в интернет пропал в
	// момент старта ядра), и тогда connected становится false, хотя
	// пользователь по-прежнему хочет туннель — тумблер стоит в положении
	// «включено», а обработчик кнопки срабатывает только на СМЕНУ
	// положения и повторно не вызовется.
	//
	// Без этого разделения демон после неудачной попытки замолкал навсегда,
	// и починить это можно было только перещёлкиванием тумблера туда-обратно
	// или перезапуском сервиса.
	wantConnected bool
	// retryDelay - текущая пауза между повторными попытками. Растёт вдвое
	// при каждой неудаче, чтобы не долбить сервер в отсутствие связи.
	retryDelay time.Duration
	// nextRetry - когда watchdog имеет право попробовать снова.
	nextRetry time.Time

	// led - штатные светодиоды роутера, которыми показываем состояние
	// туннеля: активный мигает при подключении и ровно горит при поднятом
	// туннеле, простойный горит когда туннеля нет. Исходное состояние обоих
	// запоминается при старте и возвращается при выходе.
	led leds

	// coreStats - последняя строка статистики от ядра. Хранится отдельно
	// потому, что в лог такие строки попадают прорежёнными, а текущие
	// цифры хочется видеть сразу и целиком.
	coreStats string
	// tunIP и connectedAt нужны панели: адрес туннеля и время в сети.
	tunIP       string
	connectedAt time.Time
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

	// Домены провайдера, которые иначе режет защита от DNS rebinding.
	applyRebindDomains(app.config.RebindDomains)

	// Режим согласования скорости на проводном порту LAN восстанавливаем
	// при старте: ethtool настройку не сохраняет, она сбрасывается при
	// перезагрузке и при пересоздании интерфейса.
	if app.config.LanLinkMode == lanMode100Full {
		applyLanLinkMode(lanPort(app.config.LanPort), app.config.LanLinkMode)
	}

	go app.watchdog()
	go app.startAPI()

	if app.shouldAutoConnect() {
		go app.autoConnect()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log("Завершение по сигналу...")
	app.persistLogs("завершение по сигналу")
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

// WantsConnection - хочет ли пользователь, чтобы туннель был поднят. Это не
// то же самое, что IsConnected: между неудачной попыткой и следующим
// повтором фактического подключения нет, но намерение есть.
//
// Именно это состояние должно управлять переключением: иначе кнопка
// «Отключить», нажатая во время ожидания повтора, запускала бы новую
// попытку вместо отмены.
func (a *App) WantsConnection() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.connected || a.wantConnected
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

	cmd, stdin, done, err := startCore(corePath, logPath, args)
	if err != nil {
		return fmt.Errorf("не удалось запустить ядро: %w", err)
	}

	a.mu.Lock()
	a.connected = true
	a.coreCmd = cmd
	a.coreDone = done
	a.coreStdin = stdin
	a.corePID = cmd.Process.Pid
	a.lanSubnets = subnets
	// Считаем сессии живыми на момент запуска, иначе детектор зависания
	// сработает раньше, чем ядро успеет их поднять.
	a.lastActive = time.Now()
	a.captchaBlocked = false
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

	a.mu.Lock()
	// Номер сессии позволяет опоздавшей горутине понять, что её
	// подключение уже отменили, и молча уйти вместо того, чтобы что-то
	// делать с чужим туннелем.
	a.session++
	session := a.session
	a.watchCancel = watchCancel
	a.mu.Unlock()

	go watcher.run(watchCancel)
	go a.finishConnect(session, cmd, listenPort, tunConfCh, trafficCh, watchCancel)

	return nil
}

// sessionValid сообщает, что подключение с этим номером всё ещё актуально.
//
// Нужна из-за того, что finishConnect живёт в отдельной горутине и может
// провести в ожидании TUNCONF до полутора минут. За это время подключение
// успевает быть отменённым и запущенным заново — и без этой проверки
// старая горутина доделывала бы своё поверх нового туннеля.
func (a *App) sessionValid(session uint64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.connected && a.session == session
}

// logCoreLine пишет строку из лога ядра в общий лог, прореживая те, что
// ядро повторяет постоянно (см. coreNoise в process.go). Последняя строка
// статистики при этом всегда сохраняется целиком и отдаётся в /api/status,
// так что текущие цифры доступны без выуживания их из лога.
func (a *App) logCoreLine(line string) {
	// Запрос капчи уходит в отдельный канал, а в общий лог — только
	// человекочитаемое уведомление: в строке есть одноразовый session_token.
	if a.noteCaptchaRequest(line) {
		return
	}

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

	// Отдельно отмечаем отказ из-за антибот-проверки: по нему выбирается
	// длинная пауза, а панель показывает внятную причину вместо таймаута.
	if strings.Contains(line, "check status=BOT") {
		a.mu.Lock()
		a.captchaBlocked = true
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
func (a *App) finishConnect(session uint64, cmd *exec.Cmd, listenPort int, tunConfCh <-chan tunConf, trafficCh <-chan struct{}, watchCancel chan struct{}) {
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
			a.scheduleRetry("таймаут подключения")
			return
		case <-watchCancel:
			return
		}
	}

	// Между получением TUNCONF и этим местом подключение могло быть
	// отменено и запущено заново. Создавать TUN тогда нельзя: интерфейс уже
	// занят новой сессией, ioctl вернёт "device or resource busy", а
	// следом Disconnect снесёт чужой, только что поднятый туннель.
	if !a.sessionValid(session) {
		log("[TUN] Подключение №%d отменено, пока ждали конфигурацию — выхожу", session)
		return
	}

	ifce, err := setupTunDevice(a.currentTunName(), conf.ip, tunMTU)
	if err != nil {
		log("[TUN] Ошибка настройки TUN: %v", err)
		a.Disconnect()
		a.scheduleRetry("не удалось создать TUN")
		return
	}

	udpConn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: listenPort})
	if err != nil {
		log("[TUN] Ошибка подключения к ядру по UDP: %v", err)
		ifce.Close()
		a.Disconnect()
		a.scheduleRetry("нет связи с ядром по UDP")
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
	a.tunIP = conf.ip
	a.connectedAt = time.Now()
	// Туннель поднялся — счётчик неудач больше не актуален.
	a.retryDelay = retryDelayMin
	a.nextRetry = time.Time{}
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
			if err := a.RequestConnect(); err != nil {
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
	watchCancel := a.watchCancel
	a.watchCancel = nil
	stdin := a.coreStdin
	a.coreStdin = nil
	a.captcha = nil

	a.connected = false
	a.tunUp = false
	a.tunIP = ""
	a.connectedAt = time.Time{}
	a.coreCmd = nil
	a.coreDone = nil
	a.corePID = 0
	a.ifce = nil
	a.udpConn = nil
	a.bridgeCh = nil
	a.lanSubnets = nil
	a.mu.Unlock()

	log("[INFO] Отключение...")

	// Останавливаем наблюдателя за логом ядра и ожидающую finishConnect
	// ПЕРВЫМ делом: пока они живы, следующее подключение пересоздаст
	// /tmp/csqtt-client.log, осиротевший наблюдатель примет его за
	// усечённый, начнёт читать с начала и разбудит старую finishConnect
	// чужими событиями.
	if watchCancel != nil {
		close(watchCancel)
	}
	if stdin != nil {
		stdin.Close()
	}

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

// Пауза перед повторной попыткой после неудачи. Растёт вдвое до максимума:
// если канала в интернет нет, долбить сервер каждые десять секунд смысла
// нет, но и ждать полчаса после короткого сбоя тоже неправильно.
const (
	retryDelayMin = 10 * time.Second
	retryDelayMax = 5 * time.Minute
)

// Отдельная пауза для случая, когда ВК потребовала капчу.
//
// Быстрый повтор здесь бесполезен и вреден: причина не в связи, а в
// репутации адреса, и десяток попыток подряд её только ухудшает. У
// мобильных операторов адрес со временем меняется, так что ждать разумнее
// долго. Ловится по строке из лога ядра, см. noteCaptchaFailure.
const retryDelayCaptcha = 10 * time.Minute

// RequestConnect и RequestDisconnect выражают НАМЕРЕНИЕ пользователя, в
// отличие от Connect/Disconnect, которые просто выполняют механику. Разница
// в том, что намерение переживает неудачу: если подключиться не вышло,
// watchdog будет повторять попытки, пока намерение не отменят.
//
// Вызывать их надо отовсюду, где решение принимает человек или его
// настройка: API, переключатель, автоподключение при старте. Внутренние
// сбои (таймаут, зависший туннель) должны звать Connect/Disconnect напрямую,
// чтобы не сбрасывать намерение.
func (a *App) RequestConnect() error {
	a.mu.Lock()
	a.wantConnected = true
	a.retryDelay = retryDelayMin
	a.nextRetry = time.Time{}
	a.mu.Unlock()

	err := a.Connect()
	if err != nil {
		a.scheduleRetry(err.Error())
	}
	return err
}

func (a *App) RequestDisconnect() bool {
	a.mu.Lock()
	a.wantConnected = false
	a.nextRetry = time.Time{}
	a.mu.Unlock()

	return a.Disconnect()
}

// scheduleRetry назначает следующую попытку и увеличивает паузу.
func (a *App) scheduleRetry(reason string) {
	a.mu.Lock()
	if !a.wantConnected {
		a.mu.Unlock()
		return
	}
	if a.retryDelay < retryDelayMin {
		a.retryDelay = retryDelayMin
	}
	delay := a.retryDelay
	a.nextRetry = time.Now().Add(delay)
	if a.retryDelay *= 2; a.retryDelay > retryDelayMax {
		a.retryDelay = retryDelayMax
	}

	// Отказ из-за антибот-проверки лечится не настойчивостью, а временем:
	// дело в репутации адреса, и частые попытки её только ухудшают.
	captcha := a.captchaBlocked
	if captcha {
		delay = retryDelayCaptcha
		a.nextRetry = time.Now().Add(delay)
		a.retryDelay = retryDelayCaptcha
	}
	a.mu.Unlock()

	if captcha {
		log("[WATCHDOG] ВК не пропустила авторизацию (антибот-проверка). "+
			"Это не сбой связи: у мобильных операторов адрес общий, и ВК "+
			"считает его подозрительным. Следующая попытка через %s; "+
			"с проводного канала обычно проходит сразу.", delay)
		a.persistLogs("ВК отклонила авторизацию как ботовую")
		return
	}

	log("[WATCHDOG] Не удалось подключиться (%s) — повтор через %s", reason, delay)
	a.persistLogs("не удалось подключиться: " + reason)
}

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
		want := a.wantConnected
		nextRetry := a.nextRetry
		a.mu.Unlock()

		// Туннеля нет, но его хотят — значит попытка провалилась (таймаут
		// подключения, пропавший канал, недоступный сервер). Раньше эта
		// ветка отсутствовала, и демон после первой же неудачи замолкал
		// навсегда, хотя тумблер оставался в положении «включено».
		if !connected {
			if !want || nextRetry.IsZero() || time.Now().Before(nextRetry) {
				continue
			}
			log("[WATCHDOG] Пробую подключиться снова")
			if err := a.Connect(); err != nil {
				a.scheduleRetry(err.Error())
			}
			continue
		}

		if done == nil {
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
	a.persistLogs("watchdog: " + reason)
	a.Disconnect()
	time.Sleep(2 * time.Second)
	if err := a.Connect(); err != nil {
		a.scheduleRetry(err.Error())
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
		writeJSON(w, a.snapshot())
	})

	mux.HandleFunc("/api/connect", func(w http.ResponseWriter, r *http.Request) {
		err := a.RequestConnect()
		resp := map[string]interface{}{"success": err == nil}
		if err != nil {
			resp["error"] = err.Error()
		}
		writeJSON(w, resp)
	})

	mux.HandleFunc("/api/disconnect", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]bool{"success": a.RequestDisconnect()})
	})

	// /api/toggle - для физической кнопки на роутере: решение о том, что
	// делать, принимается здесь под тем же мьютексом, что и само действие.
	// Если бы кнопка сначала спрашивала /api/status, а потом дёргала
	// connect или disconnect, между двумя запросами состояние могло бы
	// смениться (нажали дважды подряд, сработал watchdog).
	mux.HandleFunc("/api/toggle", func(w http.ResponseWriter, r *http.Request) {
		if a.WantsConnection() {
			a.RequestDisconnect()
			writeJSON(w, map[string]interface{}{"success": true, "action": "disconnected"})
			return
		}
		err := a.RequestConnect()
		resp := map[string]interface{}{"success": err == nil, "action": "connected"}
		if err != nil {
			resp["action"] = "failed"
			resp["error"] = err.Error()
		}
		writeJSON(w, resp)
	})

	mux.HandleFunc("/", a.handlePanel)
	mux.HandleFunc("/api/config/link", a.handleLink)
	mux.HandleFunc("/api/rebind", a.handleRebind)
	mux.HandleFunc("/api/lanport", a.handleLanPort)
	mux.HandleFunc("/api/captcha", a.handleCaptcha)

	// Сохранённые на флеш логи прошлых сбоев — чтобы смотреть их из панели,
	// а не только по ssh. Переживают перезагрузку, в отличие от /api/logs.
	mux.HandleFunc("/api/logs/incidents", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		data, err := os.ReadFile(persistLogPath)
		if err != nil {
			fmt.Fprintln(w, "Сохранённых инцидентов нет.")
			return
		}
		w.Write(data)
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

	// Слушаем каждый адрес отдельным сервером на общем mux: один
	// ListenAndServe умеет только один адрес, а нам нужны и loopback (для
	// скрипта переключателя и отладки), и LAN (для панели).
	addrs := a.listenAddrs()
	var wg sync.WaitGroup
	for _, addr := range addrs {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			log("[API] Слушаю http://%s/", addr)
			if err := http.ListenAndServe(addr, mux); err != nil {
				log("[API] %s остановлен: %v", addr, err)
			}
		}(addr)
	}
	wg.Wait()
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
