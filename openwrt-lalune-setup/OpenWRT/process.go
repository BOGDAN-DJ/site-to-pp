package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const maxVkHashes = 6

// buildCoreArgs собирает аргументы командной строки для csqtt-client в точности
// как это делает официальный Desktop-клиент (Desktop/Libs/bridge.go в LaLune) —
// это единственный источник истины, потому что сам csqtt-core CLI не имеет флага
// --tun: TUN-интерфейсом занимается демон (см. tunnel.go), а ядро только слушает
// локальный UDP-порт и гоняет через него сырые IP-пакеты.
func buildCoreArgs(cfg Config, listenPort int) []string {
	hashes := normalizeHashes(cfg.VkHashes)

	args := []string{
		"-peer", cfg.Peer,
		"-n", strconv.Itoa(cfg.Workers),
		"-listen", fmt.Sprintf("127.0.0.1:%d", listenPort),
		"-vk", hashes,
		"-fingerprint", cfg.Fingerprint,
		"-client-ids", cfg.ClientIDs,
		"-obfs", cfg.Obfs,
		"-vk-auth-mode", cfg.VkAuthMode,
		"-device-id", cfg.DeviceID,
		"-password", cfg.Password,
		"-captcha-mode", cfg.CaptchaMode,
	}

	if cfg.TurnHost != "" {
		args = append(args, "-turn", cfg.TurnHost)
	}
	if cfg.TurnPort != "" {
		args = append(args, "-port", cfg.TurnPort)
	}

	return args
}

// normalizeHashes приводит список VK-хешей к виду "h1,h2,h3": разделители
// (пробел/таб/перевод строки) заменяются на запятую, пустые элементы
// отбрасываются, список обрезается до maxVkHashes элементов.
func normalizeHashes(raw string) string {
	replacer := strings.NewReplacer(" ", ",", "\t", ",", "\n", ",", "\r", ",")
	normalized := replacer.Replace(raw)

	var clean []string
	for _, h := range strings.Split(normalized, ",") {
		h = strings.TrimSpace(h)
		if h != "" {
			clean = append(clean, h)
		}
	}
	if len(clean) > maxVkHashes {
		clean = clean[:maxVkHashes]
	}
	return strings.Join(clean, ",")
}

// peerHost возвращает хост из "host:port" (без резолва).
func peerHost(peer string) string {
	host, _, err := net.SplitHostPort(peer)
	if err != nil {
		return peer
	}
	return host
}

// Ядро повторяет эти строки бесконечно: статистику раз в секунду, а
// keepalive TURN — на каждую сессию (их 18). Пропускать их в лог как есть
// нельзя: кольцевой буфер демона на 1000 строк заполнялся ими целиком за
// четверть часа, а поскольку stdout демона procd отправляет в системный
// лог, туда же уходило и всё остальное — logread на 97% состоял из csqtt,
// и разобраться по логам в чём-либо становилось невозможно ровно тогда,
// когда это нужнее всего.
//
// Поэтому такие строки логируются не чаще раза в coreNoiseInterval, а
// последняя статистика всегда доступна целиком через /api/status.
var coreNoise = map[string]*regexp.Regexp{
	"stats":       regexp.MustCompile(`\[СТАТИСТИКА\]`),
	"channelbind": regexp.MustCompile(`ChannelBind активен`),
	"refresh":     regexp.MustCompile(`Refresh аллокации`),
}

const coreNoiseInterval = time.Minute

// coreNoiseClass возвращает класс повторяющейся строки или "" для строк,
// которые надо логировать всегда.
func coreNoiseClass(line string) string {
	for class, re := range coreNoise {
		if re.MatchString(line) {
			return class
		}
	}
	return ""
}

var (
	reTunConf  = regexp.MustCompile(`Tunnel IP:\s*([\d.]+)(?:/\d+)?\s*\|\s*DNS:\s*([\d.,\s]+)`)
	reListen   = regexp.MustCompile(`Слушаю:\s*127\.0\.0\.1:(\d+)`)
	reActive   = regexp.MustCompile(`Активных:\s*(\d+)`)
	reIPv4     = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	reFatal    = regexp.MustCompile(`\[ФАТАЛ\]|\[PANIC\]`)
	reTurnLine = regexp.MustCompile(`TURN|Relay|Relay-адрес`)
)

// tunConf - результат разбора строки "Tunnel IP: X | DNS: Y" из лога ядра.
type tunConf struct {
	ip  string
	dns string
}

// logWatcher инкрементально читает лог-файл ядра и рассылает найденные
// события в предоставленные каналы. Останавливается по cancel.
type logWatcher struct {
	path       string
	offset     int64
	onLine     func(line string)
	onTunConf  chan<- tunConf
	onTraffic  chan<- struct{}
	onBypassIP chan<- string
}

func (w *logWatcher) run(cancel <-chan struct{}) {
	ticker := time.NewTicker(400 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-cancel:
			return
		case <-ticker.C:
			w.poll()
		}
	}
}

func (w *logWatcher) poll() {
	f, err := os.Open(w.path)
	if err != nil {
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return
	}
	if info.Size() <= w.offset {
		if info.Size() < w.offset {
			w.offset = 0 // файл пересоздан (перезапуск ядра)
		}
		return
	}

	if _, err := f.Seek(w.offset, 0); err != nil {
		return
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var readBytes int64
	for scanner.Scan() {
		line := scanner.Text()
		readBytes += int64(len(line)) + 1
		w.handleLine(line)
	}
	w.offset += readBytes
}

func (w *logWatcher) handleLine(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	if w.onLine != nil {
		w.onLine(line)
	}

	if m := reTunConf.FindStringSubmatch(line); m != nil {
		select {
		case w.onTunConf <- tunConf{ip: m[1], dns: strings.TrimSpace(m[2])}:
		default:
		}
	}

	if m := reActive.FindStringSubmatch(line); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil && n > 0 {
			select {
			case w.onTraffic <- struct{}{}:
			default:
			}
		}
	}

	if reTurnLine.MatchString(line) {
		for _, ip := range reIPv4.FindAllString(line, -1) {
			select {
			case w.onBypassIP <- ip:
			default:
			}
		}
	}
}

// startCore запускает бинарник csqtt-client, перенаправляя весь его
// stdout/stderr в лог-файл (перезаписывая его при каждом подключении).
// Возвращаемый канал done закрывается, когда процесс завершается — это
// единственный безопасный (без гонки по данным) способ для другой горутины
// (watchdog) узнать, что ядро умерло, не читая внутренние поля exec.Cmd,
// которые cmd.Wait() пишет без синхронизации.
func startCore(corePath, logPath string, args []string) (*exec.Cmd, <-chan struct{}, error) {
	os.Remove(logPath)

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, nil, err
	}

	cmd := exec.Command(corePath, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		logFile.Close()
		return nil, nil, err
	}

	done := make(chan struct{})
	go func() {
		cmd.Wait()
		logFile.Close()
		close(done)
	}()

	return cmd, done, nil
}
