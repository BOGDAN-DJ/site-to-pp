package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/songgao/water"
)

// defaultRoute - «нижележащий» маршрут по умолчанию, то есть тот, которым
// роутер ходит в интернет помимо туннеля. Нужен, чтобы прокладывать через
// него обходные маршруты к peer/TURN: сам туннель поднимается через сервер,
// до которого надо как-то добраться, и заворачивать этот трафик в туннель
// нельзя.
//
// На роутерах с несколькими WAN (у Cudy TR3000 это usb0 с метрикой 10 и
// eth0 с метрикой 300) такой маршрут меняется на ходу — модем воткнули,
// модем вынули. Поэтому он не снимается один раз при подключении, а
// перечитывается: см. watchUnderlay в main.go.
type defaultRoute struct {
	has     bool
	gateway string
	dev     string
	metric  string
}

func (r defaultRoute) sameAs(o defaultRoute) bool {
	return r.has == o.has && r.gateway == o.gateway && r.dev == o.dev
}

func (r defaultRoute) String() string {
	if !r.has {
		return "(нет)"
	}
	if r.gateway == "" {
		return "dev " + r.dev
	}
	return "via " + r.gateway + " dev " + r.dev
}

var reDefaultRoute = regexp.MustCompile(`^default\s+(?:via\s+(\S+)\s+)?dev\s+(\S+)(?:.*?\bmetric\s+(\d+))?`)

// getDefaultRoute возвращает лучший default route, игнорируя маршрут через
// excludeDev (передаём туда имя TUN, чтобы не принять собственный маршрут
// за нижележащий) .
//
// Выбираем именно наименьшую метрику, а не первую попавшуюся строку: при
// нескольких активных WAN в выводе несколько default-маршрутов, и ядро
// пользуется тем, у которого метрика меньше. Строки `ip route show`
// отсортированы по метрике, но полагаться на это не стоит — маршрут без
// метрики (т.е. metric 0) может оказаться где угодно.
func getDefaultRoute(excludeDev string) defaultRoute {
	out, err := exec.Command("ip", "-4", "route", "show", "default").Output()
	if err != nil {
		return defaultRoute{}
	}

	best := defaultRoute{}
	bestMetric := -1

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		m := reDefaultRoute.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if excludeDev != "" && m[2] == excludeDev {
			continue
		}

		metric := 0
		if m[3] != "" {
			if v, err := strconv.Atoi(m[3]); err == nil {
				metric = v
			}
		}
		if bestMetric == -1 || metric < bestMetric {
			best = defaultRoute{has: true, gateway: m[1], dev: m[2], metric: m[3]}
			bestMetric = metric
		}
	}
	return best
}

// runIP выполняет `ip ...` и логирует неуспешные команды (но не прерывает
// выполнение — большинство вызовов идемпотентны и могут "проваливаться"
// на повторных запусках, например del на уже удалённом маршруте).
func runIP(args ...string) error {
	cmd := exec.Command("ip", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log("[IP] ip %s -> %v (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return err
}

// needsBypassRoute сообщает, нужен ли отдельный host-маршрут к ip.
//
// Если адрес лежит в подсети, подключённой к интерфейсу напрямую, его уже
// обслуживает connected-маршрут: он длиннее default и спокойно переживёт
// его подмену на туннель. Прокладывать для такого адреса /32 "via шлюз" не
// просто лишнее, а вредно — пакет уходит на шлюз, которому приходится
// разворачивать его обратно в ту же подсеть, и часть роутеров этого не
// делает вовсе.
//
// Отличаем одно от другого по выводу `ip route get`: для адреса за шлюзом
// там есть "via", для напрямую доступного — только "dev".
//
//	# ip route get 192.168.31.199
//	192.168.31.199 dev eth0 src 192.168.31.179
//	# ip route get 8.8.8.8
//	8.8.8.8 via 192.168.31.100 dev eth0 src 192.168.31.179
//
// Вызывать до подмены default route — после неё ответ будет уже про туннель.
func needsBypassRoute(ip string) bool {
	out, err := exec.Command("ip", "-4", "route", "get", ip).Output()
	if err != nil {
		// Не смогли выяснить — безопаснее проложить маршрут, чем остаться
		// без связи с сервером после переключения default route.
		return true
	}
	return strings.Contains(string(out), " via ")
}

// addBypassRoute прокладывает host-маршрут (/32) к ip через исходный шлюз,
// чтобы трафик к серверу CSQTT (и его TURN/relay-узлам) не пытался уйти
// в туннель, который сам через этот сервер и поднимается.
//
// Возвращает true, если маршрут действительно был добавлен — вызывающий код
// запоминает только такие адреса, чтобы при отключении не удалить чужой
// маршрут, которого он не создавал.
func addBypassRoute(orig defaultRoute, ip string) bool {
	if !orig.has || net.ParseIP(ip) == nil {
		return false
	}
	if !needsBypassRoute(ip) {
		log("[ROUTE] %s доступен напрямую, обходной маршрут не нужен", ip)
		return false
	}
	args := []string{"route", "replace", ip + "/32"}
	if orig.gateway != "" {
		args = append(args, "via", orig.gateway)
	}
	args = append(args, "dev", orig.dev)
	return runIP(args...) == nil
}

func removeBypassRoute(ip string) {
	runIP("route", "del", ip+"/32")
}

// setDefaultViaTun направляет трафик по умолчанию в туннель.
//
// Маршрут netifd при этом НЕ удаляется: наш default получает метрику 1, а у
// WAN-интерфейсов метрики заметно больше (на Cudy TR3000 это 10 у usb0 и
// 300 у eth0), так что ядро и без того выберет туннель. Сосуществование
// маршрутов вместо подмены даёт три вещи сразу:
//
//   - отключение сводится к удалению одной строки, восстанавливать чужой
//     маршрут и терять при этом его атрибуты (proto static, src) не нужно;
//   - переключение WAN (воткнули/вынули USB-модем) netifd отрабатывает сам,
//     нам остаётся только переложить обходные маршруты;
//   - если демон умрёт, не успев прибраться, роутер останется с рабочим
//     маршрутом в интернет, а не без маршрута вообще.
func setDefaultViaTun(tunName string) {
	runIP("route", "replace", "default", "dev", tunName, "metric", "1")
}

// restoreDefaultRoute убирает наш маршрут через TUN. Маршрут WAN всё это
// время оставался на месте, так что после удаления ядро просто вернётся к
// нему. orig нужен лишь как страховка на случай, если default пропал по
// не зависящим от нас причинам (например, netifd переподнимал интерфейс
// ровно в этот момент).
func restoreDefaultRoute(tunName string, orig defaultRoute) {
	runIP("route", "del", "default", "dev", tunName)

	if getDefaultRoute(tunName).has || !orig.has {
		return
	}

	log("[ROUTE] После отключения не осталось ни одного default — восстанавливаю %s", orig)
	args := []string{"route", "add", "default"}
	if orig.gateway != "" {
		args = append(args, "via", orig.gateway)
	}
	args = append(args, "dev", orig.dev)
	if orig.metric != "" {
		args = append(args, "metric", orig.metric)
	}
	runIP(args...)
}

// setupTunDevice создаёт TUN-интерфейс через ioctl(TUNSETIFF) (без PI-заголовка,
// это важно: csqtt-client на другом конце UDP-моста ждёт "сырые" IP-пакеты один
// в один с тем, как это делает Wintun-мост в Desktop-версии на Windows) и
// настраивает его адрес/MTU средствами `ip`, ровно как это делает оригинальный
// демон LaLune для рабочего стола.
func setupTunDevice(name, ip, mtu string) (*water.Interface, error) {
	ifce, err := water.New(water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: name,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("создание TUN: %w", err)
	}

	if err := runIP("addr", "add", ip+"/32", "dev", ifce.Name()); err != nil {
		ifce.Close()
		return nil, err
	}
	if err := runIP("link", "set", ifce.Name(), "mtu", mtu); err != nil {
		ifce.Close()
		return nil, err
	}
	if err := runIP("link", "set", ifce.Name(), "up"); err != nil {
		ifce.Close()
		return nil, err
	}

	return ifce, nil
}

// bridgeTunUDP перекачивает пакеты между TUN-интерфейсом и локальным UDP-сокетом
// ядра в обе стороны без какой-либо инкапсуляции: один UDP-датаграм = один
// IP-пакет. Останавливается, когда закрывается ifce или udpConn (что приводит
// к ошибке чтения в соответствующей горутине).
func bridgeTunUDP(ifce io.ReadWriter, udpConn *net.UDPConn, stop <-chan struct{}) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			n, err := ifce.Read(buf)
			if err != nil {
				return
			}
			if _, err := udpConn.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			n, err := udpConn.Read(buf)
			if err != nil {
				return
			}
			if _, err := ifce.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	go func() {
		<-stop
		udpConn.Close()
	}()

	wg.Wait()
}

// ---- Интеграция с firewall4 (nftables) стокового OpenWrt ----
//
// TUN-интерфейс создаётся "на лету" через ioctl и не является логическим
// интерфейсом из /etc/config/network, поэтому обычный `option network`
// в зоне firewall для него не резолвится. firewall4 (используется по
// умолчанию в современных релизах OpenWrt, включая ветку 24.10/25.x)
// умеет добавлять в зону произвольные netdev через `list device`, этим и
// пользуемся — создаём отдельную именованную зону "csqtt" с masquerade
// и разрешаем форвардинг lan -> csqtt.

func firewallUp(tunName string) {
	uci("set", "firewall.csqtt=zone")
	uci("set", "firewall.csqtt.name=csqtt")
	uci("delete", "firewall.csqtt.device")
	uci("add_list", "firewall.csqtt.device="+tunName)
	uci("set", "firewall.csqtt.input=REJECT")
	uci("set", "firewall.csqtt.output=ACCEPT")
	uci("set", "firewall.csqtt.forward=REJECT")
	uci("set", "firewall.csqtt.masq=1")
	uci("set", "firewall.csqtt.mtu_fix=1")

	uci("set", "firewall.csqtt_fwd=forwarding")
	uci("set", "firewall.csqtt_fwd.src=lan")
	uci("set", "firewall.csqtt_fwd.dest=csqtt")

	uci("commit", "firewall")
	reloadFirewall()
}

func firewallDown() {
	uci("delete", "firewall.csqtt_fwd")
	uci("delete", "firewall.csqtt")
	uci("commit", "firewall")
	reloadFirewall()
}

// hwSwitchOn читает положение аппаратного переключателя по его метке в
// devicetree (на Cudy TR3000 это "mode").
//
// Нужно на старте: обработчик /etc/rc.button/BTN_0 вызывается только при
// СМЕНЕ положения, поэтому после перезагрузки демон сам по себе не знает,
// куда переключатель выставлен физически, и без этой проверки мог бы
// поднять туннель вопреки положению тумблера.
//
// Читаем /sys/kernel/debug/gpio, строки вида:
//
//	gpio-512 (                    |mode                ) in  hi IRQ ACTIVE LOW
//
// Уровень (hi/lo) сопоставляем с полярностью: при "ACTIVE LOW" активному
// состоянию соответствует lo, иначе hi. Второе возвращаемое значение
// говорит, удалось ли вообще определить положение — формат debugfs не
// является стабильным ABI, и если разобрать не вышло, вызывающий код
// должен откатиться к обычному булеву AUTOCONNECT, а не гадать.
func hwSwitchOn(label string) (on bool, known bool) {
	data, err := os.ReadFile("/sys/kernel/debug/gpio")
	if err != nil {
		return false, false
	}

	for _, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(line, "|"+label) {
			continue
		}

		fields := strings.Fields(line)
		level := ""
		for _, f := range fields {
			if f == "hi" || f == "lo" {
				level = f
				break
			}
		}
		if level == "" {
			return false, false
		}

		activeLow := strings.Contains(line, "ACTIVE LOW")
		if activeLow {
			return level == "lo", true
		}
		return level == "hi", true
	}

	return false, false
}

// clearStaleFirewall убирает зону csqtt, оставшуюся в /etc/config/firewall
// от прошлого запуска.
//
// firewallUp вынужден делать `uci commit`, иначе fw4 не увидит новую зону,
// а commit пишет на диск. Поэтому после жёсткой перезагрузки (питание
// выдернули, паника ядра) зона переживает ребут и ссылается на csqtt0,
// которого больше нет. Само по себе это не ломает firewall — fw4 такую
// зону просто игнорирует, — но оставлять мусор и, что хуже, разрешение
// форвардинга lan -> csqtt в конфиге не стоит.
//
// Вызывается один раз при старте демона, до всякого подключения.
func clearStaleFirewall() {
	out, err := exec.Command("uci", "-q", "get", "firewall.csqtt").Output()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return
	}
	log("[FW] Найдена зона csqtt от прошлого запуска — убираю")
	firewallDown()
}

func uci(args ...string) {
	cmd := exec.Command("uci", append([]string{"-q"}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		log("[UCI] uci %s -> %v (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
}

func reloadFirewall() {
	if err := exec.Command("fw4", "reload").Run(); err == nil {
		return
	}
	exec.Command("/etc/init.d/firewall", "reload").Run()
}

// appendResolvConf дописывает DNS-серверы туннеля в /etc/resolv.conf.
// На части конфигураций OpenWrt этот файл — симлинк на /tmp/resolv.conf.auto,
// управляемый dnsmasq/netifd, и может быть перезаписан при следующем событии
// сети; при необходимости стабильного DNS настройте dhcp через uci отдельно.
func appendResolvConf(dnsList string) {
	f, err := os.OpenFile("/etc/resolv.conf", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log("[DNS] Не удалось открыть /etc/resolv.conf: %v", err)
		return
	}
	defer f.Close()

	for _, dns := range strings.Split(dnsList, ",") {
		dns = strings.TrimSpace(dns)
		// net.ParseIP уже гарантирует, что тут только цифры/точки/двоеточия,
		// так что безопасно писать значение напрямую в файл.
		if dns == "" || net.ParseIP(dns) == nil {
			continue
		}
		fmt.Fprintf(f, "nameserver %s\n", dns)
	}
}
