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

// defaultRoute - маршрут по умолчанию из основной таблицы, то есть канал,
// которым роутер ходит в интернет помимо туннеля.
//
// Управлять им не нужно — этим занимается netifd, в том числе при
// переключении между WAN (на Cudy TR3000 это usb0 с метрикой 10 и eth0 с
// метрикой 300). Демон только смотрит на него: чтобы дождаться готовности
// сети перед автоподключением и чтобы записать в лог, через какой канал
// поднимается туннель.
type defaultRoute struct {
	has     bool
	gateway string
	dev     string
	metric  string
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

// Направление трафика в туннель через policy routing.
//
// Основная таблица маршрутизации не трогается вообще: default route,
// которым управляет netifd, остаётся единственным и нетронутым. Туннельный
// default живёт в отдельной таблице tunTable, а попадают в неё только
// пакеты из локальной сети — по правилам `ip rule`.
//
// Почему не проще, через default с метрикой 1 в основной таблице (как было
// раньше): туда попадал и трафик самого ядра csqtt-client. А ядру, чтобы
// поднять или восстановить сессии, надо ходить на серверы авторизации VK —
// и эти запросы уходили в туннель, который ядро в этот момент и пытается
// починить. Получался замкнутый круг: стоило туннелю упасть, и подняться
// сам он уже не мог никогда, потому что DNS и HTTP к VK уходили в мёртвый
// интерфейс. Наблюдалось вживую:
//
//	[CORE] ... dns error: Yandex DNS не ответил за 5 секунд для login.vk.ru
//	[CORE] [СТАТИСТИКА] Активных: 0
//
// Теперь трафик роутера (включая ядро и сам демон) всегда идёт по основной
// таблице напрямую, а в туннель уходит только то, что пришло из LAN. Заодно
// это убрало необходимость в обходных маршрутах к peer/TURN и в слежении за
// сменой WAN: переключением каналов целиком занимается netifd.
const (
	tunTable = "100"

	// Приоритеты правил. Оба ниже 32766 (main), чтобы срабатывать раньше
	// него, и заметно выше 0 (local), чтобы не мешать обращениям к самому
	// роутеру.
	ruleLocalPrio  = "29000"
	ruleTunnelPrio = "29001"
)

// setTunnelPolicyRoutes отправляет в туннель трафик из перечисленных
// подсетей.
//
// Правил на подсеть два, и порядок важен:
//
//	29000: from <lan> lookup main suppress_prefixlength 0
//	29001: from <lan> lookup 100
//
// Первое разрешает по основной таблице всё, у чего есть конкретный маршрут
// (соседи по локальной сети, сама WAN-подсеть), но благодаря
// suppress_prefixlength 0 пропускает мимо default route. Без него весь
// трафик внутри локальной сети тоже уходил бы в туннель. Всё, что не нашло
// конкретного маршрута, доходит до второго правила и уходит в туннель.
func setTunnelPolicyRoutes(tunName string, subnets []string) {
	runIP("route", "replace", "default", "dev", tunName, "table", tunTable)

	for _, s := range subnets {
		runIP("rule", "add", "from", s, "lookup", "main",
			"suppress_prefixlength", "0", "priority", ruleLocalPrio)
		runIP("rule", "add", "from", s, "lookup", tunTable, "priority", ruleTunnelPrio)
	}
}

// clearTunnelPolicyRoutes снимает правила и чистит таблицу. Основная таблица
// при этом не менялась, поэтому восстанавливать в ней нечего — маршрут WAN
// всё это время был на месте.
func clearTunnelPolicyRoutes(subnets []string) {
	for range subnets {
		// Удаляем по приоритету: правил с одним приоритетом столько же,
		// сколько подсетей, и каждый вызов снимает по одному.
		runIP("rule", "del", "priority", ruleLocalPrio)
		runIP("rule", "del", "priority", ruleTunnelPrio)
	}
	runIP("route", "flush", "table", tunTable)
}

// lanSubnets возвращает подсети, трафик которых надо заворачивать в туннель.
// По умолчанию это адреса LAN-интерфейса из uci (на OpenWrt br-lan).
func lanSubnets(configured string) []string {
	if configured != "" {
		var out []string
		for _, s := range strings.Split(configured, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	}

	dev := "br-lan"
	if out, err := exec.Command("uci", "-q", "get", "network.lan.device").Output(); err == nil {
		if d := strings.TrimSpace(string(out)); d != "" {
			dev = d
		}
	}

	out, err := exec.Command("ip", "-4", "-o", "addr", "show", "dev", dev).Output()
	if err != nil {
		log("[ROUTE] Не удалось определить подсети %s: %v", dev, err)
		return nil
	}

	var subnets []string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		for i, f := range fields {
			if f != "inet" || i+1 >= len(fields) {
				continue
			}
			// ParseCIDR из "192.168.1.1/24" даёт сеть 192.168.1.0/24 —
			// именно её и надо указывать в правиле.
			if _, network, err := net.ParseCIDR(fields[i+1]); err == nil {
				subnets = append(subnets, network.String())
			}
		}
	}
	return subnets
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
