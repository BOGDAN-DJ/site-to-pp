package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"github.com/songgao/water"
)

// defaultRoute - маршрут по умолчанию, существовавший на роутере до
// подключения CSQTT. Сохраняется, чтобы: а) проложить обходные маршруты для
// peer/TURN до переключения шлюза, б) корректно откатить default route при
// отключении, вместо того чтобы оставить роутер без интернета.
type defaultRoute struct {
	has     bool
	gateway string
	dev     string
	metric  string
}

var reDefaultRoute = regexp.MustCompile(`^default\s+(?:via\s+(\S+)\s+)?dev\s+(\S+)(?:.*?\bmetric\s+(\d+))?`)

func getDefaultRoute() defaultRoute {
	out, err := exec.Command("ip", "-4", "route", "show", "default").Output()
	if err != nil {
		return defaultRoute{}
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		m := reDefaultRoute.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		return defaultRoute{has: true, gateway: m[1], dev: m[2], metric: m[3]}
	}
	return defaultRoute{}
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

// addBypassRoute прокладывает host-маршрут (/32) к ip через исходный шлюз,
// чтобы трафик к серверу CSQTT (и его TURN/relay-узлам) не пытался уйти
// в туннель, который сам через этот сервер и поднимается.
func addBypassRoute(orig defaultRoute, ip string) {
	if !orig.has || net.ParseIP(ip) == nil {
		return
	}
	args := []string{"route", "replace", ip + "/32"}
	if orig.gateway != "" {
		args = append(args, "via", orig.gateway)
	}
	args = append(args, "dev", orig.dev)
	runIP(args...)
}

func removeBypassRoute(ip string) {
	runIP("route", "del", ip+"/32")
}

// setDefaultViaTun переключает маршрут по умолчанию на TUN-интерфейс.
// Существовавший default удаляется явно (а не заменяется по metric), потому
// что "ip route replace" не гарантированно попадёт в тот же route-selector,
// если метрика/шлюз отличаются.
func setDefaultViaTun(tunName string) {
	runIP("route", "del", "default")
	runIP("route", "add", "default", "dev", tunName, "metric", "1")
}

// restoreDefaultRoute убирает маршрут через TUN и, если до подключения
// существовал другой default, восстанавливает именно его.
func restoreDefaultRoute(tunName string, orig defaultRoute) {
	runIP("route", "del", "default", "dev", tunName)
	if !orig.has {
		return
	}
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
