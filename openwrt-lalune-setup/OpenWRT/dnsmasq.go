package main

import (
	"net"
	"os/exec"
	"strings"
)

// Домены, которые нельзя резать защитой dnsmasq от DNS rebinding.
//
// Провайдеры нередко публикуют внутренние сервисы в обычном публичном DNS,
// но с приватными адресами вида 10.x. Записи при этом видны отовсюду,
// включая 8.8.8.8, так что «не резолвится только у меня» — обманчивый
// симптом: дело не в том, где живёт запись, а в том, на что она указывает.
// Разбор реального случая — в README, раздел про сервисы провайдера.
//
// dnsmasq в OpenWrt по умолчанию отбрасывает ответы с приватными адресами,
// пришедшие от внешних резолверов (rebind_protection). Защита правильная —
// она мешает внешнему сайту заставить браузер лезть внутрь локальной сети,
// — но на такие сервисы срабатывает ложно. В логе это видно прямо:
//
//	dnsmasq: possible DNS-rebind attack detected: имя.домен
//
// Домены перечисляются в REBIND_DOMAINS в csqtt.conf, а не зашиваются в
// код и не кладутся в образ прошивки: это личные адреса конкретной сети,
// и им место рядом с остальными приватными настройками, а не в публичном
// репозитории. Заодно они переживают обновление прошивки — csqtt.conf
// указан в /etc/sysupgrade.conf.
//
// Отключать rebind_protection целиком не стоит: она прикрывает всю
// локальную сеть, а проблема касается нескольких доменов.

// currentRebindDomains возвращает список, который сейчас стоит в dnsmasq.
// uci отдаёт его одной строкой через пробел.
func currentRebindDomains() []string {
	out, err := exec.Command("uci", "-q", "get", "dhcp.@dnsmasq[0].rebind_domain").Output()
	if err != nil {
		return nil
	}
	return strings.Fields(string(out))
}

// applyRebindDomains приводит список в dnsmasq в точное соответствие с
// конфигом демона: добавляет недостающее и убирает лишнее.
//
// Именно приводит в соответствие, а не только дописывает — иначе домен,
// удалённый через панель, остался бы в dnsmasq навсегда. Побочный эффект:
// записи, добавленные в dhcp.@dnsmasq[0].rebind_domain вручную мимо
// REBIND_DOMAINS, будут стёрты. Это осознанный выбор: у настройки должен
// быть один владелец, иначе панель показывает одно, а работает другое.
//
// Пустой список означает «убрать все». Единственный случай, когда dnsmasq
// не трогается вовсе, — когда он уже в нужном состоянии.
//
// Идемпотентность здесь не украшение: функция вызывается при каждом старте
// демона, а перезапуск dnsmasq рвёт DNS всей локальной сети на пару секунд.
func applyRebindDomains(list string) {
	wanted := splitList(list)
	existing := currentRebindDomains()

	if sameSet(wanted, existing) {
		return
	}

	// Список переписываем целиком: uci умеет add_list, но не умеет удалять
	// отдельный элемент, так что проще снести и собрать заново.
	uci("delete", "dhcp.@dnsmasq[0].rebind_domain")
	for _, d := range wanted {
		uci("add_list", "dhcp.@dnsmasq[0].rebind_domain="+d)
	}

	uci("commit", "dhcp")
	if err := exec.Command("/etc/init.d/dnsmasq", "restart").Run(); err != nil {
		log("[DNS] Не удалось перезапустить dnsmasq: %v", err)
		return
	}

	if len(wanted) == 0 {
		log("[DNS] Исключения rebind очищены")
		return
	}
	log("[DNS] Исключения rebind: %s", strings.Join(wanted, ", "))
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]bool, len(a))
	for _, v := range a {
		set[v] = true
	}
	for _, v := range b {
		if !set[v] {
			return false
		}
	}
	return true
}

// validDomain проверяет, что строка похожа на доменное имя.
//
// Проверка нужна не от инъекций — uci вызывается через exec.Command без
// оболочки, — а чтобы опечатка из панели не уехала молча в конфиг dnsmasq
// и не заставила его ругаться при следующем старте.
func validDomain(s string) bool {
	if s == "" || len(s) > 253 || strings.HasPrefix(s, "-") || strings.HasPrefix(s, ".") {
		return false
	}
	// Адрес, а не имя: у IP нет DNS-ответа, резать который могла бы защита
	// от rebinding, так что в этом списке ему делать нечего.
	if net.ParseIP(s) != nil {
		return false
	}
	if !strings.Contains(s, ".") {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-':
		default:
			return false
		}
	}
	return true
}

// splitList разбирает список, записанный через запятую или пробелы.
func splitList(s string) []string {
	replacer := strings.NewReplacer(",", " ", "\t", " ", "\n", " ")
	var out []string
	for _, item := range strings.Fields(replacer.Replace(s)) {
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}
