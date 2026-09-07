package main

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// parseCSQTTLink разбирает ссылку подключения вида
//
//	csqtt://connect?v=2&host=HOST&peer=PORT&password=PASS&hashes=H1+H2+H3
//
// и возвращает только те три поля, которые она несёт. Остальные настройки
// (workers, obfs, fingerprint и прочее) ссылка не содержит, поэтому
// вызывающий код должен накладывать результат на существующий конфиг, а не
// заменять его целиком.
//
// Про "peer": в ссылке это ПОРТ, а не адрес, хотя название сбивает с толку.
// Адрес лежит в "host", и PEER в конфиге — это склейка "host:peer".
func parseCSQTTLink(raw string) (peer, password, vk string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", "", fmt.Errorf("пустая ссылка")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", "", "", fmt.Errorf("не разобрать ссылку: %w", err)
	}
	if u.Scheme != "csqtt" {
		return "", "", "", fmt.Errorf("ожидалась ссылка csqtt://, а не %q", u.Scheme)
	}

	q := u.Query()
	host := strings.TrimSpace(q.Get("host"))
	port := strings.TrimSpace(q.Get("peer"))
	password = q.Get("password")
	// url.Values уже раскодировал "+" в пробелы — normalizeHashes принимает
	// и пробелы, и запятые, так что дополнительная обработка не нужна.
	vk = normalizeHashes(q.Get("hashes"))

	var missing []string
	if host == "" {
		missing = append(missing, "host")
	}
	if port == "" {
		missing = append(missing, "peer")
	}
	if password == "" {
		missing = append(missing, "password")
	}
	if vk == "" {
		missing = append(missing, "hashes")
	}
	if len(missing) > 0 {
		return "", "", "", fmt.Errorf("в ссылке нет обязательных полей: %s", strings.Join(missing, ", "))
	}

	return net.JoinHostPort(host, port), password, vk, nil
}
