package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Сохранение лога на флеш при сбоях.
//
// Зачем: и системный лог OpenWrt (logread), и кольцевой буфер демона живут
// в оперативной памяти. Роутер перезагрузился или у него выдернули питание —
// и разбираться в причине сбоя уже не по чему. На живом железе это случилось
// дважды: туннель не поднимался, пользователь снял питание, и от инцидента
// не осталось ничего.
//
// Пишем не при каждом отключении, а только когда что-то пошло не так
// (неудачная попытка, срабатывание watchdog) и при штатном завершении по
// сигналу. Это несколько килобайт на событие, для флеша несущественно.

const (
	persistLogPath = "/etc/csqtt/incidents.log"
	// Сколько последних строк буфера сохранять на событие.
	persistLogLines = 200
	// Потолок размера файла. При превышении старое отрезается спереди:
	// свежий инцидент всегда важнее давнего.
	persistLogMaxBytes = 96 * 1024
)

// persistLogs дописывает хвост кольцевого буфера в файл на флеше.
//
// Ошибки записи намеренно не поднимаются наверх и не логируются как
// проблема: сохранение диагностики — вспомогательная задача, и она не
// должна мешать основной работе, если, например, кончилось место.
func (a *App) persistLogs(reason string) {
	a.mu.Lock()
	lines := a.logs
	if len(lines) > persistLogLines {
		lines = lines[len(lines)-persistLogLines:]
	}
	snapshot := append([]string{}, lines...)
	a.mu.Unlock()

	if len(snapshot) == 0 {
		return
	}

	var b strings.Builder
	fmt.Fprintf(&b, "\n===== %s | %s =====\n",
		time.Now().Format("2006-01-02 15:04:05"), reason)
	for _, l := range snapshot {
		b.WriteString(l)
		b.WriteByte('\n')
	}

	if err := os.MkdirAll(filepath.Dir(persistLogPath), 0755); err != nil {
		return
	}

	old, _ := os.ReadFile(persistLogPath)
	combined := append(old, b.String()...)

	// Обрезаем спереди по границе строки, чтобы файл не начинался с обрывка.
	if len(combined) > persistLogMaxBytes {
		combined = combined[len(combined)-persistLogMaxBytes:]
		if i := strings.IndexByte(string(combined), '\n'); i >= 0 {
			combined = combined[i+1:]
		}
	}

	// Права как у конфига: в логе могут мелькать адреса серверов и
	// внутренние детали сети. Пароль в лог не попадает (см. safeArgsForLog),
	// но осторожность не лишняя.
	os.WriteFile(persistLogPath, combined, 0600)
}
