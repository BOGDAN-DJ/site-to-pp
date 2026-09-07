package main

import (
	"os"
	"path/filepath"
	"strings"
)

// Индикация состояния туннеля штатным светодиодом роутера.
//
// На Cudy TR3000 это white:status — тот самый, который в обычной жизни
// горит ровным светом. Мы его на время забираем себе, поэтому исходное
// состояние (триггер + яркость) запоминается при старте демона и
// возвращается при выходе: если демон убрать, роутер должен выглядеть
// ровно так же, как до него.
//
// Мигание делает само ядро через триггер "timer", а не горутина в демоне:
// так индикация не зависит от того, чем занят процесс, и переживает даже
// его зависание.

const (
	ledDir = "/sys/class/leds"

	ledBlinkOnMs  = "300"
	ledBlinkOffMs = "300"
)

// ledState - то, чем светодиод был занят до нас.
type ledState struct {
	name       string
	trigger    string
	brightness string
	valid      bool
}

// leds - пара индикаторов: активный горит при поднятом туннеле, простойный
// при выключенном.
//
// Две штуки, а не одна, потому что на Cudy TR3000 это один физический
// двухцветный светодиод (white:status и red:power — два входа к нему).
// Гасить его совсем при выключенном туннеле неудачно: роутер выглядел бы
// мёртвым, хотя он работает и просто ходит в интернет напрямую. Поэтому
// "туннеля нет" показывается вторым цветом, а не темнотой.
type leds struct {
	active ledState
	idle   ledState
}

func captureLeds(activeName, idleName string) leds {
	return leds{
		active: ledCapture(activeName),
		idle:   ledCapture(idleName),
	}
}

// tunnelUp - туннель поднят и возит трафик.
func (l leds) tunnelUp() {
	l.idle.off()
	l.active.solid()
}

// connecting - ядро запущено, туннель ещё не поднят.
func (l leds) connecting() {
	l.idle.off()
	l.active.blink()
}

// tunnelDown - туннеля нет, роутер работает напрямую.
func (l leds) tunnelDown() {
	l.active.off()
	l.idle.solid()
}

func (l leds) restore() {
	l.active.restore()
	l.idle.restore()
}

func ledPath(name, attr string) string {
	return filepath.Join(ledDir, name, attr)
}

func ledWrite(name, attr, value string) error {
	return os.WriteFile(ledPath(name, attr), []byte(value), 0644)
}

func ledRead(name, attr string) string {
	data, err := os.ReadFile(ledPath(name, attr))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// ledCapture запоминает текущее состояние светодиода.
//
// Файл trigger отдаёт весь список доступных триггеров, а активный помечен
// квадратными скобками: "none timer [heartbeat] ...". Вытаскиваем именно
// его.
func ledCapture(name string) ledState {
	if name == "" {
		return ledState{}
	}
	if _, err := os.Stat(filepath.Join(ledDir, name)); err != nil {
		log("[LED] Светодиод %q не найден — индикации не будет", name)
		return ledState{}
	}

	s := ledState{name: name, valid: true, brightness: ledRead(name, "brightness")}

	for _, t := range strings.Fields(ledRead(name, "trigger")) {
		if strings.HasPrefix(t, "[") {
			s.trigger = strings.Trim(t, "[]")
			break
		}
	}

	log("[LED] Беру управление %q (было: триггер %q, яркость %s)", name, s.trigger, s.brightness)
	return s
}

// ledRestore возвращает светодиод в исходное состояние.
func (s ledState) restore() {
	if !s.valid {
		return
	}
	if s.trigger != "" {
		ledWrite(s.name, "trigger", s.trigger)
	}
	// Яркость пишем после триггера: смена триггера сбрасывает её.
	if s.brightness != "" && (s.trigger == "" || s.trigger == "none") {
		ledWrite(s.name, "brightness", s.brightness)
	}
}

func (s ledState) solid() {
	if !s.valid {
		return
	}
	ledWrite(s.name, "trigger", "none")
	ledWrite(s.name, "brightness", ledRead(s.name, "max_brightness"))
}

func (s ledState) off() {
	if !s.valid {
		return
	}
	ledWrite(s.name, "trigger", "none")
	ledWrite(s.name, "brightness", "0")
}

// blink переводит светодиод в мигание силами ядра. Файлы delay_on/delay_off
// появляются только после того, как выбран триггер "timer", поэтому порядок
// записи здесь важен.
func (s ledState) blink() {
	if !s.valid {
		return
	}
	if err := ledWrite(s.name, "trigger", "timer"); err != nil {
		// Триггера timer может не быть в сборке ядра — тогда просто ровный
		// свет, это лучше, чем ничего.
		s.solid()
		return
	}
	ledWrite(s.name, "delay_on", ledBlinkOnMs)
	ledWrite(s.name, "delay_off", ledBlinkOffMs)
}
