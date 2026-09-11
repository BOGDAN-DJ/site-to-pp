package main

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Ретрансляция капчи VK между ядром и человеком.
//
// Как это устроено в самом ядре (amurcanov/csqtt, rust-client/captcha.rs):
// когда VK требует пройти проверку, ядро печатает в stdout строку
//
//	CAPTCHA_SOLVE|<режим>|<redirect_uri>|<session_token>
//
// и ждёт на stdin ответа
//
//	CAPTCHA_RESULT|<success_token>
//
// В Android-приложении на это подписан WebView: он открывает redirect_uri,
// внедряет в страницу свой JavaScript, перехватывает ответ на запрос
// `captchaNotRobot.check` и достаёт оттуда `response.success_token`.
//
// Веб-страница так не может: внедрить код в чужой источник запрещает
// правило одного источника, и обойти это заголовками нельзя. Поэтому здесь
// два пути получения токена, оба через человека:
//
//   - юзерскрипт в браузере (Tampermonkey и подобные) делает ровно то же,
//     что WebView, и сам отправляет токен в /api/captcha/solve;
//   - либо токен вставляется в панель руками.
//
// Демон капчу не решает и не пытается обходить проверку: он только
// доставляет запрос тому, кто может её пройти, и возвращает ответ обратно.

// reCaptchaSolve разбирает строку запроса от ядра. Поля разделены "|", а
// в redirect_uri и session_token символ "|" не встречается.
var reCaptchaSolve = regexp.MustCompile(`^CAPTCHA_SOLVE\|([^|]*)\|([^|]*)\|(.*)$`)

// captchaRequest - незакрытый запрос капчи.
type captchaRequest struct {
	Mode        string    `json:"mode"`
	RedirectURI string    `json:"redirect_uri"`
	Since       time.Time `json:"-"`
	WaitingSec  int       `json:"waiting_sec"`
}

// captchaTimeout - после какого простоя считать запрос протухшим.
//
// Ядро ждёт ответа от 10 до 120 секунд в зависимости от шага цепочки.
// Держим запрос в панели дольше самого длинного шага, чтобы человек успел
// его увидеть, а потом убираем: показывать капчу, которую уже никто не
// ждёт, значит вводить в заблуждение.
const captchaTimeout = 3 * time.Minute

// noteCaptchaRequest вызывается на каждую строку лога ядра. Возвращает
// true, если строка была запросом капчи и её не надо показывать как
// обычную запись.
func (a *App) noteCaptchaRequest(line string) bool {
	m := reCaptchaSolve.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return false
	}

	req := &captchaRequest{Mode: m[1], RedirectURI: m[2], Since: time.Now()}

	a.mu.Lock()
	a.captcha = req
	a.captchaSeen++
	a.mu.Unlock()

	// session_token в лог не пишем: он одноразовый, но всё же учётные данные.
	log("[КАПЧА] ВК требует проверку (режим %s). Откройте панель роутера, "+
		"ссылка для решения там.", req.Mode)
	return true
}

// pendingCaptcha возвращает актуальный запрос или nil.
func (a *App) pendingCaptcha() *captchaRequest {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.captcha == nil {
		return nil
	}
	if time.Since(a.captcha.Since) > captchaTimeout {
		a.captcha = nil
		return nil
	}

	copy := *a.captcha
	copy.WaitingSec = int(time.Since(a.captcha.Since).Seconds())
	return &copy
}

// solveCaptcha отправляет ядру полученный от человека токен.
func (a *App) solveCaptcha(token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return fmt.Errorf("пустой токен")
	}
	// В канал управления ядра строка уходит целиком, поэтому перевод строки
	// внутри токена сломал бы протокол.
	if strings.ContainsAny(token, "\r\n") {
		return fmt.Errorf("токен не должен содержать переводов строк")
	}

	a.mu.Lock()
	stdin := a.coreStdin
	pending := a.captcha
	a.mu.Unlock()

	if stdin == nil {
		return fmt.Errorf("ядро не запущено")
	}
	if pending == nil {
		return fmt.Errorf("сейчас капча не запрашивается")
	}

	if _, err := fmt.Fprintf(stdin, "CAPTCHA_RESULT|%s\n", token); err != nil {
		return fmt.Errorf("не удалось передать токен ядру: %w", err)
	}

	a.mu.Lock()
	a.captcha = nil
	a.mu.Unlock()

	log("[КАПЧА] Токен передан ядру")
	return nil
}
