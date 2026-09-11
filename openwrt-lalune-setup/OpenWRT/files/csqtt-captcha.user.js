// ==UserScript==
// @name         CSQTT: возврат токена капчи на роутер
// @namespace    https://github.com/BOGDAN-DJ/site-to-pp
// @version      1.0
// @description  Перехватывает результат проверки VK и отправляет его демону CSQTT, чтобы не вставлять токен вручную
// @match        https://id.vk.ru/*
// @match        https://id.vk.com/*
// @run-at       document-start
// @grant        none
// ==/UserScript==

// Зачем это нужно
// ---------------
// Когда VK требует пройти проверку, ядро csqtt-client печатает запрос и ждёт
// в ответ success_token. В Android-приложении токен достаёт WebView: он
// внедряет свой код в страницу проверки и перехватывает ответ на запрос
// captchaNotRobot.check.
//
// Веб-страница так не может — внедрить код в чужой источник запрещает
// правило одного источника. Юзерскрипт это единственный механизм, дающий
// браузеру те же возможности, поэтому здесь повторена ровно та же логика,
// что в CaptchaWebViewManager.kt у amurcanov/csqtt.
//
// Скрипт НИЧЕГО не решает и не обходит: капчу проходит человек, руками.
// Задача скрипта — избавить от копирования токена в панель вручную.
//
// Установка: Tampermonkey (или Violentmonkey) -> создать скрипт -> вставить
// этот файл. Адрес роутера при необходимости поправьте ниже.

(function () {
    'use strict';

    // Адрес панели роутера. Если LAN-адрес другой — поменяйте здесь.
    var PANEL = 'http://192.168.1.1:8080/api/captcha';

    if (window.__csqtt_captcha_installed) return;
    window.__csqtt_captcha_installed = true;

    function send(token) {
        if (!token) return;
        // Демон отвечает на OPTIONS и разрешает запросы с чужого источника —
        // иначе браузер не выпустил бы этот запрос со страницы VK.
        fetch(PANEL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: token })
        }).then(function (r) { return r.json(); }).then(function (r) {
            console.log('[CSQTT] токен отправлен на роутер:', r);
        }).catch(function (e) {
            console.warn('[CSQTT] не удалось отправить токен:', e,
                '— вставьте его в панель вручную:', token);
        });
    }

    // Ответ проверки приходит на captchaNotRobot.check, и success_token
    // лежит в data.response. Перехватываем оба способа отправки запросов:
    // страница может пользоваться как fetch, так и XMLHttpRequest.
    function inspect(raw) {
        try {
            var data = JSON.parse(raw);
            if (data && data.response && data.response.success_token) {
                send(data.response.success_token);
            }
        } catch (e) { /* неJSON — не наш ответ */ }
    }

    var origFetch = window.fetch;
    window.fetch = async function () {
        var url = arguments[0] || '';
        if (typeof url !== 'string') url = (url && url.url) || '';
        var response = await origFetch.apply(this, arguments);
        if (url.indexOf('captchaNotRobot.check') !== -1) {
            // Клонируем: тело ответа читается один раз, и страница должна
            // получить его нетронутым.
            response.clone().text().then(inspect).catch(function () { });
        }
        return response;
    };

    var origOpen = XMLHttpRequest.prototype.open;
    var origSend = XMLHttpRequest.prototype.send;

    XMLHttpRequest.prototype.open = function (method, url) {
        this.__csqtt_url = url;
        return origOpen.apply(this, arguments);
    };

    XMLHttpRequest.prototype.send = function () {
        var xhr = this;
        if (xhr.__csqtt_url && String(xhr.__csqtt_url).indexOf('captchaNotRobot.check') !== -1) {
            xhr.addEventListener('load', function () {
                inspect(xhr.responseText);
            });
        }
        return origSend.apply(this, arguments);
    };

    console.log('[CSQTT] перехватчик токена капчи установлен');
})();
