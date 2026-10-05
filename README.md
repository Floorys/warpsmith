# AWG WARP Architect

Генератор конфигов **Cloudflare WARP** для **AmneziaWG** и обычного WireGuard —
с настоящим ядром на Node.js, веб-интерфейсом, CLI и без единой зависимости.

*A Cloudflare WARP config generator for AmneziaWG / WireGuard with a real
backend core, a web UI and a CLI. Zero npm dependencies.*

---

## Что это умеет

| Возможность | Как это сделано |
| --- | --- |
| Регистрация устройства в Cloudflare | Настоящие запросы к `api.cloudflareclient.com/v0a2158` |
| Ключи X25519 | `node:crypto`, без сторонних библиотек |
| Активация WARP+ по лицензии | `PUT /reg/:id/account` |
| Выбор локации | Реальное измерение: probe `/cdn-cgi/trace` → IATA-код дата-центра + RTT |
| Обфускация AmneziaWG | 7 профилей, разделённых по совместимости, + ручной режим с валидацией |
| Совместимость с WARP | Профили `warp-*` физически не выдают `S1`/`S2`/`H1`–`H4`, ломающие handshake |
| AmneziaWG 1.5 (mimicry) | Шаблоны `I1..I5` под TLS / QUIC / DTLS / STUN / DNS / RTP / OpenVPN |
| Подставной домен (SNI) | `github.com`, `vk.com`, `yandex.ru`, свой — попадает в реальные байты пакета |
| Интерфейс | Русский и английский, переключение на лету, русский по умолчанию |
| Расчёт MTU | Честная арифметика оверхеда, а не «на глаз» |
| Воспроизводимость | `--seed` — одинаковый seed даёт одинаковый конфиг |
| Форматы вывода | `.conf` AmneziaWG, `.conf` WireGuard, `.json` |

---

## Быстрый старт

Нужен только **Node.js ≥ 18.17**. Больше ничего ставить не надо — `node_modules` вообще нет.

```bash
git clone https://github.com/<your-name>/awg-warp-architect.git
cd awg-warp-architect
npm start
```

Открыть `http://localhost:8787`.

### CLI

```bash
# Сгенерировать конфиг со сбалансированной обфускацией
node bin/awg-warp.js generate --obfuscation warp-balanced --out warp.conf

# Найти ближайшие дата-центры Cloudflare (реальный замер)
node bin/awg-warp.js scan

# Привязаться к конкретному дата-центру
node bin/awg-warp.js generate --endpoint 188.114.98.7:2408 --detect-location

# Посмотреть параметры обфускации, ничего не регистрируя
node bin/awg-warp.js obfuscate --obfuscation awg-mimicry

# Повторить ровно тот же конфиг
node bin/awg-warp.js generate --seed cafebabe

# WARP+ по лицензии
node bin/awg-warp.js generate --license XXXXXXXX-XXXXXXXX-XXXXXXXX
```

Без сети (демо-режим, ничего не отправляется наружу):

```bash
MOCK_WARP=1 npm start
MOCK_WARP=1 node test/smoke.mjs
```

---

## Честно про выбор локации

Это главное, о чём молчат почти все генераторы.

Cloudflare WARP работает на **anycast**. Один и тот же IP-адрес объявлен
одновременно в сотнях дата-центров мира. Куда именно придёт ваш трафик,
решает BGP-маршрутизация вашего провайдера, **а не строчка в конфиге**.

Поэтому:

* **Нельзя** написать в конфиге «хочу Нидерланды» и получить Нидерланды.
  Генераторы с выпадашкой стран вам врут.
* **Можно** перебрать разные префиксы и порты и измерить, куда вы фактически
  попадаете. Разные префиксы часто уходят в разные дата-центры.
* Кнопка **Scan datacenters** в интерфейсе (`awg-warp scan` в CLI) именно это
  и делает: стучится в `/cdn-cgi/trace` через каждый кандидат-IP, читает
  поле `colo=` и показывает реальный город и RTT. Дальше вы выбираете лучший.
* Если нужна **гарантированная** страна — нужен WARP+ / Zero Trust с dedicated
  egress либо свой собственный сервер AmneziaWG. Никакой генератор этого
  обойти не может.

Интерфейс говорит об этом прямо, а не обещает невозможного.

---

## ⚠️ Главное: WARP — это обычный WireGuard

Серверы Cloudflare WARP работают на **стоковом WireGuard**, а не на AmneziaWG.
Они ничего не знают про расширения Amnezia. Отсюда железное правило:

| Параметр | С Cloudflare WARP | Почему |
| --- | --- | --- |
| `Jc` / `Jmin` / `Jmax` | ✅ **работает** | Мусор летит отдельными UDP-датаграммами. Cloudflare их не может разобрать, молча отбрасывает — и настоящий handshake проходит. |
| `S1` / `S2` | ❌ **ломает** | Добивка вставляется **внутрь** пакетов handshake. Cloudflare читает нулевой байт как тип сообщения, видит мусор и дропает. |
| `H1`–`H4` | ❌ **ломает** | Cloudflare ждёт типы пакетов ровно 1/2/3/4. |
| `I1`–`I5`, `J1`–`J3` | ❌ **ломает** | Фейковые пакеты AWG 1.5 сервер не понимает. |

Именно поэтому конфиги с полной обфускацией **импортируются без ошибок,
показывают «Подключение», но никогда не соединяются**. Ошибки нет — сервер
просто молча выбрасывает handshake.

Генератор больше не даёт наступить на эти грабли: для WARP он физически не
выдаёт `S1`/`S2`/`H1`–`H4`, а при выборе профиля для своего сервера пишет
предупреждение прямо в шапку `.conf` и в интерфейсе.

**Единственное исключение** — `--client-id-headers`. Первые 4 байта пакета
WireGuard это `тип:u8` + `reserved:u8[3]`, а AmneziaWG читает их как одно
число little-endian. Cloudflare хранит в reserved свой `client_id`, поэтому
`H(n) = n + r0·2⁸ + r1·2¹⁶ + r2·2²⁴` оставляет младший байт равным настоящему
типу пакета (сервер доволен), но заголовок перестаёт быть константой
01/02/03/04, по которой его ловит DPI.

---

## Профили обфускации

### Для Cloudflare WARP — работают «из коробки»

| Профиль | Для чего |
| --- | --- |
| `off` | Чистый WireGuard. Максимальная скорость, нулевая маскировка. |
| `warp-light` | Немного мусорных пакетов. Почти нулевая цена по трафику. |
| `warp-balanced` | **По умолчанию.** Баланс скрытности и скорости. |
| `warp-heavy` | Максимум мусора для жёсткого DPI. Дороже по трафику. |

### Для своего сервера AmneziaWG — с Cloudflare НЕ соединятся

| Профиль | Для чего |
| --- | --- |
| `awg-standard` | Полная обфускация: мусор + добивка + магические заголовки. |
| `awg-paranoid` | Агрессивная маскировка для самого жёсткого DPI. |
| `awg-mimicry` | AmneziaWG 1.5: туннель начинается как TLS / QUIC / DNS и т.д. |

### Мимикрия под протокол и подставной домен

Профиль `awg-mimicry` умеет притворяться реальным протоколом, причём с
настоящим доменом внутри пакета:

| Сигнатура | Что имитирует | Использует домен |
| --- | --- | --- |
| `tls` | TLS 1.3 ClientHello (HTTPS) | ✅ SNI |
| `quic` | QUIC Initial (HTTP/3) | ✅ SNI |
| `dns` | DNS-запрос | ✅ QNAME |
| `dtls` | DTLS (WebRTC) | — |
| `stun` | STUN (WebRTC) | — |
| `rtp` | RTP (видеозвонок) | — |
| `openvpn` | OpenVPN | — |

Домен выбирается из списка (`github.com`, `vk.com`, `yandex.ru`,
`www.google.com`, `telegram.org`, `discord.com`, `www.youtube.com`,
`www.cloudflare.com`) или вписывается свой. TLS ClientHello собирается
**побайтово корректным**, с честно посчитанными длинами — DPI видит обычное
обращение к github.com.

```bash
awg-warp generate --obfuscation awg-mimicry \
  --signatures tls,quic --mimicry-domain github.com --out home.conf
```

### Что означают параметры

* **`Jc`** — сколько мусорных пакетов слать перед handshake.
* **`Jmin` / `Jmax`** — диапазон размера этих пакетов. Требование: `Jmin < Jmax`.
* **`S1` / `S2`** — добивка init- и response-пакетов handshake.
  Жёсткое ограничение протокола: **`S1 + 56 ≠ S2`**. Иначе init становится
  байт-в-байт неотличим от response (148 − 92 = 56) и туннель не поднимется.
* **`H1`–`H4`** — «магические» заголовки, заменяющие штатные типы пакетов
  WireGuard 1–4. Должны быть **четырьмя разными** числами в диапазоне
  `5 … 2147483647`.
* **`I1`–`I5`, `J1`–`J3`, `Itime`** — только AmneziaWG 1.5: шаблоны пакетов
  для мимикрии под другие протоколы.

**Все узлы туннеля обязаны иметь одинаковые значения.** Поэтому есть `--seed`:
один и тот же seed на разных машинах даст идентичные параметры.

Любое ручное значение проверяется на лету — интерфейс не даст сохранить
конфиг, который не запустится.

---

## Про MTU

Оверхед WireGuard считается так:

```
IP-заголовок  20 (IPv4) / 40 (IPv6)
UDP-заголовок  8
WG transport  16
Poly1305 tag  16
------------------
итого         60 (IPv4) / 80 (IPv6)
```

При обычном Ethernet-пути 1500: `1500 − 60 = 1440`.
По умолчанию ставится **1280** — ровно столько использует официальный клиент
WARP, это значение не фрагментируется практически нигде.

**AmneziaWG не добавляет оверхеда к MTU**: `H1`–`H4` заменяют уже существующее
4-байтовое поле типа, junk-пакеты — это отдельные пакеты, а `S1`/`S2`
падят только два пакета handshake.

---

## HTTP API

Сервер — чистый `node:http`, без фреймворков.

| Метод | Путь | Назначение |
| --- | --- | --- |
| `GET` | `/api/health` | Статус, версия, режим mock |
| `GET` | `/api/options` | Все справочники для интерфейса |
| `POST` | `/api/obfuscation` | Сгенерировать параметры по профилю |
| `POST` | `/api/validate` | Проверить ручные параметры |
| `POST` | `/api/mtu` | Посчитать MTU |
| `POST` | `/api/scan` | Просканировать дата-центры |
| `POST` | `/api/probe` | Определить colo конкретного IP |
| `POST` | `/api/generate` | Полный цикл: регистрация + конфиг |

Пример:

```bash
curl -s localhost:8787/api/generate \
  -H 'Content-Type: application/json' \
  -d '{"obfuscation":"balanced","pathMtu":1500}' | jq -r .configs.amneziawg.content
```

Токен устройства Cloudflare **никогда** не отдаётся в браузер: им можно удалить
регистрацию, поэтому он вырезается из ответа `/api/generate`.

### Переменные окружения

| Переменная | По умолчанию | Что делает |
| --- | --- | --- |
| `PORT` | `8787` | Порт |
| `HOST` | `0.0.0.0` | Интерфейс |
| `MOCK_WARP` | — | `1` — работать без сети, на синтетических данных |
| `CORS_ORIGIN` | — | Разрешённый origin для CORS |
| `RATE_MAX_GENERATE` | `10` | Лимит генераций в минуту с одного IP |
| `RATE_MAX_OTHER` | `60` | Лимит прочих запросов в минуту |

---

## Деплой

### ⚠️ GitHub Pages не подойдёт

GitHub Pages отдаёт только статику, а браузер **физически не может** сам
сходить в `api.cloudflareclient.com`: там нет CORS-заголовков, запрос упадёт.
Поэтому бэкенд обязателен — именно этого не хватало в чисто-HTML варианте.

### Docker

```bash
docker compose up -d
# или
docker build -t awg-warp-architect .
docker run -p 8787:8787 awg-warp-architect
```

### VPS (systemd)

```ini
[Unit]
Description=AWG WARP Architect
After=network.target

[Service]
WorkingDirectory=/opt/awg-warp-architect
ExecStart=/usr/bin/node src/server.js
Environment=PORT=8787
Restart=always
User=www-data

[Install]
WantedBy=multi-user.target
```

### Vercel / serverless

В репозитории есть `vercel.json` и `api/index.js` — достаточно импортировать
репозиторий в Vercel. Оговорка: сканирование локаций в serverless покажет
дата-центр, ближайший **к серверу Vercel**, а не к вам. Для честного замера
лучше self-hosted.

---

## Структура

```
src/core/keys.js        X25519, кодирование ключей
src/core/rand.js        Детерминированный ГПСЧ (seed)
src/core/endpoints.js   Префиксы, порты, карта colo, сканер локаций
src/core/amnezia.js     Профили обфускации, валидация, объяснения
src/core/warp.js        Клиент Cloudflare WARP API
src/core/mtu.js         Расчёт MTU, пресеты AllowedIPs и DNS
src/core/render.js      Рендер .conf / .json
src/core/generate.js    Оркестратор
src/server.js           HTTP-сервер и API
api/index.js            Точка входа для serverless
bin/awg-warp.js         CLI
public/                 Веб-интерфейс (HTML + CSS + ванильный JS)
test/smoke.mjs          Тесты (работают офлайн)
```

---

## Тесты

```bash
npm run smoke
```

28 проверок: ключи, все профили обфускации, все запреты валидатора,
арифметика MTU, endpoint'ы, воспроизводимость по seed и полный пайплайн.

---

## Благодарности

Идеи и протокольные детали подсмотрены у
[ImMALWARE/bash-warp-generator](https://github.com/ImMALWARE/bash-warp-generator)
и [Vadim-Khristenko/AmneziaWG-Architect](https://github.com/Vadim-Khristenko/AmneziaWG-Architect).
Обфускация — проект [Amnezia VPN](https://github.com/amnezia-vpn/amneziawg-go).

## Лицензия

MIT
