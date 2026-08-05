/**
 * Frontend for AWG WARP Architect.
 *
 * The browser never talks to Cloudflare directly - it cannot, there is no CORS
 * on the WARP API. Everything real happens in the backend; this file is purely
 * presentation plus a live preview of obfuscation parameters.
 */

const $ = (id) => document.getElementById(id)

// ------------------------------------------------------------------- i18n

const I18N = {
	ru: {
		"brand.sub": "Сборщик конфигов WARP + AmneziaWG",
		"badge.mock": "Тестовый режим",
		"badge.connecting": "Подключение…",
		"badge.ready": "Сервер готов",
		"badge.down": "Сервер недоступен",
		"common.optional": "необязательно",
		"loc.title": "Локация",
		"loc.scan": "Сканировать дата-центры",
		"loc.scanning": "Сканирую",
		"loc.why": "Почему нет выпадающего списка стран",
		"loc.prefix": "Префикс endpoint",
		"loc.port": "UDP-порт",
		"loc.pin": "Закрепить точный endpoint",
		"loc.pinHint": "Переопределяет префикс и порт выше.",
		"loc.measure": "Измерить реальный дата-центр выхода после генерации",
		"loc.measureHint": "Добавляет около секунды, зато показывает, где вы реально выходите.",
		"prefix.auto": "Автоматически (случайный IPv4-префикс)",
		"prefix.autoHint": "Префикс выбирается случайно.",
		"port.auto": "Автоматически (случайный рабочий порт)",
		"port.hint": "Смена порта помогает против блокировок по порту.",
		"scan.probing": "Проверяю endpoint'ы Cloudflare и их реальные дата-центры…",
		"scan.none": "Ни один endpoint не ответил из {n}. Возможно, Cloudflare заблокирован с этого сервера.",
		"scan.found": "Доступно дата-центров: {n} из {total} проверок. Нажмите, чтобы закрепить.",
		"scan.unknown": "Неизвестный центр {colo}",
		"scan.pinned": "Закреплён {ep} ({city})",
		"scan.single":
			"Все {answered} ответивших endpoint'ов пришли из одного дата-центра ({colo}). Это нормальный результат: anycast с одной точки всегда ведёт в ближайший колокейшн.",
		"scan.failed": "Не ответили: {failed} (таймаут или блокировка).",
		"viewer.checking": "Определяю ваш дата-центр прямо из браузера…",
		"viewer.ok":
			"Ваш браузер выходит через {colo} — {city}, {country}. Вот в какой дата-центр вас направляет ваш провайдер; именно это число имеет значение, а не результат скана с сервера.",
		"viewer.fail":
			"Не удалось определить ваш дата-центр из браузера: запрос к Cloudflare заблокирован или нет сети.",
		"srv.hosted":
			"Сканирование выполняется на сервере{region}, поэтому оно измеряет дата-центр хостинга, а не ваш. Для своих цифр запустите генератор локально: npm start.",
		"obf.title": "Обфускация",
		"obf.reroll": "Перегенерировать",
		"obf.params": "Сгенерированные параметры",
		"obf.plain": "чистый WireGuard",
		"obf.manual": "Править параметры вручную",
		"obf.manualWarn": "У всех пиров значения должны совпадать. Ограничения проверяются на лету: Jmin < Jmax, S1 + 56 ≠ S2, и H1–H4 должны различаться.",
		"obf.valid": "Параметры корректны.",
		"obf.seed": "Seed",
		"obf.seedOpt": "воспроизводит профиль",
		"obf.seedPh": "оставьте пустым для нового",
		"obf.seedHint": "Вставьте прошлый seed, чтобы получить точно такую же обфускацию на другом устройстве.",
		"mim.title": "Под какой протокол маскироваться",
		"mim.intro": "Первые пакеты туннеля будут выглядеть как выбранный протокол. Выберите до пяти.",
		"mim.domain": "Домен для подстановки (SNI)",
		"mim.custom": "Свой домен",
		"mim.customHint": "Перебивает выбор слева.",
		"mim.domainUsed": "Домен попадёт в сами байты пакета — DPI увидит обращение к нему.",
		"mim.domainUnused": "Выбранные протоколы не используют домен.",
		"mim.needOne": "Выберите хотя бы один протокол.",
		"net.title": "Сеть",
		"net.routing": "Маршрутизация",
		"net.mtu": "MTU канала",
		"net.keepalive": "Keepalive (секунды)",
		"net.keepaliveHint": "0 отключает. 25 держит NAT открытым на мобильном.",
		"net.ipv6": "Включить IPv6",
		"net.ipv6Hint": "Выключите, если у провайдера IPv6 сломан или течёт.",
		"net.psk": "Добавить pre-shared key",
		"net.pskHint": "Дополнительный симметричный слой. Для WARP необязателен.",
		"mtu.default": "Безопасное значение (MTU 1280)",
		"mtu.defaultHint": "MTU 1280 — то же, что у официального клиента WARP. Никогда не фрагментируется.",
		"mtu.tunnel": "MTU туннеля {mtu} ({path} минус {overhead} байт накладных).",
		"id.title": "Идентичность",
		"id.privateKey": "Существующий приватный ключ",
		"id.privateKeyPh": "base64, 44 символа",
		"id.privateKeyHint": "Переиспользуйте ключ, чтобы пересобрать конфиг, не меняя идентичность.",
		"id.license": "Лицензия WARP+",
		"action.generate": "Сгенерировать конфиг",
		"action.hint": "Регистрирует новое устройство в Cloudflare и собирает конфиг. Ключи не покидают память сервера.",
		"action.registering": "Регистрация в Cloudflare",
		"out.empty": "Конфига пока нет",
		"out.emptyHint": "Выберите настройки и нажмите «Сгенерировать конфиг».",
		"out.copy": "Копировать",
		"out.download": "Скачать",
		"out.result": "Результат",
		"out.copied": "Скопировано в буфер",
		"out.copyFail": "Буфер обмена заблокирован — выделите текст вручную",
		"out.downloaded": "Скачано {name}",
		"out.generated": "Конфиг создан",
		"sum.endpoint": "Endpoint",
		"sum.exit": "Точка выхода",
		"sum.exitUnknown": "не удалось измерить",
		"sum.address": "Адрес",
		"sum.mtu": "MTU",
		"sum.account": "Аккаунт",
		"sum.obf": "Обфускация",
		"sum.mimicry": "Маскировка",
		"sum.seed": "Seed",
		footer: "Самостоятельный хостинг. Конфиги создаются по запросу и не сохраняются на диск. Держите PrivateKey в секрете.",
	},
	en: {
		"brand.sub": "WARP + AmneziaWG config builder",
		"badge.mock": "Mock mode",
		"badge.connecting": "Connecting…",
		"badge.ready": "Server ready",
		"badge.down": "Server unreachable",
		"common.optional": "optional",
		"loc.title": "Location",
		"loc.scan": "Scan datacenters",
		"loc.scanning": "Scanning",
		"loc.why": "Why there is no country dropdown",
		"loc.prefix": "Endpoint prefix",
		"loc.port": "UDP port",
		"loc.pin": "Pin an exact endpoint",
		"loc.pinHint": "Overrides the prefix and port above.",
		"loc.measure": "Measure the real exit datacenter after generating",
		"loc.measureHint": "Adds about a second, tells you where you actually come out.",
		"prefix.auto": "Automatic (random IPv4 prefix)",
		"prefix.autoHint": "A prefix is chosen at random for you.",
		"port.auto": "Automatic (random known-good port)",
		"port.hint": "Rotating the port helps against port-based throttling.",
		"scan.probing": "Probing Cloudflare endpoints for their real datacenter…",
		"scan.none": "No endpoint answered out of {n}. Cloudflare may be blocked from this server.",
		"scan.found": "{n} datacenter(s) reachable, from {total} probes. Click one to pin it.",
		"scan.unknown": "Unknown colo {colo}",
		"scan.pinned": "Pinned {ep} ({city})",
		"scan.single":
			"All {answered} responding endpoints came from one datacenter ({colo}). That is the normal result: from a single vantage point anycast always lands in the nearest colo.",
		"scan.failed": "No answer from {failed} (timeout or blocked).",
		"viewer.checking": "Detecting your datacenter straight from the browser…",
		"viewer.ok":
			"Your browser exits through {colo} — {city}, {country}. That is the datacenter your ISP routes you to, and it is the number that matters, not the server-side scan.",
		"viewer.fail":
			"Could not detect your datacenter from the browser: the Cloudflare request was blocked or there is no network.",
		"srv.hosted":
			"The scan runs on the server{region}, so it measures the hosting datacenter, not yours. Run the generator locally for your own numbers: npm start.",
		"obf.title": "Obfuscation",
		"obf.reroll": "Re-roll values",
		"obf.params": "Generated parameters",
		"obf.plain": "plain WireGuard",
		"obf.manual": "Edit parameters by hand",
		"obf.manualWarn": "Every peer must use identical values. Constraints are enforced live: Jmin < Jmax, S1 + 56 ≠ S2, and H1–H4 must all differ.",
		"obf.valid": "Parameters are valid.",
		"obf.seed": "Seed",
		"obf.seedOpt": "reproduces a profile",
		"obf.seedPh": "leave empty for a new one",
		"obf.seedHint": "Paste a previous seed to rebuild the exact same obfuscation on another device.",
		"mim.title": "Which protocol to imitate",
		"mim.intro": "The first tunnel packets will look like the chosen protocol. Pick up to five.",
		"mim.domain": "Domain to imitate (SNI)",
		"mim.custom": "Custom domain",
		"mim.customHint": "Overrides the choice on the left.",
		"mim.domainUsed": "The domain goes into the actual packet bytes — DPI sees a request to it.",
		"mim.domainUnused": "The selected protocols do not use a domain.",
		"mim.needOne": "Pick at least one protocol.",
		"net.title": "Network",
		"net.routing": "Routing",
		"net.mtu": "Link MTU",
		"net.keepalive": "Keepalive (seconds)",
		"net.keepaliveHint": "0 disables. 25 keeps NAT open on mobile.",
		"net.ipv6": "Include IPv6",
		"net.ipv6Hint": "Turn off if your ISP's IPv6 is broken or leaks.",
		"net.psk": "Add a pre-shared key",
		"net.pskHint": "Extra symmetric layer. Optional for WARP.",
		"mtu.default": "Safe default (MTU 1280)",
		"mtu.defaultHint": "MTU 1280 — what the official WARP client uses. Never fragments.",
		"mtu.tunnel": "Tunnel MTU {mtu} ({path} minus {overhead} bytes overhead).",
		"id.title": "Identity",
		"id.privateKey": "Existing private key",
		"id.privateKeyPh": "base64, 44 characters",
		"id.privateKeyHint": "Reuse a key to regenerate a config without changing your identity.",
		"id.license": "WARP+ license",
		"action.generate": "Generate config",
		"action.hint": "Registers a fresh device with Cloudflare, then builds the config. Keys never leave this server's memory.",
		"action.registering": "Registering with Cloudflare",
		"out.empty": "No config yet",
		"out.emptyHint": "Pick your settings, then press Generate config.",
		"out.copy": "Copy",
		"out.download": "Download",
		"out.result": "Result",
		"out.copied": "Copied to clipboard",
		"out.copyFail": "Clipboard blocked — select the text manually",
		"out.downloaded": "Downloaded {name}",
		"out.generated": "Config generated",
		"sum.endpoint": "Endpoint",
		"sum.exit": "Exit",
		"sum.exitUnknown": "could not be measured",
		"sum.address": "Address",
		"sum.mtu": "MTU",
		"sum.account": "Account",
		"sum.obf": "Obfuscation",
		"sum.mimicry": "Mimicry",
		"sum.seed": "Seed",
		footer: "Self-hosted. Configs are generated on request and never stored on disk. Keep your PrivateKey secret.",
	},
}

const state = {
	lang: localStorage.getItem("awg-lang") || "ru",
	options: null,
	profile: "warp-balanced",
	signatures: [],
	mimicryDomain: "",
	obfuscation: null,
	overrides: {},
	result: null,
	tab: "amneziawg",
	busy: false,
	health: null,
	// undefined = not measured yet, null = measurement failed, object = colo meta
	viewerColo: undefined,
}

/** Translate a key, interpolating {placeholders}. */
function t(key, vars) {
	const dict = I18N[state.lang] || I18N.ru
	let text = dict[key] ?? I18N.ru[key] ?? key
	if (vars) {
		for (const [name, value] of Object.entries(vars)) {
			text = text.replaceAll(`{${name}}`, String(value))
		}
	}
	return text
}

/**
 * Prefer a Russian field from the API when the UI is in Russian.
 * `pickText(profile, "label")` reads `labelRu` first, then `label`.
 */
function pickText(object, field) {
	if (!object) return ""
	if (state.lang === "ru") {
		const ru = object[`${field}Ru`]
		if (ru) return ru
	}
	return object[field] ?? ""
}

const OVERRIDE_FIELDS = [
	{ key: "jc", label: "Jc" },
	{ key: "jmin", label: "Jmin" },
	{ key: "jmax", label: "Jmax" },
	{ key: "s1", label: "S1" },
	{ key: "s2", label: "S2" },
	{ key: "h1", label: "H1" },
	{ key: "h2", label: "H2" },
	{ key: "h3", label: "H3" },
	{ key: "h4", label: "H4" },
]

// ---------------------------------------------------------------- utilities

async function api(path, body) {
	const res = await fetch(path, {
		method: body ? "POST" : "GET",
		headers: body ? { "Content-Type": "application/json" } : undefined,
		body: body ? JSON.stringify(body) : undefined,
	})
	const data = await res.json().catch(() => ({ error: "Bad JSON from server" }))
	if (!res.ok) {
		const err = new Error(data.error || `HTTP ${res.status}`)
		err.hint = data.hint
		throw err
	}
	return data
}

let toastTimer
function toast(message, tone = "") {
	const el = $("toast")
	el.textContent = message
	el.hidden = false
	el.style.background = tone === "error" ? "var(--red)" : "var(--text)"
	el.style.color = tone === "error" ? "#fff" : "var(--canvas)"
	clearTimeout(toastTimer)
	toastTimer = setTimeout(() => {
		el.hidden = true
	}, 3200)
}

function setBusy(button, busy, label) {
	button.disabled = busy
	if (busy) {
		button.dataset.label = button.textContent
		button.innerHTML = `<span class="spinner"></span>${label}`
	} else if (button.dataset.label) {
		button.textContent = button.dataset.label
	}
}

function el(tag, className, text) {
	const node = document.createElement(tag)
	if (className) node.className = className
	if (text !== undefined) node.textContent = text
	return node
}

// --------------------------------------------------------------- language

function applyStaticI18n() {
	document.documentElement.lang = state.lang
	for (const node of document.querySelectorAll("[data-i18n]")) {
		node.textContent = t(node.dataset.i18n)
	}
	for (const node of document.querySelectorAll("[data-i18n-ph]")) {
		node.placeholder = t(node.dataset.i18nPh)
	}
	$("langRu").classList.toggle("is-active", state.lang === "ru")
	$("langEn").classList.toggle("is-active", state.lang === "en")
	$("advancedWarn").textContent = t("obf.manualWarn")
}

/** Re-render everything that carries text coming from the API. */
function setLanguage(lang) {
	state.lang = lang
	localStorage.setItem("awg-lang", lang)
	applyStaticI18n()

	// These two are driven by measurements, not by options, so they must be
	// re-rendered even before the options request has landed.
	renderServerlessNote()
	renderViewerColo()

	const options = state.options
	if (!options) return

	const prefix = $("endpointPrefix").value
	const port = $("endpointPort").value
	const allowed = $("allowedIps").value
	const dns = $("dns").value
	const mtu = $("pathMtu").value

	renderLocality(options.locationReality)
	renderPrefixes(options.endpointPrefixes)
	renderPorts(options.endpointPorts, options.camouflagePorts)
	renderProfiles(options.obfuscationProfiles)
	renderSignatures(options.signatures)
	renderMimicryDomains(options.mimicryDomains)
	renderSelect($("allowedIps"), options.allowedIps, allowed)
	renderSelect($("dns"), options.dns, dns)
	renderPathMtu(options.pathMtuPresets)

	$("endpointPrefix").value = prefix
	$("endpointPort").value = port
	$("pathMtu").value = mtu

	updateAllowedHint()
	updateMtuHint()
	updateCompatNote()
	if (state.obfuscation) renderParams(state.obfuscation)
	if (state.result) renderSummary(state.result)
}

// --------------------------------------------------------------- bootstrap

async function init() {
	applyStaticI18n()
	try {
		const [options, health] = await Promise.all([
			api("/api/options"),
			api("/api/health"),
		])
		state.options = options
		state.profile = options.defaultProfile || state.profile
		state.mimicryDomain = options.defaultMimicryDomain || ""

		$("healthBadge").textContent = t("badge.ready")
		$("healthBadge").className = "pill pill--ok"
		$("mockBadge").hidden = !health.mock
		state.health = health
		renderServerlessNote()
		// Fire and forget: the browser measurement is the honest one, but it must
		// never block the rest of the UI from booting.
		detectViewerColo()

		renderLocality(options.locationReality)
		renderPrefixes(options.endpointPrefixes)
		renderPorts(options.endpointPorts, options.camouflagePorts)
		renderProfiles(options.obfuscationProfiles)
		renderSignatures(options.signatures)
		renderMimicryDomains(options.mimicryDomains)
		renderSelect($("allowedIps"), options.allowedIps, "full")
		renderSelect($("dns"), options.dns, "cloudflare")
		renderPathMtu(options.pathMtuPresets)
		renderOverrideFields()

		updateAllowedHint()
		updateCompatNote()
		await refreshObfuscation()
	} catch (error) {
		$("healthBadge").textContent = t("badge.down")
		$("healthBadge").className = "pill pill--err"
		toast(error.message, "error")
	}
}

function renderLocality(reality) {
	$("localitySummary").textContent = pickText(reality, "summary")
	const details = state.lang === "ru" && reality.detailsRu ? reality.detailsRu : reality.details
	$("localityDetails").replaceChildren(...details.map((d) => el("li", null, d)))
}

function renderPrefixes(prefixes) {
	const select = $("endpointPrefix")
	select.replaceChildren()
	select.append(new Option(t("prefix.auto"), ""))
	for (const p of prefixes) {
		const opt = new Option(`${p.cidr}${p.family === 6 ? "  (IPv6)" : ""}`, p.id)
		opt.dataset.note = pickText(p, "note")
		opt.dataset.family = String(p.family)
		select.append(opt)
	}
	select.onchange = () => {
		$("prefixHint").textContent = select.selectedOptions[0]?.dataset.note || t("prefix.autoHint")
	}
	$("prefixHint").textContent = t("prefix.autoHint")
}

function renderPorts(ports, camouflage) {
	const select = $("endpointPort")
	select.replaceChildren()
	select.append(new Option(t("port.auto"), ""))
	for (const port of ports) {
		const hint = camouflage[port]
		const opt = new Option(hint ? `${port}  -  ${hint.split(" (")[0]}` : String(port), String(port))
		if (hint) opt.dataset.note = hint
		select.append(opt)
	}
	select.onchange = () => {
		$("portHint").textContent = select.selectedOptions[0]?.dataset.note || t("port.hint")
	}
	$("portHint").textContent = t("port.hint")
}

// ---------------------------------------------------------------- profiles

function currentProfile() {
	return state.options?.obfuscationProfiles.find((p) => p.id === state.profile)
}

/**
 * Profiles are grouped by what they are compatible with, because mixing them
 * up is exactly what produces a config that imports fine and never connects.
 */
function renderProfiles(profiles) {
	const wrap = $("profiles")
	wrap.replaceChildren()

	const groups = state.options?.compat || []
	const order = groups.length ? groups : [{ id: "warp" }, { id: "awg" }]

	for (const group of order) {
		const inGroup = profiles.filter((p) => (p.compat || "warp") === group.id)
		if (!inGroup.length) continue

		if (group.label || group.labelRu) {
			wrap.append(el("div", "profiles__group", pickText(group, "label")))
		}

		for (const p of inGroup) {
			const label = el("label", "profile")
			if (p.id === state.profile) label.classList.add("is-active")

			const input = document.createElement("input")
			input.type = "radio"
			input.name = "obfProfile"
			input.value = p.id
			input.checked = p.id === state.profile

			const body = el("div", "profile__body")
			const name = el("div", "profile__name")
			name.append(el("span", null, pickText(p, "label")))
			if (p.version === "1.5") name.append(el("span", "tag", "AWG 1.5"))
			if (p.worksWithWarp === false) name.append(el("span", "tag tag--warn", "≠ WARP"))
			body.append(name, el("div", "profile__desc", pickText(p, "summary")))

			label.append(input, body)
			wrap.append(label)

			input.addEventListener("change", async () => {
				state.profile = p.id
				state.overrides = {}
				for (const node of wrap.querySelectorAll(".profile")) {
					node.classList.toggle("is-active", node.contains(input))
				}
				updateCompatNote()
				await refreshObfuscation()
			})
		}
	}
}

/** Warn loudly when the chosen profile cannot talk to Cloudflare. */
function updateCompatNote() {
	const profile = currentProfile()
	const note = $("compatNote")
	if (!profile) {
		note.hidden = true
		return
	}
	const group = state.options?.compat?.find((c) => c.id === (profile.compat || "warp"))
	const text = pickText(group, "note")
	note.hidden = !text
	$("compatNoteText").textContent = text
	note.classList.toggle("note--warn", profile.worksWithWarp === false)
	note.classList.toggle("note--info", profile.worksWithWarp !== false)
	updateMimicryVisibility()
}

// ---------------------------------------------------------------- mimicry

function renderSignatures(signatures) {
	const wrap = $("mimicrySignatures")
	if (!wrap || !signatures) return
	wrap.replaceChildren()

	for (const sig of signatures) {
		const label = el("label", "sig")
		const input = document.createElement("input")
		input.type = "checkbox"
		input.value = sig.id
		input.checked = state.signatures.includes(sig.id)

		const body = el("div", "sig__body")
		const head = el("div", "sig__name")
		head.append(el("span", null, pickText(sig, "label")))
		if (sig.usesDomain) head.append(el("span", "tag", "SNI"))
		body.append(head, el("div", "sig__desc", pickText(sig, "description")))

		label.append(input, body)
		wrap.append(label)

		input.addEventListener("change", async () => {
			const picked = [...wrap.querySelectorAll("input:checked")].map((i) => i.value)
			if (!picked.length) {
				input.checked = true
				toast(t("mim.needOne"), "error")
				return
			}
			state.signatures = picked.slice(0, 5)
			label.classList.toggle("is-active", input.checked)
			updateDomainHint()
			await refreshObfuscation()
		})
		label.classList.toggle("is-active", input.checked)
	}
}

function renderMimicryDomains(domains) {
	const select = $("mimicryDomain")
	if (!select || !domains) return
	select.replaceChildren()
	for (const domain of domains) {
		const id = typeof domain === "string" ? domain : domain.id
		const label = typeof domain === "string" ? domain : pickText(domain, "label") || domain.id
		select.append(new Option(label, id))
	}
	if (state.mimicryDomain) select.value = state.mimicryDomain
	select.onchange = async () => {
		state.mimicryDomain = select.value
		await refreshObfuscation()
	}
	updateDomainHint()
}

/** The mimicry block only makes sense for AmneziaWG 1.5 profiles. */
function updateMimicryVisibility() {
	const profile = currentProfile()
	const supportsMimicry = profile?.version === "1.5"
	$("mimicryWrap").hidden = !supportsMimicry
	if (supportsMimicry && !state.signatures.length) {
		state.signatures = state.obfuscation?.signatures?.map((s) => s.id) || ["tls", "quic"]
		renderSignatures(state.options?.signatures)
	}
	updateDomainHint()
}

function updateDomainHint() {
	const all = state.options?.signatures || []
	const usesDomain = state.signatures.some((id) => all.find((s) => s.id === id)?.usesDomain)
	$("mimicryDomain").disabled = !usesDomain
	$("mimicryDomainCustom").disabled = !usesDomain
	$("mimicryDomainHint").textContent = usesDomain ? t("mim.domainUsed") : t("mim.domainUnused")
}

function resolvedDomain() {
	return $("mimicryDomainCustom").value.trim() || $("mimicryDomain").value || undefined
}

// ----------------------------------------------------------------- fields

function renderSelect(select, items, defaultId) {
	select.replaceChildren()
	for (const item of items) {
		const opt = new Option(pickText(item, "label"), item.id)
		const note = pickText(item, "note")
		if (note) opt.dataset.note = note
		select.append(opt)
	}
	select.value = defaultId
}

function renderPathMtu(presets) {
	const select = $("pathMtu")
	select.replaceChildren()
	select.append(new Option(t("mtu.default"), ""))
	for (const p of presets) {
		select.append(new Option(pickText(p, "label"), String(p.pathMtu)))
	}
	select.onchange = updateMtuHint
	updateMtuHint()
}

async function updateMtuHint() {
	const raw = $("pathMtu").value
	if (!raw) {
		$("mtuHint").textContent = t("mtu.defaultHint")
		return
	}
	try {
		const info = await api("/api/mtu", { pathMtu: Number(raw), outerFamily: 4 })
		$("mtuHint").textContent = t("mtu.tunnel", {
			mtu: info.mtu,
			path: info.pathMtu,
			overhead: info.overhead,
		})
	} catch {
		$("mtuHint").textContent = ""
	}
}

function updateAllowedHint() {
	$("allowedHint").textContent = $("allowedIps").selectedOptions[0]?.dataset.note || ""
}

function renderOverrideFields() {
	const grid = $("overrideGrid")
	grid.replaceChildren()
	for (const field of OVERRIDE_FIELDS) {
		const label = el("label", "override")
		label.append(el("span", null, field.label))
		const input = document.createElement("input")
		input.type = "number"
		input.id = `ov_${field.key}`
		input.addEventListener("input", onOverrideInput)
		label.append(input)
		grid.append(label)
	}
}

// ------------------------------------------------------------- obfuscation

async function refreshObfuscation(seed) {
	try {
		const profile = currentProfile()
		const useMimicry = profile?.version === "1.5"
		const result = await api("/api/obfuscation", {
			profile: state.profile,
			seed: seed || $("seed").value.trim() || undefined,
			signatures: useMimicry && state.signatures.length ? state.signatures : undefined,
			mimicryDomain: useMimicry ? resolvedDomain() : undefined,
		})
		state.obfuscation = result
		renderParams(result)
		fillOverrides(result)
		renderValidation(result.validation)
	} catch (error) {
		toast(error.message, "error")
	}
}

function renderParams(obf) {
	const list = $("paramsList")
	const version = $("awgVersion")
	list.replaceChildren()

	if (!obf.enabled) {
		version.textContent = t("obf.plain")
		const row = el("div", "param__what", pickText(obf, "summary"))
		row.style.gridColumn = "1"
		list.append(row)
		$("advancedWrap").hidden = true
		return
	}

	$("advancedWrap").hidden = false
	version.textContent = `AmneziaWG ${obf.version}`

	for (const row of obf.explain) {
		const wrap = el("div", "param")
		wrap.append(el("dt", "param__key", row.key))
		wrap.append(el("dd", "param__val", String(row.value)))
		wrap.append(el("dd", "param__what", pickText(row, "what")))
		list.append(wrap)
	}
}

function fillOverrides(obf) {
	for (const field of OVERRIDE_FIELDS) {
		const input = $(`ov_${field.key}`)
		if (!input) continue
		input.value = obf.enabled ? (obf.params[field.key] ?? "") : ""
		input.disabled = !obf.enabled
		input.classList.remove("is-bad")
	}
}

let validateTimer
function onOverrideInput() {
	clearTimeout(validateTimer)
	validateTimer = setTimeout(async () => {
		const params = { enabled: true }
		for (const field of OVERRIDE_FIELDS) {
			const raw = $(`ov_${field.key}`).value
			params[field.key] = raw === "" ? null : Number(raw)
		}
		state.overrides = params
		try {
			const validation = await api("/api/validate", {
				params,
				compat: currentProfile()?.compat,
			})
			renderValidation(validation)
			highlightBadFields(validation.errors)
		} catch (error) {
			toast(error.message, "error")
		}
	}, 250)
}

function highlightBadFields(errors) {
	const text = errors.join(" ")
	for (const field of OVERRIDE_FIELDS) {
		const input = $(`ov_${field.key}`)
		const mentioned = new RegExp(`\\b${field.label}\\b`, "i").test(text)
		input.classList.toggle("is-bad", mentioned)
	}
}

function renderValidation(validation) {
	const wrap = $("validation")
	wrap.replaceChildren()
	if (!validation) return

	for (const error of validation.errors) {
		wrap.append(el("div", "msg msg--err", error))
	}
	for (const warning of validation.warnings) {
		wrap.append(el("div", "msg msg--warn", warning))
	}
	if (validation.valid && !validation.warnings.length) {
		wrap.append(el("div", "msg msg--ok", t("obf.valid")))
	}
}

// -------------------------------------------------------- vantage point

/**
 * Warn that a hosted deployment measures its own region, not the visitor's.
 * This is the whole reason a Vercel deployment keeps reporting one datacenter
 * on the other side of the planet.
 */
function renderServerlessNote() {
	const health = state.health
	if (!health?.serverless) {
		$("serverlessNote").hidden = true
		return
	}
	$("serverlessNote").hidden = false
	$("serverlessNoteText").textContent = t("srv.hosted", {
		region: health.region ? ` (${health.region})` : "",
	})
}

/**
 * Ask Cloudflare, from the visitor's own browser, which colo it lands in.
 * The server cannot answer this: it would only ever report its own routing.
 */
function renderViewerColo() {
	const note = $("viewerNote")
	const text = $("viewerColoText")
	const meta = state.viewerColo

	if (meta === undefined) {
		note.hidden = false
		text.textContent = t("viewer.checking")
		return
	}
	if (meta === null) {
		note.hidden = false
		text.textContent = t("viewer.fail")
		return
	}
	note.hidden = false
	text.textContent = t("viewer.ok", {
		colo: meta.colo,
		city: meta.city || meta.colo,
		country: meta.country || "?",
	})
}

async function detectViewerColo() {
	state.viewerColo = undefined
	renderViewerColo()

	try {
		const controller = new AbortController()
		const timer = setTimeout(() => controller.abort(), 6000)
		const response = await fetch("https://speed.cloudflare.com/meta", {
			signal: controller.signal,
			cache: "no-store",
		})
		clearTimeout(timer)
		if (!response.ok) throw new Error(`HTTP ${response.status}`)

		const meta = await response.json()
		if (!meta.colo) throw new Error("no colo")

		state.viewerColo = meta
	} catch {
		state.viewerColo = null
	}
	renderViewerColo()
}

// -------------------------------------------------------------------- scan

async function runScan() {
	const button = $("scanBtn")
	setBusy(button, true, t("loc.scanning"))
	$("scanPanel").hidden = false
	$("scanStatus").textContent = t("scan.probing")
	$("scanList").replaceChildren()

	try {
		const { scanned, byLocation, stats } = await api("/api/scan", {
			perPrefix: 4,
		})

		if (!byLocation.length) {
			$("scanStatus").textContent = t("scan.none", { n: scanned })
			return
		}

		// One datacenter is the expected outcome, so say so explicitly instead of
		// letting "1 of 14" read like a broken scan.
		const status = [t("scan.found", { n: byLocation.length, total: scanned })]
		if (stats?.singleColo) {
			status.push(
				t("scan.single", {
					answered: stats.answered,
					colo: byLocation[0].colo,
				}),
			)
		}
		if (stats?.failed) {
			status.push(t("scan.failed", { failed: stats.failed }))
		}
		$("scanStatus").textContent = status.join(" ")

		for (const loc of byLocation) {
			const best = loc.endpoints[0]
			const locBtn = el("button", "loc")
			locBtn.type = "button"
			locBtn.append(el("span", "loc__colo", loc.colo))
			locBtn.append(
				el(
					"span",
					"loc__name",
					loc.known ? `${loc.city}, ${loc.country}` : t("scan.unknown", { colo: loc.colo }),
				),
			)
			locBtn.append(el("span", "loc__rtt", `${loc.bestRttMs} ms`))
			locBtn.addEventListener("click", () => {
				const port = $("endpointPort").value || "2408"
				$("endpointHost").value = `${best.ip}:${port}`
				toast(t("scan.pinned", { ep: `${best.ip}:${port}`, city: loc.city }))
			})
			$("scanList").append(locBtn)
		}
	} catch (error) {
		$("scanStatus").textContent = error.message
	} finally {
		setBusy(button, false)
	}
}

// ---------------------------------------------------------------- generate

async function generate() {
	const button = $("generateBtn")
	if (state.busy) return
	state.busy = true
	setBusy(button, true, t("action.registering"))

	const hasOverrides =
		$("advancedWrap").open &&
		Object.keys(state.overrides).length > 0 &&
		OVERRIDE_FIELDS.every((f) => Number.isFinite(state.overrides[f.key]))

	const pathMtu = $("pathMtu").value
	const useMimicry = currentProfile()?.version === "1.5"

	try {
		const result = await api("/api/generate", {
			obfuscation: state.profile,
			obfuscationOverrides: hasOverrides ? state.overrides : undefined,
			signatures: useMimicry && state.signatures.length ? state.signatures : undefined,
			mimicryDomain: useMimicry ? resolvedDomain() : undefined,
			seed: $("seed").value.trim() || undefined,
			privateKey: $("privateKey").value.trim() || undefined,
			license: $("license").value.trim() || undefined,
			endpointPrefix: $("endpointPrefix").value || undefined,
			endpointPort: $("endpointPort").value ? Number($("endpointPort").value) : undefined,
			endpointHost: $("endpointHost").value.trim() || undefined,
			detectLocation: $("detectLocation").checked,
			allowedIps: $("allowedIps").value,
			dns: $("dns").value,
			pathMtu: pathMtu ? Number(pathMtu) : undefined,
			conservativeMtu: !pathMtu,
			keepalive: Number($("keepalive").value || 0),
			ipv6: $("ipv6").checked,
			presharedKey: $("presharedKey").checked,
		})

		state.result = result
		$("seed").value = result.meta.seed
		renderOutput()
		renderSummary(result)
		toast(t("out.generated"))
	} catch (error) {
		toast(error.hint ? `${error.message} - ${error.hint}` : error.message, "error")
	} finally {
		state.busy = false
		setBusy(button, false)
	}
}

/** Tiny syntax highlighter for the config preview. */
function highlight(text) {
	const escaped = text
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")

	return escaped
		.split("\n")
		.map((line) => {
			if (line.startsWith("#")) return `<span class="c-comment">${line}</span>`
			if (/^\[.+\]$/.test(line.trim())) return `<span class="c-section">${line}</span>`
			const match = line.match(/^([A-Za-z0-9]+)(\s*=\s*)(.*)$/)
			if (match) {
				return `<span class="c-key">${match[1]}</span>${match[2]}${match[3]}`
			}
			return line
		})
		.join("\n")
}

function renderOutput() {
	if (!state.result) return
	const config = state.result.configs[state.tab]

	$("emptyState").hidden = true
	$("configOut").hidden = false
	$("outputFoot").hidden = false
	$("configOut").querySelector("code").innerHTML = highlight(config.content)
	$("fileName").textContent = config.filename
}

function renderSummary(result) {
	const card = $("summaryCard")
	const list = $("summaryList")
	card.hidden = false
	list.replaceChildren()

	const obf = result.obfuscation
	const rows = [
		[t("sum.endpoint"), result.endpoint.endpoint],
		[t("sum.address"), result.network.addresses.join(", ")],
		[t("sum.mtu"), String(result.network.mtu)],
		[t("sum.account"), result.warp.accountType + (result.warp.warpPlus ? " (WARP+)" : "")],
		[t("sum.obf"), pickText(obf, "profileLabel")],
	]

	if (obf.signatures?.length) {
		const names = obf.signatures.map((s) => s.id.toUpperCase()).join(", ")
		rows.push([t("sum.mimicry"), obf.mimicryDomain ? `${names} → ${obf.mimicryDomain}` : names])
	}
	rows.push([t("sum.seed"), result.meta.seed])

	if (result.location?.measured) {
		rows.splice(1, 0, [
			t("sum.exit"),
			`${result.location.city}, ${result.location.country} (${result.location.colo}, ${result.location.rttMs} ms)`,
		])
	} else if (result.location && !result.location.measured) {
		rows.splice(1, 0, [t("sum.exit"), t("sum.exitUnknown")])
	}

	for (const [key, value] of rows) {
		list.append(el("dt", null, key))
		list.append(el("dd", null, value))
	}

	const warns = $("warnList")
	warns.replaceChildren()
	for (const warning of result.warnings || []) {
		warns.append(el("div", "msg msg--warn", warning))
	}
}

// ------------------------------------------------------------------ events

function wire() {
	$("langRu").addEventListener("click", () => setLanguage("ru"))
	$("langEn").addEventListener("click", () => setLanguage("en"))

	$("generateBtn").addEventListener("click", generate)
	$("scanBtn").addEventListener("click", runScan)

	$("rerollBtn").addEventListener("click", () => {
		$("seed").value = ""
		refreshObfuscation()
	})

	$("seed").addEventListener("change", () => refreshObfuscation())
	$("allowedIps").addEventListener("change", updateAllowedHint)
	$("mimicryDomainCustom").addEventListener("change", () => refreshObfuscation())

	for (const tab of document.querySelectorAll(".tab")) {
		tab.addEventListener("click", () => {
			for (const other of document.querySelectorAll(".tab")) {
				other.classList.toggle("is-active", other === tab)
			}
			state.tab = tab.dataset.tab
			renderOutput()
		})
	}

	$("copyBtn").addEventListener("click", async () => {
		if (!state.result) return
		const { content } = state.result.configs[state.tab]
		try {
			await navigator.clipboard.writeText(content)
			toast(t("out.copied"))
		} catch {
			toast(t("out.copyFail"), "error")
		}
	})

	$("downloadBtn").addEventListener("click", () => {
		if (!state.result) return
		const { content, filename } = state.result.configs[state.tab]
		const blob = new Blob([content], { type: "text/plain;charset=utf-8" })
		const url = URL.createObjectURL(blob)
		const a = document.createElement("a")
		a.href = url
		a.download = filename
		a.click()
		URL.revokeObjectURL(url)
		toast(t("out.downloaded", { name: filename }))
	})
}

wire()
init()
