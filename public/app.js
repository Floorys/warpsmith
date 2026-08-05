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
		"net.routing": "��аршрутизация",
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
		afterParams()
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
		afterGenerate(result)
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

// ==========================================================================
// Sectioned shell: navigation, FAQ and history.
//
// This block is appended after wire()/init() on purpose. Everything here is
// additive: it never rewrites the generator logic above, it only reads the
// state that logic already produces.
// ==========================================================================

const EXTRA_I18N = {
	ru: {
		"nav.gen": "Генератор",
		"nav.params": "Разбор параметров",
		"nav.sim": "Симулятор пакетов",
		"nav.hist": "История",
		"nav.faq": "FAQ",
		"side.note": "Ключи создаются на сервере по запросу и не пишутся на диск.",
		"hero.title": "Чертёж конфига, а не кнопка «сгенерировать»",
		"hero.lead":
			"Каждое число в конфиге можно раскрыть: откуда взята граница, кто его читает и что сломается, если стороны разойдутся.",
		"hero.warpTag": "работает с WARP",
		"hero.warpDesc":
			"Это обычный WireGuard. Допустим только junk-мусор Jc/Jmin/Jmax.",
		"hero.awgTag": "только свой сервер",
		"hero.awgDesc":
			"S1/S2, H1–H4 и мимикрия под протокол. WARP такое рукопожатие отвергнет.",
		"obf.explain": "Разобрать каждое число →",
		"pdoc.title": "Разбор параметров",
		"pdoc.lead":
			"У каждого параметра: значение, кто его читает, откуда взята граница и что произойдёт, если на сервере он окажется другим.",
		"pdoc.tagGen": "сгенерирован",
		"pdoc.tagMan": "задан вручную",
		"pdoc.tagOff": "выключен намеренно",
		"pdoc.empty": "Параметры появятся, как только загрузится профиль обфускации.",
		"pdoc.who": "Кто читает",
		"pdoc.bound": "Откуда граница",
		"pdoc.break": "Если разойдётся",
		"sim.title": "Симулятор пакетов",
		"sim.lead":
			"Как выглядит начало сессии в проводе: сначала мусорные пакеты, потом настоящее рукопожатие, потом данные.",
		"sim.wire": "Поток на проводе",
		"sim.junk": "junk-мусор",
		"sim.init": "handshake initiation",
		"sim.resp": "handshake response",
		"sim.data": "данные",
		"sim.fp": "Отпечаток, от которого уходим",
		"sim.fpHint":
			"Чистый WireGuard: 148 байт, затем 92. Две фиксированные величины подряд — этого достаточно, чтобы опознать протокол по первым двум пакетам.",
		"sim.noteJunk":
			"Перед рукопожатием уходит {jc} мусорных пакетов по {jmin}–{jmax} байт. Для стороннего наблюдателя размеры перестают быть предсказуемыми, а WARP их молча отбрасывает: это отдельные UDP-датаграммы, а не часть рукопожатия.",
		"sim.noteNoJunk":
			"Junk-пакеты выключены (Jc = 0), поэтому первым же пакетом уходит рукопожатие фиксированного размера — ровно тот отпечаток, который видно ниже.",
		"sim.notePad":
			" Паддинг S1/S2 добавляет {s1} и {s2} байт внутрь самих пакетов рукопожатия, поэтому 148 и 92 превращаются в {i} и {r}.",
		"sim.bytes": "байт",
		"hist.title": "История",
		"hist.lead":
			"Seed каждой генерации хранится в этом браузере. По seed конфиг воспроизводится побайтово — приватные ключи здесь не сохраняются.",
		"hist.saved": "Сохранённые сборки",
		"hist.export": "Экспорт в файл",
		"hist.clear": "Очистить",
		"hist.empty": "Пока пусто. Сгенерируйте конфиг — сюда попадёт его seed.",
		"hist.restore": "Восстановить",
		"hist.restored": "Seed подставлен, параметры пересобраны",
		"hist.cleared": "История очищена",
		"hist.exported": "История сохранена в файл",
		"faq.title": "FAQ",
		"faq.lead": "Ответы на то, из-за чего конфиг обычно не поднимается.",
	},
	en: {
		"nav.gen": "Generator",
		"nav.params": "Parameter breakdown",
		"nav.sim": "Packet simulator",
		"nav.hist": "History",
		"nav.faq": "FAQ",
		"side.note": "Keys are created on the server per request and never written to disk.",
		"hero.title": "A blueprint, not a generate button",
		"hero.lead":
			"Every number in the config can be unfolded: where its bound comes from, which side reads it, and what breaks if the two sides disagree.",
		"hero.warpTag": "works with WARP",
		"hero.warpDesc":
			"It is plain WireGuard. Only junk packets Jc/Jmin/Jmax are allowed.",
		"hero.awgTag": "your own server only",
		"hero.awgDesc":
			"S1/S2, H1–H4 and protocol mimicry. WARP rejects that handshake.",
		"obf.explain": "Explain every number →",
		"pdoc.title": "Parameter breakdown",
		"pdoc.lead":
			"For every parameter: the value, which side reads it, where its bound comes from, and what happens if the server has a different one.",
		"pdoc.tagGen": "generated",
		"pdoc.tagMan": "set by hand",
		"pdoc.tagOff": "deliberately off",
		"pdoc.empty": "Parameters appear as soon as the obfuscation profile loads.",
		"pdoc.who": "Read by",
		"pdoc.bound": "Bound comes from",
		"pdoc.break": "If the sides disagree",
		"sim.title": "Packet simulator",
		"sim.lead":
			"What the start of a session looks like on the wire: junk packets first, then the real handshake, then data.",
		"sim.wire": "Traffic on the wire",
		"sim.junk": "junk packets",
		"sim.init": "handshake initiation",
		"sim.resp": "handshake response",
		"sim.data": "data",
		"sim.fp": "The fingerprint we are escaping",
		"sim.fpHint":
			"Plain WireGuard: 148 bytes, then 92. Two fixed sizes in a row are enough to identify the protocol from the first two packets.",
		"sim.noteJunk":
			"{jc} junk packets of {jmin}–{jmax} bytes go out before the handshake. Sizes stop being predictable for an observer, and WARP drops them silently: they are separate UDP datagrams, not part of the handshake.",
		"sim.noteNoJunk":
			"Junk packets are off (Jc = 0), so the very first packet is a fixed-size handshake — exactly the fingerprint shown below.",
		"sim.notePad":
			" S1/S2 padding adds {s1} and {s2} bytes inside the handshake packets themselves, so 148 and 92 become {i} and {r}.",
		"sim.bytes": "bytes",
		"hist.title": "History",
		"hist.lead":
			"The seed of every build is kept in this browser. A seed reproduces the config byte for byte — private keys are never stored here.",
		"hist.saved": "Saved builds",
		"hist.export": "Export to file",
		"hist.clear": "Clear",
		"hist.empty": "Empty so far. Generate a config and its seed lands here.",
		"hist.restore": "Restore",
		"hist.restored": "Seed applied, parameters rebuilt",
		"hist.cleared": "History cleared",
		"hist.exported": "History saved to a file",
		"faq.title": "FAQ",
		"faq.lead": "Answers to the things that usually keep a config from connecting.",
	},
}

Object.assign(I18N.ru, EXTRA_I18N.ru)
Object.assign(I18N.en, EXTRA_I18N.en)

// ------------------------------------------------------------------ router

const VIEWS = ["gen", "params", "sim", "hist", "faq"]

function showView(name) {
	const target = VIEWS.includes(name) ? name : "gen"
	for (const view of VIEWS) {
		const node = $("view-" + view)
		if (!node) continue
		node.hidden = view !== target
		node.classList.toggle("is-active", view === target)
	}
	for (const item of document.querySelectorAll(".nav__item")) {
		item.classList.toggle("is-active", item.dataset.view === target)
	}
	// Deep links keep a section shareable and survive a refresh.
	if (location.hash.slice(1) !== target) {
		history.replaceState(null, "", "#" + target)
	}
	window.scrollTo({ top: 0, behavior: "instant" })
}

// --------------------------------------------------------------------- FAQ

const FAQ = [
	{
		q: {
			ru: "Конфиг импортируется, но туннель не поднимается. Почему?",
			en: "The config imports fine but the tunnel never connects. Why?",
		},
		a: {
			ru: "Почти всегда потому, что в конфиге есть S1/S2 или H1–H4, а сервер — Cloudflare WARP. WARP работает на стоковом WireGuard: паддинг S1/S2 лежит внутри пакетов рукопожатия и меняет их длину, а H1–H4 подменяют байт типа сообщения, который сервер ждёт равным 1, 2, 3 или 4. Клиент такой конфиг примет, от��равит рукопожатие — и не получит ответа. Выбирайте профили warp-*: в них только junk-пакеты.",
			en: "Almost always because the config carries S1/S2 or H1–H4 while the server is Cloudflare WARP. WARP runs stock WireGuard: S1/S2 padding sits inside the handshake packets and changes their length, and H1–H4 replace the message type byte the server expects to be 1, 2, 3 or 4. The client accepts such a config, sends the handshake, and gets nothing back. Pick the warp-* profiles: they only use junk packets.",
		},
	},
	{
		q: {
			ru: "Почему junk-пакеты не ломают WARP, а S1/S2 ломают?",
			en: "Why do junk packets not break WARP while S1/S2 do?",
		},
		a: {
			ru: "Junk — это отдельные UDP-датаграммы со случайным содержимым, отправленные перед рукопожатием. Для сервера это мусор на порту: он не разбирает их как WireGuard и молча отбрасывает. S1/S2 же добавляют байты внутрь самого пакета рукопожатия, а его длина в WireGuard фиксирована — 148 байт у initiation и 92 у response. Пакет другой длины сервер не примет.",
			en: "Junk is separate UDP datagrams with random content sent before the handshake. To the server it is noise on the port: it never parses them as WireGuard and drops them silently. S1/S2 instead add bytes inside the handshake packet, and its length in WireGuard is fixed — 148 bytes for initiation, 92 for response. A packet of any other length is rejected.",
		},
	},
	{
		q: {
			ru: "Сканирование всегда находит один дата-центр. Это баг?",
			en: "The scan always finds a single datacenter. Is that a bug?",
		},
		a: {
			ru: "Нет, это как работает anycast. Cloudflare анонсирует одни и те же адреса из сотен дата-центров, и маршрут выбирает BGP, а не IP. Из одной точки все адреса ведут в один ближайший колокейшн, поэтому «1 из 14» — правильный ответ. Если сайт где-то захостен, точка эта — регион хостинга, а не ваш провайдер; свой настоящий колокейшн показывает браузерное измерение в блоке «Локация».",
			en: "No, that is how anycast works. Cloudflare announces the same addresses from hundreds of datacenters and BGP picks the route, not the IP. From a single vantage point every address leads to the same nearest colo, so \"1 of 14\" is the correct answer. If the site is hosted somewhere, that vantage point is the hosting region rather than your ISP; your own real colo is shown by the browser-side measurement in the Location card.",
		},
	},
	{
		q: { ru: "Можно ли выбрать страну выхода?", en: "Can I choose the exit country?" },
		a: {
			ru: "Обычным бесплатным WARP — нет, и ни один генератор этого не изменит: маршрут решает anycast. Влиять можно косвенно — сменой префикса и порта, потому что провайдеры маршрутизируют разные префиксы по-разному. Гарантированный выбор страны даёт WARP+ / Zero Trust с выделенным egress либо свой сервер AmneziaWG в нужной стране.",
			en: "Not with plain free WARP, and no generator can change that: anycast decides the route. You can influence it indirectly by changing the prefix and port, because ISPs route different prefixes differently. A guaranteed country requires WARP+ / Zero Trust with dedicated egress, or your own AmneziaWG server there.",
		},
	},
	{
		q: { ru: "Зачем seed?", en: "What is the seed for?" },
		a: {
			ru: "Обфускация обязана совпадать на обеих сторонах. Seed делает набор параметров воспроизводимым: вставьте тот же seed на другом устройстве или на сервере — получите те же Jc, Jmin, Jmax, S1, S2 и заголовки. Без него каждая генерация даёт новый набор, и стороны разойдутся.",
			en: "Obfuscation has to match on both sides. The seed makes the parameter set reproducible: paste the same seed on another device or on the server and you get the same Jc, Jmin, Jmax, S1, S2 and headers. Without it every run produces a new set and the sides drift apart.",
		},
	},
	{
		q: { ru: "Почему MTU 1280, а не 1420?", en: "Why is the MTU 1280 and not 1420?" },
		a: {
			ru: "1280 — значение по умолчанию у самого WARP и минимальный MTU, обязательный для IPv6, поэтому он безопасен в любой сети. Накладные расходы WireGuard: 20 байт IPv4 (40 для IPv6) + 8 UDP + 16 заголовок transport + 16 Poly1305, то есть 60 или 80. От 1500 остаётся 1440 в идеальной сети, но мобильные и PPPoE-каналы часто меньше. AmneziaWG сверху ничего не добавляет: junk уходит отдельными пакетами.",
			en: "1280 is WARP's own default and the minimum MTU required for IPv6, so it is safe on any network. WireGuard overhead is 20 bytes IPv4 (40 for IPv6) + 8 UDP + 16 transport header + 16 Poly1305, i.e. 60 or 80. That leaves 1440 out of 1500 on a perfect link, but mobile and PPPoE paths are often smaller. AmneziaWG adds nothing on top: junk goes out as separate packets.",
		},
	},
	{
		q: {
			ru: "Что делает мимикрия под протокол и почему только со своим сервером?",
			en: "What does protocol mimicry do and why only with your own server?",
		},
		a: {
			ru: "Мимикрия заставляет первые пакеты выглядеть как TLS ClientHello, QUIC Initial или DNS-запрос — вплоть до подставного домена в SNI. Это возможности AmneziaWG 1.5+, и их обязан понимать сервер. WARP о них не знает, поэтому такие профили помечены «≠ WARP» и годятся только для вашего собственного сервера AmneziaWG.",
			en: "Mimicry makes the first packets look like a TLS ClientHello, a QUIC Initial or a DNS query, down to a fake domain in the SNI. These are AmneziaWG 1.5+ features and the server has to understand them. WARP does not, which is why those profiles are marked \"≠ WARP\" and only fit your own AmneziaWG server.",
		},
	},
	{
		q: {
			ru: "H1–H4 можно использовать с WARP хоть как-нибудь?",
			en: "Can H1–H4 be used with WARP at all?",
		},
		a: {
			ru: "Только в одном частном случае: если вывести их из client id вашей регистрации WARP по формуле H(n) = n + r0·2⁸ + r1·2¹⁶ + r2·2²⁴, где r — три байта reserved. Тогда старший байт остаётся равным номеру типа сообщения, и сервер по-прежнему видит 1, 2, 3, 4. Это включается флагом --client-id-headers и по умолчанию выключено, потому что случайные H1–H4 туннель гарантированно ломают.",
			en: "Only in one special case: derive them from your WARP registration's client id as H(n) = n + r0·2⁸ + r1·2¹⁶ + r2·2²⁴, where r is the three reserved bytes. The low byte then still equals the message type, so the server keeps seeing 1, 2, 3, 4. This is enabled with --client-id-headers and off by default, because random H1–H4 break the tunnel for certain.",
		},
	},
]

function renderFaq() {
	const host = $("faqList")
	if (!host) return
	const lang = state.lang === "en" ? "en" : "ru"
	host.replaceChildren(
		...FAQ.map((item) => {
			const details = document.createElement("details")
			details.className = "faq__item"
			const summary = document.createElement("summary")
			summary.textContent = item.q[lang]
			details.append(summary, el("p", null, item.a[lang]))
			return details
		}),
	)
}

// ----------------------------------------------------------------- history

const HIST_KEY = "awg-history"
const HIST_LIMIT = 20

function readHistory() {
	try {
		const parsed = JSON.parse(localStorage.getItem(HIST_KEY) || "[]")
		return Array.isArray(parsed) ? parsed : []
	} catch {
		return []
	}
}

function writeHistory(entries) {
	try {
		localStorage.setItem(HIST_KEY, JSON.stringify(entries.slice(0, HIST_LIMIT)))
	} catch {
		// Private mode or a full quota: history is a convenience, never a blocker.
	}
}

/** Store only what a seed needs to be reproducible. Never key material. */
function pushHistory(result) {
	const obf = result.obfuscation || {}
	const entry = {
		ts: Date.now(),
		seed: result.meta?.seed || "",
		profile: obf.profileLabel || "",
		profileRu: obf.profileLabelRu || "",
		compat: obf.compat || "",
		endpoint: result.endpoint?.endpoint || "",
		mtu: result.network?.mtu || null,
		colo: result.location?.measured ? result.location.colo : "",
	}
	const entries = readHistory().filter((e) => e.seed !== entry.seed)
	entries.unshift(entry)
	writeHistory(entries)
	renderHistory()
}

function renderHistory() {
	const host = $("histList")
	if (!host) return
	const entries = readHistory()
	const count = $("navHistCount")
	if (count) count.textContent = entries.length ? String(entries.length) : ""

	if (!entries.length) {
		host.replaceChildren(el("p", "field__hint", t("hist.empty")))
		return
	}

	host.replaceChildren(
		...entries.map((entry) => {
			const row = el("div", "histrow")
			const label =
				state.lang === "ru" && entry.profileRu ? entry.profileRu : entry.profile

			const main = el("div", "histrow__main")
			main.append(el("code", "histrow__seed", entry.seed))
			main.append(el("span", "histrow__label", label))

			const meta = el("div", "histrow__meta")
			const bits = [new Date(entry.ts).toLocaleString()]
			if (entry.endpoint) bits.push(entry.endpoint)
			if (entry.colo) bits.push(entry.colo)
			if (entry.mtu) bits.push("MTU " + entry.mtu)
			meta.textContent = bits.join(" · ")

			const button = el("button", "btn btn--ghost btn--sm", t("hist.restore"))
			button.type = "button"
			button.addEventListener("click", () => {
				$("seed").value = entry.seed
				refreshObfuscation(entry.seed)
				showView("gen")
				toast(t("hist.restored"))
			})

			const left = el("div")
			left.append(main, meta)
			row.append(left, button)
			return row
		}),
	)
}

// ------------------------------------------------------- parameter breakdown

/**
 * Per-parameter provenance. The generator already explains *what* a number
 * does (obf.explain[].what); this adds the three things that actually decide
 * whether a tunnel comes up: who reads it, where its bound comes from, and
 * what breaks when the two sides disagree.
 */
const PARAM_DOCS = {
	jc: {
		who: { ru: "только отправитель", en: "sender only" },
		bound: { ru: "0–128, граница AmneziaWG", en: "0–128, AmneziaWG limit" },
		break: {
			ru: "Ничего. Серверу не нужно знать это число — он просто отбрасывает мусор. Поэтому junk безопасен для WARP.",
			en: "Nothing. The server never needs this number — it just drops the junk. That is why junk is safe with WARP.",
		},
	},
	jmin: {
		who: { ru: "только отправитель", en: "sender only" },
		bound: { ru: "8–1280, должно быть меньше Jmax", en: "8–1280, must stay below Jmax" },
		break: {
			ru: "Ничего на стороне сервера. Но Jmin = Jmax даёт мусор постоянного размера — тот же отпечаток, от которого уходим.",
			en: "Nothing server-side. But Jmin = Jmax produces constant-size junk — the very fingerprint we are trying to lose.",
		},
	},
	jmax: {
		who: { ru: "только отправитель", en: "sender only" },
		bound: {
			ru: "≤ 1280, чтобы мусор не фрагментировался",
			en: "≤ 1280 so junk never fragments",
		},
		break: {
			ru: "Сервер не заметит. Но если поставить больше MTU канала, мусорные пакеты начнут дробиться и станут заметнее обычного трафика.",
			en: "The server will not notice. But above the path MTU the junk starts fragmenting and stands out more than plain traffic.",
		},
	},
	s1: {
		who: { ru: "обе стороны", en: "both sides" },
		bound: { ru: "15–1280, и S1 + 56 ≠ S2", en: "15–1280, and S1 + 56 ≠ S2" },
		break: {
			ru: "Рукопожатие молча отбрасывается: пакет initiation пришёл не того размера. С WARP всегда должен быть 0. Ограничение S1 + 56 ≠ S2 нужно, чтобы initiation с паддингом не стал ровно размером с response.",
			en: "The handshake is dropped silently: the initiation packet arrived at the wrong size. With WARP it must always be 0. The S1 + 56 ≠ S2 rule keeps a padded initiation from becoming exactly the size of a response.",
		},
	},
	s2: {
		who: { ru: "обе стороны", en: "both sides" },
		bound: { ru: "15–1280, и S1 + 56 ≠ S2", en: "15–1280, and S1 + 56 ≠ S2" },
		break: {
			ru: "Клиент не узнаёт ответ сервера и будет повторять рукопожатие до таймаута. С WARP всегда 0.",
			en: "The client fails to recognise the server's reply and retries the handshake until it times out. With WARP always 0.",
		},
	},
	h1: {
		who: { ru: "обе стороны", en: "both sides" },
		bound: {
			ru: "5–2147483647, все четыре H различны",
			en: "5–2147483647, all four H values distinct",
		},
		break: {
			ru: "Сервер видит неизвестный тип сообщения и не отвечает вовсе. Граница «от 5» существует потому, что 1–4 заняты штатными типами WireGuard.",
			en: "The server sees an unknown message type and answers nothing at all. The \"from 5\" bound exists because 1–4 are taken by the standard WireGuard types.",
		},
	},
	h2: {
		who: { ru: "обе стороны", en: "both sides" },
		bound: { ru: "как H1, но ≠ H1", en: "same as H1 but ≠ H1" },
		break: {
			ru: "То же, что с H1, только теряется ответ сервера, а не запрос клиента.",
			en: "Same as H1, except the server's reply is lost rather than the client's request.",
		},
	},
	h3: {
		who: { ru: "обе стороны", en: "both sides" },
		bound: { ru: "как H1, но ≠ H1, H2", en: "same as H1 but ≠ H1, H2" },
		break: {
			ru: "Ломается cookie reply — защита от перегрузки. Туннель может работать, пока сервер не под нагрузкой — самый коварный вариант расхождения.",
			en: "Breaks the cookie reply, the overload protection. The tunnel may work until the server is under load — the nastiest kind of mismatch.",
		},
	},
	h4: {
		who: { ru: "обе стороны", en: "both sides" },
		bound: { ru: "как H1, но ≠ H1–H3", en: "same as H1 but ≠ H1–H3" },
		break: {
			ru: "Ломаются транспортные пакеты, то есть сами данные. Рукопожатие пройдёт, интерфейс поднимется, но трафик идти не будет.",
			en: "Breaks transport packets, i.e. the data itself. The handshake completes and the interface comes up, but no traffic flows.",
		},
	},
	itime: {
		who: { ru: "отправитель, AmneziaWG 1.5+", en: "sender, AmneziaWG 1.5+" },
		bound: { ru: "0–3600 секунд", en: "0–3600 seconds" },
		break: {
			ru: "Старые сборки клиента просто не примут поле и откажутся импортировать конфиг.",
			en: "Older client builds simply do not accept the field and refuse to import the config.",
		},
	},
}

function docFor(key) {
	return PARAM_DOCS[String(key).toLowerCase()] || null
}

function paramTag(key, value) {
	// Rows can cover several parameters at once: "Jmin / Jmax", "H1-H4".
	const parts = String(key)
		.toLowerCase()
		.replace(/\s+/g, "")
		.replace("h1-h4", "h1/h2/h3/h4")
		.split("/")

	// Values may be strings such as "0 / 0" or "58 / 162", so read every number.
	const numbers = String(value).match(/-?\d+/g)
	if (numbers && numbers.every((n) => Number(n) === 0)) {
		return { cls: "tagd--off", label: t("pdoc.tagOff") }
	}

	const manual = parts.some((part) => {
		const raw = state.overrides ? state.overrides[part] : undefined
		return raw !== undefined && raw !== null && raw !== "" && Number.isFinite(Number(raw))
	})
	if (manual) return { cls: "tagd--man", label: t("pdoc.tagMan") }

	return { cls: "tagd--gen", label: t("pdoc.tagGen") }
}

function renderParamDocs() {
	const host = $("pdocList")
	if (!host) return
	const obf = state.obfuscation
	const rows = obf && obf.enabled && Array.isArray(obf.explain) ? obf.explain : []
	const count = $("navParamsCount")
	if (count) count.textContent = rows.length ? String(rows.length) : ""

	if (!rows.length) {
		const text = obf && !obf.enabled ? pickText(obf, "summary") : t("pdoc.empty")
		host.replaceChildren(el("p", "field__hint", text))
		return
	}

	host.replaceChildren(
		...rows.map((row) => {
			const card = el("article", "pdoc__item")
			const head = el("div", "pdoc__head")
			head.append(el("code", "pdoc__key", row.key))
			head.append(el("span", "pdoc__val", String(row.value)))
			const tag = paramTag(row.key, row.value)
			head.append(el("span", `tagd ${tag.cls}`, tag.label))
			card.append(head)
			card.append(el("p", "pdoc__what", pickText(row, "what")))

			const doc = docFor(row.key)
			if (doc) {
				const lang = state.lang === "en" ? "en" : "ru"
				const grid = el("dl", "pdoc__grid")
				for (const [label, value] of [
					[t("pdoc.who"), doc.who[lang]],
					[t("pdoc.bound"), doc.bound[lang]],
					[t("pdoc.break"), doc.break[lang]],
				]) {
					grid.append(el("dt", null, label))
					grid.append(el("dd", null, value))
				}
				card.append(grid)
			}
			return card
		}),
	)
}

// ------------------------------------------------------------ packet simulator

/** Fixed WireGuard sizes: this is the fingerprint obfuscation hides. */
const WG_INIT = 148
const WG_RESP = 92

function simBar(kind, bytes, label, max) {
	const row = el("div", "simbar")
	const track = el("div", "simbar__track")
	const fill = el("div", `simbar__fill simbar__fill--${kind}`)
	fill.style.width = `${Math.max(4, Math.round((bytes / max) * 100))}%`
	track.append(fill)
	row.append(el("span", "simbar__label", label))
	row.append(track)
	row.append(el("span", "simbar__size", `${bytes} ${t("sim.bytes")}`))
	return row
}

function renderSimulator() {
	const host = $("simWire")
	const plain = $("simPlain")
	if (!host || !plain) return

	const obf = state.obfuscation
	const params = obf && obf.enabled ? obf.params || {} : {}
	const jc = Number(params.jc || 0)
	const jmin = Number(params.jmin || 0)
	const jmax = Number(params.jmax || 0)
	const s1 = Number(params.s1 || 0)
	const s2 = Number(params.s2 || 0)
	const initSize = WG_INIT + s1
	const respSize = WG_RESP + s2

	const profile = $("simProfile")
	if (profile) {
		profile.textContent = obf ? pickText(obf, "label") || "" : ""
	}

	// Junk sizes are random per packet; spread them across the range so the
	// picture shows variance rather than one repeated number.
	const rows = []
	for (let i = 0; i < Math.min(jc, 12); i += 1) {
		const span = Math.max(0, jmax - jmin)
		const size = jc <= 1 ? jmax : jmin + Math.round((span * i) / Math.max(1, jc - 1))
		rows.push({ kind: "junk", bytes: size, label: `junk ${i + 1}` })
	}
	rows.push({ kind: "init", bytes: initSize, label: t("sim.init") })
	rows.push({ kind: "resp", bytes: respSize, label: t("sim.resp") })
	rows.push({ kind: "data", bytes: 128, label: t("sim.data") })
	rows.push({ kind: "data", bytes: 1280, label: t("sim.data") })

	const max = Math.max(...rows.map((r) => r.bytes), 1280)
	host.replaceChildren(...rows.map((r) => simBar(r.kind, r.bytes, r.label, max)))

	plain.replaceChildren(
		simBar("init", WG_INIT, t("sim.init"), max),
		simBar("resp", WG_RESP, t("sim.resp"), max),
	)

	const note = $("simNote")
	if (note) {
		let text =
			jc > 0
				? t("sim.noteJunk", { jc, jmin, jmax })
				: t("sim.noteNoJunk")
		if (s1 > 0 || s2 > 0) {
			text += t("sim.notePad", { s1, s2, i: initSize, r: respSize })
		}
		note.textContent = text
	}
}

// ------------------------------------------------------------------- hooks

/** Called at the end of renderParams(): keeps the new sections in sync. */
function afterParams() {
	try {
		renderParamDocs()
		renderSimulator()
	} catch {
		// A broken side panel must never take the generator down with it.
	}
}

/** Called after renderSummary(): a finished build becomes a history entry. */
function afterGenerate(result) {
	try {
		pushHistory(result)
	} catch {
		// ignore
	}
}

function rerenderSections() {
	applyStaticI18n()
	renderFaq()
	renderHistory()
	renderParamDocs()
	renderSimulator()
}

function wireSections() {
	for (const item of document.querySelectorAll(".nav__item")) {
		item.addEventListener("click", () => showView(item.dataset.view))
	}
	$("toParams")?.addEventListener("click", () => showView("params"))

	$("histClear")?.addEventListener("click", () => {
		writeHistory([])
		renderHistory()
		toast(t("hist.cleared"))
	})

	$("histExport")?.addEventListener("click", () => {
		const blob = new Blob([JSON.stringify(readHistory(), null, 2)], {
			type: "application/json",
		})
		const url = URL.createObjectURL(blob)
		const link = document.createElement("a")
		link.href = url
		link.download = "awg-warp-history.json"
		link.click()
		URL.revokeObjectURL(url)
		toast(t("hist.exported"))
	})

	// The language buttons already have their handler from wire(); ours runs
	// afterwards and re-renders the sections this file owns.
	$("langRu")?.addEventListener("click", rerenderSections)
	$("langEn")?.addEventListener("click", rerenderSections)

	window.addEventListener("hashchange", () => showView(location.hash.slice(1)))
}

wireSections()
// init() ran before this block was evaluated, so re-apply the labels that only
// exist in EXTRA_I18N now that they are merged in.
applyStaticI18n()
renderFaq()
renderHistory()
showView(location.hash.slice(1) || "gen")

/*
 * The API returns some parameters as one combined row ("Jmin / Jmax",
 * "S1 / S2", "H1-H4") and the mimicry signatures as I1-I5. Their notes live in
 * param-docs.js, keyed by the lowercased row label so docFor() finds them
 * without any extra lookup logic.
 */
import { GROUP_PARAM_DOCS } from "./param-docs.js"

Object.assign(PARAM_DOCS, GROUP_PARAM_DOCS)
