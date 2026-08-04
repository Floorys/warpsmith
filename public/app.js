/**
 * Frontend for AWG WARP Architect.
 *
 * The browser never talks to Cloudflare directly - it cannot, there is no CORS
 * on the WARP API. Everything real happens in the backend; this file is purely
 * presentation plus a live preview of obfuscation parameters.
 */

const $ = (id) => document.getElementById(id)

const state = {
	options: null,
	profile: "balanced",
	obfuscation: null,
	overrides: {},
	result: null,
	tab: "amneziawg",
	busy: false,
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

// --------------------------------------------------------------- bootstrap

async function init() {
	try {
		const [options, health] = await Promise.all([
			api("/api/options"),
			api("/api/health"),
		])
		state.options = options

		$("healthBadge").textContent = "Server ready"
		$("healthBadge").className = "pill pill--ok"
		$("mockBadge").hidden = !health.mock

		renderLocality(options.locationReality)
		renderPrefixes(options.endpointPrefixes)
		renderPorts(options.endpointPorts, options.camouflagePorts)
		renderProfiles(options.obfuscationProfiles)
		renderSelect($("allowedIps"), options.allowedIps, "full")
		renderSelect($("dns"), options.dns, "cloudflare")
		renderPathMtu(options.pathMtuPresets)
		renderOverrideFields()

		updateAllowedHint()
		await refreshObfuscation()
	} catch (error) {
		$("healthBadge").textContent = "Server unreachable"
		$("healthBadge").className = "pill pill--err"
		toast(error.message, "error")
	}
}

function renderLocality(reality) {
	$("localitySummary").textContent = reality.summary
	const ul = $("localityDetails")
	ul.replaceChildren(...reality.details.map((d) => el("li", null, d)))
}

function renderPrefixes(prefixes) {
	const select = $("endpointPrefix")
	select.replaceChildren()
	const auto = new Option("Automatic (random IPv4 prefix)", "")
	select.append(auto)
	for (const p of prefixes) {
		const opt = new Option(`${p.cidr}${p.family === 6 ? "  (IPv6)" : ""}`, p.id)
		opt.dataset.note = p.note
		opt.dataset.family = String(p.family)
		select.append(opt)
	}
	select.addEventListener("change", () => {
		const opt = select.selectedOptions[0]
		$("prefixHint").textContent = opt?.dataset.note || "A prefix is chosen at random for you."
	})
	$("prefixHint").textContent = "A prefix is chosen at random for you."
}

function renderPorts(ports, camouflage) {
	const select = $("endpointPort")
	select.replaceChildren()
	select.append(new Option("Automatic (random known-good port)", ""))
	for (const port of ports) {
		const hint = camouflage[port]
		const opt = new Option(hint ? `${port}  -  ${hint.split(" (")[0]}` : String(port), String(port))
		if (hint) opt.dataset.note = hint
		select.append(opt)
	}
	select.addEventListener("change", () => {
		const opt = select.selectedOptions[0]
		$("portHint").textContent =
			opt?.dataset.note || "Rotating the port helps against port-based throttling."
	})
	$("portHint").textContent = "Rotating the port helps against port-based throttling."
}

function renderProfiles(profiles) {
	const wrap = $("profiles")
	wrap.replaceChildren()
	for (const p of profiles) {
		const label = el("label", "profile")
		if (p.id === state.profile) label.classList.add("is-active")

		const input = document.createElement("input")
		input.type = "radio"
		input.name = "obfProfile"
		input.value = p.id
		input.checked = p.id === state.profile

		const body = el("div", "profile__body")
		const name = el("div", "profile__name")
		name.append(el("span", null, p.label))
		if (p.version === "1.5") name.append(el("span", "tag", "AWG 1.5"))
		body.append(name, el("div", "profile__desc", p.summary))

		label.append(input, body)
		wrap.append(label)

		input.addEventListener("change", async () => {
			state.profile = p.id
			state.overrides = {}
			for (const node of wrap.querySelectorAll(".profile")) {
				node.classList.toggle("is-active", node.contains(input))
			}
			await refreshObfuscation()
		})
	}
}

function renderSelect(select, items, defaultId) {
	select.replaceChildren()
	for (const item of items) {
		const opt = new Option(item.label, item.id)
		if (item.note) opt.dataset.note = item.note
		select.append(opt)
	}
	select.value = defaultId
}

function renderPathMtu(presets) {
	const select = $("pathMtu")
	select.replaceChildren()
	select.append(new Option("Safe default (MTU 1280)", ""))
	for (const p of presets) {
		select.append(new Option(p.label, String(p.pathMtu)))
	}
	select.addEventListener("change", updateMtuHint)
	updateMtuHint()
}

async function updateMtuHint() {
	const raw = $("pathMtu").value
	if (!raw) {
		$("mtuHint").textContent = "MTU 1280 - what the official WARP client uses. Never fragments."
		return
	}
	try {
		const info = await api("/api/mtu", { pathMtu: Number(raw), outerFamily: 4 })
		$("mtuHint").textContent = `Tunnel MTU ${info.mtu} (${info.pathMtu} minus ${info.overhead} bytes overhead).`
	} catch {
		$("mtuHint").textContent = ""
	}
}

function updateAllowedHint() {
	const opt = $("allowedIps").selectedOptions[0]
	$("allowedHint").textContent = opt?.dataset.note || ""
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
		const result = await api("/api/obfuscation", {
			profile: state.profile,
			seed: seed || $("seed").value.trim() || undefined,
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
		version.textContent = "plain WireGuard"
		const row = el("div", "param__what", obf.summary)
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
		wrap.append(el("dd", "param__what", row.what))
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
			const validation = await api("/api/validate", { params })
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
		wrap.append(el("div", "msg msg--ok", "Parameters are valid."))
	}
}

// -------------------------------------------------------------------- scan

async function runScan() {
	const button = $("scanBtn")
	setBusy(button, true, "Scanning")
	$("scanPanel").hidden = false
	$("scanStatus").textContent = "Probing Cloudflare endpoints for their real datacenter..."
	$("scanList").replaceChildren()

	try {
		const { scanned, byLocation } = await api("/api/scan", { perPrefix: 2 })

		if (!byLocation.length) {
			$("scanStatus").textContent = `No endpoint answered out of ${scanned}. Cloudflare may be blocked from this server.`
			return
		}

		$("scanStatus").textContent = `${byLocation.length} datacenter(s) reachable, from ${scanned} probes. Click one to pin it.`

		for (const loc of byLocation) {
			const best = loc.endpoints[0]
			const locBtn = el("button", "loc")
			locBtn.type = "button"
			locBtn.append(el("span", "loc__colo", loc.colo))
			locBtn.append(
				el("span", "loc__name", loc.known ? `${loc.city}, ${loc.country}` : `Unknown colo ${loc.colo}`),
			)
			locBtn.append(el("span", "loc__rtt", `${loc.bestRttMs} ms`))
			locBtn.addEventListener("click", () => {
				const port = $("endpointPort").value || "2408"
				$("endpointHost").value = `${best.ip}:${port}`
				toast(`Pinned ${best.ip}:${port} (${loc.city})`)
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
	setBusy(button, true, "Registering with Cloudflare")

	const hasOverrides =
		$("advancedWrap").open &&
		Object.keys(state.overrides).length > 0 &&
		OVERRIDE_FIELDS.every((f) => Number.isFinite(state.overrides[f.key]))

	const pathMtu = $("pathMtu").value

	try {
		const result = await api("/api/generate", {
			obfuscation: state.profile,
			obfuscationOverrides: hasOverrides ? state.overrides : undefined,
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
		toast("Config generated")
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

	const rows = [
		["Endpoint", result.endpoint.endpoint],
		["Address", result.network.addresses.join(", ")],
		["MTU", String(result.network.mtu)],
		["Account", result.warp.accountType + (result.warp.warpPlus ? " (WARP+)" : "")],
		["Obfuscation", result.obfuscation.profileLabel],
		["Seed", result.meta.seed],
	]

	if (result.location?.measured) {
		rows.splice(1, 0, [
			"Exit",
			`${result.location.city}, ${result.location.country} (${result.location.colo}, ${result.location.rttMs} ms)`,
		])
	} else if (result.location && !result.location.measured) {
		rows.splice(1, 0, ["Exit", "could not be measured"])
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
	$("generateBtn").addEventListener("click", generate)
	$("scanBtn").addEventListener("click", runScan)

	$("rerollBtn").addEventListener("click", () => {
		$("seed").value = ""
		refreshObfuscation()
	})

	$("seed").addEventListener("change", () => refreshObfuscation())
	$("allowedIps").addEventListener("change", updateAllowedHint)

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
			toast("Copied to clipboard")
		} catch {
			toast("Clipboard blocked - select the text manually", "error")
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
		toast(`Downloaded ${filename}`)
	})
}

wire()
init()
