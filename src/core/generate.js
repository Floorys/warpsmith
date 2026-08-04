/**
 * The orchestrator: one function that turns user options into a finished,
 * ready-to-import config. Everything else in the project (HTTP API, CLI, UI)
 * is a thin wrapper around `generateProfile`.
 */

import { resolveKeyPair, generatePresharedKey } from "./keys.js"
import { makeSeed } from "./rand.js"
import { buildEndpoint, describeColo, probeColo } from "./endpoints.js"
import { generateObfuscation, validateObfuscation, PROFILES } from "./amnezia.js"
import { calculateMtu, ALLOWED_IPS_PRESETS, DNS_PRESETS } from "./mtu.js"
import {
	registerDevice,
	applyLicense,
	getRegistration,
	normalizeRegistration,
	isMockMode,
	WarpApiError,
} from "./warp.js"
import { renderAll } from "./render.js"

export class GenerateError extends Error {
	constructor(message, meta = {}) {
		super(message)
		this.name = "GenerateError"
		Object.assign(this, meta)
	}
}

/**
 * @typedef {Object} GenerateOptions
 * @property {string}   [privateKey]      Reuse an existing identity.
 * @property {string}   [license]         WARP+ license key.
 * @property {string}   [seed]            Reproduce a previous profile exactly.
 * @property {string}   [obfuscation]     Profile id from amnezia.js PROFILES.
 * @property {Object}   [obfuscationOverrides] Explicit Jc/S1/H1/... values.
 * @property {string[]} [signatures]      Mimicry signature ids (AmneziaWG 1.5).
 * @property {string}   [endpointPrefix]  e.g. "188.114.98".
 * @property {number}   [endpointPort]
 * @property {string}   [endpointHost]    Fully explicit "host:port" override.
 * @property {boolean}  [useHostname]     Use engage.cloudflareclient.com.
 * @property {4|6}      [family]
 * @property {boolean}  [detectLocation]  Probe the endpoint for its real colo.
 * @property {string}   [allowedIps]      Preset id, or comma-separated CIDRs.
 * @property {string}   [dns]             Preset id, or comma-separated servers.
 * @property {number}   [mtu]             Explicit MTU; otherwise computed.
 * @property {number}   [pathMtu]
 * @property {boolean}  [conservativeMtu]
 * @property {number}   [keepalive]       Seconds; 0 disables.
 * @property {boolean}  [ipv6]            Include IPv6 address + routes.
 * @property {boolean}  [presharedKey]    Generate an extra PSK.
 */

/**
 * Resolve AllowedIPs from a preset id or a raw list.
 * @param {string|undefined} input
 * @param {boolean} ipv6
 */
function resolveAllowedIps(input, ipv6) {
	let list
	if (!input) {
		list = ALLOWED_IPS_PRESETS.full.value
	} else if (ALLOWED_IPS_PRESETS[input]) {
		list = ALLOWED_IPS_PRESETS[input].value
	} else {
		list = String(input)
			.split(",")
			.map((s) => s.trim())
			.filter(Boolean)
		if (!list.length) {
			throw new GenerateError(`Could not parse allowedIps: ${JSON.stringify(input)}`)
		}
		const bad = list.find((cidr) => !/^[0-9a-fA-F:.]+\/\d{1,3}$/.test(cidr))
		if (bad) throw new GenerateError(`"${bad}" is not a valid CIDR`)
	}
	return ipv6 ? list : list.filter((cidr) => !cidr.includes(":"))
}

/**
 * Resolve DNS servers from a preset id or a raw list.
 * @param {string|undefined} input
 * @param {boolean} ipv6
 */
function resolveDns(input, ipv6) {
	let list
	if (!input) {
		list = DNS_PRESETS.cloudflare.value
	} else if (DNS_PRESETS[input]) {
		list = DNS_PRESETS[input].value
	} else {
		list = String(input)
			.split(",")
			.map((s) => s.trim())
			.filter(Boolean)
		if (!list.length) throw new GenerateError("DNS list is empty")
	}
	return ipv6 ? list : list.filter((server) => !server.includes(":"))
}

/**
 * Parse an explicit "host:port" or "[v6]:port" endpoint override.
 * @param {string} raw
 */
function parseEndpointOverride(raw) {
	const value = String(raw).trim()
	const v6 = value.match(/^\[([0-9a-fA-F:]+)\]:(\d{1,5})$/)
	if (v6) {
		return {
			host: v6[1],
			port: Number(v6[2]),
			endpoint: value,
			prefix: null,
			family: 6,
			note: "User-supplied endpoint.",
		}
	}
	const v4 = value.match(/^([A-Za-z0-9.\-]+):(\d{1,5})$/)
	if (v4) {
		const port = Number(v4[2])
		if (port < 1 || port > 65535) throw new GenerateError(`Port ${port} is out of range`)
		return {
			host: v4[1],
			port,
			endpoint: value,
			prefix: null,
			family: 4,
			note: "User-supplied endpoint.",
		}
	}
	throw new GenerateError(
		`Could not parse endpoint "${raw}". Expected "1.2.3.4:2408" or "[2606:4700::1]:2408".`,
	)
}

/**
 * Generate a complete WARP + AmneziaWG profile.
 * @param {GenerateOptions} [options]
 * @returns {Promise<Object>} profile with `.configs` ready to download
 */
export async function generateProfile(options = {}) {
	const seed = options.seed || makeSeed()
	const ipv6 = options.ipv6 !== false

	// 1. Identity -------------------------------------------------------------
	const keys = resolveKeyPair({ privateKey: options.privateKey })

	// 2. Register with Cloudflare ---------------------------------------------
	let raw
	try {
		raw = await registerDevice({ publicKey: keys.publicKey })
	} catch (error) {
		if (error instanceof WarpApiError) throw error
		throw new GenerateError(`Device registration failed: ${error.message}`, {
			cause: error,
		})
	}
	let warp = normalizeRegistration(raw)

	// 3. Optional WARP+ license ------------------------------------------------
	let licenseResult = null
	if (options.license) {
		try {
			licenseResult = await applyLicense({
				registrationId: warp.registrationId,
				token: warp.token,
				license: options.license,
			})
			const refreshed = await getRegistration({
				registrationId: warp.registrationId,
				token: warp.token,
			})
			if (refreshed) warp = normalizeRegistration(refreshed)
			else if (licenseResult) {
				warp.accountType = licenseResult.account_type ?? warp.accountType
				warp.warpPlus = Boolean(licenseResult.warp_plus)
			}
		} catch (error) {
			// A bad license should not throw away a perfectly good free config.
			licenseResult = {
				applied: false,
				error: error.message,
				hint: "The config below still works on the free tier.",
			}
		}
	}

	if (!warp.peerPublicKey) {
		throw new GenerateError("Cloudflare did not return a peer public key", { warp })
	}

	// 4. Endpoint / location ---------------------------------------------------
	let endpoint
	if (options.endpointHost) {
		endpoint = parseEndpointOverride(options.endpointHost)
	} else {
		endpoint = buildEndpoint({
			prefix: options.endpointPrefix,
			port: options.endpointPort,
			family: options.family,
			useHostname: options.useHostname,
			seed: `${seed}:endpoint`,
		})
	}

	let location = null
	if (options.detectLocation && endpoint.family === 4 && !isMockMode()) {
		const probe = await probeColo(endpoint.host, { timeoutMs: 4000 })
		location = probe.ok
			? { ...probe.location, rttMs: probe.rttMs, measured: true }
			: { measured: false, error: probe.error, ...describeColo("") }
	} else if (options.detectLocation && isMockMode()) {
		location = { ...describeColo("FRA"), rttMs: 21, measured: false, mock: true }
	}

	// 5. Obfuscation -----------------------------------------------------------
	const obfuscation = generateObfuscation({
		profile: options.obfuscation ?? "balanced",
		seed: `${seed}:obfuscation`,
		overrides: options.obfuscationOverrides,
		signatures: options.signatures,
	})
	if (!obfuscation.validation.valid) {
		throw new GenerateError(
			`Invalid obfuscation parameters: ${obfuscation.validation.errors.join("; ")}`,
			{ validation: obfuscation.validation },
		)
	}

	// 6. Network settings ------------------------------------------------------
	const mtuInfo = calculateMtu({
		pathMtu: options.pathMtu,
		outerFamily: endpoint.family,
		conservative: options.conservativeMtu ?? !options.pathMtu,
	})
	const mtu = Number.isInteger(options.mtu) ? options.mtu : mtuInfo.mtu

	const addresses = [`${warp.addressV4}/32`]
	if (ipv6 && warp.addressV6) addresses.push(`${warp.addressV6}/128`)

	const network = {
		addresses,
		dns: resolveDns(options.dns, ipv6),
		allowedIps: resolveAllowedIps(options.allowedIps, ipv6),
		mtu,
		mtuInfo,
		keepalive: Number.isInteger(options.keepalive) ? options.keepalive : 25,
		presharedKey: options.presharedKey ? generatePresharedKey() : null,
	}

	// 7. Assemble --------------------------------------------------------------
	const profile = {
		meta: {
			generatedAt: new Date().toISOString(),
			generator: "awg-warp-architect/1.0.0",
			seed,
			mock: warp.mock,
			reusedIdentity: keys.reused,
		},
		keys: { privateKey: keys.privateKey, publicKey: keys.publicKey },
		warp,
		endpoint,
		location,
		network,
		obfuscation,
		license: licenseResult,
	}

	profile.configs = renderAll(profile)
	profile.warnings = collectWarnings(profile)
	return profile
}

/**
 * Non-fatal things the user should know about, surfaced in the UI.
 * @param {Object} profile
 * @returns {string[]}
 */
function collectWarnings(profile) {
	const warnings = [...(profile.obfuscation.validation?.warnings ?? [])]

	if (profile.meta.mock) {
		warnings.unshift(
			"MOCK MODE is on. This config contains synthetic credentials and will not connect.",
		)
	}
	if (profile.license && profile.license.applied === false) {
		warnings.push(`WARP+ license was not applied: ${profile.license.error}`)
	}
	if (profile.network.mtu > 1420) {
		warnings.push(
			`MTU ${profile.network.mtu} is aggressive. If some sites hang while ping works, drop it to 1280.`,
		)
	}
	if (profile.endpoint.family === 6) {
		warnings.push(
			"You picked an IPv6 endpoint. It only works if your ISP gives you real IPv6 connectivity.",
		)
	}
	if (profile.obfuscation.version === "1.5") {
		warnings.push(
			"This profile uses AmneziaWG 1.5 features (I1..I5). Older AmneziaWG clients cannot parse it.",
		)
	}
	if (!profile.network.allowedIps.some((c) => c.includes(":")) && profile.network.addresses.length > 1) {
		warnings.push(
			"An IPv6 address is assigned but no IPv6 routes are set, so IPv6 traffic will bypass the tunnel.",
		)
	}
	return warnings
}

/**
 * Everything the UI needs to render its forms. Keeps option lists in one place
 * so the frontend never hardcodes them.
 */
export function describeOptions() {
	return {
		obfuscationProfiles: Object.entries(PROFILES).map(([id, p]) => ({
			id,
			label: p.label,
			summary: p.summary,
			obfuscated: p.obfuscated,
			version: p.version ?? "1.0",
		})),
		allowedIps: Object.entries(ALLOWED_IPS_PRESETS).map(([id, p]) => ({
			id,
			label: p.label,
			note: p.note,
		})),
		dns: Object.entries(DNS_PRESETS).map(([id, p]) => ({ id, label: p.label })),
	}
}

export { validateObfuscation }
