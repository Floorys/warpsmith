/**
 * AmneziaWG obfuscation engine.
 *
 * AmneziaWG is WireGuard plus traffic-shaping parameters that break passive DPI
 * fingerprinting. Nothing here is proprietary; the parameters are documented by
 * the AmneziaWG project. This module's job is to produce values that are both
 * VALID (the tunnel actually comes up) and USEFUL (the traffic stops looking
 * like textbook WireGuard).
 *
 * AmneziaWG 1.0 parameters
 * ------------------------
 *   Jc          Number of junk packets sent before the real handshake.
 *   Jmin/Jmax   Size bounds (bytes) for each junk packet.
 *   S1          Junk bytes prepended to the handshake INITIATION packet.
 *   S2          Junk bytes prepended to the handshake RESPONSE packet.
 *   H1..H4      Custom magic headers replacing WireGuard's message types
 *               1=init, 2=response, 3=cookie, 4=transport.
 *
 * AmneziaWG 1.5 additions
 * -----------------------
 *   I1..I5      Fully-templated fake packets sent on connect, so the first
 *               bytes on the wire imitate a different protocol entirely.
 *   J1..J3      Templated junk packets used in place of the random Jc junk.
 *   Itime       Interval (seconds) for re-sending the I-packets.
 *
 * HARD CONSTRAINTS (violating these breaks the tunnel)
 * ----------------------------------------------------
 *   - Jmin < Jmax, Jmax <= 1280.
 *   - S1 + 56 != S2. WireGuard's init packet is 148 bytes and its response is
 *     92 bytes; if S1 + 148 == S2 + 92 the two obfuscated packets become the
 *     same length and AmneziaWG refuses the config.
 *   - H1..H4 must be four DISTINCT values in [5, 2^31-1]. Values 1-4 are
 *     reserved for stock WireGuard message types.
 *   - Every peer in the tunnel must use IDENTICAL values. Use the returned
 *     `seed` to reproduce a profile on another device.
 */

import { createRng, makeSeed } from "./rand.js"

/** Stock WireGuard packet sizes, used for the S1/S2 collision rule. */
export const WG_PACKET_SIZES = {
	handshakeInitiation: 148,
	handshakeResponse: 92,
	cookieReply: 64,
	transportHeader: 32,
}

export const LIMITS = {
	jc: { min: 0, max: 128 },
	junkSize: { min: 8, max: 1280 },
	s: { min: 15, max: 1280 },
	header: { min: 5, max: 2147483647 },
	itime: { min: 0, max: 3600 },
}

export class ObfuscationError extends Error {}

/**
 * Fake-packet templates for AmneziaWG 1.5 I1..I5.
 *
 * Template DSL understood by AmneziaWG:
 *   <b 0xHEX>  literal bytes
 *   <c>        4-byte incrementing counter
 *   <t>        4-byte unix timestamp
 *   <r N>      N random bytes
 *
 * Each entry below reproduces the opening bytes of a real, extremely common
 * protocol so the first packet of the tunnel blends into background noise.
 */
export const PACKET_SIGNATURES = {
	quic: {
		label: "QUIC Initial (HTTP/3)",
		description:
			"Long-header QUIC v1 Initial packet. Ubiquitous on UDP/443, so DPI that blocks it breaks YouTube and Google.",
		build: (rng) =>
			`<b 0xc00000000108><r 8><b 0x0000044180410d><c><r ${rng.int(180, 420)}>`,
	},
	dtls: {
		label: "DTLS 1.2 ClientHello",
		description:
			"Mimics a WebRTC/DTLS handshake. Blocking it kills voice and video calls, so it is usually allowed.",
		build: (rng) =>
			`<b 0x16fefd0000000000000000><b 0x00360100002a000000000000002a><b 0xfefd><t><r 28><b 0x000002002f0100>` +
			`<r ${rng.int(40, 120)}>`,
	},
	stun: {
		label: "STUN Binding Request",
		description:
			"NAT-traversal probe with the real 0x2112A442 magic cookie. Tiny, boring and whitelisted almost everywhere.",
		build: (rng) => `<b 0x0001002c2112a442><r 12><b 0x00060009><r ${rng.int(24, 72)}>`,
	},
	dns: {
		label: "DNS query over UDP",
		description:
			"Looks like a plain recursive DNS lookup. Extremely low-suspicion first packet.",
		build: (rng) =>
			`<r 2><b 0x0100000100000000000003777777076578616d706c6503636f6d0000010001><r ${rng.int(0, 24)}>`,
	},
	rtp: {
		label: "SRTP media stream",
		description:
			"Imitates an ongoing encrypted voice call. Good camouflage for long-lived tunnels.",
		build: (rng) => `<b 0x80${rng.int(96, 127).toString(16)}><c><t><r 4><r ${rng.int(80, 200)}>`,
	},
	openvpn: {
		label: "OpenVPN hard-reset",
		description:
			"Decoy that identifies as OpenVPN. Only useful where OpenVPN is tolerated but WireGuard is throttled.",
		build: (rng) => `<b 0x38><r 8><b 0x0000000000><c><r ${rng.int(16, 48)}>`,
	},
}

/**
 * Presets. `profile` is the knob most users should touch.
 * Higher levels resist DPI harder but add handshake latency and overhead.
 */
export const PROFILES = {
	off: {
		label: "Off - plain WireGuard",
		summary: "No obfuscation. Fastest, but trivially fingerprinted by DPI.",
		obfuscated: false,
	},
	light: {
		label: "Light",
		summary:
			"Magic headers only, no junk packets. Zero added latency; defeats naive signature matching.",
		obfuscated: true,
		jc: [0, 0],
		junk: [8, 80],
		s1: [15, 60],
		s2: [15, 60],
		signatures: 0,
	},
	balanced: {
		label: "Balanced (recommended)",
		summary:
			"Magic headers, a few junk packets and handshake padding. The setting most people should use.",
		obfuscated: true,
		jc: [4, 8],
		junk: [40, 200],
		s1: [30, 90],
		s2: [30, 90],
		signatures: 0,
	},
	mobile: {
		label: "Mobile / battery-friendly",
		summary:
			"Fewer, smaller junk packets so radio wake-ups and data use stay low on LTE/5G.",
		obfuscated: true,
		jc: [2, 4],
		junk: [16, 96],
		s1: [20, 60],
		s2: [20, 60],
		signatures: 0,
	},
	paranoid: {
		label: "Paranoid",
		summary:
			"Heavy junk volume plus large handshake padding. Slower to connect, hardest to classify.",
		obfuscated: true,
		jc: [8, 16],
		junk: [64, 640],
		s1: [60, 150],
		s2: [60, 150],
		signatures: 0,
	},
	mimicry: {
		label: "Mimicry (AmneziaWG 1.5+)",
		summary:
			"Sends templated fake QUIC/DTLS/STUN packets so the tunnel opens looking like another protocol. Needs AmneziaWG 1.5 or newer on BOTH ends.",
		obfuscated: true,
		version: "1.5",
		jc: [0, 0],
		junk: [32, 160],
		s1: [30, 90],
		s2: [30, 90],
		signatures: 3,
		itime: [30, 120],
	},
}

/**
 * Pick S1/S2 while respecting the `S1 + 56 != S2` collision rule.
 * @param {import('./rand.js').Rng} rng
 * @param {[number, number]} s1Range
 * @param {[number, number]} s2Range
 * @returns {{ s1: number, s2: number }}
 */
function pickHandshakePadding(rng, s1Range, s2Range) {
	const delta =
		WG_PACKET_SIZES.handshakeInitiation - WG_PACKET_SIZES.handshakeResponse // 56

	for (let attempt = 0; attempt < 64; attempt++) {
		const s1 = rng.int(s1Range[0], s1Range[1])
		const s2 = rng.int(s2Range[0], s2Range[1])
		if (s1 + delta !== s2) return { s1, s2 }
	}
	// Deterministic fallback that cannot collide.
	const s1 = s1Range[0]
	let s2 = s2Range[0]
	if (s1 + delta === s2) s2 = s2 + 1
	return { s1, s2 }
}

/**
 * Pick four distinct magic headers.
 * @param {import('./rand.js').Rng} rng
 * @returns {{ h1: number, h2: number, h3: number, h4: number }}
 */
function pickMagicHeaders(rng) {
	const seen = new Set()
	while (seen.size < 4) {
		seen.add(rng.int(LIMITS.header.min, LIMITS.header.max))
	}
	const [h1, h2, h3, h4] = [...seen]
	return { h1, h2, h3, h4 }
}

/**
 * Validate a complete parameter set. Returns problems instead of throwing so
 * the UI can show all of them at once.
 * @param {Object} params
 * @returns {{ valid: boolean, errors: string[], warnings: string[] }}
 */
export function validateObfuscation(params) {
	const errors = []
	const warnings = []
	if (!params || params.enabled === false) return { valid: true, errors, warnings }

	const { jc, jmin, jmax, s1, s2, h1, h2, h3, h4 } = params
	const intIn = (name, value, lo, hi) => {
		if (!Number.isInteger(value)) {
			errors.push(`${name} must be an integer, got ${JSON.stringify(value)}`)
			return false
		}
		if (value < lo || value > hi) {
			errors.push(`${name}=${value} is outside the allowed range ${lo}..${hi}`)
			return false
		}
		return true
	}

	intIn("Jc", jc, LIMITS.jc.min, LIMITS.jc.max)
	intIn("Jmin", jmin, LIMITS.junkSize.min, LIMITS.junkSize.max)
	intIn("Jmax", jmax, LIMITS.junkSize.min, LIMITS.junkSize.max)
	intIn("S1", s1, 0, LIMITS.s.max)
	intIn("S2", s2, 0, LIMITS.s.max)

	if (Number.isInteger(jmin) && Number.isInteger(jmax) && jmin >= jmax) {
		errors.push(`Jmin (${jmin}) must be strictly less than Jmax (${jmax})`)
	}

	const delta =
		WG_PACKET_SIZES.handshakeInitiation - WG_PACKET_SIZES.handshakeResponse
	if (Number.isInteger(s1) && Number.isInteger(s2) && s1 + delta === s2) {
		errors.push(
			`S1 + ${delta} must not equal S2 (S1=${s1}, S2=${s2}). ` +
				`Otherwise the padded initiation and response packets are the same size ` +
				`and AmneziaWG rejects the config.`,
		)
	}

	const headers = [h1, h2, h3, h4]
	headers.forEach((h, i) =>
		intIn(`H${i + 1}`, h, LIMITS.header.min, LIMITS.header.max),
	)
	if (headers.every(Number.isInteger) && new Set(headers).size !== 4) {
		errors.push("H1, H2, H3 and H4 must all be different values")
	}

	if (Number.isInteger(jc) && jc === 0 && (params.signatures?.length ?? 0) === 0) {
		warnings.push(
			"Jc=0 means no junk packets. Header obfuscation still applies, but volumetric analysis is easier.",
		)
	}
	if (Number.isInteger(jc) && jc > 32) {
		warnings.push(
			`Jc=${jc} sends a lot of junk on every handshake. This can be slow on high-latency links.`,
		)
	}
	if (Number.isInteger(jmax) && jmax > 1280) {
		warnings.push("Jmax above 1280 risks IP fragmentation, which is itself a DPI signal.")
	}
	if (params.version === "1.5") {
		warnings.push(
			"I1..I5 / J1..J3 require AmneziaWG 1.5+ on both peers. Older clients will refuse to parse this config.",
		)
	}

	return { valid: errors.length === 0, errors, warnings }
}

/**
 * Generate an obfuscation parameter set.
 *
 * @param {Object} [options]
 * @param {keyof typeof PROFILES} [options.profile] Default "balanced".
 * @param {string} [options.seed] Reuse to reproduce the exact same profile.
 * @param {Object} [options.overrides] Explicit values that win over the preset.
 * @param {string[]} [options.signatures] Signature ids for the 1.5 mimicry mode.
 * @returns {Object} obfuscation descriptor
 */
export function generateObfuscation(options = {}) {
	const profileName = options.profile ?? "balanced"
	const preset = PROFILES[profileName]
	if (!preset) {
		throw new ObfuscationError(
			`Unknown profile "${profileName}". Available: ${Object.keys(PROFILES).join(", ")}`,
		)
	}

	const seed = options.seed || makeSeed()
	const rng = createRng(seed)

	if (!preset.obfuscated) {
		return {
			enabled: false,
			profile: profileName,
			profileLabel: preset.label,
			summary: preset.summary,
			seed,
			version: "wireguard",
			params: {},
			signatures: [],
			validation: { valid: true, errors: [], warnings: [] },
		}
	}

	const jc = rng.int(preset.jc[0], preset.jc[1])
	let jmin = rng.int(preset.junk[0], Math.max(preset.junk[0], preset.junk[1] - 8))
	let jmax = rng.int(jmin + 8, Math.max(jmin + 8, preset.junk[1]))
	if (jmax > LIMITS.junkSize.max) jmax = LIMITS.junkSize.max
	if (jmin >= jmax) jmin = Math.max(LIMITS.junkSize.min, jmax - 8)

	const { s1, s2 } = pickHandshakePadding(rng, preset.s1, preset.s2)
	const headers = pickMagicHeaders(rng)

	// AmneziaWG 1.5 fake-packet templates.
	const requested =
		options.signatures && options.signatures.length
			? options.signatures.filter((id) => PACKET_SIGNATURES[id])
			: rng
					.shuffle(Object.keys(PACKET_SIGNATURES))
					.slice(0, preset.signatures ?? 0)

	const signatures = requested.slice(0, 5).map((id, index) => ({
		key: `I${index + 1}`,
		id,
		label: PACKET_SIGNATURES[id].label,
		description: PACKET_SIGNATURES[id].description,
		template: PACKET_SIGNATURES[id].build(rng),
	}))

	const version = signatures.length || preset.version === "1.5" ? "1.5" : "1.0"

	const params = {
		enabled: true,
		version,
		jc,
		jmin,
		jmax,
		s1,
		s2,
		...headers,
		...(version === "1.5" && preset.itime
			? { itime: rng.int(preset.itime[0], preset.itime[1]) }
			: {}),
		...(options.overrides || {}),
	}

	const validation = validateObfuscation({ ...params, signatures })

	return {
		enabled: true,
		profile: profileName,
		profileLabel: preset.label,
		summary: preset.summary,
		seed,
		version,
		params,
		signatures,
		validation,
		explain: explainParams(params, signatures),
	}
}

/**
 * Human-readable explanation of each parameter, for tooltips in the UI.
 * @param {Object} params
 * @param {Array} [signatures]
 * @returns {Array<{ key: string, value: string|number, what: string }>}
 */
export function explainParams(params, signatures = []) {
	if (!params?.enabled) return []
	const rows = [
		{
			key: "Jc",
			value: params.jc,
			what: `${params.jc} junk packet(s) are sent before each real handshake, so the first thing DPI sees is not a WireGuard initiation.`,
		},
		{
			key: "Jmin / Jmax",
			value: `${params.jmin} / ${params.jmax}`,
			what: `Each junk packet is a random ${params.jmin}-${params.jmax} bytes, so packet-size histograms do not form a clean signature.`,
		},
		{
			key: "S1",
			value: params.s1,
			what: `${params.s1} bytes of padding are prepended to the handshake initiation, changing it from the well-known 148 bytes to ${148 + params.s1}.`,
		},
		{
			key: "S2",
			value: params.s2,
			what: `${params.s2} bytes are prepended to the handshake response, moving it from 92 to ${92 + params.s2} bytes.`,
		},
		{
			key: "H1-H4",
			value: `${params.h1}, ${params.h2}, ${params.h3}, ${params.h4}`,
			what: "Replaces WireGuard's message type bytes 1/2/3/4 (init, response, cookie, transport) with custom values, defeating signature matching on the first four bytes.",
		},
	]
	if (params.itime) {
		rows.push({
			key: "Itime",
			value: params.itime,
			what: `Fake protocol packets are re-sent every ${params.itime}s to keep the disguise alive on long sessions.`,
		})
	}
	for (const sig of signatures) {
		rows.push({
			key: sig.key,
			value: sig.label,
			what: sig.description,
		})
	}
	return rows
}

/**
 * Emit the `[Interface]` lines for the obfuscation parameters, in the order the
 * AmneziaWG clients expect.
 * @param {Object} obfuscation
 * @returns {string[]}
 */
export function renderObfuscationLines(obfuscation) {
	if (!obfuscation?.enabled) return []
	const p = obfuscation.params
	const lines = [
		`Jc = ${p.jc}`,
		`Jmin = ${p.jmin}`,
		`Jmax = ${p.jmax}`,
		`S1 = ${p.s1}`,
		`S2 = ${p.s2}`,
		`H1 = ${p.h1}`,
		`H2 = ${p.h2}`,
		`H3 = ${p.h3}`,
		`H4 = ${p.h4}`,
	]
	for (const sig of obfuscation.signatures || []) {
		lines.push(`${sig.key} = ${sig.template}`)
	}
	if (p.itime) lines.push(`Itime = ${p.itime}`)
	return lines
}
