/**
 * Cloudflare WARP endpoint pool + real location (colo) detection.
 *
 * ---------------------------------------------------------------------------
 * HONEST NOTE ABOUT "CHOOSING A COUNTRY"
 * ---------------------------------------------------------------------------
 * Cloudflare WARP runs on ANYCAST. Every endpoint IP below is announced from
 * hundreds of Cloudflare datacenters at once, so the exit location is decided
 * by BGP routing from your ISP, not by the config file. There is no free WARP
 * endpoint that reliably means "give me the Netherlands".
 *
 * What actually DOES work, and what this module implements:
 *
 *   1. Different anycast prefixes are routed differently by many ISPs, so
 *      switching prefix/port genuinely changes which colo you land in.
 *   2. We can MEASURE the truth instead of guessing: every Cloudflare edge IP
 *      answers `GET /cdn-cgi/trace` over TLS and reports `colo=XXX`, which is
 *      the IATA code of the datacenter that terminated the request. We probe
 *      the candidate endpoints, read the real colo, map it to a city/country,
 *      and let the user pick from measured results with real RTT.
 *   3. If you need a guaranteed country, you need WARP+/Zero Trust with a
 *      dedicated egress policy, or your own AmneziaWG server in that country.
 *      `describeLocationReality()` returns that explanation for the UI.
 *
 * So: the location picker here is measurement-based and truthful, not a
 * decorative dropdown of flags that does nothing.
 */

import https from "node:https"
import net from "node:net"
import { createRng } from "./rand.js"

/**
 * Anycast prefixes Cloudflare uses for WARP/WireGuard.
 * `probeable: true` means the prefix also serves HTTPS, so colo detection works.
 */
export const ENDPOINT_PREFIXES = [
	{
		id: "162.159.192",
		cidr: "162.159.192.0/24",
		family: 4,
		hostRange: [1, 254],
		probeable: true,
		note: "Classic WARP consumer prefix. Most widely reachable.",
	},
	{
		id: "162.159.193",
		cidr: "162.159.193.0/24",
		family: 4,
		hostRange: [1, 254],
		probeable: true,
		note: "Secondary WARP prefix. Often survives when .192 is throttled.",
	},
	{
		id: "162.159.195",
		cidr: "162.159.195.0/24",
		family: 4,
		hostRange: [1, 254],
		probeable: true,
		note: "Less commonly filtered by DPI vendors.",
	},
	{
		id: "188.114.96",
		cidr: "188.114.96.0/24",
		family: 4,
		hostRange: [1, 254],
		probeable: true,
		note: "European-leaning routing for many ISPs.",
	},
	{
		id: "188.114.97",
		cidr: "188.114.97.0/24",
		family: 4,
		hostRange: [1, 254],
		probeable: true,
		note: "European-leaning routing for many ISPs.",
	},
	{
		id: "188.114.98",
		cidr: "188.114.98.0/24",
		family: 4,
		hostRange: [1, 254],
		probeable: true,
		note: "European-leaning routing for many ISPs.",
	},
	{
		id: "188.114.99",
		cidr: "188.114.99.0/24",
		family: 4,
		hostRange: [1, 254],
		probeable: true,
		note: "European-leaning routing for many ISPs.",
	},
	{
		id: "2606:4700:d0",
		cidr: "2606:4700:d0::/48",
		family: 6,
		probeable: false,
		note: "IPv6 WARP endpoint. Use only if your ISP has working IPv6.",
	},
	{
		id: "2606:4700:d1",
		cidr: "2606:4700:d1::/48",
		family: 6,
		probeable: false,
		note: "IPv6 WARP endpoint. Use only if your ISP has working IPv6.",
	},
]

/**
 * UDP ports Cloudflare WARP accepts handshakes on.
 * 2408 is the documented default; the rest are alternates that frequently slip
 * past port-based QoS/throttling rules.
 */
export const ENDPOINT_PORTS = [
	500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942,
	943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180,
	1387, 1701, 1843, 2371, 2408, 2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233,
	4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886,
]

/** Ports that also look like ordinary traffic to naive DPI. */
export const CAMOUFLAGE_PORTS = {
	500: "IKE / IPsec VPN (rarely blocked, sometimes prioritised)",
	1701: "L2TP (looks like a legacy corporate VPN)",
	4500: "IPsec NAT-T (extremely common, hard to block wholesale)",
	2408: "WARP default (most reliable, most fingerprinted)",
}

/** Default hostname endpoint. Resolves via DNS to the anycast pool. */
export const DEFAULT_HOST_ENDPOINT = "engage.cloudflareclient.com"

/**
 * IATA colo code -> human location. Used to translate a measured `colo=` into
 * something a person can read.
 */
export const COLO_MAP = {
	DME: { city: "Moscow", country: "Russia", cc: "RU", region: "Europe" },
	SVO: { city: "Moscow", country: "Russia", cc: "RU", region: "Europe" },
	LED: { city: "Saint Petersburg", country: "Russia", cc: "RU", region: "Europe" },
	SVX: { city: "Yekaterinburg", country: "Russia", cc: "RU", region: "Europe" },
	OVB: { city: "Novosibirsk", country: "Russia", cc: "RU", region: "Asia" },
	KJA: { city: "Krasnoyarsk", country: "Russia", cc: "RU", region: "Asia" },
	KHV: { city: "Khabarovsk", country: "Russia", cc: "RU", region: "Asia" },
	ROV: { city: "Rostov-on-Don", country: "Russia", cc: "RU", region: "Europe" },
	KUF: { city: "Samara", country: "Russia", cc: "RU", region: "Europe" },
	HEL: { city: "Helsinki", country: "Finland", cc: "FI", region: "Europe" },
	ARN: { city: "Stockholm", country: "Sweden", cc: "SE", region: "Europe" },
	OSL: { city: "Oslo", country: "Norway", cc: "NO", region: "Europe" },
	CPH: { city: "Copenhagen", country: "Denmark", cc: "DK", region: "Europe" },
	KEF: { city: "Reykjavik", country: "Iceland", cc: "IS", region: "Europe" },
	RIX: { city: "Riga", country: "Latvia", cc: "LV", region: "Europe" },
	TLL: { city: "Tallinn", country: "Estonia", cc: "EE", region: "Europe" },
	VNO: { city: "Vilnius", country: "Lithuania", cc: "LT", region: "Europe" },
	WAW: { city: "Warsaw", country: "Poland", cc: "PL", region: "Europe" },
	KTW: { city: "Katowice", country: "Poland", cc: "PL", region: "Europe" },
	PRG: { city: "Prague", country: "Czechia", cc: "CZ", region: "Europe" },
	VIE: { city: "Vienna", country: "Austria", cc: "AT", region: "Europe" },
	BUD: { city: "Budapest", country: "Hungary", cc: "HU", region: "Europe" },
	OTP: { city: "Bucharest", country: "Romania", cc: "RO", region: "Europe" },
	SOF: { city: "Sofia", country: "Bulgaria", cc: "BG", region: "Europe" },
	BEG: { city: "Belgrade", country: "Serbia", cc: "RS", region: "Europe" },
	ZAG: { city: "Zagreb", country: "Croatia", cc: "HR", region: "Europe" },
	SKP: { city: "Skopje", country: "North Macedonia", cc: "MK", region: "Europe" },
	TIA: { city: "Tirana", country: "Albania", cc: "AL", region: "Europe" },
	ATH: { city: "Athens", country: "Greece", cc: "GR", region: "Europe" },
	LCA: { city: "Nicosia", country: "Cyprus", cc: "CY", region: "Europe" },
	KIV: { city: "Chisinau", country: "Moldova", cc: "MD", region: "Europe" },
	KBP: { city: "Kyiv", country: "Ukraine", cc: "UA", region: "Europe" },
	MSQ: { city: "Minsk", country: "Belarus", cc: "BY", region: "Europe" },
	FRA: { city: "Frankfurt", country: "Germany", cc: "DE", region: "Europe" },
	MUC: { city: "Munich", country: "Germany", cc: "DE", region: "Europe" },
	DUS: { city: "Dusseldorf", country: "Germany", cc: "DE", region: "Europe" },
	HAM: { city: "Hamburg", country: "Germany", cc: "DE", region: "Europe" },
	BER: { city: "Berlin", country: "Germany", cc: "DE", region: "Europe" },
	AMS: { city: "Amsterdam", country: "Netherlands", cc: "NL", region: "Europe" },
	BRU: { city: "Brussels", country: "Belgium", cc: "BE", region: "Europe" },
	LUX: { city: "Luxembourg", country: "Luxembourg", cc: "LU", region: "Europe" },
	CDG: { city: "Paris", country: "France", cc: "FR", region: "Europe" },
	MRS: { city: "Marseille", country: "France", cc: "FR", region: "Europe" },
	LHR: { city: "London", country: "United Kingdom", cc: "GB", region: "Europe" },
	MAN: { city: "Manchester", country: "United Kingdom", cc: "GB", region: "Europe" },
	EDI: { city: "Edinburgh", country: "United Kingdom", cc: "GB", region: "Europe" },
	DUB: { city: "Dublin", country: "Ireland", cc: "IE", region: "Europe" },
	MAD: { city: "Madrid", country: "Spain", cc: "ES", region: "Europe" },
	BCN: { city: "Barcelona", country: "Spain", cc: "ES", region: "Europe" },
	LIS: { city: "Lisbon", country: "Portugal", cc: "PT", region: "Europe" },
	MXP: { city: "Milan", country: "Italy", cc: "IT", region: "Europe" },
	FCO: { city: "Rome", country: "Italy", cc: "IT", region: "Europe" },
	PMO: { city: "Palermo", country: "Italy", cc: "IT", region: "Europe" },
	ZRH: { city: "Zurich", country: "Switzerland", cc: "CH", region: "Europe" },
	GVA: { city: "Geneva", country: "Switzerland", cc: "CH", region: "Europe" },
	IST: { city: "Istanbul", country: "Turkey", cc: "TR", region: "Europe" },
	ADB: { city: "Izmir", country: "Turkey", cc: "TR", region: "Europe" },
	GYD: { city: "Baku", country: "Azerbaijan", cc: "AZ", region: "Asia" },
	TBS: { city: "Tbilisi", country: "Georgia", cc: "GE", region: "Asia" },
	EVN: { city: "Yerevan", country: "Armenia", cc: "AM", region: "Asia" },
	ALA: { city: "Almaty", country: "Kazakhstan", cc: "KZ", region: "Asia" },
	NQZ: { city: "Astana", country: "Kazakhstan", cc: "KZ", region: "Asia" },
	TSE: { city: "Astana", country: "Kazakhstan", cc: "KZ", region: "Asia" },
	TAS: { city: "Tashkent", country: "Uzbekistan", cc: "UZ", region: "Asia" },
	FRU: { city: "Bishkek", country: "Kyrgyzstan", cc: "KG", region: "Asia" },
	DYU: { city: "Dushanbe", country: "Tajikistan", cc: "TJ", region: "Asia" },
	TLV: { city: "Tel Aviv", country: "Israel", cc: "IL", region: "Middle East" },
	DXB: { city: "Dubai", country: "UAE", cc: "AE", region: "Middle East" },
	DOH: { city: "Doha", country: "Qatar", cc: "QA", region: "Middle East" },
	KWI: { city: "Kuwait City", country: "Kuwait", cc: "KW", region: "Middle East" },
	RUH: { city: "Riyadh", country: "Saudi Arabia", cc: "SA", region: "Middle East" },
	JED: { city: "Jeddah", country: "Saudi Arabia", cc: "SA", region: "Middle East" },
	BEY: { city: "Beirut", country: "Lebanon", cc: "LB", region: "Middle East" },
	AMM: { city: "Amman", country: "Jordan", cc: "JO", region: "Middle East" },
	BGW: { city: "Baghdad", country: "Iraq", cc: "IQ", region: "Middle East" },
	CAI: { city: "Cairo", country: "Egypt", cc: "EG", region: "Africa" },
	JNB: { city: "Johannesburg", country: "South Africa", cc: "ZA", region: "Africa" },
	CPT: { city: "Cape Town", country: "South Africa", cc: "ZA", region: "Africa" },
	LOS: { city: "Lagos", country: "Nigeria", cc: "NG", region: "Africa" },
	NBO: { city: "Nairobi", country: "Kenya", cc: "KE", region: "Africa" },
	CMN: { city: "Casablanca", country: "Morocco", cc: "MA", region: "Africa" },
	TUN: { city: "Tunis", country: "Tunisia", cc: "TN", region: "Africa" },
	IAD: { city: "Ashburn", country: "United States", cc: "US", region: "North America" },
	EWR: { city: "Newark", country: "United States", cc: "US", region: "North America" },
	BOS: { city: "Boston", country: "United States", cc: "US", region: "North America" },
	PHL: { city: "Philadelphia", country: "United States", cc: "US", region: "North America" },
	ATL: { city: "Atlanta", country: "United States", cc: "US", region: "North America" },
	MIA: { city: "Miami", country: "United States", cc: "US", region: "North America" },
	ORD: { city: "Chicago", country: "United States", cc: "US", region: "North America" },
	DFW: { city: "Dallas", country: "United States", cc: "US", region: "North America" },
	IAH: { city: "Houston", country: "United States", cc: "US", region: "North America" },
	DEN: { city: "Denver", country: "United States", cc: "US", region: "North America" },
	LAX: { city: "Los Angeles", country: "United States", cc: "US", region: "North America" },
	SJC: { city: "San Jose", country: "United States", cc: "US", region: "North America" },
	SEA: { city: "Seattle", country: "United States", cc: "US", region: "North America" },
	LAS: { city: "Las Vegas", country: "United States", cc: "US", region: "North America" },
	PHX: { city: "Phoenix", country: "United States", cc: "US", region: "North America" },
	YYZ: { city: "Toronto", country: "Canada", cc: "CA", region: "North America" },
	YUL: { city: "Montreal", country: "Canada", cc: "CA", region: "North America" },
	YVR: { city: "Vancouver", country: "Canada", cc: "CA", region: "North America" },
	MEX: { city: "Mexico City", country: "Mexico", cc: "MX", region: "North America" },
	QRO: { city: "Queretaro", country: "Mexico", cc: "MX", region: "North America" },
	GRU: { city: "Sao Paulo", country: "Brazil", cc: "BR", region: "South America" },
	GIG: { city: "Rio de Janeiro", country: "Brazil", cc: "BR", region: "South America" },
	EZE: { city: "Buenos Aires", country: "Argentina", cc: "AR", region: "South America" },
	SCL: { city: "Santiago", country: "Chile", cc: "CL", region: "South America" },
	LIM: { city: "Lima", country: "Peru", cc: "PE", region: "South America" },
	BOG: { city: "Bogota", country: "Colombia", cc: "CO", region: "South America" },
	UIO: { city: "Quito", country: "Ecuador", cc: "EC", region: "South America" },
	PTY: { city: "Panama City", country: "Panama", cc: "PA", region: "North America" },
	SIN: { city: "Singapore", country: "Singapore", cc: "SG", region: "Asia" },
	HKG: { city: "Hong Kong", country: "Hong Kong", cc: "HK", region: "Asia" },
	NRT: { city: "Tokyo", country: "Japan", cc: "JP", region: "Asia" },
	KIX: { city: "Osaka", country: "Japan", cc: "JP", region: "Asia" },
	ICN: { city: "Seoul", country: "South Korea", cc: "KR", region: "Asia" },
	TPE: { city: "Taipei", country: "Taiwan", cc: "TW", region: "Asia" },
	BOM: { city: "Mumbai", country: "India", cc: "IN", region: "Asia" },
	DEL: { city: "New Delhi", country: "India", cc: "IN", region: "Asia" },
	BLR: { city: "Bengaluru", country: "India", cc: "IN", region: "Asia" },
	MAA: { city: "Chennai", country: "India", cc: "IN", region: "Asia" },
	KUL: { city: "Kuala Lumpur", country: "Malaysia", cc: "MY", region: "Asia" },
	BKK: { city: "Bangkok", country: "Thailand", cc: "TH", region: "Asia" },
	CGK: { city: "Jakarta", country: "Indonesia", cc: "ID", region: "Asia" },
	MNL: { city: "Manila", country: "Philippines", cc: "PH", region: "Asia" },
	SGN: { city: "Ho Chi Minh City", country: "Vietnam", cc: "VN", region: "Asia" },
	HAN: { city: "Hanoi", country: "Vietnam", cc: "VN", region: "Asia" },
	CMB: { city: "Colombo", country: "Sri Lanka", cc: "LK", region: "Asia" },
	DAC: { city: "Dhaka", country: "Bangladesh", cc: "BD", region: "Asia" },
	KHI: { city: "Karachi", country: "Pakistan", cc: "PK", region: "Asia" },
	ISB: { city: "Islamabad", country: "Pakistan", cc: "PK", region: "Asia" },
	KTM: { city: "Kathmandu", country: "Nepal", cc: "NP", region: "Asia" },
	SYD: { city: "Sydney", country: "Australia", cc: "AU", region: "Oceania" },
	MEL: { city: "Melbourne", country: "Australia", cc: "AU", region: "Oceania" },
	PER: { city: "Perth", country: "Australia", cc: "AU", region: "Oceania" },
	BNE: { city: "Brisbane", country: "Australia", cc: "AU", region: "Oceania" },
	AKL: { city: "Auckland", country: "New Zealand", cc: "NZ", region: "Oceania" },
}

/**
 * Look up a colo code.
 * @param {string} colo
 * @returns {{ colo: string, city: string, country: string, cc: string, region: string, known: boolean }}
 */
export function describeColo(colo) {
	const code = String(colo || "").trim().toUpperCase()
	const hit = COLO_MAP[code]
	if (hit) return { colo: code, ...hit, known: true }
	return {
		colo: code || "UNKNOWN",
		city: code || "Unknown",
		country: "Unknown",
		cc: "",
		region: "Unknown",
		known: false,
	}
}

/**
 * Build a concrete endpoint (ip:port) from a prefix id.
 * @param {Object} [options]
 * @param {string} [options.prefix] Prefix id, e.g. "162.159.192". Omit to pick one.
 * @param {number} [options.port] Explicit port. Omit to pick one.
 * @param {4|6} [options.family]
 * @param {string} [options.seed]
 * @param {boolean} [options.useHostname] Prefer engage.cloudflareclient.com.
 * @returns {{ host: string, port: number, endpoint: string, prefix: string|null, family: 4|6, note: string }}
 */
export function buildEndpoint(options = {}) {
	const rng = createRng(options.seed)
	const port =
		Number.isInteger(options.port) && options.port > 0 && options.port < 65536
			? options.port
			: rng.pick(ENDPOINT_PORTS)

	if (options.useHostname) {
		return {
			host: DEFAULT_HOST_ENDPOINT,
			port,
			endpoint: `${DEFAULT_HOST_ENDPOINT}:${port}`,
			prefix: null,
			family: 4,
			note: "Hostname endpoint. Requires working DNS but follows Cloudflare's own routing.",
		}
	}

	const family = options.family === 6 ? 6 : 4
	const candidates = ENDPOINT_PREFIXES.filter((p) => p.family === family)
	const prefix =
		candidates.find((p) => p.id === options.prefix) || rng.pick(candidates)

	if (prefix.family === 6) {
		const tail = rng.int(1, 0xffff).toString(16)
		const host = `${prefix.id}::${tail}`
		return {
			host,
			port,
			endpoint: `[${host}]:${port}`,
			prefix: prefix.id,
			family: 6,
			note: prefix.note,
		}
	}

	const [lo, hi] = prefix.hostRange
	const host = `${prefix.id}.${rng.int(lo, hi)}`
	return {
		host,
		port,
		endpoint: `${host}:${port}`,
		prefix: prefix.id,
		family: 4,
		note: prefix.note,
	}
}

/**
 * Probe one Cloudflare IP over TLS and read /cdn-cgi/trace.
 * This is the part that tells us the REAL exit location.
 * @param {string} ip
 * @param {{ timeoutMs?: number }} [options]
 * @returns {Promise<Object>}
 */
export function probeColo(ip, options = {}) {
	const timeoutMs = options.timeoutMs ?? 4000
	const started = Date.now()

	return new Promise((resolve) => {
		const isV6 = ip.includes(":")
		const req = https.request(
			{
				host: ip,
				family: isV6 ? 6 : 4,
				port: 443,
				path: "/cdn-cgi/trace",
				method: "GET",
				// SNI + Host must be a real Cloudflare-fronted name, otherwise the
				// edge returns a 403/handshake failure instead of the trace body.
				servername: "cloudflare.com",
				headers: { Host: "cloudflare.com", "User-Agent": "awg-warp-architect/1.0" },
				timeout: timeoutMs,
				rejectUnauthorized: false,
			},
			(res) => {
				let body = ""
				res.setEncoding("utf8")
				res.on("data", (c) => {
					if (body.length < 4096) body += c
				})
				res.on("end", () => {
					const rtt = Date.now() - started
					const fields = {}
					for (const line of body.split("\n")) {
						const idx = line.indexOf("=")
						if (idx > 0) fields[line.slice(0, idx)] = line.slice(idx + 1).trim()
					}
					if (!fields.colo) {
						resolve({ ip, ok: false, rttMs: rtt, error: "no colo in trace" })
						return
					}
					resolve({
						ip,
						ok: true,
						rttMs: rtt,
						location: describeColo(fields.colo),
						warpStatus: fields.warp || "off",
						visibleIp: fields.ip || null,
						loc: fields.loc || null,
					})
				})
			},
		)

		const fail = (error) => {
			req.destroy()
			resolve({ ip, ok: false, rttMs: Date.now() - started, error: String(error?.message || error) })
		}
		req.on("timeout", () => fail(new Error(`timeout after ${timeoutMs}ms`)))
		req.on("error", fail)
		req.end()
	})
}

/**
 * Measure raw TCP reachability + RTT for host:port.
 * UDP handshakes cannot be probed without full Noise crypto, but TCP latency to
 * the same anycast IP is a solid proxy for how close that colo is.
 * @param {string} host
 * @param {number} [port]
 * @param {{ timeoutMs?: number }} [options]
 */
export function probeLatency(host, port = 443, options = {}) {
	const timeoutMs = options.timeoutMs ?? 3000
	const started = Date.now()
	return new Promise((resolve) => {
		const socket = net.connect({ host, port, timeout: timeoutMs })
		const done = (ok, error) => {
			socket.destroy()
			resolve({ host, port, ok, rttMs: Date.now() - started, error: error || null })
		}
		socket.on("connect", () => done(true))
		socket.on("timeout", () => done(false, "timeout"))
		socket.on("error", (e) => done(false, String(e.message)))
	})
}

/**
 * Scan a spread of endpoints across every probeable prefix, resolve their real
 * colo, and return them sorted by latency. This powers the location picker.
 * @param {Object} [options]
 * @param {number} [options.perPrefix] Candidate IPs per prefix (default 2).
 * @param {number} [options.concurrency]
 * @param {number} [options.timeoutMs]
 * @param {string} [options.seed]
 * @returns {Promise<{ scanned: number, results: Object[], byLocation: Object[] }>}
 */
export async function scanLocations(options = {}) {
	// Defaults are deliberately generous: a thin scan makes anycast look broken
	// when it is merely doing its job.
	const perPrefix = Math.min(Math.max(options.perPrefix ?? 4, 1), 12)
	const concurrency = Math.min(Math.max(options.concurrency ?? 12, 1), 32)
	const timeoutMs = options.timeoutMs ?? 5000
	const rng = createRng(options.seed)

	/** @type {string[]} */
	const targets = []
	for (const prefix of ENDPOINT_PREFIXES) {
		if (!prefix.probeable) continue
		const seen = new Set()
		while (seen.size < perPrefix) {
			seen.add(rng.int(prefix.hostRange[0], prefix.hostRange[1]))
		}
		for (const host of seen) targets.push(`${prefix.id}.${host}`)
	}

	const results = []
	let cursor = 0
	async function worker() {
		while (cursor < targets.length) {
			const ip = targets[cursor++]
			results.push(await probeColo(ip, { timeoutMs }))
		}
	}
	await Promise.all(
		Array.from({ length: Math.min(concurrency, targets.length) }, worker),
	)

	const ok = results.filter((r) => r.ok).sort((a, b) => a.rttMs - b.rttMs)

	// Group by measured colo so the UI can show "Frankfurt (3 endpoints, 28 ms)".
	const groups = new Map()
	for (const r of ok) {
		const key = r.location.colo
		if (!groups.has(key)) {
			groups.set(key, { ...r.location, endpoints: [], bestRttMs: r.rttMs })
		}
		const g = groups.get(key)
		g.endpoints.push({ ip: r.ip, rttMs: r.rttMs })
		g.bestRttMs = Math.min(g.bestRttMs, r.rttMs)
	}

	// Without these counters a scan that mostly timed out looks identical to a
	// scan where every endpoint answered from one datacenter. Those are very
	// different situations and the UI must be able to tell them apart.
	const failed = results.filter((r) => !r.ok)
	const timedOut = failed.filter((r) => /timeout/i.test(r.error || "")).length

	return {
		scanned: results.length,
		results,
		byLocation: [...groups.values()].sort((a, b) => a.bestRttMs - b.bestRttMs),
		stats: {
			probes: results.length,
			answered: ok.length,
			failed: failed.length,
			timedOut,
			blocked: failed.length - timedOut,
			uniqueColos: groups.size,
			// True when everything answered but landed in one place. That is normal
			// anycast behaviour from a single vantage point, not a failure.
			singleColo: groups.size === 1 && ok.length > 1,
		},
	}
}

/**
 * Text the UI shows next to the location picker so nobody is misled.
 * @returns {{ summary: string, details: string[] }}
 */
export function describeLocationReality() {
	return {
		summary:
			"Cloudflare WARP is anycast: the exit datacenter is chosen by BGP routing, not by the config file.",
		details: [
			"Every endpoint below is announced from hundreds of Cloudflare datacenters simultaneously.",
			"Switching prefix or port does often change which datacenter you reach, because ISPs route prefixes differently.",
			"Scan endpoints to see the datacenter (colo) you actually land in, measured live, plus RTT.",
			"Finding only ONE datacenter is the normal result: from a single vantage point anycast sends every Cloudflare IP to the same nearest colo.",
			"The scan runs on the server. If this site is hosted (Vercel, Render, a VPS), it measures the hosting region, not your ISP. Run it locally for your own numbers.",
			"For a guaranteed country you need WARP+/Zero Trust with a dedicated egress, or your own AmneziaWG server there.",
		],
	}
}
