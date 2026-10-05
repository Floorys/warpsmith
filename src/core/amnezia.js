/**
 * AmneziaWG obfuscation engine.
 *
 * ============================================================================
 * THE MOST IMPORTANT THING IN THIS FILE
 * ============================================================================
 * Cloudflare WARP servers run STOCK WireGuard. They have never heard of
 * AmneziaWG. That single fact decides which parameters may be used:
 *
 *   Jc / Jmin / Jmax   SAFE with WARP.  Junk packets are separate UDP
 *                      datagrams. Cloudflare sees garbage, fails to parse it,
 *                      drops it, and the real handshake that follows still
 *                      works. DPI, meanwhile, no longer sees a lone 148-byte
 *                      packet as the first thing on the wire.
 *
 *   S1 / S2            BREAKS WARP.  These prepend padding INSIDE the real
 *                      handshake packets. Cloudflare parses byte 0 as the
 *                      message type, reads garbage, and drops the handshake.
 *
 *   H1..H4             BREAKS WARP, always.  These replace the 4-byte
 *                      message-type header and BOTH sides must agree on
 *                      them. Cloudflare (boringtun, parse_incoming_packet)
 *                      reads the full little-endian u32 of every incoming
 *                      packet and accepts only exactly 1/2/3/4, and its
 *                      own replies carry the stock header: an AmneziaWG
 *                      client with non-default H values drops every reply
 *                      from Cloudflare, so the handshake dies. A client
 *                      with NO H lines falls back to exactly 1/2/3/4
 *                      (amneziawg-go NewDevice defaults), which is why
 *                      WARP configs simply omit them.
 *
 *   I1..I5             SAFE with WARP on AmneziaWG 1.5+ CLIENTS.  These
 *                      are fake protocol packets (e.g. a QUIC Initial) sent
 *                      alongside the junk; Cloudflare cannot parse them and
 *                      drops them like junk. The client must be 1.5+; the
 *                      server does not care. This is exactly what the
 *                      proven bash-warp-generator does with its I1 packet.
 *
 * So every profile declares a `compat`:
 *   "warp" - works against Cloudflare WARP (junk packets, optionally I1..I5)
 *   "awg"  - requires your OWN AmneziaWG server on the other end
 *
 * Generating an "awg" profile against WARP produces a config that imports
 * cleanly, shows no error, and simply never connects. That is exactly the
 * failure mode this module now refuses to produce silently.
 *
 * ============================================================================
 * Parameter reference
 * ============================================================================
 *   Jc          Number of junk packets sent before the real handshake.
 *   Jmin/Jmax   Size bounds (bytes) for each junk packet.
 *   S1          Junk bytes prepended to the handshake INITIATION packet.
 *   S2          Junk bytes prepended to the handshake RESPONSE packet.
 *   H1..H4      Custom magic headers replacing WireGuard message types
 *               1=init, 2=response, 3=cookie, 4=transport.
 *   I1..I5      (1.5) Templated fake packets sent on connect.
 *   Itime       (1.5) Interval in seconds for re-sending I-packets.
 *
 * HARD CONSTRAINTS (violating these breaks the tunnel even on AmneziaWG)
 *   - Jmin < Jmax, Jmax <= 1280.
 *   - S1 + 56 != S2. The init packet is 148 bytes, the response is 92; if
 *     S1 + 148 == S2 + 92 both become the same length and AmneziaWG refuses.
 *   - H1..H4 must be four DISTINCT values in [5, 2^31-1]. 1-4 are reserved.
 *   - Every peer must use IDENTICAL values. Reproduce them with `seed`.
 */

import crypto from "node:crypto"
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

/**
 * H1-H4 are a uint32 on the wire. LIMITS.header keeps randomly generated
 * headers inside the int32 range because several AmneziaWG UIs parse the
 * field as a signed integer and reject anything above it.
 */
export const HEADER_UINT32_MAX = 4294967295

export class ObfuscationError extends Error {}

/** Compatibility targets. */
export const COMPAT = {
	warp: {
		id: "warp",
		label: "Cloudflare WARP",
		labelRu: "Cloudflare WARP",
		note:
			"Cloudflare runs stock WireGuard, so only junk packets (Jc/Jmin/Jmax) and, on AmneziaWG 1.5+ clients, fake protocol packets (I1-I5) may be used. " +
			"S1/S2 and H1-H4 would silently break the handshake.",
		noteRu:
			"Cloudflare \u0440\u0430\u0431\u043e\u0442\u0430\u0435\u0442 \u043d\u0430 \u043e\u0431\u044b\u0447\u043d\u043e\u043c WireGuard, \u043f\u043e\u044d\u0442\u043e\u043c\u0443 \u0434\u043e\u043f\u0443\u0441\u0442\u0438\u043c\u044b \u0442\u043e\u043b\u044c\u043a\u043e \u043c\u0443\u0441\u043e\u0440\u043d\u044b\u0435 \u043f\u0430\u043a\u0435\u0442\u044b (Jc/Jmin/Jmax) \u0438, \u043d\u0430 \u043a\u043b\u0438\u0435\u043d\u0442\u0430\u0445 AmneziaWG 1.5+, \u0444\u0430\u043b\u044c\u0448\u0438\u0432\u044b\u0435 \u043f\u0430\u043a\u0435\u0442\u044b \u043f\u0440\u043e\u0442\u043e\u043a\u043e\u043b\u043e\u0432 (I1-I5). " +
			"S1/S2 \u0438 H1-H4 \u043d\u0435\u0437\u0430\u043c\u0435\u0442\u043d\u043e \u0441\u043b\u043e\u043c\u0430\u044e\u0442 handshake.",
	},
	awg: {
		id: "awg",
		label: "Your own AmneziaWG server",
		labelRu: "\u0421\u0432\u043e\u0439 \u0441\u0435\u0440\u0432\u0435\u0440 AmneziaWG",
		note:
			"Full obfuscation. The peer must also be AmneziaWG with identical parameters. " +
			"These configs will NOT connect to Cloudflare WARP.",
		noteRu:
			"\u041f\u043e\u043b\u043d\u0430\u044f \u043e\u0431\u0444\u0443\u0441\u043a\u0430\u0446\u0438\u044f. \u041d\u0430 \u0442\u043e\u0439 \u0441\u0442\u043e\u0440\u043e\u043d\u0435 \u0442\u043e\u0436\u0435 \u0434\u043e\u043b\u0436\u0435\u043d \u0431\u044b\u0442\u044c AmneziaWG \u0441 \u0442\u0435\u043c\u0438 \u0436\u0435 \u043f\u0430\u0440\u0430\u043c\u0435\u0442\u0440\u0430\u043c\u0438. " +
			"\u041a Cloudflare WARP \u0442\u0430\u043a\u043e\u0439 \u043a\u043e\u043d\u0444\u0438\u0433 \u041d\u0415 \u043f\u043e\u0434\u043a\u043b\u044e\u0447\u0438\u0442\u0441\u044f.",
	},
}

// ---------------------------------------------------------------------------
// Domains used for protocol mimicry (the SNI written into the fake packets)
// ---------------------------------------------------------------------------

/**
 * A mimicry domain should be somewhere that is (a) huge, (b) served over the
 * same transport you are imitating, and (c) painful for a censor to block.
 */
export const MIMICRY_DOMAINS = [
	{ id: "www.apple.com", label: "www.apple.com", note: "Apple services (iCloud/AppStore). Trusted globally, never blocked by DPI." },
	{ id: "www.microsoft.com", label: "www.microsoft.com", note: "Microsoft Windows/Office update traffic. Whitelisted everywhere." },
	{ id: "cdn.jsdelivr.net", label: "cdn.jsdelivr.net", note: "High-volume open CDN. Universal HTTPS/QUIC traffic." },
	{ id: "www.cloudflare.com", label: "www.cloudflare.com", note: "Matches the real WARP endpoint IPs, so the SNI and the IP agree." },
	{ id: "www.google.com", label: "www.google.com", note: "The single most common TLS destination on earth." },
	{ id: "www.youtube.com", label: "www.youtube.com", note: "Huge QUIC volume. Best paired with the QUIC signature." },
	{ id: "github.com", label: "github.com", note: "Developer traffic. Rarely blocked, blocking it angers businesses." },
	{ id: "yandex.ru", label: "yandex.ru", note: "Domestic RU traffic, high volume, never blocked in RU." },
	{ id: "vk.com", label: "vk.com", note: "Domestic RU traffic. Very high volume, never blocked in RU." },
	{ id: "telegram.org", label: "telegram.org", note: "Only sensible where Telegram is not itself filtered." },
	{ id: "discord.com", label: "discord.com", note: "Mixed TLS + WebRTC, pairs well with the DTLS signature." },
]

export const DEFAULT_MIMICRY_DOMAIN = "www.apple.com"

// ---------------------------------------------------------------------------
// Byte-accurate fake packet builders
// ---------------------------------------------------------------------------

const u8 = (n) => [n & 0xff]
const u16 = (n) => [(n >> 8) & 0xff, n & 0xff]
const u24 = (n) => [(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]
const ascii = (s) => Array.from(Buffer.from(s, "ascii"))
const hex = (bytes) => bytes.map((b) => b.toString(16).padStart(2, "0")).join("")

/** A TLS extension: type + length + payload. */
function tlsExt(type, payload) {
	return [...u16(type), ...u16(payload.length), ...payload]
}

/**
 * Build a byte-accurate TLS 1.3 ClientHello carrying `domain` as the SNI.
 *
 * All length prefixes are computed, not hardcoded, so a DPI box that actually
 * parses the record sees a well-formed ClientHello rather than noise that
 * merely starts with 0x16 0x03 0x01.
 *
 * @param {string} domain
 * @param {import('./rand.js').Rng} rng
 * @returns {{ hexBytes: string, length: number }}
 */
export function buildTlsClientHello(domain, rng) {
	const name = ascii(domain)

	// server_name: list( name_type(0) + len + host )
	const sniEntry = [0x00, ...u16(name.length), ...name]
	const extServerName = tlsExt(0x0000, [...u16(sniEntry.length), ...sniEntry])

	// supported_groups: x25519, secp256r1, secp384r1, secp521r1
	const groups = [0x001d, 0x0017, 0x0018, 0x0019].flatMap(u16)
	const extGroups = tlsExt(0x000a, [...u16(groups.length), ...groups])

	// ec_point_formats: uncompressed, ansiX962_*
	const extPointFormats = tlsExt(0x000b, [0x03, 0x00, 0x01, 0x02])

	// ALPN: h2, http/1.1
	const alpn = [2, ...ascii("h2"), 8, ...ascii("http/1.1")]
	const extAlpn = tlsExt(0x0010, [...u16(alpn.length), ...alpn])

	// signature_algorithms
	const sigAlgs = [
		0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
	].flatMap(u16)
	const extSigAlgs = tlsExt(0x000d, [...u16(sigAlgs.length), ...sigAlgs])

	// supported_versions: TLS 1.3, 1.2
	const versions = [0x0304, 0x0303].flatMap(u16)
	const extVersions = tlsExt(0x002b, [versions.length, ...versions])

	// psk_key_exchange_modes: psk_dhe_ke
	const extPskModes = tlsExt(0x002d, [0x01, 0x01])

	// key_share: one x25519 share (32 bytes)
	const share = [...u16(0x001d), ...u16(32), ...rng.bytes(32)]
	const extKeyShare = tlsExt(0x0033, [...u16(share.length), ...share])

	// session_ticket (empty) and encrypt_then_mac, for a realistic mix
	const extSessionTicket = tlsExt(0x0023, [])
	const extRenegotiation = tlsExt(0xff01, [0x00])

	const extensions = [
		...extServerName,
		...extPointFormats,
		...extGroups,
		...extSessionTicket,
		...extAlpn,
		...extSigAlgs,
		...extVersions,
		...extPskModes,
		...extKeyShare,
		...extRenegotiation,
	]

	// TLS 1.3 sends a fake 32-byte legacy session id for middlebox compatibility.
	const sessionId = rng.bytes(32)

	// A realistic modern cipher suite list.
	const suites = [
		0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9,
		0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
	].flatMap(u16)

	const body = [
		...u16(0x0303), // legacy_version = TLS 1.2
		...rng.bytes(32), // client_random
		32,
		...sessionId,
		...u16(suites.length),
		...suites,
		0x01,
		0x00, // compression: null
		...u16(extensions.length),
		...extensions,
	]

	const handshake = [0x01, ...u24(body.length), ...body]
	const record = [0x16, ...u16(0x0301), ...u16(handshake.length), ...handshake]

	return { hexBytes: hex(record), length: record.length }
}

const QUIC_INITIAL_SALT = Buffer.from([
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
])

function quicHmac(key, data) {
	return crypto.createHmac("sha256", key).update(data).digest()
}

function quicExpandLabel(secret, label, length) {
	const labelBytes = Buffer.from("tls13 " + label, "utf8")
	const info = Buffer.concat([
		Buffer.from([(length >> 8) & 0xff, length & 0xff]),
		Buffer.from([labelBytes.length]),
		labelBytes,
		Buffer.from([0, 1]),
	])
	return quicHmac(secret, info).subarray(0, length)
}

function quicVarint(x) {
	if (x < 0x40) return Buffer.from([x])
	if (x < 0x4000) return Buffer.from([(x >> 8) | 0x40, x & 0xff])
	return Buffer.from([(x >> 24) | 0x80, (x >> 16) & 0xff, (x >> 8) & 0xff, x & 0xff])
}

function quicCryptoFrame(clientHello) {
	const offset = quicVarint(0)
	const len = quicVarint(clientHello.length)
	return Buffer.concat([Buffer.from([0x06]), offset, len, clientHello])
}

/**
 * Build a byte-accurate, RFC 9000-compliant QUIC v1 Initial packet with HKDF,
 * AES-128-GCM encryption and header protection carrying TLS 1.3 ClientHello with SNI.
 * Indistinguishable from real HTTP/3 traffic by DPI/TSPU boxes.
 */
export function buildQuicInitial(domain, rng) {
	const dcid = rng ? Buffer.from(rng.bytes(8)) : crypto.randomBytes(8)
	const pkn = Buffer.from([0])
	const { hexBytes: clientHelloHex } = buildTlsClientHello(domain, rng)
	const clientHello = Buffer.from(clientHelloHex, "hex")
	const payload = quicCryptoFrame(clientHello)

	const headerParts = [
		Buffer.from([0xc0 | (pkn.length - 1)]),
		Buffer.from([0x00, 0x00, 0x00, 0x01]), // Version 1
		Buffer.from([dcid.length]),
		dcid,
		Buffer.from([0x00, 0x00]), // SCID len 0, token len 0
		quicVarint(pkn.length + payload.length + 16),
		pkn,
	]
	const header = Buffer.concat(headerParts)
	const headerLen = header.length

	const initialSecret = quicHmac(QUIC_INITIAL_SALT, dcid)
	const clientIn = quicExpandLabel(initialSecret, "client in", 32)
	const key = quicExpandLabel(clientIn, "quic key", 16)
	const iv = quicExpandLabel(clientIn, "quic iv", 12)
	const hp = quicExpandLabel(clientIn, "quic hp", 16)

	for (let i = 0; i < pkn.length; i++) {
		iv[iv.length - pkn.length + i] ^= pkn[i]
	}

	const cipher = crypto.createCipheriv("aes-128-gcm", key, iv)
	cipher.setAAD(header)
	const encryptedPayload = cipher.update(payload)
	cipher.final()
	const authTag = cipher.getAuthTag()
	const ciphertext = Buffer.concat([encryptedPayload, authTag])

	const sampleOffset = 4 - pkn.length
	const sample = ciphertext.subarray(sampleOffset, sampleOffset + 16)
	const hpCipher = crypto.createCipheriv("aes-128-ecb", hp, null)
	hpCipher.setAutoPadding(false)
	const mask = hpCipher.update(sample)

	header[0] ^= mask[0] & 0x0f
	for (let i = 0; i < pkn.length; i++) {
		header[headerLen - pkn.length + i] ^= mask[1 + i]
	}

	const packet = Buffer.concat([header, ciphertext])
	return { hexBytes: packet.toString("hex"), length: packet.length }
}

/**
 * Fake-packet templates for AmneziaWG 1.5 I1..I5.
 *
 * Template DSL understood by AmneziaWG:
 *   <b 0xHEX>  literal bytes
 *   <c>        4-byte incrementing counter
 *   <t>        4-byte unix timestamp
 *   <r N>      N random bytes
 */
export const PACKET_SIGNATURES = {
	tls: {
		label: "TLS 1.3 ClientHello (HTTPS)",
		labelRu: "TLS 1.3 ClientHello (HTTPS)",
		usesDomain: true,
		description:
			"A byte-accurate HTTPS handshake carrying a real SNI. The most boring packet on the internet.",
		descriptionRu:
			"Побайтово корректный HTTPS-handshake с настоящим SNI. Самый обычный пакет в интернете.",
		build: (rng, domain) => {
			const { hexBytes } = buildTlsClientHello(domain, rng)
			return `<b 0x${hexBytes}>`
		},
	},
	quic: {
		label: "QUIC Initial (HTTP/3)",
		labelRu: "QUIC Initial (HTTP/3)",
		usesDomain: true,
		description:
			"Long-header QUIC v1 Initial with real AES-GCM encryption & SNI. Bypasses strict DPI.",
		descriptionRu:
			"QUIC v1 Initial с настоящим шифрованием AES-GCM и подменой SNI. Пробивает строгий DPI.",
		build: (rng, domain) => {
			const { hexBytes } = buildQuicInitial(domain, rng)
			return `<b 0x${hexBytes}>`
		},
	},
	dtls: {
		label: "DTLS 1.2 ClientHello (WebRTC)",
		labelRu: "DTLS 1.2 ClientHello (WebRTC)",
		usesDomain: false,
		description:
			"Mimics a video-call handshake. Blocking it kills Zoom, Meet and Discord, so it is usually allowed.",
		descriptionRu:
			"\u0418\u043c\u0438\u0442\u0438\u0440\u0443\u0435\u0442 handshake \u0432\u0438\u0434\u0435\u043e\u0437\u0432\u043e\u043d\u043a\u0430. \u0411\u043b\u043e\u043a\u0438\u0440\u043e\u0432\u043a\u0430 \u043b\u043e\u043c\u0430\u0435\u0442 Zoom, Meet \u0438 Discord.",
		build: (rng) =>
			`<b 0x16fefd0000000000000000><b 0x00360100002a000000000000002a><b 0xfefd><t><r 28><b 0x000002002f0100><r ${rng.int(40, 120)}>`,
	},
	stun: {
		label: "STUN Binding Request",
		labelRu: "STUN Binding Request",
		usesDomain: false,
		description:
			"NAT-traversal probe with the real 0x2112A442 magic cookie. Tiny, boring, whitelisted almost everywhere.",
		descriptionRu:
			"NAT-\u0437\u0430\u043f\u0440\u043e\u0441 \u0441 \u043d\u0430\u0441\u0442\u043e\u044f\u0449\u0438\u043c cookie 0x2112A442. \u041a\u0440\u043e\u0448\u0435\u0447\u043d\u044b\u0439 \u0438 \u0440\u0430\u0437\u0440\u0435\u0448\u0451\u043d \u043f\u043e\u0447\u0442\u0438 \u0432\u0435\u0437\u0434\u0435.",
		build: (rng) => `<b 0x0001002c2112a442><r 12><b 0x00060009><r ${rng.int(24, 72)}>`,
	},
	dns: {
		label: "DNS query over UDP",
		labelRu: "DNS-\u0437\u0430\u043f\u0440\u043e\u0441 \u043f\u043e UDP",
		usesDomain: true,
		description: "Looks like a plain recursive lookup for the chosen domain. Very low suspicion.",
		descriptionRu:
			"\u0412\u044b\u0433\u043b\u044f\u0434\u0438\u0442 \u043a\u0430\u043a \u043e\u0431\u044b\u0447\u043d\u044b\u0439 DNS-\u0437\u0430\u043f\u0440\u043e\u0441 \u0432\u044b\u0431\u0440\u0430\u043d\u043d\u043e\u0433\u043e \u0434\u043e\u043c\u0435\u043d\u0430.",
		build: (rng, domain) => {
			// QNAME is length-prefixed labels terminated by a zero byte.
			const qname = domain
				.split(".")
				.flatMap((label) => [label.length, ...ascii(label)])
			const query = [
				...u16(0x0100), // standard query, recursion desired
				...u16(1), // qdcount
				...u16(0),
				...u16(0),
				...u16(0),
				...qname,
				0x00,
				...u16(1), // type A
				...u16(1), // class IN
			]
			return `<r 2><b 0x${hex(query)}>`
		},
	},
	rtp: {
		label: "SRTP media stream",
		labelRu: "SRTP \u043c\u0435\u0434\u0438\u0430-\u043f\u043e\u0442\u043e\u043a",
		usesDomain: false,
		description: "Imitates an ongoing encrypted voice call. Good camouflage for long-lived tunnels.",
		descriptionRu:
			"\u0418\u043c\u0438\u0442\u0438\u0440\u0443\u0435\u0442 \u0438\u0434\u0443\u0449\u0438\u0439 \u0433\u043e\u043b\u043e\u0441\u043e\u0432\u043e\u0439 \u0437\u0432\u043e\u043d\u043e\u043a. \u0425\u043e\u0440\u043e\u0448\u043e \u0434\u043b\u044f \u0434\u043e\u043b\u0433\u0438\u0445 \u0441\u0435\u0441\u0441\u0438\u0439.",
		build: (rng) => `<b 0x80${rng.int(96, 127).toString(16)}><c><t><r 4><r ${rng.int(80, 200)}>`,
	},
	openvpn: {
		label: "OpenVPN hard-reset",
		labelRu: "OpenVPN hard-reset",
		usesDomain: false,
		description: "Identifies as OpenVPN. Useful only where OpenVPN is tolerated but WireGuard is throttled.",
		descriptionRu:
			"\u041f\u0440\u0435\u0434\u0441\u0442\u0430\u0432\u043b\u044f\u0435\u0442\u0441\u044f OpenVPN. \u041f\u043e\u043b\u0435\u0437\u043d\u043e \u0442\u0430\u043c, \u0433\u0434\u0435 \u0440\u0435\u0436\u0443\u0442 WireGuard, \u043d\u043e \u043d\u0435 OpenVPN.",
		build: (rng) => `<b 0x38><r 8><b 0x0000000000><c><r ${rng.int(16, 48)}>`,
	},
}

// ---------------------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------------------

/**
 * `compat: "warp"` profiles keep S1/S2 at 0 and never emit H1-H4 (an
 * AmneziaWG client without H lines falls back to the stock 1/2/3/4 header,
 * which is the only form Cloudflare accepts). That is not laziness - it is
 * the only way the tunnel actually connects.
 */
export const PROFILES = {
	off: {
		label: "Off - plain WireGuard",
		labelRu: "\u0412\u044b\u043a\u043b - \u0447\u0438\u0441\u0442\u044b\u0439 WireGuard",
		summary: "No obfuscation. Fastest, but trivially fingerprinted by DPI.",
		summaryRu:
			"\u0411\u0435\u0437 \u043e\u0431\u0444\u0443\u0441\u043a\u0430\u0446\u0438\u0438. \u0411\u044b\u0441\u0442\u0440\u0435\u0435 \u0432\u0441\u0435\u0433\u043e, \u043d\u043e DPI \u0432\u0438\u0434\u0438\u0442 \u0435\u0433\u043e \u043c\u0433\u043d\u043e\u0432\u0435\u043d\u043d\u043e.",
		compat: "warp",
		obfuscated: false,
	},
	"warp-light": {
		label: "Light - a few junk packets",
		labelRu: "\u041b\u0451\u0433\u043a\u0430\u044f - \u043d\u0435\u043c\u043d\u043e\u0433\u043e \u043c\u0443\u0441\u043e\u0440\u0430",
		summary: "Two to four small junk packets. Almost no overhead, hides the lone handshake.",
		summaryRu:
			"\u0414\u0432\u0430-\u0447\u0435\u0442\u044b\u0440\u0435 \u043c\u0435\u043b\u043a\u0438\u0445 \u043c\u0443\u0441\u043e\u0440\u043d\u044b\u0445 \u043f\u0430\u043a\u0435\u0442\u0430. \u041f\u043e\u0447\u0442\u0438 \u0431\u0435\u0437 \u043d\u0430\u043a\u043b\u0430\u0434\u043d\u044b\u0445 \u0440\u0430\u0441\u0445\u043e\u0434\u043e\u0432.",
		compat: "warp",
		obfuscated: true,
		jc: [2, 4],
		junk: [24, 96],
	},
	"warp-balanced": {
		label: "Balanced (recommended)",
		labelRu: "\u0421\u0431\u0430\u043b\u0430\u043d\u0441\u0438\u0440\u043e\u0432\u0430\u043d\u043d\u0430\u044f (\u0440\u0435\u043a\u043e\u043c\u0435\u043d\u0434\u0443\u0435\u0442\u0441\u044f)",
		summary: "Five to nine junk packets of varied size. The setting most people should use with WARP.",
		summaryRu:
			"\u041f\u044f\u0442\u044c-\u0434\u0435\u0432\u044f\u0442\u044c \u043c\u0443\u0441\u043e\u0440\u043d\u044b\u0445 \u043f\u0430\u043a\u0435\u0442\u043e\u0432 \u0440\u0430\u0437\u043d\u043e\u0433\u043e \u0440\u0430\u0437\u043c\u0435\u0440\u0430. \u041b\u0443\u0447\u0448\u0438\u0439 \u0432\u044b\u0431\u043e\u0440 \u0434\u043b\u044f WARP.",
		compat: "warp",
		obfuscated: true,
		jc: [5, 9],
		junk: [40, 200],
	},
	"warp-heavy": {
		label: "Heavy - maximum junk",
		labelRu: "\u0422\u044f\u0436\u0451\u043b\u0430\u044f - \u043c\u0430\u043a\u0441\u0438\u043c\u0443\u043c \u043c\u0443\u0441\u043e\u0440\u0430",
		summary: "Twelve to twenty larger junk packets. Slower to connect, hardest to classify by volume.",
		summaryRu:
			"\u0414\u0432\u0435\u043d\u0430\u0434\u0446\u0430\u0442\u044c-\u0434\u0432\u0430\u0434\u0446\u0430\u0442\u044c \u043a\u0440\u0443\u043f\u043d\u044b\u0445 \u043f\u0430\u043a\u0435\u0442\u043e\u0432. \u041f\u043e\u0434\u043a\u043b\u044e\u0447\u0430\u0435\u0442\u0441\u044f \u043c\u0435\u0434\u043b\u0435\u043d\u043d\u0435\u0435.",
		compat: "warp",
		obfuscated: true,
		jc: [12, 20],
		junk: [64, 512],
	},
	"warp-cloak": {
		label: "Cloak - proven bash-warp recipe",
		labelRu: "\u041f\u043b\u0430\u0449 - \u043e\u0431\u043a\u0430\u0442\u0430\u043d\u043d\u044b\u0439 \u0440\u0435\u0446\u0435\u043f\u0442 bash-warp",
		summary:
			"Exactly the numbers the widely used bash-warp-generator ships: 120 junk packets of 23-911 bytes plus one fake QUIC packet. Needs AmneziaWG 1.5+.",
		summaryRu:
			"\u0420\u043e\u0432\u043d\u043e \u0442\u0435 \u0447\u0438\u0441\u043b\u0430, \u0447\u0442\u043e \u043e\u0442\u0434\u0430\u0451\u0442 \u043c\u0430\u0441\u0441\u043e\u0432\u044b\u0439 bash-warp-generator: 120 \u043c\u0443\u0441\u043e\u0440\u043d\u044b\u0445 \u043f\u0430\u043a\u0435\u0442\u043e\u0432 \u043f\u043e 23-911 \u0431\u0430\u0439\u0442 \u0438 \u043e\u0434\u0438\u043d \u0444\u0430\u043b\u044c\u0448\u0438\u0432\u044b\u0439 QUIC-\u043f\u0430\u043a\u0435\u0442. \u041d\u0443\u0436\u0435\u043d AmneziaWG 1.5+.",
		compat: "warp",
		obfuscated: true,
		version: "1.5",
		// Pinned on purpose: this exact combination is proven in the field by
		// thousands of bash-warp-generator users. Reproducible regardless of seed.
		fixed: { jc: 120, jmin: 23, jmax: 911 },
		jc: [120, 120],
		junk: [23, 911],
		signatures: ["quic"],
		itime: [0, 0],
	},
	"awg-standard": {
		label: "Full obfuscation (own server)",
		labelRu: "\u041f\u043e\u043b\u043d\u0430\u044f \u043e\u0431\u0444\u0443\u0441\u043a\u0430\u0446\u0438\u044f (\u0441\u0432\u043e\u0439 \u0441\u0435\u0440\u0432\u0435\u0440)",
		summary: "Junk packets, handshake padding and magic headers. Requires your own AmneziaWG server.",
		summaryRu:
			"\u041c\u0443\u0441\u043e\u0440, \u0434\u043e\u0431\u0438\u0432\u043a\u0430 handshake \u0438 \u043c\u0430\u0433\u0438\u0447\u0435\u0441\u043a\u0438\u0435 \u0437\u0430\u0433\u043e\u043b\u043e\u0432\u043a\u0438. \u041d\u0443\u0436\u0435\u043d \u0441\u0432\u043e\u0439 \u0441\u0435\u0440\u0432\u0435\u0440 AmneziaWG.",
		compat: "awg",
		obfuscated: true,
		jc: [4, 8],
		junk: [40, 200],
		s1: [30, 90],
		s2: [30, 90],
		headers: true,
	},
	"awg-paranoid": {
		label: "Paranoid (own server)",
		labelRu: "\u041f\u0430\u0440\u0430\u043d\u043e\u0438\u0434\u0430\u043b\u044c\u043d\u0430\u044f (\u0441\u0432\u043e\u0439 \u0441\u0435\u0440\u0432\u0435\u0440)",
		summary: "Heavy junk plus large handshake padding. Hardest to classify, slowest to connect.",
		summaryRu:
			"\u041c\u043d\u043e\u0433\u043e \u043c\u0443\u0441\u043e\u0440\u0430 \u0438 \u0431\u043e\u043b\u044c\u0448\u0430\u044f \u0434\u043e\u0431\u0438\u0432\u043a\u0430. \u0421\u0430\u043c\u0430\u044f \u0441\u043a\u0440\u044b\u0442\u043d\u0430\u044f \u0438 \u0441\u0430\u043c\u0430\u044f \u043c\u0435\u0434\u043b\u0435\u043d\u043d\u0430\u044f.",
		compat: "awg",
		obfuscated: true,
		jc: [8, 16],
		junk: [64, 640],
		s1: [60, 150],
		s2: [60, 150],
		headers: true,
	},
	"awg-mimicry": {
		label: "Protocol mimicry (AmneziaWG 1.5+, own server)",
		labelRu: "\u041c\u0438\u043c\u0438\u043a\u0440\u0438\u044f \u043f\u0440\u043e\u0442\u043e\u043a\u043e\u043b\u0430 (AmneziaWG 1.5+, \u0441\u0432\u043e\u0439 \u0441\u0435\u0440\u0432\u0435\u0440)",
		summary: "Opens the tunnel with fake TLS/QUIC packets carrying a real domain. Needs AmneziaWG 1.5 on both ends.",
		summaryRu:
			"\u041e\u0442\u043a\u0440\u044b\u0432\u0430\u0435\u0442 \u0442\u0443\u043d\u043d\u0435\u043b\u044c \u0444\u0430\u043b\u044c\u0448\u0438\u0432\u044b\u043c\u0438 TLS/QUIC-\u043f\u0430\u043a\u0435\u0442\u0430\u043c\u0438 \u0441 \u043d\u0430\u0441\u0442\u043e\u044f\u0449\u0438\u043c \u0434\u043e\u043c\u0435\u043d\u043e\u043c. \u041d\u0443\u0436\u0435\u043d AmneziaWG 1.5.",
		compat: "awg",
		obfuscated: true,
		version: "1.5",
		jc: [0, 2],
		junk: [32, 160],
		s1: [30, 90],
		s2: [30, 90],
		headers: true,
		signatures: ["tls", "quic"],
		itime: [30, 120],
	},
}

export const DEFAULT_PROFILE = "warp-cloak"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Pick S1/S2 while respecting the `S1 + 56 != S2` collision rule.
 * @param {import('./rand.js').Rng} rng
 */
function pickHandshakePadding(rng, s1Range, s2Range) {
	const delta = WG_PACKET_SIZES.handshakeInitiation - WG_PACKET_SIZES.handshakeResponse
	for (let attempt = 0; attempt < 64; attempt++) {
		const s1 = rng.int(s1Range[0], s1Range[1])
		const s2 = rng.int(s2Range[0], s2Range[1])
		if (s1 + delta !== s2) return { s1, s2 }
	}
	const s1 = s1Range[0]
	let s2 = s2Range[0]
	if (s1 + delta === s2) s2 += 1
	return { s1, s2 }
}

/** Pick four distinct magic headers. */
function pickMagicHeaders(rng) {
	const seen = new Set()
	while (seen.size < 4) seen.add(rng.int(LIMITS.header.min, LIMITS.header.max))
	const [h1, h2, h3, h4] = [...seen]
	return { h1, h2, h3, h4 }
}

/**
 * Cloudflare assigns 3 reserved bytes [r0, r1, r2] to each device at registration.
 * In WireGuard / AmneziaWG, H1-H4 are 32-bit little-endian message type headers.
 * Setting:
 *   H1 = 1 | (r0 << 8) | (r1 << 16) | (r2 * 0x1000000)
 *   H2 = 2 | (r0 << 8) | (r1 << 16) | (r2 * 0x1000000)
 *   H3 = 3 | (r0 << 8) | (r1 << 16) | (r2 * 0x1000000)
 *   H4 = 4 | (r0 << 8) | (r1 << 16) | (r2 * 0x1000000)
 * puts the client_id directly into the reserved bytes of WireGuard packets on the wire,
 * allowing Cloudflare to identify the tunnel and route internet traffic.
 *
 * @param {number[]|undefined} bytes 3 reserved bytes
 * @returns {{ h1: number, h2: number, h3: number, h4: number }|null}
 */
export function deriveWarpHeaders(bytes) {
	if (!bytes || !Array.isArray(bytes) || bytes.length !== 3) return null
	if (bytes[0] === 0 && bytes[1] === 0 && bytes[2] === 0) return null
	const [r0, r1, r2] = bytes
	const base = r0 * 0x100 + r1 * 0x10000 + r2 * 0x1000000
	return {
		h1: base + 1,
		h2: base + 2,
		h3: base + 3,
		h4: base + 4,
	}
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/**
 * Validate a complete parameter set. Returns problems instead of throwing so
 * the UI can show all of them at once.
 *
 * @param {Object} params
 * @param {Object} [context]
 * @param {"warp"|"awg"} [context.compat] Target server type.
 * @param {boolean} [context.headersFromClientId] Whether H1-H4 are derived from Cloudflare client_id.
 * @returns {{ valid: boolean, errors: string[], warnings: string[] }}
 */
export function validateObfuscation(params, context = {}) {
	const errors = []
	const warnings = []
	if (!params || params.enabled === false) return { valid: true, errors, warnings }

	const { jc, jmin, jmax, s1, s2, h1, h2, h3, h4 } = params
	const compat = context.compat ?? params.compat ?? "awg"
	const headersFromClientId = Boolean(context.headersFromClientId || params.headersFromClientId)

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

	if (Number.isInteger(jmin) && Number.isInteger(jmax) && jmin >= jmax) {
		errors.push(`Jmin (${jmin}) must be strictly less than Jmax (${jmax})`)
	}

	const hasS = Number.isInteger(s1) || Number.isInteger(s2)
	if (hasS) {
		intIn("S1", s1, 0, LIMITS.s.max)
		intIn("S2", s2, 0, LIMITS.s.max)
		const delta = WG_PACKET_SIZES.handshakeInitiation - WG_PACKET_SIZES.handshakeResponse
		if (Number.isInteger(s1) && Number.isInteger(s2) && s1 + delta === s2) {
			errors.push(
				`S1 + ${delta} must not equal S2 (S1=${s1}, S2=${s2}). Otherwise the padded ` +
					`initiation and response packets become the same size and AmneziaWG rejects the config.`,
			)
		}
	}

	const headers = [h1, h2, h3, h4]
	const hasHeaders = headers.some((h) => h !== undefined && h !== null)
	if (hasHeaders) {
		const isStock = h1 === 1 && h2 === 2 && h3 === 3 && h4 === 4
		const minH = compat === "warp" && isStock ? 1 : LIMITS.header.min
		const maxH = headersFromClientId ? HEADER_UINT32_MAX : LIMITS.header.max
		headers.forEach((h, i) => intIn(`H${i + 1}`, h, minH, maxH))
		if (headers.every(Number.isInteger) && new Set(headers).size !== 4) {
			errors.push("H1, H2, H3 and H4 must all be different values")
		}
	}

	// --- The WARP compatibility rules, the whole point of this rewrite --------
	if (compat === "warp") {
		if (Number.isInteger(s1) && s1 !== 0) {
			errors.push(
				`S1 must be 0 for Cloudflare WARP (got ${s1}). WARP runs stock WireGuard and ` +
					`cannot parse a padded handshake initiation, so the tunnel would never connect.`,
			)
		}
		if (Number.isInteger(s2) && s2 !== 0) {
			errors.push(
				`S2 must be 0 for Cloudflare WARP (got ${s2}). WARP runs stock WireGuard and ` +
					`cannot parse a padded handshake response.`,
			)
		}
		if (hasHeaders) {
			const isStock = h1 === 1 && h2 === 2 && h3 === 3 && h4 === 4
			if (!isStock && !headersFromClientId) {
				errors.push(
					"H1-H4 cannot be random: Cloudflare WARP requires stock headers (H1=1, H2=2, H3=3, H4=4) or client_id derived headers.",
				)
			} else if (headersFromClientId) {
				if (
					(h1 & 0xff) !== 1 ||
					(h2 & 0xff) !== 2 ||
					(h3 & 0xff) !== 3 ||
					(h4 & 0xff) !== 4
				) {
					errors.push(
						"H1-H4 derived from client_id must preserve WireGuard message types 1, 2, 3, 4 in the low byte.",
					)
				}
			}
		}
		// I1-I5 are sender-side camouflage: Cloudflare drops them like junk.
		// The only constraint is the CLIENT being AmneziaWG 1.5+.
		if ((params.signatures?.length ?? 0) > 0 || params.version === "1.5") {
			warnings.push(
				"Fake packets (I1-I5) need AmneziaWG 1.5+ on the CLIENT; older clients refuse to " +
					"import this config. Cloudflare just drops them, like junk packets.",
			)
		}
		if (Number.isInteger(jc) && jc === 0 && (params.signatures?.length ?? 0) === 0) {
			warnings.push(
				"Jc=0 and no fake packets means no obfuscation at all: S1/S2 and H1-H4 are unavailable with WARP.",
			)
		}
	}

	if (Number.isInteger(jc) && jc > 32) {
		warnings.push(`Jc=${jc} sends a lot of junk on every handshake. This is slow on high-latency links.`)
	}
	if (Number.isInteger(jmax) && jmax > 1280) {
		warnings.push("Jmax above 1280 risks IP fragmentation, which is itself a DPI signal.")
	}
	if (compat === "awg" && params.version === "1.5") {
		warnings.push(
			"I1-I5 require AmneziaWG 1.5+ on BOTH peers. Older clients refuse to parse this config.",
		)
	}
	if (compat === "awg") {
		warnings.push(
			"This profile targets your own AmneziaWG server. It will NOT connect to Cloudflare WARP.",
		)
	}

	return { valid: errors.length === 0, errors, warnings }
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

/**
 * Generate an obfuscation parameter set.
 *
 * @param {Object} [options]
 * @param {keyof typeof PROFILES} [options.profile]
 * @param {string} [options.seed]
 * @param {Object} [options.overrides]
 * @param {string[]} [options.signatures] Signature ids for mimicry mode.
 * @param {string} [options.mimicryDomain] SNI written into the fake packets.
 * @returns {Object} obfuscation descriptor
 */
export function generateObfuscation(options = {}) {
	const profileName = options.profile ?? DEFAULT_PROFILE
	const preset = PROFILES[profileName]
	if (!preset) {
		throw new ObfuscationError(
			`Unknown profile "${profileName}". Available: ${Object.keys(PROFILES).join(", ")}`,
		)
	}

	const seed = options.seed || makeSeed()
	const rng = createRng(seed)
	const compat = preset.compat
	const domain = options.mimicryDomain || DEFAULT_MIMICRY_DOMAIN

	if (!preset.obfuscated) {
		return {
			enabled: false,
			profile: profileName,
			profileLabel: preset.label,
			profileLabelRu: preset.labelRu,
			summary: preset.summary,
			summaryRu: preset.summaryRu,
			compat,
			seed,
			version: "wireguard",
			params: {},
			signatures: [],
			mimicryDomain: null,
			validation: { valid: true, errors: [], warnings: [] },
			explain: [],
		}
	}

	// --- Junk packets ----------------------------------------------------------
	// A profile may pin exact junk numbers (`fixed`) instead of rolling them,
	// which is how warp-cloak reproduces the proven bash-warp recipe.
	const jc = preset.fixed?.jc ?? rng.int(preset.jc[0], preset.jc[1])
	let jmin =
		preset.fixed?.jmin ?? rng.int(preset.junk[0], Math.max(preset.junk[0], preset.junk[1] - 8))
	let jmax =
		preset.fixed?.jmax ?? rng.int(jmin + 8, Math.max(jmin + 8, preset.junk[1]))
	if (jmax > LIMITS.junkSize.max) jmax = LIMITS.junkSize.max
	if (jmin >= jmax) jmin = Math.max(LIMITS.junkSize.min, jmax - 8)

	/** @type {Record<string, number>} */
	const params = { enabled: true, compat, jc, jmin, jmax }

	if (compat === "warp") {
		// Stock WireGuard on the far end: padding must stay at zero and the
		// header must stay stock WireGuard (1/2/3/4). No H lines: an AmneziaWG
		// client without H1-H4 falls back to stock values (1, 2, 3, 4), which is
		// the only format Cloudflare accepts.
		params.s1 = 0
		params.s2 = 0
	} else {
		const { s1, s2 } = pickHandshakePadding(rng, preset.s1, preset.s2)
		params.s1 = s1
		params.s2 = s2
		if (preset.headers) Object.assign(params, pickMagicHeaders(rng))
	}

	// --- AmneziaWG 1.5 fake packets ---------------------------------------------
	// Sender-side camouflage. Against WARP the server simply drops them (the
	// proven bash-warp-generator ships exactly one such packet); against an
	// own AmneziaWG server both sides understand them.
	let signatures = []
	if (preset.signatures?.length || options.signatures?.length) {
		const requested = (
			options.signatures?.length ? options.signatures : preset.signatures
		).filter((id) => PACKET_SIGNATURES[id])

		signatures = requested.slice(0, 5).map((id, index) => {
			const sig = PACKET_SIGNATURES[id]
			return {
				key: `I${index + 1}`,
				id,
				label: sig.label,
				labelRu: sig.labelRu,
				description: sig.description,
				descriptionRu: sig.descriptionRu,
				domain: sig.usesDomain ? domain : null,
				template: sig.build(rng, domain),
			}
		})
	}

	const version = signatures.length || preset.version === "1.5" ? "1.5" : "1.0"
	params.version = version
	if (version === "1.5" && preset.itime) {
		params.itime = preset.fixed?.itime ?? rng.int(preset.itime[0], preset.itime[1])
	}

	Object.assign(params, options.overrides || {})

	const validation = validateObfuscation({ ...params, signatures }, { compat })

	return {
		enabled: true,
		profile: profileName,
		profileLabel: preset.label,
		profileLabelRu: preset.labelRu,
		summary: preset.summary,
		summaryRu: preset.summaryRu,
		compat,
		seed,
		version,
		params,
		signatures,
		mimicryDomain: signatures.some((s) => s.domain) ? domain : null,
		validation,
		explain: explainParams(params, signatures),
	}
}

// ---------------------------------------------------------------------------
// Explanation + rendering
// ---------------------------------------------------------------------------

/**
 * Human-readable explanation of each parameter, for the UI.
 * @param {Object} params
 * @param {Array} [signatures]
 * @returns {Array<{ key: string, value: string|number, what: string, whatRu: string }>}
 */
export function explainParams(params, signatures = []) {
	if (!params?.enabled) return []
	const rows = [
		{
			key: "Jc",
			value: params.jc,
			what: `${params.jc} junk packet(s) are sent before each real handshake, so the first thing DPI sees is not a WireGuard initiation.`,
			whatRu: `\u041f\u0435\u0440\u0435\u0434 \u043a\u0430\u0436\u0434\u044b\u043c handshake \u043e\u0442\u043f\u0440\u0430\u0432\u043b\u044f\u0435\u0442\u0441\u044f ${params.jc} \u043c\u0443\u0441\u043e\u0440\u043d\u044b\u0445 \u043f\u0430\u043a\u0435\u0442\u043e\u0432, \u043f\u043e\u044d\u0442\u043e\u043c\u0443 DPI \u0432\u0438\u0434\u0438\u0442 \u043d\u0435 \u0447\u0438\u0441\u0442\u044b\u0439 WireGuard.`,
		},
		{
			key: "Jmin / Jmax",
			value: `${params.jmin} / ${params.jmax}`,
			what: `Each junk packet is a random ${params.jmin}-${params.jmax} bytes, so packet-size histograms do not form a clean signature.`,
			whatRu: `\u041a\u0430\u0436\u0434\u044b\u0439 \u043c\u0443\u0441\u043e\u0440\u043d\u044b\u0439 \u043f\u0430\u043a\u0435\u0442 \u2014 \u0441\u043b\u0443\u0447\u0430\u0439\u043d\u044b\u0435 ${params.jmin}-${params.jmax} \u0431\u0430\u0439\u0442, \u0447\u0442\u043e\u0431\u044b \u0440\u0430\u0437\u043c\u0435\u0440\u044b \u043d\u0435 \u0441\u043a\u043b\u0430\u0434\u044b\u0432\u0430\u043b\u0438\u0441\u044c \u0432 \u0441\u0438\u0433\u043d\u0430\u0442\u0443\u0440\u0443.`,
		},
	]

	if (params.compat === "warp") {
		rows.push({
			key: "S1 / S2",
			value: "0 / 0",
			what: "Forced to zero. Cloudflare runs stock WireGuard and cannot parse padded handshake packets - any other value means the tunnel never connects.",
			whatRu:
				"\u041f\u0440\u0438\u043d\u0443\u0434\u0438\u0442\u0435\u043b\u044c\u043d\u043e 0. Cloudflare \u2014 \u043e\u0431\u044b\u0447\u043d\u044b\u0439 WireGuard \u0438 \u043d\u0435 \u043f\u043e\u043d\u0438\u043c\u0430\u0435\u0442 \u0434\u043e\u0431\u0438\u0442\u044b\u0439 handshake. \u041b\u044e\u0431\u043e\u0435 \u0434\u0440\u0443\u0433\u043e\u0435 \u0437\u043d\u0430\u0447\u0435\u043d\u0438\u0435 \u2014 \u0442\u0443\u043d\u043d\u0435\u043b\u044c \u043d\u0435 \u043f\u043e\u0434\u043d\u0438\u043c\u0435\u0442\u0441\u044f.",
		})
	} else {
		rows.push(
			{
				key: "S1",
				value: params.s1,
				what: `${params.s1} bytes of padding are prepended to the handshake initiation, changing it from the well-known 148 bytes to ${148 + params.s1}.`,
				whatRu: `\u041a handshake-\u0438\u043d\u0438\u0446\u0438\u0430\u0446\u0438\u0438 \u0434\u043e\u0431\u0430\u0432\u043b\u044f\u0435\u0442\u0441\u044f ${params.s1} \u0431\u0430\u0439\u0442, \u0440\u0430\u0437\u043c\u0435\u0440 \u043c\u0435\u043d\u044f\u0435\u0442\u0441\u044f \u0441\u043e 148 \u043d\u0430 ${148 + params.s1}.`,
			},
			{
				key: "S2",
				value: params.s2,
				what: `${params.s2} bytes are prepended to the handshake response, moving it from 92 to ${92 + params.s2} bytes.`,
				whatRu: `\u041a \u043e\u0442\u0432\u0435\u0442\u0443 handshake \u0434\u043e\u0431\u0430\u0432\u043b\u044f\u0435\u0442\u0441\u044f ${params.s2} \u0431\u0430\u0439\u0442: \u0441 92 \u043d\u0430 ${92 + params.s2}.`,
			},
		)
	}

	if (Number.isInteger(params.h1)) {
		rows.push({
			key: "H1-H4",
			value: `${params.h1}, ${params.h2}, ${params.h3}, ${params.h4}`,
			what: "Replaces WireGuard's message type bytes 1/2/3/4 (init, response, cookie, transport) with custom values, defeating signature matching on the first four bytes. The far end must run AmneziaWG with the SAME values.",
			whatRu:
				"\u0417\u0430\u043c\u0435\u043d\u044f\u0435\u0442 \u0442\u0438\u043f\u044b \u043f\u0430\u043a\u0435\u0442\u043e\u0432 WireGuard 1/2/3/4 \u043d\u0430 \u0441\u0432\u043e\u0438 \u0437\u043d\u0430\u0447\u0435\u043d\u0438\u044f, \u043b\u043e\u043c\u0430\u044f \u043f\u043e\u0438\u0441\u043a \u043f\u043e \u043f\u0435\u0440\u0432\u044b\u043c \u0447\u0435\u0442\u044b\u0440\u0451\u043c \u0431\u0430\u0439\u0442\u0430\u043c. \u041d\u0430 \u0442\u043e\u043c \u043a\u043e\u043d\u0446\u0435 \u0442\u043e\u0436\u0435 \u0434\u043e\u043b\u0436\u0435\u043d \u0431\u044b\u0442\u044c AmneziaWG \u0441 \u0442\u0435\u043c\u0438 \u0436\u0435 \u0437\u043d\u0430\u0447\u0435\u043d\u0438\u044f\u043c\u0438.",
		})
	}

	if (params.itime) {
		rows.push({
			key: "Itime",
			value: params.itime,
			what: `Fake protocol packets are re-sent every ${params.itime}s to keep the disguise alive on long sessions.`,
			whatRu: `\u0424\u0430\u043b\u044c\u0448\u0438\u0432\u044b\u0435 \u043f\u0430\u043a\u0435\u0442\u044b \u043f\u043e\u0432\u0442\u043e\u0440\u044f\u044e\u0442\u0441\u044f \u043a\u0430\u0436\u0434\u044b\u0435 ${params.itime} \u0441, \u0447\u0442\u043e\u0431\u044b \u043c\u0430\u0441\u043a\u0438\u0440\u043e\u0432\u043a\u0430 \u0436\u0438\u043b\u0430 \u0434\u043e\u043b\u044c\u0448\u0435.`,
		})
	}

	for (const sig of signatures) {
		rows.push({
			key: sig.key,
			value: sig.domain ? `${sig.label} \u2192 ${sig.domain}` : sig.label,
			what: sig.description,
			whatRu: sig.descriptionRu,
		})
	}
	return rows
}

/**
 * Emit the `[Interface]` lines for the obfuscation parameters, in the order the
 * AmneziaWG clients expect. Keys that are not applicable are omitted entirely
 * rather than written as zero, because some clients treat a present-but-zero
 * H1 differently from an absent one.
 *
 * @param {Object} obfuscation
 * @returns {string[]}
 */
export function renderObfuscationLines(obfuscation) {
	if (!obfuscation?.enabled) return []
	const p = obfuscation.params
	const lines = [`Jc = ${p.jc}`, `Jmin = ${p.jmin}`, `Jmax = ${p.jmax}`]

	// Only emit S1/S2 when they carry meaning. On WARP they are always 0 and
	// writing them makes the config look configurable when it is not.
	if (Number.isInteger(p.s1) && Number.isInteger(p.s2) && (p.s1 !== 0 || p.s2 !== 0)) {
		lines.push(`S1 = ${p.s1}`, `S2 = ${p.s2}`)
	}

	if (Number.isInteger(p.h1)) {
		lines.push(`H1 = ${p.h1}`, `H2 = ${p.h2}`, `H3 = ${p.h3}`, `H4 = ${p.h4}`)
	}

	for (const sig of obfuscation.signatures ?? []) {
		lines.push(`${sig.key} = ${sig.template}`)
	}
	if (p.itime) lines.push(`Itime = ${p.itime}`)

	return lines
}
