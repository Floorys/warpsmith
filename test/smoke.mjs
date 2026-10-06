/**
 * End-to-end smoke test of the core pipeline, using MOCK_WARP so it needs no
 * network access. Run with: npm run smoke
 */

import assert from "node:assert/strict"

process.env.MOCK_WARP = "1"

const { generateProfile } = await import("../src/core/generate.js")
const {
	generateObfuscation,
	validateObfuscation,
	renderObfuscationLines,
	buildTlsClientHello,
	deriveWarpHeaders,
	PROFILES,
} = await import("../src/core/amnezia.js")
const { createRng } = await import("../src/core/rand.js")
const { generateKeyPair, derivePublicKey } = await import("../src/core/keys.js")
const { calculateMtu, DNS_PRESETS } = await import("../src/core/mtu.js")
const { buildEndpoint } = await import("../src/core/endpoints.js")
const { resolvePathname, handleRequest } = await import("../src/server.js")

let passed = 0
let failed = 0

async function test(name, fn) {
	try {
		await fn()
		passed++
		console.log(`  ok   ${name}`)
	} catch (error) {
		failed++
		console.error(`  FAIL ${name}`)
		console.error(`       ${error.message}`)
	}
}

console.log("\nkeys")

await test("generates a valid X25519 keypair", () => {
	const { privateKey, publicKey } = generateKeyPair()
	assert.equal(Buffer.from(privateKey, "base64").length, 32)
	assert.equal(Buffer.from(publicKey, "base64").length, 32)
})

await test("derives the same public key from a private key", () => {
	const { privateKey, publicKey } = generateKeyPair()
	assert.equal(derivePublicKey(privateKey), publicKey)
})

await test("rejects a malformed private key", () => {
	assert.throws(() => derivePublicKey("not-a-key"))
})

console.log("\nobfuscation")

for (const profileId of Object.keys(PROFILES)) {
	await test(`profile "${profileId}" produces valid parameters`, () => {
		const result = generateObfuscation({ profile: profileId })
		assert.equal(result.validation.valid, true, result.validation.errors.join("; "))
		if (!result.enabled) return
		const p = result.params
		assert.ok(p.jmin < p.jmax, "Jmin must be < Jmax")
		assert.notEqual(p.s1 + 56, p.s2, "S1 + 56 must not equal S2")

		if (p.h1 !== undefined) {
			assert.equal(new Set([p.h1, p.h2, p.h3, p.h4]).size, 4, "H1-H4 must be distinct")
			for (const h of [p.h1, p.h2, p.h3, p.h4]) {
				assert.ok(h >= 5 && h <= 2147483647, `H value ${h} out of range`)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// The regression suite for the bug that made real configs fail to connect:
// Cloudflare WARP speaks stock WireGuard, so S1/S2 padding, random magic
// headers and 1.5 fake packets all silently kill the handshake.
// ---------------------------------------------------------------------------

for (const [profileId, preset] of Object.entries(PROFILES)) {
	if (preset.compat !== "warp") continue
	if (preset.version === "1.5" || preset.signatures?.length) continue
	await test(`WARP profile "${profileId}" stays wire-compatible with stock WireGuard`, () => {
		const result = generateObfuscation({ profile: profileId, seed: "warpcompat" })
		if (!result.enabled) return
		const p = result.params
		assert.equal(p.s1, 0, "S1 must be 0 or Cloudflare drops the handshake initiation")
		assert.equal(p.s2, 0, "S2 must be 0 or Cloudflare drops the handshake response")
		assert.equal(p.h1, undefined, "random H1-H4 would break the WARP handshake")
		assert.equal(result.signatures.length, 0, "stock WARP profile has no signatures")

		const lines = renderObfuscationLines(result)
		assert.ok(
			!lines.some((l) => /^(S[12]|H[1-4]|I[1-5]) /.test(l)),
			`WARP config must not emit S/H/I lines, got: ${lines.join(", ")}`,
		)
		assert.ok(lines.some((l) => l.startsWith("Jc = ")), "junk packets are the one safe knob")
	})
}

await test("padded handshakes are rejected for WARP", () => {
	const r = validateObfuscation(
		{ enabled: true, jc: 4, jmin: 40, jmax: 200, s1: 50, s2: 70 },
		{ compat: "warp" },
	)
	assert.equal(r.valid, false)
	assert.ok(r.errors.some((e) => e.includes("S1 must be 0")))
	assert.ok(r.errors.some((e) => e.includes("S2 must be 0")))
})

await test("random magic headers are rejected for WARP", () => {
	const r = validateObfuscation(
		{ enabled: true, jc: 4, jmin: 40, jmax: 200, s1: 0, s2: 0, h1: 11, h2: 22, h3: 33, h4: 44 },
		{ compat: "warp" },
	)
	assert.equal(r.valid, false)
	assert.ok(r.errors.some((e) => e.includes("H1-H4 cannot be random")))
})

await test("client_id derived headers keep the real WireGuard message type", () => {
	const h = deriveWarpHeaders([0x2a, 0xdd, 0x5b])
	assert.ok(h, "a non-zero client_id must yield headers")
	assert.equal(h.h1 & 0xff, 1, "low byte must stay message type 1 (initiation)")
	assert.equal(h.h2 & 0xff, 2, "low byte must stay message type 2 (response)")
	assert.equal(h.h3 & 0xff, 3, "low byte must stay message type 3 (cookie)")
	assert.equal(h.h4 & 0xff, 4, "low byte must stay message type 4 (transport)")
	assert.equal(new Set(Object.values(h)).size, 4)
	// These must survive the validator when flagged as client_id derived.
	const r = validateObfuscation(
		{ enabled: true, jc: 4, jmin: 40, jmax: 200, s1: 0, s2: 0, ...h },
		{ compat: "warp", headersFromClientId: true },
	)
	assert.equal(r.valid, true, r.errors.join("; "))
})

await test("an unusable client_id yields no headers rather than a broken config", () => {
	assert.equal(deriveWarpHeaders([0, 0, 0]), null, "all-zero client_id")
	assert.equal(deriveWarpHeaders(undefined), null)
	assert.equal(deriveWarpHeaders([1, 2]), null, "a client_id is exactly three bytes")
	// A high third byte is NOT unusable. It only pushes the header past 2^31,
	// which is an int32 UI habit rather than a protocol limit; treating it as
	// unusable is what stripped the client_id from half of all configs.
})

console.log("\nprotocol mimicry")

await test("the TLS ClientHello is byte-accurate and carries the chosen domain", () => {
	for (const domain of ["github.com", "vk.com", "www.cloudflare.com"]) {
		const { hexBytes } = buildTlsClientHello(domain, createRng("tls"))
		const buf = Buffer.from(hexBytes, "hex")

		assert.equal(buf[0], 0x16, "TLS handshake record type")
		assert.equal(buf.readUInt16BE(1), 0x0301, "legacy record version")
		assert.equal(buf.readUInt16BE(3), buf.length - 5, "record length must match the body")

		assert.equal(buf[5], 0x01, "handshake type ClientHello")
		const hsLen = (buf[6] << 16) | (buf[7] << 8) | buf[8]
		assert.equal(hsLen, buf.length - 9, "handshake length must match the body")

		assert.ok(buf.includes(Buffer.from(domain, "ascii")), `SNI ${domain} must appear verbatim`)
	}
})

/**
 * Pull the literal bytes out of an AmneziaWG packet template, i.e. every
 * `<b 0xHEX>` chunk. Naive hex-stripping is wrong here because the DSL itself
 * contains the hex-looking letters b, a..f.
 */
function literalBytes(template) {
	const chunks = []
	for (const match of template.matchAll(/<b 0x([0-9a-fA-F]+)>/g)) {
		chunks.push(Buffer.from(match[1], "hex"))
	}
	return Buffer.concat(chunks)
}

await test("the mimicry domain reaches the generated I-packet", () => {
	for (const domain of ["vk.com", "github.com"]) {
		const result = generateObfuscation({
			profile: "awg-mimicry",
			seed: "mim",
			mimicryDomain: domain,
		})
		assert.equal(result.mimicryDomain, domain)
		assert.ok(result.signatures.length >= 1)
		assert.ok(
			literalBytes(result.signatures[0].template).includes(Buffer.from(domain)),
			`the SNI ${domain} must appear in the actual packet bytes`,
		)
	}
})

await test("the DNS signature encodes the domain as length-prefixed labels", () => {
	const result = generateObfuscation({
		profile: "awg-mimicry",
		seed: "dns",
		signatures: ["dns"],
		mimicryDomain: "github.com",
	})
	// "github" is 6 chars, "com" is 3 -> 06 g i t h u b 03 c o m 00
	const qname = Buffer.from([6, ...Buffer.from("github"), 3, ...Buffer.from("com"), 0])
	assert.ok(literalBytes(result.signatures[0].template).includes(qname))
})

await test("the same seed reproduces identical parameters", () => {
	const a = generateObfuscation({ profile: "awg-paranoid", seed: "deadbeef" })
	const b = generateObfuscation({ profile: "awg-paranoid", seed: "deadbeef" })
	assert.deepEqual(a.params, b.params)
})

await test("different seeds produce different parameters", () => {
	const a = generateObfuscation({ profile: "awg-paranoid", seed: "aaaa" })
	const b = generateObfuscation({ profile: "awg-paranoid", seed: "bbbb" })
	assert.notDeepEqual(a.params, b.params)
})

await test("catches the S1 + 56 == S2 collision", () => {
	const result = validateObfuscation({
		enabled: true,
		jc: 4,
		jmin: 40,
		jmax: 80,
		s1: 30,
		s2: 86,
		h1: 10,
		h2: 20,
		h3: 30,
		h4: 40,
	})
	assert.equal(result.valid, false)
	assert.ok(result.errors.some((e) => e.includes("S2")))
})

await test("catches duplicate magic headers", () => {
	const result = validateObfuscation({
		enabled: true,
		jc: 4,
		jmin: 40,
		jmax: 80,
		s1: 30,
		s2: 40,
		h1: 10,
		h2: 10,
		h3: 30,
		h4: 40,
	})
	assert.equal(result.valid, false)
	assert.ok(result.errors.some((e) => e.includes("different")))
})

await test("catches Jmin >= Jmax", () => {
	const result = validateObfuscation({
		enabled: true,
		jc: 4,
		jmin: 100,
		jmax: 50,
		s1: 30,
		s2: 40,
		h1: 10,
		h2: 20,
		h3: 30,
		h4: 40,
	})
	assert.equal(result.valid, false)
})

console.log("\nmtu + endpoints")

await test("MTU math matches WireGuard overhead", () => {
	const result = calculateMtu({ pathMtu: 1500, outerFamily: 4 })
	assert.equal(result.overhead, 60)
	assert.equal(result.mtu, 1440)
})

await test("conservative MTU clamps to 1280", () => {
	assert.equal(calculateMtu({ pathMtu: 1500, conservative: true }).mtu, 1280)
})

await test("endpoint honours an explicit prefix and port", () => {
	const ep = buildEndpoint({ prefix: "188.114.98", port: 4500 })
	assert.ok(ep.host.startsWith("188.114.98."))
	assert.equal(ep.port, 4500)
	assert.equal(ep.endpoint, `${ep.host}:4500`)
})

await test("IPv6 endpoints are bracketed", () => {
	const ep = buildEndpoint({ family: 6, port: 2408 })
	assert.match(ep.endpoint, /^\[.+\]:2408$/)
})

console.log("\nfull pipeline")

await test("generates a complete AmneziaWG config", async () => {
	const profile = await generateProfile({ obfuscation: "warp-balanced" })
	const conf = profile.configs.amneziawg.content

	for (const key of [
		"[Interface]",
		"PrivateKey",
		"Address",
		"DNS",
		"MTU",
		"Jc",
		"Jmin",
		"Jmax",
		"[Peer]",
		"PublicKey",
		"AllowedIPs",
		"Endpoint",
	]) {
		assert.ok(conf.includes(key), `config is missing ${key}`)
	}

	const body = conf
		.split("\n")
		.filter((l) => !l.trim().startsWith("#"))
		.join("\n")

	// Padding and fake packets are not in balanced WARP profile.
	for (const key of ["S1 =", "S2 =", "I1 ="]) {
		assert.ok(!body.includes(key), `WARP balanced config must not contain ${key}`)
	}
})

await test("an own-server profile is loudly flagged as incompatible with WARP", async () => {
	const profile = await generateProfile({ obfuscation: "awg-standard" })
	const conf = profile.configs.amneziawg.content

	// The full-obfuscation keys are present, as requested...
	for (const key of ["S1 =", "H1 ="]) {
		assert.ok(conf.includes(key), `config is missing ${key}`)
	}
	// ...but the user must be told it will not connect to Cloudflare.
	assert.ok(
		profile.warnings.some((w) => w.includes("own AmneziaWG server")),
		`expected an incompatibility warning, got: ${JSON.stringify(profile.warnings)}`,
	)
})

await test("plain WireGuard output has no AmneziaWG keys", async () => {
	const profile = await generateProfile({ obfuscation: "awg-paranoid" })
	const conf = profile.configs.wireguard.content
	const body = conf
		.split("\n")
		.filter((l) => !l.trim().startsWith("#"))
		.join("\n")
	for (const key of ["Jc =", "Jmin =", "S1 =", "H1 ="]) {
		assert.ok(!body.includes(key), `wg config must not contain ${key}`)
	}
	assert.ok(body.includes("PrivateKey"))
})

await test("the off profile emits no obfuscation", async () => {
	const profile = await generateProfile({ obfuscation: "off" })
	const body = profile.configs.amneziawg.content
		.split("\n")
		.filter((l) => !l.trim().startsWith("#"))
		.join("\n")
	assert.ok(!body.includes("Jc ="))
})

await test("--no-ipv6 strips v6 addresses and routes", async () => {
	const profile = await generateProfile({ ipv6: false })
	assert.equal(profile.network.addresses.length, 1)
	assert.ok(!profile.network.allowedIps.some((c) => c.includes(":")))
	assert.ok(!profile.network.dns.some((d) => d.includes(":")))
})

await test("reusing a seed reproduces the same obfuscation", async () => {
	// The identity has to be pinned too: H1-H4 follow the Cloudflare client_id,
	// which comes from the key pair, not from the seed.
	const { privateKey } = generateKeyPair()
	const a = await generateProfile({ seed: "cafebabe", obfuscation: "warp-light", privateKey })
	const b = await generateProfile({ seed: "cafebabe", obfuscation: "warp-light", privateKey })
	assert.deepEqual(a.obfuscation.params, b.obfuscation.params)
	assert.equal(a.endpoint.endpoint, b.endpoint.endpoint)
})

await test("reusing a private key keeps the identity", async () => {
	const { privateKey, publicKey } = generateKeyPair()
	const profile = await generateProfile({ privateKey })
	assert.equal(profile.keys.privateKey, privateKey)
	assert.equal(profile.keys.publicKey, publicKey)
	assert.equal(profile.meta.reusedIdentity, true)
})

await test("the mimicry profile emits I-packet templates", async () => {
	const profile = await generateProfile({ obfuscation: "awg-mimicry" })
	assert.ok(profile.obfuscation.signatures.length > 0)
	assert.ok(profile.configs.amneziawg.content.includes("I1 = "))
	assert.equal(profile.obfuscation.version, "1.5")
})

await test("a custom CIDR list is accepted", async () => {
	const profile = await generateProfile({ allowedIps: "1.2.3.0/24, 10.0.0.0/8" })
	assert.deepEqual(profile.network.allowedIps, ["1.2.3.0/24", "10.0.0.0/8"])
})

await test("an invalid CIDR is rejected", async () => {
	await assert.rejects(() => generateProfile({ allowedIps: "not-a-cidr" }))
})

await test("JSON output parses and carries the parameters", async () => {
	const profile = await generateProfile({ obfuscation: "warp-balanced" })
	const parsed = JSON.parse(profile.configs.json.content)
	assert.equal(typeof parsed.obfuscation.jc, "number")
	assert.ok(parsed.peer.endpoint)
	assert.ok(parsed.interface.privateKey)
})

await test("every DNS preset ships IPv6 resolvers unless marked IPv4-only", async () => {
	for (const [id, preset] of Object.entries(DNS_PRESETS)) {
		const hasV6 = preset.value.some((server) => server.includes(":"))
		if (preset.ipv4Only) {
			// The flag is a claim about the provider; make sure it stays true.
			assert.ok(!hasV6, `DNS preset ${id} is flagged IPv4-only but has IPv6`)
			continue
		}
		assert.ok(hasV6, `DNS preset ${id} has no IPv6 resolver`)
	}
})

await test("an IPv4-only resolver still reaches an IPv6 tunnel", async () => {
	const profile = await generateProfile({ dns: "comss", ipv6: true })
	assert.deepEqual(profile.network.dns, [
		"83.220.169.155",
		"212.109.195.93",
		"1.1.1.1",
		"2606:4700:4700::1111",
	])
})

await test("an unblocking resolver never travels alone", async () => {
	const profile = await generateProfile({ dns: "xboxdns", ipv6: false })
	// Its own servers stay first, so the unblocking still happens; a neutral
	// resolver closes the list so a refusal cannot black out the whole tunnel.
	assert.equal(profile.network.dns[0], "111.88.96.50")
	assert.equal(profile.network.dns.at(-1), "1.1.1.1")
	assert.ok(profile.warnings.some((w) => w.includes("Unblocking resolver")))
})

await test("a neutral resolver gets no fallback appended", async () => {
	const profile = await generateProfile({ dns: "quad9", ipv6: true })
	assert.ok(!profile.network.dns.includes("1.1.1.1"))
	assert.ok(!profile.warnings.some((w) => w.includes("Unblocking resolver")))
})

await test("opting out of the fallback keeps the resolver list untouched", async () => {
	const profile = await generateProfile({ dns: "comss", ipv6: false, dnsFallback: false })
	assert.deepEqual(profile.network.dns, ["83.220.169.155", "212.109.195.93"])
})

await test("unblocking presets carry a caveat in both languages", async () => {
	for (const id of ["xboxdns", "malwlink", "comss"]) {
		assert.ok(DNS_PRESETS[id].note, `${id} has no note`)
		assert.ok(DNS_PRESETS[id].noteRu, `${id} has no Russian note`)
	}
	assert.ok(!DNS_PRESETS.cloudflare.note, "a neutral resolver must not warn")
})

await test("DNS presets fall back to IPv4 only when the tunnel has no IPv6", async () => {
	const profile = await generateProfile({ dns: "quad9", ipv6: false })
	assert.deepEqual(profile.network.dns, ["9.9.9.9", "149.112.112.112"])
})

await test("an IPv6 tunnel keeps the v6 resolvers", async () => {
	const profile = await generateProfile({ dns: "google", ipv6: true })
	assert.ok(profile.network.dns.includes("2001:4860:4860::8888"))
})

await test("a custom DNS list is accepted", async () => {
	const profile = await generateProfile({ dns: "9.9.9.9, 1.1.1.1", ipv6: false })
	assert.deepEqual(profile.network.dns, ["9.9.9.9", "1.1.1.1"])
})

await test("the chosen resolvers reach the rendered config", async () => {
	const profile = await generateProfile({ dns: "adguard", ipv6: false })
	assert.ok(profile.configs.amneziawg.content.includes("94.140.14.14"))
})

/*
 * WARP client_id derived headers test (when explicitly requested with useClientIdHeaders: true).
 */
await test("the WARP client_id lands in the packet header when useClientIdHeaders is enabled", async () => {
	const profile = await generateProfile({ seed: "clientid", useClientIdHeaders: true })
	const [r0, r1, r2] = profile.warp.reserved.bytes
	const base = r0 * 0x100 + r1 * 0x10000 + r2 * 0x1000000
	assert.equal(profile.obfuscation.headersFromClientId, true)
	assert.equal(profile.obfuscation.params.h1, base + 1)
	assert.equal(profile.obfuscation.params.h4, base + 4)
	// The low byte must remain the real message type or Cloudflare drops it.
	assert.equal(profile.obfuscation.params.h1 & 0xff, 1)
	assert.ok(profile.configs.amneziawg.content.includes("H1 = "))
	assert.ok(profile.configs.amneziawg.content.includes(String(base + 1)))
})

await test("by default WARP configs stay wire-compatible without custom headers", async () => {
	const profile = await generateProfile({ seed: "clientid" })
	assert.equal(profile.obfuscation.headersFromClientId, false)
	assert.equal(profile.obfuscation.params.h1, undefined)
})

await test("a high client_id byte still produces headers", async () => {
	// Third byte >= 128 puts the header above 2^31. Cloudflare issues those
	// constantly, and clamping them to int32 silently dropped the client_id
	// from roughly half of all generated configs.
	const derived = deriveWarpHeaders([1, 2, 200])
	assert.ok(derived, "a high client_id must still derive headers")
	assert.equal(derived.h1 & 0xff, 1)
	assert.equal(derived.h4 & 0xff, 4)
	assert.ok(derived.h1 > 2147483647)
	const check = validateObfuscation(
		{ jc: 4, jmin: 40, jmax: 70, s1: 0, s2: 0, ...derived },
		{ compat: "warp", headersFromClientId: true },
	)
	assert.equal(check.valid, true, check.errors.join("; "))
})

await test("every registration gets its client_id derived when requested", async () => {
	for (let i = 0; i < 25; i++) {
		const profile = await generateProfile({ useClientIdHeaders: true })
		assert.equal(
			profile.obfuscation.headersFromClientId,
			true,
			`registration ${i} lost its client_id (${profile.warp.reserved?.bytes})`,
		)
	}
})

await test("client_id headers never bring forbidden padding with them", async () => {
	const profile = await generateProfile({ seed: "clientid", useClientIdHeaders: true })
	// S1/S2 are AmneziaWG-only. Cloudflare runs stock WireGuard and would drop
	// the handshake outright, so they must stay at zero on every WARP profile.
	assert.equal(profile.obfuscation.params.s1, 0)
	assert.equal(profile.obfuscation.params.s2, 0)
	assert.equal(profile.obfuscation.validation.valid, true)
})

console.log("\nserverless & routing")

await test("resolvePathname handles standard requests", () => {
	const req = { headers: {} }
	const url = new URL("http://localhost/api/options")
	assert.equal(resolvePathname(req, url), "/api/options")
})

await test("resolvePathname handles Vercel __route rewrite query param", () => {
	const req = { headers: {} }
	const url = new URL("http://localhost/api/index.js?__route=options")
	assert.equal(resolvePathname(req, url), "/api/options")
})

await test("resolvePathname handles Vercel x-matched-path header", () => {
	const req = { headers: { "x-matched-path": "/api/health" } }
	const url = new URL("http://localhost/api/index.js")
	assert.equal(resolvePathname(req, url), "/api/health")
})

await test("resolvePathname handles Vercel x-now-route-matches regex header", () => {
	const req = { headers: { "x-now-route-matches": "1=scout%2Fscan" } }
	const url = new URL("http://localhost/api/index.js")
	assert.equal(resolvePathname(req, url), "/api/scout/scan")
})

await test("resolvePathname handles Vercel catch-all query path array", () => {
	const req = { headers: {}, query: { path: ["scout", "status"] } }
	const url = new URL("http://localhost/api/index.js")
	assert.equal(resolvePathname(req, url), "/api/scout/status")
})

await test("handleRequest serves options and health on Vercel rewrite", async () => {
	function createMockRes() {
		return {
			headers: {},
			statusCode: 200,
			body: "",
			setHeader(k, v) { this.headers[k] = v },
			writeHead(code, h) { this.statusCode = code; Object.assign(this.headers, h) },
			end(data) { this.body = data },
		}
	}

	// Simulated Vercel rewrite with __route
	const req1 = {
		method: "GET",
		url: "/api/index.js?__route=options",
		headers: { host: "warpsmith-vggf.vercel.app" },
	}
	const res1 = createMockRes()
	await handleRequest(req1, res1)
	assert.equal(res1.statusCode, 200)
	const parsed1 = JSON.parse(res1.body)
	assert.ok(parsed1.obfuscationProfiles)

	// Simulated Vercel rewrite with x-matched-path
	const req2 = {
		method: "GET",
		url: "/api/index.js",
		headers: {
			host: "warpsmith-vggf.vercel.app",
			"x-matched-path": "/api/health",
		},
	}
	const res2 = createMockRes()
	await handleRequest(req2, res2)
	assert.equal(res2.statusCode, 200)
	const parsed2 = JSON.parse(res2.body)
	assert.equal(parsed2.ok, true)

	// Fallback when /api/index.js is directly called
	const req3 = {
		method: "GET",
		url: "/api/index.js",
		headers: { host: "warpsmith-vggf.vercel.app" },
	}
	const res3 = createMockRes()
	await handleRequest(req3, res3)
	assert.equal(res3.statusCode, 200)
	const parsed3 = JSON.parse(res3.body)
	assert.equal(parsed3.ok, true)

	// Simulated POST with pre-parsed req.body in serverless
	const req4 = {
		method: "POST",
		url: "/api/index.js?__route=obfuscation",
		headers: { host: "warpsmith-vggf.vercel.app" },
		body: { profile: "warp-cloak" },
	}
	const res4 = createMockRes()
	await handleRequest(req4, res4)
	assert.equal(res4.statusCode, 200)
	const parsed4 = JSON.parse(res4.body)
	assert.equal(parsed4.profile, "warp-cloak")
})

console.log(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed ? 1 : 0)

