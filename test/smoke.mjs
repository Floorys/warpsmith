/**
 * End-to-end smoke test of the core pipeline, using MOCK_WARP so it needs no
 * network access. Run with: npm run smoke
 */

import assert from "node:assert/strict"

process.env.MOCK_WARP = "1"

const { generateProfile } = await import("../src/core/generate.js")
const { generateObfuscation, validateObfuscation, PROFILES } = await import(
	"../src/core/amnezia.js"
)
const { generateKeyPair, derivePublicKey } = await import("../src/core/keys.js")
const { calculateMtu } = await import("../src/core/mtu.js")
const { buildEndpoint } = await import("../src/core/endpoints.js")

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
		assert.equal(new Set([p.h1, p.h2, p.h3, p.h4]).size, 4, "H1-H4 must be distinct")
		for (const h of [p.h1, p.h2, p.h3, p.h4]) {
			assert.ok(h >= 5 && h <= 2147483647, `H value ${h} out of range`)
		}
	})
}

await test("the same seed reproduces identical parameters", () => {
	const a = generateObfuscation({ profile: "paranoid", seed: "deadbeef" })
	const b = generateObfuscation({ profile: "paranoid", seed: "deadbeef" })
	assert.deepEqual(a.params, b.params)
})

await test("different seeds produce different parameters", () => {
	const a = generateObfuscation({ profile: "paranoid", seed: "aaaa" })
	const b = generateObfuscation({ profile: "paranoid", seed: "bbbb" })
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
	const profile = await generateProfile({ obfuscation: "balanced" })
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
		"S1",
		"S2",
		"H1",
		"H2",
		"H3",
		"H4",
		"[Peer]",
		"PublicKey",
		"AllowedIPs",
		"Endpoint",
	]) {
		assert.ok(conf.includes(key), `config is missing ${key}`)
	}
})

await test("plain WireGuard output has no AmneziaWG keys", async () => {
	const profile = await generateProfile({ obfuscation: "paranoid" })
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
	const a = await generateProfile({ seed: "cafebabe", obfuscation: "mobile" })
	const b = await generateProfile({ seed: "cafebabe", obfuscation: "mobile" })
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
	const profile = await generateProfile({ obfuscation: "mimicry" })
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
	const profile = await generateProfile({ obfuscation: "balanced" })
	const parsed = JSON.parse(profile.configs.json.content)
	assert.equal(typeof parsed.obfuscation.jc, "number")
	assert.ok(parsed.peer.endpoint)
	assert.ok(parsed.interface.privateKey)
})

console.log(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed ? 1 : 0)
