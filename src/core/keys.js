/**
 * Curve25519 key handling for WireGuard / AmneziaWG.
 *
 * WireGuard keys are raw 32-byte X25519 keys encoded as base64.
 * Node's crypto module only exports DER (PKCS#8 / SPKI), so we slice the raw
 * key material off the end of the DER structure, which is always the last 32
 * bytes for X25519.
 */

import {
	createPublicKey,
	createPrivateKey,
	generateKeyPairSync,
	randomBytes,
} from "node:crypto"

/** DER prefix for a PKCS#8-wrapped X25519 private key. */
const PKCS8_X25519_PREFIX = Buffer.from(
	"302e020100300506032b656e04220420",
	"hex",
)

/** DER prefix for an SPKI-wrapped X25519 public key. */
const SPKI_X25519_PREFIX = Buffer.from("302a300506032b656e032100", "hex")

export class KeyError extends Error {}

/**
 * Decode a base64 (or base64url, or hex) 32-byte key into a Buffer.
 * @param {string} value
 * @param {string} label
 * @returns {Buffer}
 */
export function decodeKey(value, label = "key") {
	if (typeof value !== "string" || value.trim() === "") {
		throw new KeyError(`${label} is empty`)
	}
	const raw = value.trim()

	let buf
	if (/^[0-9a-fA-F]{64}$/.test(raw)) {
		buf = Buffer.from(raw, "hex")
	} else {
		const normalized = raw.replace(/-/g, "+").replace(/_/g, "/")
		buf = Buffer.from(normalized, "base64")
	}

	if (buf.length !== 32) {
		throw new KeyError(
			`${label} must decode to 32 bytes, got ${buf.length}. ` +
				`Expected a base64 WireGuard key (44 chars) or 64 hex chars.`,
		)
	}
	return buf
}

/**
 * Generate a fresh X25519 keypair in WireGuard's base64 format.
 * @returns {{ privateKey: string, publicKey: string }}
 */
export function generateKeyPair() {
	const { publicKey, privateKey } = generateKeyPairSync("x25519")

	const privRaw = privateKey
		.export({ type: "pkcs8", format: "der" })
		.subarray(-32)
	const pubRaw = publicKey.export({ type: "spki", format: "der" }).subarray(-32)

	return {
		privateKey: Buffer.from(privRaw).toString("base64"),
		publicKey: Buffer.from(pubRaw).toString("base64"),
	}
}

/**
 * Derive the WireGuard public key from an existing private key.
 * Lets users re-generate a config while keeping their identity.
 * @param {string} privateKeyBase64
 * @returns {string} base64 public key
 */
export function derivePublicKey(privateKeyBase64) {
	const raw = decodeKey(privateKeyBase64, "PrivateKey")

	const der = Buffer.concat([PKCS8_X25519_PREFIX, raw])
	const keyObject = createPrivateKey({ key: der, format: "der", type: "pkcs8" })
	const pubRaw = createPublicKey(keyObject)
		.export({ type: "spki", format: "der" })
		.subarray(-32)

	return Buffer.from(pubRaw).toString("base64")
}

/**
 * Validate that a string looks like a usable WireGuard public key.
 * @param {string} publicKeyBase64
 * @returns {string} normalized base64 public key
 */
export function normalizePublicKey(publicKeyBase64) {
	const raw = decodeKey(publicKeyBase64, "PublicKey")
	const der = Buffer.concat([SPKI_X25519_PREFIX, raw])
	// Throws if the point is not a valid X25519 public key encoding.
	createPublicKey({ key: der, format: "der", type: "spki" })
	return Buffer.from(raw).toString("base64")
}

/**
 * Generate a WireGuard pre-shared key (32 random bytes, base64).
 * Optional in WARP, but supported by AmneziaWG and adds post-quantum-ish
 * symmetric hardening if you ever peer this config elsewhere.
 * @returns {string}
 */
export function generatePresharedKey() {
	return randomBytes(32).toString("base64")
}

/**
 * Resolve a keypair from user input: reuse a supplied private key or make one.
 * @param {{ privateKey?: string }} [options]
 * @returns {{ privateKey: string, publicKey: string, reused: boolean }}
 */
export function resolveKeyPair(options = {}) {
	if (options.privateKey) {
		const privateKey = decodeKey(options.privateKey, "PrivateKey").toString(
			"base64",
		)
		return {
			privateKey,
			publicKey: derivePublicKey(privateKey),
			reused: true,
		}
	}
	return { ...generateKeyPair(), reused: false }
}
