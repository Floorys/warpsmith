/**
 * Cryptographically-seeded randomness helpers with a deterministic mode.
 *
 * Deterministic mode matters for obfuscation: a user may want to reproduce the
 * exact same junk-packet profile on several devices (all peers of an AmneziaWG
 * tunnel MUST share identical Jc/Jmin/Jmax/S1/S2/H1..H4 values, otherwise the
 * handshake fails). Passing a `seed` makes the generator reproducible.
 */

import { createHash, randomBytes } from "node:crypto"

/**
 * @typedef {Object} Rng
 * @property {() => number} next        Float in [0, 1)
 * @property {(min: number, max: number) => number} int  Integer in [min, max]
 * @property {(n: number) => Buffer} bytes
 * @property {<T>(items: T[]) => T} pick
 * @property {<T>(items: T[]) => T[]} shuffle
 */

/**
 * Create an RNG. Without a seed it uses node:crypto directly.
 * With a seed it uses a SHA-256 based counter stream (deterministic).
 * @param {string|null|undefined} seed
 * @returns {Rng}
 */
export function createRng(seed) {
	let buffer = Buffer.alloc(0)
	let counter = 0
	const seedBuf = seed ? createHash("sha256").update(String(seed)).digest() : null

	function refill(minBytes) {
		while (buffer.length < minBytes) {
			if (seedBuf) {
				const block = createHash("sha256")
					.update(seedBuf)
					.update(Buffer.from(String(counter++), "utf8"))
					.digest()
				buffer = Buffer.concat([buffer, block])
			} else {
				buffer = Buffer.concat([buffer, randomBytes(Math.max(64, minBytes))])
			}
		}
	}

	function take(n) {
		refill(n)
		const out = buffer.subarray(0, n)
		buffer = buffer.subarray(n)
		return Buffer.from(out)
	}

	const rng = {
		next() {
			// 53 bits of entropy -> uniform float in [0, 1)
			const b = take(7)
			let value = 0
			for (const byte of b) value = value * 256 + byte
			return value / 2 ** 56
		},
		int(min, max) {
			const lo = Math.ceil(min)
			const hi = Math.floor(max)
			if (hi < lo) throw new RangeError(`Empty range [${min}, ${max}]`)
			const span = hi - lo + 1
			// Rejection sampling keeps the distribution uniform.
			const limit = Math.floor(2 ** 32 / span) * span
			let draw
			do {
				draw = take(4).readUInt32BE(0)
			} while (draw >= limit)
			return lo + (draw % span)
		},
		bytes(n) {
			return take(n)
		},
		pick(items) {
			if (!items.length) throw new RangeError("Cannot pick from an empty list")
			return items[rng.int(0, items.length - 1)]
		},
		shuffle(items) {
			const copy = [...items]
			for (let i = copy.length - 1; i > 0; i--) {
				const j = rng.int(0, i)
				;[copy[i], copy[j]] = [copy[j], copy[i]]
			}
			return copy
		},
	}

	return rng
}

/**
 * A short human-friendly seed, useful to show the user so they can reproduce
 * the same obfuscation profile later.
 * @returns {string}
 */
export function makeSeed() {
	return randomBytes(8).toString("hex")
}
