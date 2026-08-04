/**
 * Cloudflare WARP API client.
 *
 * This is the part a pure-HTML generator cannot have: without registering a
 * device with Cloudflare you have no peer public key, no assigned tunnel
 * addresses and no account, so any "generated" config is a dead file.
 *
 * Flow:
 *   1. POST  /reg            register a device using our X25519 public key
 *   2. PATCH /reg/:id/account (optional) attach a WARP+ license key
 *   3. GET   /reg/:id        read the config back after a license change
 *
 * Set MOCK_WARP=1 to run the whole pipeline offline with synthetic data, so
 * the UI, tests and CI work without network access.
 */

import { createHash } from "node:crypto"

export const WARP_API_BASE = "https://api.cloudflareclient.com/v0a2158"

export class WarpApiError extends Error {
	constructor(message, meta = {}) {
		super(message)
		this.name = "WarpApiError"
		this.status = meta.status
		this.body = meta.body
		this.hint = meta.hint
	}
}

export function isMockMode() {
	return process.env.MOCK_WARP === "1" || process.env.MOCK_WARP === "true"
}

/** Headers that make us look like the official Android WARP client. */
function apiHeaders(token) {
	const headers = {
		"CF-Client-Version": "a-6.11-2223",
		"User-Agent": "okhttp/3.12.1",
		"Content-Type": "application/json; charset=UTF-8",
		Accept: "application/json",
	}
	if (token) headers.Authorization = `Bearer ${token}`
	return headers
}

/**
 * fetch wrapper with timeout, backoff retries and actionable error messages.
 */
async function apiFetch(url, init = {}) {
	const { timeoutMs = 15000, retries = 2, ...rest } = init
	let lastError

	for (let attempt = 0; attempt <= retries; attempt++) {
		const controller = new AbortController()
		const timer = setTimeout(() => controller.abort(), timeoutMs)
		try {
			const res = await fetch(url, { ...rest, signal: controller.signal })
			clearTimeout(timer)

			const text = await res.text()
			let body = text
			try {
				body = text ? JSON.parse(text) : null
			} catch {
				/* keep the raw text */
			}

			if (!res.ok) {
				const err = new WarpApiError(
					`Cloudflare WARP API returned ${res.status} ${res.statusText}`,
					{
						status: res.status,
						body,
						hint:
							res.status === 403
								? "Cloudflare returns 403 when registrations from your IP are rate-limited. Wait a few minutes, or run the generator from another IP."
								: res.status === 429
									? "Too many registrations. Slow down and retry later."
									: undefined,
					},
				)
				// 4xx (except 429) is our fault, so do not retry.
				if (res.status >= 400 && res.status < 500 && res.status !== 429) throw err
				throw err
			}
			return body
		} catch (error) {
			clearTimeout(timer)
			lastError = error

			const noRetry =
				error instanceof WarpApiError &&
				error.status &&
				error.status < 500 &&
				error.status !== 429
			if (noRetry) throw error

			if (error?.name === "AbortError") {
				lastError = new WarpApiError(
					`Request to Cloudflare timed out after ${timeoutMs}ms`,
					{
						hint: "api.cloudflareclient.com may be blocked on this network. Host the generator where it is reachable, or use MOCK_WARP=1 to test the pipeline offline.",
					},
				)
			}
			if (attempt < retries) await new Promise((r) => setTimeout(r, 400 * 2 ** attempt))
		}
	}
	throw lastError
}

/** Synthetic registration for offline development and CI. */
function mockRegistration(publicKey) {
	const d = createHash("sha256").update(publicKey).digest()
	return {
		id: d.subarray(0, 16).toString("hex"),
		token: d.subarray(16, 32).toString("hex"),
		type: "a",
		model: "PC",
		created: new Date().toISOString(),
		updated: new Date().toISOString(),
		account: {
			id: d.subarray(0, 12).toString("hex"),
			account_type: "free",
			license: `${d.subarray(0, 4).toString("hex")}-${d.subarray(4, 8).toString("hex")}-${d.subarray(8, 12).toString("hex")}`,
			premium_data: 0,
			quota: 0,
			warp_plus: false,
		},
		config: {
			client_id: d.subarray(0, 3).toString("base64"),
			peers: [
				{
					public_key: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
					endpoint: {
						v4: "162.159.192.1:2408",
						v6: "[2606:4700:d0::a29f:c001]:2408",
						host: "engage.cloudflareclient.com:2408",
					},
				},
			],
			interface: {
				addresses: {
					v4: `172.16.0.${(d[0] % 250) + 2}`,
					v6: `2606:4700:110:${d.subarray(1, 3).toString("hex")}:${d.subarray(3, 5).toString("hex")}::1`,
				},
			},
			services: { http_proxy: "172.16.0.1:2480" },
		},
		_mock: true,
	}
}

/**
 * Register a new WARP device against our public key.
 * @param {{ publicKey: string, locale?: string, model?: string, timeoutMs?: number }} options
 * @returns {Promise<Object>} raw registration payload
 */
export async function registerDevice(options) {
	const { publicKey, locale = "en_US", model = "PC", timeoutMs } = options
	if (!publicKey) throw new WarpApiError("registerDevice requires a publicKey")

	if (isMockMode()) return mockRegistration(publicKey)

	const payload = {
		key: publicKey,
		install_id: "",
		fcm_token: "",
		tos: new Date().toISOString().replace(/\.\d{3}Z$/, ".000Z"),
		model,
		serial_number: "",
		locale,
		type: "Android",
	}

	const body = await apiFetch(`${WARP_API_BASE}/reg`, {
		method: "POST",
		headers: apiHeaders(),
		body: JSON.stringify(payload),
		timeoutMs,
	})

	if (!body?.config?.peers?.length) {
		throw new WarpApiError("Registration succeeded but no peer was returned", { body })
	}
	return body
}

/**
 * Attach a WARP+ license key to an existing registration.
 * @param {{ registrationId: string, token: string, license: string, timeoutMs?: number }} options
 */
export async function applyLicense(options) {
	const { registrationId, token, license, timeoutMs } = options
	if (!license) return null

	if (isMockMode()) {
		return { account_type: "unlimited", warp_plus: true, license, premium_data: 1e12, _mock: true }
	}

	return apiFetch(`${WARP_API_BASE}/reg/${registrationId}/account`, {
		method: "PUT",
		headers: apiHeaders(token),
		body: JSON.stringify({ license: license.trim() }),
		timeoutMs,
	})
}

/**
 * Re-read a registration (needed after a license change to get fresh config).
 * @param {{ registrationId: string, token: string, timeoutMs?: number }} options
 */
export async function getRegistration(options) {
	const { registrationId, token, timeoutMs } = options
	if (isMockMode()) return null

	return apiFetch(`${WARP_API_BASE}/reg/${registrationId}`, {
		method: "GET",
		headers: apiHeaders(token),
		timeoutMs,
	})
}

/**
 * Delete a registration. Good hygiene: WARP accounts are cheap but not free,
 * and leaving thousands of orphan devices is what gets IPs rate-limited.
 */
export async function deleteRegistration(options) {
	const { registrationId, token, timeoutMs } = options
	if (isMockMode()) return { deleted: true, _mock: true }
	return apiFetch(`${WARP_API_BASE}/reg/${registrationId}`, {
		method: "DELETE",
		headers: apiHeaders(token),
		timeoutMs,
		retries: 0,
	})
}

/**
 * Cloudflare hands us a base64 `client_id`. Some WireGuard forks (and the
 * v2ray/sing-box wireguard outbound) need it as three "reserved" bytes.
 * Stock AmneziaWG does not use it, but we surface it so the config is portable.
 * @param {string|undefined} clientId
 * @returns {{ base64: string, bytes: number[] }|null}
 */
export function decodeReserved(clientId) {
	if (!clientId) return null
	const buf = Buffer.from(clientId, "base64")
	if (buf.length < 3) return null
	return { base64: clientId, bytes: [buf[0], buf[1], buf[2]] }
}

/**
 * Flatten a raw registration into the fields the rest of the app needs.
 * @param {Object} registration
 */
export function normalizeRegistration(registration) {
	const config = registration?.config || {}
	const peer = config.peers?.[0] || {}
	const account = registration?.account || {}

	return {
		registrationId: registration?.id ?? null,
		token: registration?.token ?? null,
		accountId: account.id ?? null,
		accountType: account.account_type ?? "free",
		warpPlus: Boolean(account.warp_plus),
		license: account.license ?? null,
		quota: account.quota ?? 0,
		peerPublicKey: peer.public_key ?? null,
		endpointV4: peer.endpoint?.v4 ?? null,
		endpointV6: peer.endpoint?.v6 ?? null,
		endpointHost: peer.endpoint?.host ?? null,
		addressV4: config.interface?.addresses?.v4 ?? null,
		addressV6: config.interface?.addresses?.v6 ?? null,
		clientId: config.client_id ?? null,
		reserved: decodeReserved(config.client_id),
		mock: Boolean(registration?._mock),
	}
}
