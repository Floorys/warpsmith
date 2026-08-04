/**
 * HTTP server: static frontend + JSON API. Zero dependencies, node:http only.
 *
 * A browser cannot call api.cloudflareclient.com directly (no CORS headers,
 * and the WARP API is not designed for it), which is exactly why a static
 * HTML-only generator can never work. This server is the backend that does the
 * real registration and hands finished configs to the page.
 */

import http from "node:http"
import fs from "node:fs/promises"
import path from "node:path"
import { fileURLToPath, pathToFileURL } from "node:url"

import { generateProfile, describeOptions, GenerateError } from "./core/generate.js"
import {
	scanLocations,
	probeColo,
	ENDPOINT_PREFIXES,
	ENDPOINT_PORTS,
	CAMOUFLAGE_PORTS,
	describeLocationReality,
} from "./core/endpoints.js"
import {
	generateObfuscation,
	validateObfuscation,
	PACKET_SIGNATURES,
	PROFILES,
	LIMITS,
} from "./core/amnezia.js"
import { calculateMtu, PATH_PRESETS } from "./core/mtu.js"
import { WarpApiError, isMockMode } from "./core/warp.js"

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const PUBLIC_DIR = path.resolve(__dirname, "../public")

const PORT = Number(process.env.PORT || 8787)
const HOST = process.env.HOST || "0.0.0.0"

const MIME = {
	".html": "text/html; charset=utf-8",
	".css": "text/css; charset=utf-8",
	".js": "text/javascript; charset=utf-8",
	".json": "application/json; charset=utf-8",
	".svg": "image/svg+xml",
	".ico": "image/x-icon",
	".webmanifest": "application/manifest+json",
}

// --- Rate limiting ----------------------------------------------------------
// Registrations are the expensive, abusable operation. Cloudflare will 403 the
// host IP if a public deployment lets anyone spam /api/generate.
const RATE = {
	windowMs: Number(process.env.RATE_WINDOW_MS || 60_000),
	maxGenerate: Number(process.env.RATE_MAX_GENERATE || 10),
	maxOther: Number(process.env.RATE_MAX_OTHER || 60),
}
const buckets = new Map()

function rateLimit(ip, cost, max) {
	const now = Date.now()
	const entry = buckets.get(ip) ?? { count: 0, resetAt: now + RATE.windowMs }
	if (now > entry.resetAt) {
		entry.count = 0
		entry.resetAt = now + RATE.windowMs
	}
	entry.count += cost
	buckets.set(ip, entry)
	return {
		allowed: entry.count <= max,
		retryAfter: Math.ceil((entry.resetAt - now) / 1000),
	}
}

// Keep the map from growing forever.
setInterval(() => {
	const now = Date.now()
	for (const [ip, entry] of buckets) if (now > entry.resetAt) buckets.delete(ip)
}, 120_000).unref?.()

// --- Helpers ----------------------------------------------------------------

function clientIp(req) {
	const fwd = req.headers["x-forwarded-for"]
	if (typeof fwd === "string" && fwd.length) return fwd.split(",")[0].trim()
	return req.socket.remoteAddress || "unknown"
}

function sendJson(res, status, payload, extraHeaders = {}) {
	const body = JSON.stringify(payload)
	res.writeHead(status, {
		"Content-Type": "application/json; charset=utf-8",
		"Content-Length": Buffer.byteLength(body),
		"Cache-Control": "no-store",
		...extraHeaders,
	})
	res.end(body)
}

async function readJsonBody(req, limitBytes = 64 * 1024) {
	const chunks = []
	let size = 0
	for await (const chunk of req) {
		size += chunk.length
		if (size > limitBytes) throw new Error("Request body too large")
		chunks.push(chunk)
	}
	if (!chunks.length) return {}
	try {
		return JSON.parse(Buffer.concat(chunks).toString("utf8"))
	} catch {
		throw new Error("Request body is not valid JSON")
	}
}

async function serveStatic(req, res, pathname) {
	const rel = pathname === "/" ? "index.html" : pathname.replace(/^\/+/, "")
	const target = path.resolve(PUBLIC_DIR, rel)

	// Path traversal guard.
	if (!target.startsWith(PUBLIC_DIR)) {
		sendJson(res, 403, { error: "Forbidden" })
		return
	}

	try {
		const data = await fs.readFile(target)
		const ext = path.extname(target).toLowerCase()
		res.writeHead(200, {
			"Content-Type": MIME[ext] || "application/octet-stream",
			"Content-Length": data.length,
			"Cache-Control": ext === ".html" ? "no-store" : "public, max-age=300",
			"X-Content-Type-Options": "nosniff",
			"Referrer-Policy": "no-referrer",
		})
		res.end(data)
	} catch {
		res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" })
		res.end("404 Not Found")
	}
}

// --- API routes -------------------------------------------------------------

const routes = {
	"GET /api/health": async () => ({
		ok: true,
		mock: isMockMode(),
		node: process.version,
		uptimeSeconds: Math.round(process.uptime()),
	}),

	"GET /api/options": async () => ({
		...describeOptions(),
		endpointPrefixes: ENDPOINT_PREFIXES.map((p) => ({
			id: p.id,
			cidr: p.cidr,
			family: p.family,
			note: p.note,
			probeable: p.probeable,
		})),
		endpointPorts: ENDPOINT_PORTS,
		camouflagePorts: CAMOUFLAGE_PORTS,
		pathMtuPresets: PATH_PRESETS,
		limits: LIMITS,
		locationReality: describeLocationReality(),
		mock: isMockMode(),
	}),

	// Live preview of obfuscation parameters. Cheap: no Cloudflare call at all,
	// so the UI can re-roll parameters instantly while the user experiments.
	"POST /api/obfuscation": async (body) => {
		return generateObfuscation({
			profile: body.profile,
			seed: body.seed,
			overrides: body.overrides,
			signatures: body.signatures,
			mimicryDomain: body.mimicryDomain,
			reserved: body.reserved,
			useClientIdHeaders: body.useClientIdHeaders === true,
		})
	},

	"POST /api/validate": async (body) =>
		validateObfuscation(body.params ?? body, {
			compat: body.compat,
			headersFromClientId: body.headersFromClientId === true,
		}),

	"POST /api/mtu": async (body) =>
		calculateMtu({
			pathMtu: body.pathMtu,
			outerFamily: body.outerFamily,
			conservative: body.conservative,
		}),

	// Measure which Cloudflare datacenter each endpoint actually lands in.
	"POST /api/scan": async (body) =>
		scanLocations({
			perPrefix: body.perPrefix,
			timeoutMs: body.timeoutMs,
			concurrency: body.concurrency,
		}),

	"POST /api/probe": async (body) => {
		if (!body.ip || !/^[0-9a-fA-F.:]+$/.test(String(body.ip))) {
			throw new GenerateError("probe requires a valid `ip`")
		}
		return probeColo(String(body.ip), { timeoutMs: body.timeoutMs })
	},

	// The main event: register with Cloudflare and build the configs.
	"POST /api/generate": async (body) => {
		const profile = await generateProfile({
			privateKey: body.privateKey,
			license: body.license,
			seed: body.seed,
			obfuscation: body.obfuscation,
			obfuscationOverrides: body.obfuscationOverrides,
			signatures: body.signatures,
			mimicryDomain: body.mimicryDomain,
			useClientIdHeaders: body.useClientIdHeaders,
			endpointPrefix: body.endpointPrefix,
			endpointPort: body.endpointPort,
			endpointHost: body.endpointHost,
			useHostname: body.useHostname,
			family: body.family,
			detectLocation: body.detectLocation,
			allowedIps: body.allowedIps,
			dns: body.dns,
			mtu: body.mtu,
			pathMtu: body.pathMtu,
			conservativeMtu: body.conservativeMtu,
			keepalive: body.keepalive,
			ipv6: body.ipv6,
			presharedKey: body.presharedKey,
		})

		// Never leak the device token to the browser; it can delete the device.
		const { token, ...warpSafe } = profile.warp
		return { ...profile, warp: warpSafe }
	},
}

// --- Server -----------------------------------------------------------------

/**
 * The full request handler. Exported so that serverless runtimes (see
 * `api/index.js`) can reuse the exact same routing without opening a port.
 */
export async function handleRequest(req, res) {
	const url = new URL(req.url, `http://${req.headers.host || "localhost"}`)
	const pathname = url.pathname
	const key = `${req.method} ${pathname}`

	res.setHeader("X-Content-Type-Options", "nosniff")
	res.setHeader("X-Frame-Options", "DENY")

	if (req.method === "OPTIONS") {
		res.writeHead(204, {
			"Access-Control-Allow-Origin": process.env.CORS_ORIGIN || "*",
			"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type",
			"Access-Control-Max-Age": "600",
		})
		res.end()
		return
	}

	if (!pathname.startsWith("/api/")) {
		await serveStatic(req, res, pathname)
		return
	}

	const handler = routes[key]
	if (!handler) {
		sendJson(res, 404, { error: `No route for ${key}` })
		return
	}

	const isGenerate = pathname === "/api/generate"
	const limit = rateLimit(
		clientIp(req),
		isGenerate ? 1 : 1,
		isGenerate ? RATE.maxGenerate : RATE.maxOther,
	)
	if (!limit.allowed) {
		sendJson(
			res,
			429,
			{
				error: "Rate limit exceeded",
				hint: "Cloudflare blocks IPs that register too many devices, so this server throttles you first.",
				retryAfterSeconds: limit.retryAfter,
			},
			{ "Retry-After": String(limit.retryAfter) },
		)
		return
	}

	try {
		const body = req.method === "POST" ? await readJsonBody(req) : {}
		const result = await handler(body, req)
		sendJson(res, 200, result, {
			"Access-Control-Allow-Origin": process.env.CORS_ORIGIN || "*",
		})
	} catch (error) {
		const status =
			error instanceof WarpApiError ? (error.status ?? 502) : error instanceof GenerateError ? 400 : 500

		// Log server-side without secrets.
		console.error(`[${key}] ${error.name}: ${error.message}`)

		sendJson(res, status >= 400 && status < 600 ? status : 502, {
			error: error.message,
			type: error.name,
			hint: error.hint,
			validation: error.validation,
		})
	}
}

const server = http.createServer(handleRequest)

const isEntryPoint =
	process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url

if (isEntryPoint) {
	server.listen(PORT, HOST, () => {
		console.log(`AWG WARP Architect listening on http://${HOST}:${PORT}`)
		if (isMockMode()) {
			console.log("MOCK_WARP=1 - generating synthetic configs, no Cloudflare calls")
		}
	})
}

export default server
