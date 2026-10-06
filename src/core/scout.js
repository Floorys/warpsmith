/**
 * WarpScout endpoint scanning & integration module.
 *
 * Supports:
 *   1. Direct integration with the `warpscout` CLI (vernette/warpscout):
 *      - Auto-detection in PATH, bin/, or project root.
 *      - Auto-download of official prebuilt binaries on demand.
 *      - Running `warpscout scan` with AWG / WG / MASQUE protocols,
 *        tun-ping (-P), I1 mimicry profiles, and custom SNI.
 *      - Parsing `warpscout` tables, stdout, and report files.
 *   2. Native fast in-process Node.js scanner:
 *      - Scans Cloudflare WARP anycast pools & camouflage ports concurrently.
 *      - Probes datacenter trace (`colo`), real RTT, and reachability.
 *      - Ranks working endpoints by latency and location.
 */

import { spawn } from "node:child_process"
import fs from "node:fs/promises"
import path from "node:path"
import os from "node:os"
import net from "node:net"
import https from "node:https"
import { fileURLToPath } from "node:url"
import {
	ENDPOINT_PREFIXES,
	ENDPOINT_PORTS,
	CAMOUFLAGE_PORTS,
	COLO_MAP,
	probeColo,
	describeColo,
} from "./endpoints.js"
import { isMockMode } from "./warp.js"

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const ROOT_DIR = path.resolve(__dirname, "../..")
const IS_SERVERLESS = Boolean(
	process.env.VERCEL ||
		process.env.AWS_LAMBDA_FUNCTION_NAME ||
		process.env.NETLIFY ||
		process.env.FUNCTIONS_WORKER_RUNTIME,
)
const BIN_DIR = IS_SERVERLESS
	? path.join(os.tmpdir(), "bin")
	: path.resolve(ROOT_DIR, "bin")

export const WARPSCOUT_REPO = "vernette/warpscout"
export const WARPSCOUT_EXE = process.platform === "win32" ? "warpscout.exe" : "warpscout"

/**
 * Locate the warpscout binary on the system.
 * @returns {Promise<{ available: boolean, path: string|null, version: string|null }>}
 */
export async function findWarpscoutBinary() {
	const candidates = [
		path.join(BIN_DIR, WARPSCOUT_EXE),
		path.join(ROOT_DIR, "bin", WARPSCOUT_EXE),
		path.join(ROOT_DIR, WARPSCOUT_EXE),
		WARPSCOUT_EXE, // PATH lookup
	]

	for (const candidate of candidates) {
		try {
			const version = await new Promise((resolve) => {
				const proc = spawn(candidate, ["version"], { timeout: 3000, stdio: ["ignore", "pipe", "pipe"] })
				let out = ""
				proc.stdout.on("data", (d) => (out += d.toString()))
				proc.stderr.on("data", (d) => (out += d.toString()))
				proc.on("error", () => resolve(null))
				proc.on("close", (code) => {
					if (code === 0 && out.trim()) {
						resolve(out.trim().split("\n")[0])
					} else {
						resolve(null)
					}
				})
			})

			if (version) {
				return { available: true, path: candidate, version }
			}
		} catch {
			// check next candidate
		}
	}

	return { available: false, path: null, version: null }
}

/**
 * Determine the GitHub release asset name for the current platform.
 */
export function getWarpscoutAssetInfo() {
	const platform = os.platform()
	const arch = os.arch()

	let osName = ""
	let archName = ""
	let ext = "tar.gz"

	if (platform === "win32") {
		osName = "windows"
		ext = "zip"
	} else if (platform === "linux") {
		osName = "linux"
	} else if (platform === "darwin") {
		osName = "darwin"
	} else {
		return null
	}

	if (arch === "x64") {
		archName = "amd64"
	} else if (arch === "arm64") {
		archName = "arm64"
	} else {
		return null
	}

	return { osName, archName, ext, pattern: `_${osName}_${archName}.${ext}` }
}

/**
 * Download warpscout from GitHub releases into bin/.
 * @returns {Promise<{ success: boolean, path?: string, error?: string }>}
 */
export async function downloadWarpscout() {
	const assetInfo = getWarpscoutAssetInfo()
	if (!assetInfo) {
		return { success: false, error: `Unsupported platform: ${os.platform()} ${os.arch()}` }
	}

	try {
		// Fetch latest release metadata from GitHub
		const relRes = await fetch(`https://api.github.com/repos/${WARPSCOUT_REPO}/releases/latest`, {
			headers: { "User-Agent": "warpsmith-scout" },
		})
		if (!relRes.ok) {
			return { success: false, error: `Failed to query GitHub releases: HTTP ${relRes.status}` }
		}
		const relData = await relRes.json()
		const asset = relData.assets?.find((a) => a.name.includes(assetInfo.pattern))
		if (!asset) {
			return { success: false, error: `Could not find release asset matching ${assetInfo.pattern}` }
		}

		await fs.mkdir(BIN_DIR, { recursive: true })
		const targetArchive = path.join(BIN_DIR, asset.name)
		const targetExe = path.join(BIN_DIR, WARPSCOUT_EXE)

		// Download binary archive
		const dlRes = await fetch(asset.browser_download_url, {
			headers: { "User-Agent": "warpsmith-scout" },
		})
		if (!dlRes.ok) {
			return { success: false, error: `Download failed: HTTP ${dlRes.status}` }
		}
		const buf = Buffer.from(await dlRes.arrayBuffer())
		await fs.writeFile(targetArchive, buf)

		// Extract archive
		if (assetInfo.ext === "zip") {
			// Extract with PowerShell Expand-Archive
			await new Promise((resolve, reject) => {
				const cmd = `Expand-Archive -LiteralPath "${targetArchive}" -DestinationPath "${BIN_DIR}" -Force`
				const proc = spawn("powershell", ["-NoProfile", "-Command", cmd], { stdio: "ignore" })
				proc.on("close", (code) => (code === 0 ? resolve() : reject(new Error(`Extract failed with code ${code}`))))
				proc.on("error", reject)
			})
		} else {
			await new Promise((resolve, reject) => {
				const proc = spawn("tar", ["-xzf", targetArchive, "-C", BIN_DIR], { stdio: "ignore" })
				proc.on("close", (code) => (code === 0 ? resolve() : reject(new Error(`Extract failed with code ${code}`))))
				proc.on("error", reject)
			})
		}

		// Find warpscout binary anywhere inside BIN_DIR (in case archive had nested directory)
		const findInDir = async (dir) => {
			const entries = await fs.readdir(dir, { withFileTypes: true }).catch(() => [])
			for (const entry of entries) {
				const full = path.join(dir, entry.name)
				if (entry.isDirectory()) {
					const found = await findInDir(full)
					if (found) return found
				} else if (entry.name.toLowerCase() === WARPSCOUT_EXE.toLowerCase()) {
					return full
				}
			}
			return null
		}

		const foundExe = await findInDir(BIN_DIR)
		if (foundExe && path.resolve(foundExe) !== path.resolve(targetExe)) {
			await fs.copyFile(foundExe, targetExe).catch(() => {})
		}

		// Cleanup downloaded archive
		await fs.unlink(targetArchive).catch(() => {})

		// Make executable on POSIX
		if (process.platform !== "win32") {
			await fs.chmod(targetExe, 0o755).catch(() => {})
		}

		return { success: true, path: targetExe }
	} catch (err) {
		return { success: false, error: err.message }
	}
}

/**
 * Parse output from warpscout text report or console output.
 * @param {string} text
 * @returns {Array<{ endpoint: string, ip: string, port: number, rttMs: number|null, tunPingMs: number|null, loss: number|null, node: string|null, country: string|null, status: string }>}
 */
export function parseWarpscoutOutput(text) {
	if (!text) return []
	const results = []
	const lines = text.split("\n")

	for (const line of lines) {
		const trimmed = line.trim()
		if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("===") || trimmed.startsWith("---")) {
			continue
		}

		// Matches IP:Port (IPv4 and IPv6)
		const match = trimmed.match(
			/(?:\[([0-9a-fA-F:]+)\]|([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)):(\d{1,5})/,
		)
		if (!match) continue

		const ip = match[1] || match[2]
		const port = Number(match[3])
		const endpoint = match[0]

		// Parse ping/rtt
		const pingMatch = trimmed.match(/(\d+(?:\.\d+)?)\s*ms/)
		const rttMs = pingMatch ? Math.round(Number(pingMatch[1])) : null

		// Parse loss
		const lossMatch = trimmed.match(/(\d+)%/)
		const loss = lossMatch ? Number(lossMatch[1]) : 0

		// Parse node IATA code (e.g. DME, FRA, AMS, HEL, ARN)
		const nodeMatch = trimmed.match(/\b([A-Z]{3})\b/g)
		let node = null
		if (nodeMatch) {
			node = nodeMatch.find((code) => COLO_MAP[code]) || nodeMatch[nodeMatch.length - 1]
		}

		const isTornDown = trimmed.toLowerCase().includes("torn down")
		const status = isTornDown ? "torn_down" : loss > 50 ? "high_loss" : "ok"

		const coloInfo = node && COLO_MAP[node] ? COLO_MAP[node] : describeColo(node || "")

		results.push({
			endpoint,
			ip,
			port,
			rttMs,
			tunPingMs: rttMs,
			loss,
			node: node || coloInfo.colo,
			city: coloInfo.city || null,
			country: coloInfo.country || null,
			cc: coloInfo.cc || null,
			status,
		})
	}

	return results
}

/**
 * Execute warpscout scan using the installed executable.
 * @param {Object} options
 * @param {string} [options.proto="awg"] "awg" | "wg" | "masque" | "masque-h2"
 * @param {boolean} [options.tunPing=true] Measure inside tunnel RTT & drop torn down
 * @param {string} [options.genI1="quic"] "quic" | "dns" | "sip" | "stun" | "random"
 * @param {string} [options.sni] Fake SNI / domain
 * @param {string} [options.masqueSni] SNI for MASQUE
 * @param {string} [options.country] Filter by country (e.g. "DE,FI")
 * @param {string} [options.node] Filter by node (e.g. "FRA,HEL")
 * @param {number} [options.sample=5] Addresses to try per subnet
 * @param {number} [options.timeout=2] Per-request timeout in seconds
 * @returns {Promise<{ ok: boolean, best: string|null, endpoints: Array<Object>, rawOutput: string, error?: string }>}
 */
export async function runWarpscoutScan(options = {}) {
	const ws = await findWarpscoutBinary()
	if (!ws.available) {
		return {
			ok: false,
			best: null,
			endpoints: [],
			rawOutput: "",
			error: "warpscout binary not found. Run download or use the native scanner.",
		}
	}

	const binDir = path.dirname(ws.path)

	// Ensure warpscout-account.json exists in binDir, or auto-register
	const accountFile = path.join(binDir, "warpscout-account.json")
	try {
		await fs.access(accountFile)
	} catch {
		await new Promise((resolve) => {
			const regProc = spawn(ws.path, ["register"], {
				cwd: binDir,
				timeout: 15000,
				stdio: "ignore",
			})
			regProc.on("close", () => resolve())
			regProc.on("error", () => resolve())
		})
	}

	const proto = options.proto || "awg"
	const args = ["scan", "-p", proto, "-no-report"]

	if (options.tunPing !== false) {
		args.push("-P")
	}

	if (proto === "awg") {
		if (options.genI1) {
			args.push("-gen-i1", options.genI1)
		}
		if (options.sni) {
			args.push("-i1-sni", options.sni)
		}
	} else if (proto.startsWith("masque")) {
		if (options.masqueSni || options.sni) {
			args.push("-masque-sni", options.masqueSni || options.sni)
		}
	}

	if (options.country) args.push("-country", options.country)
	if (options.node) {
		args.push("-node", options.node)
	} else {
		// Exclude DME (Moscow) by default to prevent routing through censored RU nodes
		args.push("-exclude-node", "DME")
	}
	if (options.sample) args.push("-sample", String(options.sample))
	if (options.timeout) args.push("-timeout", String(options.timeout))

	return new Promise((resolve) => {
		let stdout = ""
		let stderr = ""
		const proc = spawn(ws.path, args, {
			cwd: binDir,
			timeout: (options.timeout || 10) * 1000 + 45000,
			stdio: ["ignore", "pipe", "pipe"],
		})

		proc.stdout.on("data", (d) => (stdout += d.toString()))
		proc.stderr.on("data", (d) => (stderr += d.toString()))

		proc.on("error", (err) => {
			resolve({
				ok: false,
				best: null,
				endpoints: [],
				rawOutput: stderr || stdout,
				error: `Execution failed: ${err.message}`,
			})
		})

		proc.on("close", (code) => {
			const full = `${stdout}\n${stderr}`
			const endpoints = parseWarpscoutOutput(full)
			const working = endpoints.filter((e) => e.status === "ok")

			let best = null
			if (working.length > 0) {
				working.sort((a, b) => (a.rttMs ?? 9999) - (b.rttMs ?? 9999))
				best = working[0].endpoint
			}

			resolve({
				ok: code === 0 || working.length > 0,
				best,
				endpoints,
				rawOutput: full,
				error: code !== 0 && !working.length ? (stderr || stdout || `Process exited with code ${code}`) : undefined,
			})
		})
	})
}

/**
 * Built-in native Node.js scanner that tests Cloudflare WARP anycast pools
 * and popular camouflage ports concurrently without external dependencies.
 *
 * @param {Object} [options]
 * @param {number} [options.concurrency=8]
 * @param {number} [options.timeoutMs=2500]
 * @param {number} [options.candidatesPerPrefix=3]
 * @returns {Promise<{ ok: boolean, best: string|null, endpoints: Array<Object>, method: string }>}
 */
export async function nativeScanEndpoints(options = {}) {
	const {
		concurrency = 8,
		timeoutMs = 2500,
		candidatesPerPrefix = 2,
	} = options

	if (isMockMode()) {
		return {
			ok: true,
			best: "188.114.98.58:4500",
			endpoints: [
				{
					endpoint: "188.114.98.58:4500",
					ip: "188.114.98.58",
					port: 4500,
					rttMs: 24,
					colo: "FRA",
					city: "Frankfurt",
					country: "Germany",
					cc: "DE",
					status: "ok",
				},
				{
					endpoint: "162.159.193.10:1701",
					ip: "162.159.193.10",
					port: 1701,
					rttMs: 31,
					colo: "AMS",
					city: "Amsterdam",
					country: "Netherlands",
					cc: "NL",
					status: "ok",
				},
				{
					endpoint: "188.114.97.22:500",
					ip: "188.114.97.22",
					port: 500,
					rttMs: 38,
					colo: "HEL",
					city: "Helsinki",
					country: "Finland",
					cc: "FI",
					status: "ok",
				},
			],
			method: "mock",
		}
	}

	// Select top proven camouflage ports and select random IPs across candidate prefixes
	const portsToProbe = [500, 1701, 4500, 854, 859, 894, 908, 942, 2408]
	const candidateIps = []

	const prefixes = ENDPOINT_PREFIXES.filter((p) => p.probeable && p.family === 4)
	for (const p of prefixes) {
		for (let i = 0; i < candidatesPerPrefix; i++) {
			// pick spread out hosts: 1, 10, 25, 42, 100, etc.
			const hostNum = ((i * 37 + 13) % 250) + 1
			candidateIps.push(`${p.id}.${hostNum}`)
		}
	}

	// Build queue of candidate probes
	const probeTasks = []
	for (let i = 0; i < candidateIps.length; i++) {
		const ip = candidateIps[i]
		const port = portsToProbe[i % portsToProbe.length]
		probeTasks.push({ ip, port })
	}

	const results = []
	let index = 0

	const worker = async () => {
		while (index < probeTasks.length) {
			const task = probeTasks[index++]
			const endpoint = `${task.ip}:${task.port}`
			try {
				const probe = await probeColo(task.ip, { timeoutMs })
				if (probe.ok) {
					results.push({
						endpoint,
						ip: task.ip,
						port: task.port,
						rttMs: probe.rttMs,
						colo: probe.location?.colo || null,
						city: probe.location?.city || null,
						country: probe.location?.country || null,
						cc: probe.location?.cc || null,
						status: "ok",
					})
				}
			} catch {
				// unprobeable/dropped
			}
		}
	}

	const workers = Array.from({ length: Math.min(concurrency, probeTasks.length) }, () => worker())
	await Promise.all(workers)

	results.sort((a, b) => a.rttMs - b.rttMs)
	const best = results.length > 0 ? results[0].endpoint : null

	return {
		ok: results.length > 0,
		best,
		endpoints: results,
		method: "native",
	}
}

/**
 * Universal endpoint scan dispatcher.
 * Prefers warpscout if available, or falls back seamlessly to native scanner.
 *
 * @param {Object} options
 * @returns {Promise<{ ok: boolean, best: string|null, endpoints: Array<Object>, method: string }>}
 */
export async function scoutEndpoints(options = {}) {
	const ws = await findWarpscoutBinary()
	if (ws.available && !options.preferNative) {
		const wsResult = await runWarpscoutScan(options)
		if (wsResult.ok && wsResult.endpoints.length > 0) {
			return {
				ok: true,
				best: wsResult.best,
				endpoints: wsResult.endpoints,
				rawOutput: wsResult.rawOutput,
				method: `warpscout (${ws.version || "cli"})`,
			}
		}
	}

	// Fallback to native scanner
	return nativeScanEndpoints(options)
}
