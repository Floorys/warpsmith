#!/usr/bin/env node
/**
 * CLI front end. Same core as the web UI, so scripted and interactive use can
 * never drift apart.
 *
 *   awg-warp generate --obfuscation warp-heavy --out ./awg.conf
 *   awg-warp scan
 *   awg-warp obfuscate --obfuscation awg-mimicry
 */

import fs from "node:fs/promises"
import path from "node:path"

import { generateProfile, describeOptions } from "../src/core/generate.js"
import { scanLocations, describeLocationReality } from "../src/core/endpoints.js"
import {
	generateObfuscation,
	renderObfuscationLines,
	PACKET_SIGNATURES,
} from "../src/core/amnezia.js"
import { isMockMode } from "../src/core/warp.js"
import {
	findWarpscoutBinary,
	downloadWarpscout,
	scoutEndpoints,
} from "../src/core/scout.js"

const COLORS = process.stdout.isTTY && !process.env.NO_COLOR
const c = {
	dim: (s) => (COLORS ? `\x1b[2m${s}\x1b[0m` : s),
	bold: (s) => (COLORS ? `\x1b[1m${s}\x1b[0m` : s),
	green: (s) => (COLORS ? `\x1b[32m${s}\x1b[0m` : s),
	yellow: (s) => (COLORS ? `\x1b[33m${s}\x1b[0m` : s),
	red: (s) => (COLORS ? `\x1b[31m${s}\x1b[0m` : s),
	cyan: (s) => (COLORS ? `\x1b[36m${s}\x1b[0m` : s),
}

/** Minimal argv parser: --key value, --flag, --no-flag. */
function parseArgs(argv) {
	const out = { _: [] }
	for (let i = 0; i < argv.length; i++) {
		const token = argv[i]
		if (!token.startsWith("--")) {
			out._.push(token)
			continue
		}
		const key = token.slice(2)
		if (key.startsWith("no-")) {
			out[key.slice(3)] = false
			continue
		}
		const next = argv[i + 1]
		if (next === undefined || next.startsWith("--")) {
			out[key] = true
		} else {
			out[key] = /^-?\d+$/.test(next) ? Number(next) : next
			i++
		}
	}
	return out
}

/** `--signatures tls,quic` -> ["tls", "quic"]. Unknown ids fail loudly. */
function parseSignatures(value) {
	if (!value || value === true) return undefined
	const ids = String(value)
		.split(",")
		.map((s) => s.trim().toLowerCase())
		.filter(Boolean)
	if (!ids.length) return undefined

	const known = Object.keys(PACKET_SIGNATURES)
	const unknown = ids.filter((id) => !known.includes(id))
	if (unknown.length) {
		throw new Error(
			`Unknown signature(s): ${unknown.join(", ")}. Available: ${known.join(", ")}`,
		)
	}
	return ids
}

function usage() {
	const { obfuscationProfiles, allowedIps, dns } = describeOptions()
	console.log(`
${c.bold("awg-warp")} - Cloudflare WARP config generator with AmneziaWG obfuscation & WarpScout

${c.bold("COMMANDS")}
  generate            Register a WARP device and write a config
  scout               Scan and find working Cloudflare endpoints (via WarpScout / native)
  scan                Probe Cloudflare datacenters and report real locations
  obfuscate           Print an obfuscation parameter block only
  serve               Start the web UI (same as npm start)

${c.bold("GENERATE OPTIONS")}
  --obfuscation <id>  ${obfuscationProfiles.map((p) => p.id).join(" | ")}   (default: warp-balanced)
  --out <file>        Write the config here (default: stdout)
  --format <fmt>      awg | wg | json | vpn | mihomo | singbox   (default: awg)
  --scout             Automatically scan and use the best working endpoint
  --sni <domain>      Spoofed SNI domain for mimicry (e.g. www.apple.com)
  --seed <hex>        Reproduce a previous profile exactly
  --private-key <k>   Reuse an existing WireGuard identity
  --license <key>     Apply a WARP+ license
  --prefix <p>        Endpoint prefix, e.g. 188.114.98
  --port <n>          Endpoint UDP port, e.g. 2408
  --endpoint <h:p>    Fully explicit endpoint override
  --detect-location   Probe the chosen endpoint and report its datacenter
  --allowed-ips <v>   ${allowedIps.map((a) => a.id).join(" | ")} or a CIDR list
  --dns <v>           ${dns.map((d) => d.id).join(" | ")} or a server list
  --mtu <n>           Explicit MTU (default: computed, clamped to 1280)
  --path-mtu <n>      Link MTU used to compute the tunnel MTU
  --keepalive <n>     PersistentKeepalive seconds (default 25, 0 disables)
  --no-ipv6           Strip IPv6 addresses and routes
  --preshared-key     Add an extra symmetric PSK

${c.bold("MIMICRY & SNI OPTIONS")}  ${c.dim("(fake protocol packets, AmneziaWG 1.5+ client)")}
  --signatures <ids>  Comma separated: ${Object.keys(PACKET_SIGNATURES).join(",")}
  --sni <domain>      Domain for SNI spoofing, e.g. www.apple.com, cdn.jsdelivr.net, vk.com
  --mimicry-domain <d> Alias for --sni

${c.bold("SCOUT OPTIONS")}
  --proto <p>         awg | wg | masque | masque-h2 (default: awg)
  --best              Print only the single best endpoint (ip:port)
  --native            Force native Node.js scanner instead of warpscout binary
  --download          Download latest warpscout binary from GitHub

${c.bold("EXAMPLES")}
  ${c.dim("# Everyday config with auto-scouted endpoint")}
  awg-warp generate --scout --out warp.conf

  ${c.dim("# Scan working endpoints with WarpScout")}
  awg-warp scout

  ${c.dim("# The proven stealth recipe: QUIC initial + Apple SNI spoofing")}
  awg-warp generate --obfuscation warp-cloak --sni www.apple.com --out warp.conf

  ${c.dim("# Export for Clash.Meta / Mihomo with AmneziaWG obfuscation")}
  awg-warp generate --format mihomo --out warp.yaml
`)
}

async function cmdGenerate(args) {
	let endpointHost = args.endpoint
	if (!endpointHost && (args.scout || args["warp-scout"])) {
		process.stderr.write("Scouting for best working endpoint...\n")
		const sc = await scoutEndpoints({
			sni: args.sni || args["mimicry-domain"],
			preferNative: Boolean(args.native),
		})
		if (sc.best) {
			endpointHost = sc.best
			process.stderr.write(`Selected best endpoint: ${sc.best}\n`)
		}
	}

	const profile = await generateProfile({
		obfuscation: args.obfuscation,
		signatures: parseSignatures(args.signatures),
		mimicryDomain: args.sni || args["mimicry-domain"],
		seed: args.seed,
		privateKey: args["private-key"],
		license: args.license,
		endpointPrefix: args.prefix,
		endpointPort: args.port,
		endpointHost: endpointHost,
		detectLocation: Boolean(args["detect-location"]),
		allowedIps: args["allowed-ips"],
		dns: args.dns,
		mtu: Number.isInteger(args.mtu) ? args.mtu : undefined,
		pathMtu: Number.isInteger(args["path-mtu"]) ? args["path-mtu"] : undefined,
		keepalive: Number.isInteger(args.keepalive) ? args.keepalive : undefined,
		ipv6: args.ipv6 !== false,
		presharedKey: Boolean(args["preshared-key"]),
		useHostname: Boolean(args.hostname),
	})

	const format = args.format || "awg"
	const picked =
		format === "wg"
			? profile.configs.wireguard
			: format === "json"
				? profile.configs.json
				: format === "vpn"
					? profile.configs.vpn
					: format === "mihomo"
						? profile.configs.mihomo
						: format === "singbox"
							? profile.configs.singbox
							: profile.configs.amneziawg

	if (args.out) {
		const target = path.resolve(String(args.out))
		await fs.writeFile(target, picked.content, { mode: 0o600 })
		console.log(c.green(`Wrote ${target}`) + c.dim(" (mode 0600)"))
	} else {
		process.stdout.write(picked.content)
	}

	// Everything below goes to stderr so `> file` stays clean.
	const log = (s) => process.stderr.write(s + "\n")
	log("")
	log(c.bold("Summary"))
	log(`  Endpoint     ${profile.endpoint.endpoint}`)
	if (profile.location?.measured) {
		log(
			`  Location     ${profile.location.city}, ${profile.location.country} ` +
				c.dim(`(colo ${profile.location.colo}, ${profile.location.rttMs} ms)`),
		)
	}
	log(`  Address      ${profile.network.addresses.join(", ")}`)
	log(`  MTU          ${profile.network.mtu}`)
	log(`  Account      ${profile.warp.accountType}${profile.warp.warpPlus ? " (WARP+)" : ""}`)
	log(`  Obfuscation  ${profile.obfuscation.profileLabel}`)
	log(`  Seed         ${c.cyan(profile.meta.seed)} ${c.dim("<- reuse with --seed")}`)

	for (const warning of profile.warnings) log(c.yellow(`  ! ${warning}`))
}

async function cmdScan(args) {
	const reality = describeLocationReality()
	console.log(c.bold("How WARP location actually works"))
	console.log(c.dim(`  ${reality.summary}`))
	console.log("")
	console.log(c.dim("Probing Cloudflare endpoints..."))

	const { scanned, byLocation } = await scanLocations({
		perPrefix: Number.isInteger(args["per-prefix"]) ? args["per-prefix"] : 2,
		timeoutMs: Number.isInteger(args.timeout) ? args.timeout : 4000,
	})

	if (!byLocation.length) {
		console.log(c.red(`No endpoint answered out of ${scanned} probed.`))
		console.log(c.dim("Cloudflare may be blocked on this network."))
		return
	}

	console.log("")
	console.log(c.bold(`Reachable datacenters (${byLocation.length} of ${scanned} probes)`))
	for (const loc of byLocation) {
		const name = `${loc.city}, ${loc.country}`.padEnd(30)
		console.log(
			`  ${c.green(loc.colo)}  ${name} ${String(loc.bestRttMs).padStart(4)} ms  ` +
				c.dim(loc.endpoints.map((e) => e.ip).slice(0, 3).join(", ")),
		)
	}
	console.log("")
	console.log(c.dim("Pin one with:  awg-warp generate --endpoint <ip>:2408"))
}

async function cmdObfuscate(args) {
	const result = generateObfuscation({
		profile: args.obfuscation || args.profile || "warp-balanced",
		seed: args.seed,
	})
	if (!result.enabled) {
		console.log(c.dim("Obfuscation is disabled for this profile."))
		return
	}
	console.log(c.bold(`${result.profileLabel}  `) + c.dim(`AmneziaWG ${result.version}`))
	console.log(c.dim(result.summary))
	console.log("")
	console.log(renderObfuscationLines(result).join("\n"))
	console.log("")
	console.log(c.bold("What each value does"))
	for (const row of result.explain) {
		console.log(`  ${c.cyan(row.key.padEnd(12))} ${row.what}`)
	}
	console.log("")
	console.log(c.dim(`Seed ${result.seed} reproduces these exact values on another device.`))
	for (const w of result.validation.warnings) console.log(c.yellow(`  ! ${w}`))
}

async function cmdScout(args) {
	console.log(c.bold("🛰️ WARP Endpoint Scout (WarpScout)"))

	if (args.download) {
		console.log("Downloading warpscout binary from GitHub releases...")
		const res = await downloadWarpscout()
		if (res.success) {
			console.log(c.green(`Downloaded to ${res.path}`))
		} else {
			console.error(c.red(`Download failed: ${res.error}`))
		}
		return
	}

	const ws = await findWarpscoutBinary()
	if (ws.available && !args.native) {
		console.log(c.dim(`Using WarpScout CLI (${ws.version || ws.path})`))
	} else {
		console.log(c.dim("WarpScout binary not found, using built-in native prober."))
		console.log(c.dim("Run `awg-warp scout --download` to install the official warpscout binary."))
	}

	console.log("Scanning Cloudflare WARP endpoints...")
	const result = await scoutEndpoints({
		proto: args.proto || "awg",
		sni: args.sni || args["mimicry-domain"],
		genI1: args["gen-i1"] || "quic",
		preferNative: Boolean(args.native),
	})

	if (args.best && result.best) {
		console.log(result.best)
		return
	}

	console.log("")
	console.log(c.bold(`Found ${result.endpoints.length} active endpoints (via ${result.method}):`))
	for (const ep of result.endpoints) {
		const ping = ep.rttMs ? `${ep.rttMs}ms`.padStart(7) : "   ? ms"
		const loc = ep.city ? `${ep.city}, ${ep.country || ""}` : ep.colo || "Cloudflare"
		const status = ep.status === "ok" ? c.green("ACTIVE") : c.yellow(ep.status)
		console.log(`  ${c.cyan(ep.endpoint.padEnd(24))}  ${ping}  ${loc.padEnd(28)}  ${status}`)
	}
	if (result.best) {
		console.log("")
		console.log(c.green(`Best endpoint: ${c.bold(result.best)}`))
		console.log(c.dim(`Use it with: awg-warp generate --endpoint ${result.best}`))
	}
}

async function main() {
	const argv = process.argv.slice(2)
	const args = parseArgs(argv)
	const command = args._[0]

	if (!command || args.help || command === "help") {
		usage()
		return
	}
	if (isMockMode()) {
		process.stderr.write(c.yellow("MOCK_WARP=1 - synthetic output, nothing will connect\n\n"))
	}

	switch (command) {
		case "generate":
			await cmdGenerate(args)
			break
		case "scout":
			await cmdScout(args)
			break
		case "scan":
			await cmdScan(args)
			break
		case "obfuscate":
			await cmdObfuscate(args)
			break
		case "serve":
			await import("../src/server.js")
			break
		default:
			console.error(c.red(`Unknown command "${command}"`))
			usage()
			process.exitCode = 1
	}
}

main().catch((error) => {
	console.error(c.red(`\n${error.name}: ${error.message}`))
	if (error.hint) console.error(c.dim(error.hint))
	process.exitCode = 1
})
