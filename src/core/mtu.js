/**
 * MTU calculator for WireGuard / AmneziaWG tunnels.
 *
 * Overhead of one encrypted transport packet:
 *   outer IP header   20 (IPv4) or 40 (IPv6)
 * + outer UDP header   8
 * + WG transport hdr  16  (4 type+reserved, 4 receiver index, 8 counter)
 * + Poly1305 tag      16
 * ------------------------------------------------------------------
 *   = 60 bytes over IPv4, 80 bytes over IPv6
 *
 * AmneziaWG's magic headers (H1..H4) replace the existing 4-byte type field,
 * so they add ZERO bytes. Junk packets (Jc/Jmin/Jmax) are separate packets and
 * likewise do not shrink the usable MTU. S1/S2 padding only applies to the two
 * handshake packets. So AmneziaWG MTU math is identical to WireGuard's.
 */

export const OVERHEAD = {
	ipv4Header: 20,
	ipv6Header: 40,
	udpHeader: 8,
	wgTransportHeader: 16,
	poly1305Tag: 16,
}

/** Common real-world path MTUs. */
export const PATH_PRESETS = [
	{ id: "ethernet", label: "Ethernet / Wi-Fi (1500)", pathMtu: 1500 },
	{ id: "pppoe", label: "PPPoE DSL (1492)", pathMtu: 1492 },
	{ id: "mobile", label: "Mobile LTE/5G (1428)", pathMtu: 1428 },
	{ id: "tunnelled", label: "Already inside a tunnel (1400)", pathMtu: 1400 },
	{ id: "safe", label: "Guaranteed-safe minimum (1280)", pathMtu: 1340 },
]

/**
 * @param {Object} [options]
 * @param {number} [options.pathMtu] Underlying link MTU. Default 1500.
 * @param {4|6} [options.outerFamily] IP version of the outer packet. Default 4.
 * @param {boolean} [options.conservative] Clamp to WARP's official 1280.
 * @returns {{ mtu: number, pathMtu: number, overhead: number, breakdown: Object, notes: string[] }}
 */
export function calculateMtu(options = {}) {
	const pathMtu = clampInt(options.pathMtu ?? 1500, 576, 9000)
	const outerFamily = options.outerFamily === 6 ? 6 : 4

	const ipHeader =
		outerFamily === 6 ? OVERHEAD.ipv6Header : OVERHEAD.ipv4Header
	const overhead =
		ipHeader +
		OVERHEAD.udpHeader +
		OVERHEAD.wgTransportHeader +
		OVERHEAD.poly1305Tag

	let mtu = pathMtu - overhead
	const notes = []

	if (options.conservative) {
		if (mtu > 1280) {
			mtu = 1280
			notes.push(
				"Clamped to 1280, the value the official WARP client ships. It wastes a little throughput but never fragments.",
			)
		}
	} else {
		notes.push(
			`Computed from a ${pathMtu}-byte path minus ${overhead} bytes of IPv${outerFamily}+UDP+WireGuard overhead.`,
		)
	}

	if (mtu < 1280) {
		notes.push(
			"Below 1280 bytes IPv6 inside the tunnel will break. Raise the path MTU or disable IPv6.",
		)
	}
	if (mtu > 1420) {
		notes.push(
			"Above 1420 some ISPs silently drop large packets. If pages hang while pings work, lower this by 20-80.",
		)
	}

	return {
		mtu: clampInt(mtu, 576, 8920),
		pathMtu,
		overhead,
		breakdown: {
			[`ipv${outerFamily}Header`]: ipHeader,
			udpHeader: OVERHEAD.udpHeader,
			wgTransportHeader: OVERHEAD.wgTransportHeader,
			poly1305Tag: OVERHEAD.poly1305Tag,
		},
		notes,
	}
}

function clampInt(value, lo, hi) {
	const n = Math.trunc(Number(value))
	if (!Number.isFinite(n)) return lo
	return Math.min(Math.max(n, lo), hi)
}

/**
 * Ready-made AllowedIPs sets.
 * `full` is what you want for an actual VPN; the others are for split tunnelling.
 */
export const ALLOWED_IPS_PRESETS = {
	full: {
		label: "Full tunnel (IPv4 + IPv6)",
		value: ["0.0.0.0/0", "::/0"],
		note: "Everything goes through WARP.",
	},
	ipv4Only: {
		label: "Full tunnel, IPv4 only",
		value: ["0.0.0.0/0"],
		note: "Use when your ISP's IPv6 is broken or leaks.",
	},
	excludeLan: {
		label: "Full tunnel, keep LAN reachable",
		// 0.0.0.0/0 minus RFC1918, expressed as the CIDR complement.
		value: [
			"0.0.0.0/5",
			"8.0.0.0/7",
			"11.0.0.0/8",
			"12.0.0.0/6",
			"16.0.0.0/4",
			"32.0.0.0/3",
			"64.0.0.0/2",
			"128.0.0.0/3",
			"160.0.0.0/5",
			"168.0.0.0/6",
			"172.0.0.0/12",
			"172.32.0.0/11",
			"172.64.0.0/10",
			"172.128.0.0/9",
			"173.0.0.0/8",
			"174.0.0.0/7",
			"176.0.0.0/4",
			"192.0.0.0/9",
			"192.128.0.0/11",
			"192.160.0.0/13",
			"192.169.0.0/16",
			"192.170.0.0/15",
			"192.172.0.0/14",
			"192.176.0.0/12",
			"192.192.0.0/10",
			"193.0.0.0/8",
			"194.0.0.0/7",
			"196.0.0.0/6",
			"200.0.0.0/5",
			"208.0.0.0/4",
			"::/0",
		],
		note: "Routes all public traffic but leaves 10/8, 172.16/12 and 192.168/16 on your local network, so printers, NAS and your router stay reachable.",
	},
}

/** DNS presets. Cloudflare's resolvers are the natural pair for WARP. */
export const DNS_PRESETS = {
	cloudflare: {
		label: "Cloudflare (1.1.1.1)",
		value: ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
	},
	cloudflareMalware: {
		label: "Cloudflare, malware blocking (1.1.1.2)",
		value: ["1.1.1.2", "1.0.0.2", "2606:4700:4700::1112", "2606:4700:4700::1002"],
	},
	google: { label: "Google (8.8.8.8)", value: ["8.8.8.8", "8.8.4.4"] },
	quad9: { label: "Quad9 (9.9.9.9)", value: ["9.9.9.9", "149.112.112.112"] },
	adguard: { label: "AdGuard, ad blocking", value: ["94.140.14.14", "94.140.15.15"] },
}
