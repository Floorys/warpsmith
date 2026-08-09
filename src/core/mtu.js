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

/**
 * DNS presets. Cloudflare's resolvers are the natural pair for WARP.
 *
 * Every entry carries its IPv6 resolvers alongside the IPv4 ones. resolveDns()
 * strips the v6 addresses when the config is built without IPv6, so listing
 * them here is free; leaving them out is not, because an IPv6-enabled tunnel
 * would then have no v6 resolver to talk to.
 */
export const DNS_PRESETS = {
	cloudflare: {
		label: "Cloudflare (1.1.1.1)",
		labelRu: "Cloudflare (1.1.1.1)",
		value: ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
	},
	cloudflareMalware: {
		label: "Cloudflare, malware blocking (1.1.1.2)",
		labelRu: "Cloudflare, блокировка вредоносных (1.1.1.2)",
		value: ["1.1.1.2", "1.0.0.2", "2606:4700:4700::1112", "2606:4700:4700::1002"],
	},
	cloudflareFamily: {
		label: "Cloudflare, malware + adult (1.1.1.3)",
		labelRu: "Cloudflare, вредоносные + 18+ (1.1.1.3)",
		value: ["1.1.1.3", "1.0.0.3", "2606:4700:4700::1113", "2606:4700:4700::1003"],
	},
	google: {
		label: "Google (8.8.8.8)",
		labelRu: "Google (8.8.8.8)",
		value: ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
	},
	quad9: {
		label: "Quad9, malware blocking (9.9.9.9)",
		labelRu: "Quad9, блокировка вредоносных (9.9.9.9)",
		value: ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"],
	},
	quad9Unfiltered: {
		label: "Quad9, unfiltered (9.9.9.10)",
		labelRu: "Quad9, без фильтрации (9.9.9.10)",
		value: ["9.9.9.10", "149.112.112.10", "2620:fe::10", "2620:fe::fe:10"],
	},
	adguard: {
		label: "AdGuard, ad blocking",
		labelRu: "AdGuard, блокировка рекламы",
		value: [
			"94.140.14.14",
			"94.140.15.15",
			"2a10:50c0::ad1:ff",
			"2a10:50c0::ad2:ff",
		],
	},
	adguardFamily: {
		label: "AdGuard, ads + adult",
		labelRu: "AdGuard, реклама + 18+",
		value: [
			"94.140.14.15",
			"94.140.15.16",
			"2a10:50c0::bad1:ff",
			"2a10:50c0::bad2:ff",
		],
	},
	opendns: {
		label: "OpenDNS (208.67.222.222)",
		labelRu: "OpenDNS (208.67.222.222)",
		value: [
			"208.67.222.222",
			"208.67.220.220",
			"2620:119:35::35",
			"2620:119:53::53",
		],
	},
	dnssb: {
		label: "DNS.SB, no logging (185.222.222.222)",
		labelRu: "DNS.SB, без логов (185.222.222.222)",
		value: ["185.222.222.222", "45.11.45.11", "2a09::", "2a11::"],
	},
	yandex: {
		label: "Yandex (77.88.8.8)",
		labelRu: "Яндекс (77.88.8.8)",
		value: [
			"77.88.8.8",
			"77.88.8.1",
			"2a02:6b8::feed:0ff",
			"2a02:6b8:0:1::feed:0ff",
		],
	},

	/*
	 * Unblocking resolvers. These are not neutral caches: they answer with the
	 * address of their own proxy for the domains they cover, so the operator
	 * sees every query and decides what you connect to. Worth having, worth
	 * labelling honestly, and worth remembering that only their plain UDP/53
	 * addresses can go into a WireGuard config - DoH/DoT endpoints cannot.
	 */
	xboxdns: {
		label: "Xbox DNS, unblocking (111.88.96.50)",
		labelRu: "Xbox DNS, разблокировка (111.88.96.50)",
		note: "Smart DNS: geo-blocked domains are routed through its proxy. The operator sees every query.",
		noteRu: "Smart DNS: геоблокированные домены идут через его прокси. Владелец видит все запросы.",
		value: [
			"111.88.96.50",
			"111.88.96.51",
			"2a00:ab00:1233:26::50",
			"2a00:ab00:1233:26::51",
		],
	},
	malwlink: {
		label: "dns.malw.link, unblocking (95.216.204.218)",
		labelRu: "dns.malw.link, разблокировка (95.216.204.218)",
		note: "DNS + SNI proxy that also nulls out ad and tracker domains. The operator sees every query.",
		noteRu: "DNS + SNI-прокси, заодно режет рекламу и трекеры. Владелец видит все запросы.",
		value: [
			"95.216.204.218",
			"80.253.249.40",
			"2a01:4f9:c014:6dac::1",
			"2a12:bec4:1460:5b7::2",
		],
	},
	comss: {
		label: "Comss.one, unblocking (83.220.169.155)",
		labelRu: "Comss.one, разблокировка (83.220.169.155)",
		note: "IPv4 only: AI services plus ad and phishing filtering. The operator sees every query.",
		noteRu: "Только IPv4: ИИ-сервисы плюс фильтр рекламы и фишинга. Владелец видит все запросы.",
		// Comss publishes no IPv6 resolver, only these two plain IPv4 servers.
		// Flagged so the IPv6 coverage test can tell "deliberate" from "forgotten".
		ipv4Only: true,
		value: ["83.220.169.155", "212.109.195.93"],
	},
}
