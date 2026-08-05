/**
 * Provenance notes for the grouped parameter rows.
 *
 * The API returns some rows already grouped: "Jmin / Jmax", "S1 / S2",
 * "H1-H4". app.js looks documentation up by the lowercased row key, so the
 * keys below are the exact lowercase forms of those labels.
 *
 * Kept in its own module so the long bilingual text does not bloat app.js.
 */
export const GROUP_PARAM_DOCS = {
	"jmin / jmax": {
		who: { ru: "только отправитель", en: "sender only" },
		bound: {
			ru: "8–1280 байт, Jmin < Jmax, Jmax ≤ MTU канала",
			en: "8–1280 bytes, Jmin < Jmax, Jmax ≤ path MTU",
		},
		break: {
			ru: "На стороне сервера — ничего: мусор всё равно отбрасывается. Но равные Jmin и Jmax дают пакеты одного размера — тот же отпечаток, от которого уходим, а Jmax выше MTU заставляет мусор фрагментироваться и становиться заметнее обычного трафика.",
			en: "Nothing server-side: the junk is dropped either way. But equal Jmin and Jmax produce constant-size packets — the very fingerprint we are escaping — and a Jmax above the path MTU makes the junk fragment and stand out more than plain traffic.",
		},
	},
	"s1 / s2": {
		who: { ru: "обе стороны, значения обязаны совпасть", en: "both sides, values must match" },
		bound: {
			ru: "0 для WARP; 15–1280 для своего сервера, и S1 + 56 ≠ S2",
			en: "0 for WARP; 15–1280 for your own server, and S1 + 56 ≠ S2",
		},
		break: {
			ru: "Рукопожатие молча отбрасывается: пакет пришёл не того размера, и клиент повторяет попытки до таймаута. Именно эти два числа чаще всего и ломают конфиги для WARP: паддинг лежит внутри пакета рукопожатия, а его длина в WireGuard фиксирована.",
			en: "The handshake is dropped silently: the packet arrived at the wrong size and the client retries until timeout. These two numbers are the most common reason a WARP config fails — the padding sits inside the handshake packet, and its length in WireGuard is fixed.",
		},
	},
	"h1-h4": {
		who: { ru: "обе стороны, все четыре значения", en: "both sides, all four values" },
		bound: {
			ru: "5–2147483647, все четыре различны; 1–4 заняты штатными типами WireGuard",
			en: "5–2147483647, all four distinct; 1–4 are taken by the standard WireGuard types",
		},
		break: {
			ru: "Каждый из четырёх ломает свою стадию: H1 — запрос клиента, H2 — ответ сервера, H3 — cookie reply под нагрузкой, H4 — сами данные. Самый коварный случай — H4: рукопожатие проходит, интерфейс поднимается, но трафик не идёт. С WARP безопасны только заголовки, выведенные из client id.",
			en: "Each of the four breaks its own stage: H1 the client's request, H2 the server's reply, H3 the cookie reply under load, H4 the data itself. H4 is the nastiest — the handshake completes and the interface comes up, but no traffic flows. With WARP only headers derived from the client id are safe.",
		},
	},
}

const MIMICRY_DOC = {
	who: { ru: "обе стороны, AmneziaWG 1.5+", en: "both sides, AmneziaWG 1.5+" },
	bound: {
		ru: "до пяти сигнатур I1–I5; байты собираются из шаблона протокола и домена в SNI",
		en: "up to five signatures I1–I5; bytes are built from a protocol template and the SNI domain",
	},
	break: {
		ru: "Сервер без поддержки мимикрии счтёт эти пакеты мусором и отбросит их, а клиенты старее 1.5 вовсе откажутся импортировать конфиг. WARP мимикрию не поддерживает в любом виде.",
		en: "A server without mimicry support treats these packets as junk and drops them, and clients older than 1.5 refuse to import the config at all. WARP does not support mimicry in any form.",
	},
}

for (const key of ["i1", "i2", "i3", "i4", "i5"]) {
	GROUP_PARAM_DOCS[key] = MIMICRY_DOC
}
