/**
 * Serverless entry point (Vercel or any Node serverless runtime).
 *
 * Reuses the exact same request handler as the standalone server, so the API
 * behaves identically. Static files under `public/` are served by the platform
 * CDN, so only `/api/*` reaches this function.
 *
 * Caveat: location scanning from a serverless region measures the distance
 * between Cloudflare and the serverless region, not between Cloudflare and
 * you. Self-host if you want an honest measurement.
 */

import { handleRequest } from "../src/server.js"

export default async function handler(req, res) {
	await handleRequest(req, res)
}

export const config = {
	runtime: "nodejs20.x",
}
