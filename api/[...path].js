/**
 * Catch-all serverless entry point for Vercel and similar platforms.
 * Automatically catches all /api/* requests (e.g. /api/options, /api/health, /api/generate).
 */

import { handleRequest } from "../src/server.js"

export default async function handler(req, res) {
	await handleRequest(req, res)
}

export const config = {
	maxDuration: 60,
}
