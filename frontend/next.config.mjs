import path from 'node:path'

const internalApiUrl =
  process.env.INTERNAL_API_URL
  ?? process.env.NEXT_PUBLIC_API_URL
  ?? 'http://backend:8000'

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',   // Required for Docker multi-stage build
  reactStrictMode: true,
  // Pass /api/... paths through unchanged. With Next's default slash stripping,
  // `/api/v1/scans/` became `/api/v1/scans`, FastAPI redirected back to the slash
  // form on its internal host (http://backend:8000/...), and the browser failed.
  skipTrailingSlashRedirect: true,
  turbopack: {
    root: path.resolve(process.cwd()),
  },
  // Proxy the backend through the frontend origin: REST under /api, and the live
  // event WebSocket under /ws (the browser connects to ws://<frontend>/ws/events).
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: `${internalApiUrl}/api/:path*`,
      },
      {
        source: '/ws/:path*',
        destination: `${internalApiUrl}/ws/:path*`,
      },
    ];
  },
};

export default nextConfig;
