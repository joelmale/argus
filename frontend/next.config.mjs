import path from 'node:path'

const internalApiUrl =
  process.env.INTERNAL_API_URL
  ?? process.env.NEXT_PUBLIC_API_URL
  ?? 'http://backend:8000'

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',   // Required for Docker multi-stage build
  reactStrictMode: true,
  turbopack: {
    root: path.resolve(process.cwd()),
  },
  // Allow fetching from the backend container
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: `${internalApiUrl}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;
