/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',   // Required for Docker multi-stage build
  reactStrictMode: true,
  // Allow fetching from the backend container
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: `${process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000'}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;
