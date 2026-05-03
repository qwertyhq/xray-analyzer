import type { NextConfig } from "next";
import createNextIntlPlugin from 'next-intl/plugin';

const withNextIntl = createNextIntlPlugin('./src/i18n/request.ts');

const nextConfig: NextConfig = {
  output: "standalone",

  // Proxy API calls to Go backend
  // Note: WebSocket connections are handled directly in websocket-context.tsx
  // because Next.js rewrites don't support WebSocket properly
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: "http://localhost:8237/api/:path*",
      },
      {
        source: "/health",
        destination: "http://localhost:8237/health",
      },
    ];
  },
};

export default withNextIntl(nextConfig);
