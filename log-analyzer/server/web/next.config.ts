import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  
  // Proxy API calls to Go backend
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: "http://localhost:8237/api/:path*",
      },
      {
        source: "/ws",
        destination: "http://localhost:8237/ws",
      },
      {
        source: "/ws/dashboard",
        destination: "http://localhost:8237/ws/dashboard",
      },
      {
        source: "/health",
        destination: "http://localhost:8237/health",
      },
    ];
  },
};

export default nextConfig;
