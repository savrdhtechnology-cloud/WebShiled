import type { NextConfig } from "next";

const securityHeaders = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
  { key: "Cross-Origin-Resource-Policy", value: "same-origin" }
];

const nextConfig: NextConfig = {
  basePath: "/webshield",
  poweredByHeader: false,
  reactStrictMode: true,
  async redirects() {
    return process.env.NODE_ENV === "development" ? [{
      source: "/demo/:path*",
      destination: "http://127.0.0.1:3000/webshield/demo/:path*",
      basePath: false as const,
      permanent: false
    }] : [];
  },
  async headers() {
    return [{ source: "/(.*)", headers: securityHeaders }];
  }
};

export default nextConfig;
