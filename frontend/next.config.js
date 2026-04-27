/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${process.env.NEXT_PUBLIC_API_INTERNAL_URL || "http://api:8000"}/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;
