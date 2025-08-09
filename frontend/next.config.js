const withPWAInit = require("next-pwa");

const withPWA = withPWAInit({
  dest: "public",
  disable: process.env.NODE_ENV === "development",
});

const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    return [
      {
        source: '/reports/:path*',
        destination: 'http://localhost:4000/reports/:path*',
      },
    ];
  },
};

module.exports = withPWA(nextConfig);
