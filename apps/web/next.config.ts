import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  transpilePackages: ["@hookshield/contracts"],
  poweredByHeader: false,
  typedRoutes: false
};

export default nextConfig;
