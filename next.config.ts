import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  turbopack: {
    // Prevent scanning parent workspace when multiple lockfiles exist.
    root: process.cwd(),
  },
};

export default nextConfig;
