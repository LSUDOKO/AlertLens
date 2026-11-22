import type { NextConfig } from "next";

// A fully static site: every screen reads live data from the AlertLens API in the browser.
const nextConfig: NextConfig = {
  output: "export",
  trailingSlash: true,
  images: { unoptimized: true },
};

export default nextConfig;
