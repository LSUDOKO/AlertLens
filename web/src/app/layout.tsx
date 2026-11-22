import type { Metadata, Viewport } from "next";
import { JetBrains_Mono, Outfit } from "next/font/google";
import "./globals.css";

const outfit = Outfit({ subsets: ["latin"], weight: ["300", "400", "500", "600", "700"], variable: "--font-outfit", display: "swap" });
const mono = JetBrains_Mono({ subsets: ["latin"], weight: ["400", "500"], variable: "--font-mono", display: "swap" });

export const metadata: Metadata = {
  metadataBase: new URL(process.env.NEXT_PUBLIC_SITE_URL || "https://alertlens.adoranto737.workers.dev"),
  title: "AlertLens: security alerts, explained without taking orders",
  description:
    "AlertLens explains security alerts in plain language. Attackers can hide instructions inside logs; AlertLens keeps them away from the model, decides severity in code and checks every claim.",
  openGraph: { title: "AlertLens", description: "Security alerts, explained without taking orders from the logs.", images: ["/media/hero-poster.jpg"] },
};

export const viewport: Viewport = { themeColor: "#000000" };

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className={`${outfit.variable} ${mono.variable}`}>
      <body>{children}</body>
    </html>
  );
}
