import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  metadataBase: new URL(process.env.NEXT_PUBLIC_APP_URL || "https://webshield.vercel.app"),
  title: { default: "WebShield — Monitor. Detect. Protect.", template: "%s | WebShield" },
  description: "WebShield by Savrdh Technologies is a website protection and visitor security platform for monitoring traffic, detecting suspicious activity and managing website security.",
  openGraph: {
    title: "WebShield — Monitor. Detect. Protect.",
    description: "Advanced Website Protection & Visitor Security Platform",
    type: "website",
    siteName: "WebShield"
  },
  twitter: { card: "summary_large_image", title: "WebShield", description: "Monitor. Detect. Protect." },
  robots: { index: true, follow: true }
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
