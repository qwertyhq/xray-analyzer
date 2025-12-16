import type { Metadata, Viewport } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { Header } from "@/components/layout/header";
import { FloatingAIChat } from "@/components/layout/floating-ai-chat";
import { WebSocketProvider } from "@/contexts/websocket-context";
import { AuthProvider } from "@/contexts/auth-context";
import { AuthGuard } from "@/components/auth/auth-guard";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Xray Log Analyzer",
  description: "Real-time Xray access log analysis",
};

// Prevent zoom on input focus for iOS
export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  maximumScale: 1,
  userScalable: false,
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        <AuthProvider>
          <AuthGuard>
            <WebSocketProvider>
              <Header />
              <main className="min-h-[calc(100vh-3.5rem)]">
                {children}
              </main>
              <FloatingAIChat />
            </WebSocketProvider>
          </AuthGuard>
        </AuthProvider>
      </body>
    </html>
  );
}
