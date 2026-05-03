import type { Metadata, Viewport } from "next";
import { NextIntlClientProvider } from 'next-intl';
import { getLocale, getMessages } from 'next-intl/server';
import { Header } from "@/components/layout/header";
import { FloatingAIChat } from "@/components/layout/floating-ai-chat";
import { WebSocketProvider } from "@/contexts/websocket-context";
import { AuthProvider } from "@/contexts/auth-context";
import { AuthGuard } from "@/components/auth/auth-guard";
import "./globals.css";

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

export default async function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  const locale = await getLocale();
  const messages = await getMessages();

  return (
    <html lang={locale}>
      <body
        className="antialiased"
      >
        <NextIntlClientProvider locale={locale} messages={messages}>
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
        </NextIntlClientProvider>
      </body>
    </html>
  );
}
