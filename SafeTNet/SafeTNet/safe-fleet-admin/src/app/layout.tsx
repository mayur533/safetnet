import type { Metadata } from "next";
import { Poppins } from "next/font/google";
import "./globals.css";
import { QueryProvider } from "@/lib/providers/query-provider";
import { ConditionalLayout } from "@/components/layout/conditional-layout";
import { ErrorBoundary } from "@/components/error-boundary";
import { AuthProvider } from "@/lib/contexts/auth-context";
import { Toaster } from "sonner";

const poppins = Poppins({
  subsets: ["latin"],
  weight: ["300", "400", "500", "600", "700"],
  variable: "--font-poppins",
});

export const metadata: Metadata = {
  title: "SafeTNet Admin Panel",
  description: "Personal safety and community engagement platform",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={`${poppins.variable} font-sans antialiased`}>
        <ErrorBoundary>
          <QueryProvider>
            <AuthProvider>
              <ConditionalLayout>
                {children}
              </ConditionalLayout>
              <Toaster 
                richColors 
                position="top-right" 
                closeButton 
                duration={4000}
              />
            </AuthProvider>
          </QueryProvider>
        </ErrorBoundary>
      </body>
    </html>
  );
}
