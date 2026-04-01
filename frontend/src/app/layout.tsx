import type { Metadata } from "next";
import "./globals.css";
import { Sidebar } from "@/components/layout/Sidebar";
import { TopBar } from "@/components/layout/TopBar";

export const metadata: Metadata = {
  title: "TI Platform | Threat Intelligence",
  description: "Vendor-Agnostic Threat Intelligence Platform",
  icons: { icon: "/favicon.ico" },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      {/* Inline script to apply saved theme before first paint — prevents flash */}
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `(function(){var t=localStorage.getItem('theme');if(t==='light'){document.documentElement.classList.remove('dark')}else{document.documentElement.classList.add('dark')}})()`,
          }}
        />
      </head>
      <body className="min-h-screen flex">
        {/* Sidebar navigation */}
        <Sidebar />

        {/* Main content area */}
        <div className="flex-1 flex flex-col min-h-screen pl-16 lg:pl-56">
          <TopBar />
          <main className="flex-1 p-6 animate-fade-in">
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}
