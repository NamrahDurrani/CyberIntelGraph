import "./cyberintel-a11y.css";
import type { Metadata } from "next";
import "./globals.css";
import { AuthProvider } from "@/lib/auth";

export const metadata: Metadata = { title: "CyberIntel", description: "Evidence-first cyber threat intelligence investigations" };

export default function Root({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" data-theme="dark" suppressHydrationWarning>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" /><link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="" />
        <link href="https://fonts.googleapis.com/css2?family=Figtree:wght@400;500;600&family=Sora:wght@500;700&display=swap" rel="stylesheet" />
        <script dangerouslySetInnerHTML={{ __html: `try{var t=localStorage.getItem('cig_theme');if(t)document.documentElement.dataset.theme=t}catch(e){}` }} />
      </head>
      <body><AuthProvider>{children}</AuthProvider></body>
    </html>
  );
}
