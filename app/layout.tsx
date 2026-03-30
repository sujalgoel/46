import type { Metadata } from "next";
import { Geist } from "next/font/google";
import { headers } from "next/headers";
import "./globals.css";
import { TooltipProvider } from "@/components/ui/tooltip";
import { AppSidebar } from "@/components/app-sidebar";
import { SidebarProvider, SidebarInset, SidebarTrigger } from "@/components/ui/sidebar";
import { Shield } from "lucide-react";

const geist = Geist({ subsets: ["latin"] });

export async function generateMetadata(): Promise<Metadata> {
  const hdrs = await headers();
  const host  = hdrs.get("x-forwarded-host") ?? hdrs.get("host") ?? "localhost:3000";
  const proto = hdrs.get("x-forwarded-proto") ?? "http";
  const base  = `${proto}://${host}`;

  return {
    metadataBase: new URL(base),
    title: {
      default: "Cloud IDS – Intrusion Detection System",
      template: "%s · Cloud IDS",
    },
    description:
      "Rule-based Intrusion Detection System for AWS CloudTrail. Monitors AWS account activity and detects suspicious behaviour in real time. B.Tech Final Year Project, Amity University – Group 46.",
    keywords: [
      "intrusion detection system",
      "IDS",
      "AWS CloudTrail",
      "cloud security",
      "cybersecurity",
      "Amity University",
      "rule-based detection",
    ],
    authors: [
      { name: "Riya Karagwal" },
      { name: "Rhea T. Chakraborty" },
    ],
    creator: "Group 46 – Amity University",
    openGraph: {
      type: "website",
      locale: "en_IN",
      title: "Cloud IDS – Intrusion Detection System",
      description:
        "Real-time rule-based IDS for AWS CloudTrail. Detects root usage, IAM escalation, bulk downloads, mass deletion, and more.",
      siteName: "Cloud IDS",
      images: [
        {
          url: `${base}/og-image.jpg`,
          width: 1200,
          height: 630,
          alt: "Cloud IDS – Intrusion Detection System",
        },
      ],
    },
    twitter: {
      card: "summary_large_image",
      title: "Cloud IDS – Intrusion Detection System",
      description:
        "Real-time rule-based IDS for AWS CloudTrail. B.Tech Final Year Project, Amity University.",
      images: [`${base}/og-image.jpg`],
    },
    icons: {
      icon: "/icon.svg",
      shortcut: "/icon.svg",
    },
  };
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className={`${geist.className} bg-muted/40`}>
        <TooltipProvider>
          <SidebarProvider>
            <AppSidebar />
            <SidebarInset>
              {/* Mobile header — hidden on md+ */}
              <header className="md:hidden sticky top-0 z-20 flex h-13 items-center gap-3 border-b bg-sidebar px-4">
                <SidebarTrigger className="text-sidebar-foreground" />
                <div className="flex items-center gap-2">
                  <div className="flex h-7 w-7 items-center justify-center rounded-md bg-primary">
                    <Shield className="h-3.5 w-3.5 text-primary-foreground" />
                  </div>
                  <span className="text-sm font-semibold text-sidebar-foreground">Cloud IDS</span>
                </div>
              </header>
              {children}
            </SidebarInset>
          </SidebarProvider>
        </TooltipProvider>
      </body>
    </html>
  );
}
