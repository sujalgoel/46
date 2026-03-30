"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarGroup,
  SidebarGroupLabel,
  SidebarGroupContent,
} from "@/components/ui/sidebar";
import { Shield, LayoutDashboard, Bell, FileText, Settings, Cloud } from "lucide-react";
import { SimulateButton } from "./simulate-button";

const navItems = [
  { href: "/",           label: "Dashboard", icon: LayoutDashboard },
  { href: "/alerts",     label: "Alerts",    icon: Bell },
  { href: "/logs",       label: "Logs",      icon: FileText },
  { href: "/aws-rules",  label: "AWS Rules", icon: Cloud },
  { href: "/setup",      label: "Setup",     icon: Settings },
];

export function AppSidebar() {
  const pathname = usePathname();

  return (
    <Sidebar>
      <SidebarHeader className="border-b px-6 py-4">
        <div className="flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary">
            <Shield className="h-4 w-4 text-primary-foreground" />
          </div>
          <div>
            <p className="text-sm font-semibold leading-none">Cloud IDS</p>
            <p className="text-xs text-muted-foreground">s.amity.edu</p>
          </div>
        </div>
      </SidebarHeader>

      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel>Navigation</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu className="gap-1">
              {navItems.map(({ href, label, icon: Icon }) => (
                <SidebarMenuItem key={href}>
                  <SidebarMenuButton
                    render={<Link href={href} />}
                    isActive={pathname === href}
                  >
                    <Icon className="h-4 w-4" />
                    <span>{label}</span>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>

      <SidebarFooter className="border-t p-4 flex flex-col gap-3">
        <SimulateButton />
        <div className="px-1 pt-1 border-t border-dashed">
          <p className="text-[10px] font-medium text-muted-foreground/70 uppercase tracking-wide mb-1">Group 46</p>
          <p className="text-[11px] text-muted-foreground leading-snug">Riya Karagwal</p>
          <p className="text-[11px] text-muted-foreground leading-snug">Rhea T. Chakraborty</p>
          <p className="text-[10px] text-muted-foreground/60 mt-1 leading-snug">Guide: Prof. (Dr.) S. K. Dubey</p>
        </div>
      </SidebarFooter>
    </Sidebar>
  );
}
