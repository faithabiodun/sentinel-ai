"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const nav = [
  { href: "/", label: "Queue" },
  { href: "/entities", label: "Memory" },
  { href: "/about", label: "About" },
] as const;

export default function Shell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const isActive = (href: string) =>
    href === "/" ? pathname === "/" || pathname.startsWith("/incidents") : pathname.startsWith(href);

  return (
    <div className="shell">
      <nav className="sidebar">
        <div className="wordmark">
          sentinel<span>.</span>
        </div>
        {nav.map((n) => (
          <Link key={n.href} href={n.href} data-active={isActive(n.href)}>
            {n.label}
          </Link>
        ))}
        <div className="rail-foot">
          Memory layer not connected
          <br />
          Running on the sample corpus
        </div>
      </nav>

      <header className="topbar">
        <div className="wordmark">
          sentinel<span>.</span>
        </div>
        <span className="live">Sample corpus</span>
      </header>

      <main className="main">{children}</main>

      <nav className="tabbar">
        {nav.map((n) => (
          <Link key={n.href} href={n.href} data-active={isActive(n.href)}>
            {n.label}
          </Link>
        ))}
      </nav>
    </div>
  );
}
