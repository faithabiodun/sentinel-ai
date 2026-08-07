"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useAuth } from "./AuthProvider";

const nav = [
  { href: "/", label: "Queue" },
  { href: "/entities", label: "Memory" },
  { href: "/about", label: "About" },
] as const;

export default function Shell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { user, logout } = useAuth();

  // Don't render the chrome on auth pages
  const isAuthPage = pathname === "/login" || pathname === "/signup";
  if (isAuthPage) return <>{children}</>;

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
          {user ? (
            <>
              <span className="rail-user">{user.display_name}</span>
              <button className="rail-logout" onClick={logout}>
                Sign out
              </button>
            </>
          ) : (
            "Not signed in"
          )}
        </div>
      </nav>

      <header className="topbar">
        <div className="wordmark">
          sentinel<span>.</span>
        </div>
        {user && (
          <button className="topbar-logout" onClick={logout} aria-label="Sign out">
            {user.display_name}
          </button>
        )}
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
