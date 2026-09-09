import Link from "next/link";

export function Logo({ compact = false }: { compact?: boolean }) {
  return (
    <Link href="/" className="brand" aria-label="WebShield home">
      <span className="brandMark" aria-hidden="true">W</span>
      {!compact && <span><strong>WebShield</strong><small>Savrdh Technologies</small></span>}
    </Link>
  );
}
