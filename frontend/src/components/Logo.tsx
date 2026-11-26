export function LogoMark({ size = 30 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 40 40" fill="none" aria-hidden>
      <defs><linearGradient id="lg" x1="4" y1="4" x2="36" y2="36"><stop stopColor="#9D71E8" /><stop offset="1" stopColor="#6A2FC8" /></linearGradient></defs>
      <path d="M20 2.5 34.5 10.5v17L20 37.5 5.5 27.5v-17z" fill="url(#lg)" />
      <g stroke="#F2E9FF" strokeWidth="1.6" strokeLinecap="round"><path d="M14 22 20 13l7 8M14 22h13M20 13v-3" /></g>
      <g fill="#F2E9FF"><circle cx="14" cy="22" r="2.4" /><circle cx="27" cy="21" r="2.4" /><circle cx="20" cy="13" r="2.8" /></g>
    </svg>
  );
}
export function Brand() { return <span className="brand"><LogoMark />CyberIntel</span>; }
