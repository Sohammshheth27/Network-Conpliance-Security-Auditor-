import { type FC } from 'react';

const CAPABILITIES = [
  'CONFIGURATION AUDITING',
  'MULTI-VENDOR ANALYSIS',
  'SECURITY BASELINE',
  'COMPLIANCE MAPPING',
  'EXACT CONFIGURATION EVIDENCE',
  'AUTOMATED FINDINGS',
  'REMEDIATION GUIDANCE',
];

export const Marquee: FC<{ className?: string }> = ({ className = '' }) => {
  return (
    <div 
      className={`w-full overflow-hidden whitespace-nowrap py-3 border-y border-[var(--color-hairline)] bg-[var(--color-paper)] select-none relative ${className}`}
      style={{ transform: 'translateZ(0)' }}
    >
      <div className="absolute left-0 top-0 bottom-0 w-[10%] bg-gradient-to-r from-[var(--color-paper)] to-transparent z-10 pointer-events-none" />
      <div className="absolute right-0 top-0 bottom-0 w-[10%] bg-gradient-to-l from-[var(--color-paper)] to-transparent z-10 pointer-events-none" />
      <div className="inline-flex animate-marquee items-center gap-8 text-[11px] font-bold tracking-[0.25em] text-[var(--color-slate-gray)] uppercase">
        {CAPABILITIES.map((cap, i) => (
          <span key={`a-${i}`} className="inline-flex items-center gap-8">
            <span className="hover:text-[var(--color-ink-navy)] transition-colors">{cap}</span>
            <span className="text-[var(--color-mist-gray)] font-normal select-none">✦</span>
          </span>
        ))}
        {CAPABILITIES.map((cap, i) => (
          <span key={`b-${i}`} className="inline-flex items-center gap-8">
            <span className="hover:text-[var(--color-ink-navy)] transition-colors">{cap}</span>
            <span className="text-[var(--color-mist-gray)] font-normal select-none">✦</span>
          </span>
        ))}
      </div>
    </div>
  );
};
