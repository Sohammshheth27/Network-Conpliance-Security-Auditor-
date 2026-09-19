import { type HTMLAttributes, forwardRef } from 'react';
import { cn } from '../../utils/cn';


export interface BadgeProps extends HTMLAttributes<HTMLDivElement> {
  variant?: 'default' | 'success' | 'warning' | 'critical' | 'info' | 'outline';
}

const Badge = forwardRef<HTMLDivElement, BadgeProps>(
  ({ className, variant = 'default', ...props }, ref) => {
    return (
      <div
        ref={ref}
        className={cn(
          "inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium transition-colors select-none",
          variant === 'default' && "bg-[var(--color-pebble)] border border-[var(--color-hairline)] text-[var(--color-deep-cobalt)]",
          variant === 'success' && "bg-[rgba(16,185,129,0.12)] border border-[rgba(16,185,129,0.25)] text-[#10B981]",
          variant === 'warning' && "bg-[rgba(245,158,11,0.12)] border border-[rgba(245,158,11,0.25)] text-[#F59E0B]",
          variant === 'critical' && "bg-[rgba(239,68,68,0.12)] border border-[rgba(239,68,68,0.25)] text-[#EF4444]",
          variant === 'info' && "bg-[rgba(0,107,255,0.14)] border border-[rgba(0,107,255,0.28)] text-[var(--color-signal-blue)]",
          variant === 'outline' && "border border-[var(--color-hairline)] text-[var(--color-slate-gray)]",
          className
        )}
        {...props}
      />
    );
  }
);
Badge.displayName = "Badge";

export { Badge };

