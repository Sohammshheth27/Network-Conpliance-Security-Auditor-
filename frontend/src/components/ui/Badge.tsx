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
          variant === 'default' && "bg-[rgba(14,27,50,0.8)] border border-[rgba(100,150,220,0.18)] text-[#AAB8D0]",
          variant === 'success' && "bg-[rgba(50,214,168,0.12)] border border-[rgba(50,214,168,0.25)] text-[#32D6A8]",
          variant === 'warning' && "bg-[rgba(245,184,46,0.12)] border border-[rgba(245,184,46,0.25)] text-[#F5B82E]",
          variant === 'critical' && "bg-[rgba(229,72,77,0.12)] border border-[rgba(229,72,77,0.25)] text-[#E5484D]",
          variant === 'info' && "bg-[rgba(22,119,255,0.14)] border border-[rgba(80,150,255,0.28)] text-[#2D8CFF]",
          variant === 'outline' && "border border-[rgba(100,150,220,0.20)] text-[#F5F8FF]",
          className
        )}
        {...props}
      />
    );
  }
);
Badge.displayName = "Badge";

export { Badge };

