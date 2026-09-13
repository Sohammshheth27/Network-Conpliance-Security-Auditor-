import { type ButtonHTMLAttributes, forwardRef } from 'react';
import { cn } from '../../utils/cn';


export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'ghost' | 'outline' | 'action';
  size?: 'sm' | 'md' | 'lg' | 'icon';
}

const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'primary', size = 'md', ...props }, ref) => {
    return (
      <button
        ref={ref}
        className={cn(
          "inline-flex items-center justify-center font-medium transition-all duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-signal-blue)] disabled:pointer-events-none disabled:opacity-50 select-none",
          variant === 'primary' && "ncsa-btn-primary active:scale-[0.98]",
          variant === 'secondary' && "ncsa-btn-secondary active:scale-[0.98]",
          variant === 'outline' && "border border-[var(--color-hairline)] bg-transparent hover:bg-[var(--color-pebble)] text-[var(--color-ink-navy)] rounded-[8px]",
          variant === 'ghost' && "bg-transparent hover:bg-[var(--color-pebble)] text-[var(--color-slate-gray)] hover:text-[var(--color-ink-navy)] rounded-[8px]",
          variant === 'action' && "w-full justify-between ncsa-panel p-4 hover:border-[var(--color-mist-gray)] hover:bg-[var(--color-pebble)] text-[var(--color-ink-navy)] transition-all",
          size === 'sm' && "h-8 px-3.5 text-xs rounded-[8px]",
          size === 'md' && "h-10 px-5 text-sm rounded-[8px]",
          size === 'lg' && "h-12 px-6 text-base rounded-[8px]",
          size === 'icon' && "h-10 w-10 p-0 rounded-full",
          className
        )}
        {...props}
      />
    );
  }
);
Button.displayName = "Button";

export { Button };

