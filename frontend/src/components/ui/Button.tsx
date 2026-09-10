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
          "inline-flex items-center justify-center font-medium transition-all duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#1677FF] disabled:pointer-events-none disabled:opacity-50 select-none",
          variant === 'primary' && "ncsa-btn-primary active:scale-[0.98]",
          variant === 'secondary' && "ncsa-btn-secondary active:scale-[0.98]",
          variant === 'outline' && "border border-[rgba(100,150,220,0.18)] bg-transparent hover:bg-[rgba(14,27,50,0.6)] text-[#F5F8FF] rounded-[18px]",
          variant === 'ghost' && "bg-transparent hover:bg-[rgba(14,27,50,0.7)] text-[#AAB8D0] hover:text-[#F5F8FF] rounded-[16px]",
          variant === 'action' && "w-full justify-between ncsa-panel p-4 hover:border-[rgba(80,150,255,0.35)] hover:bg-[rgba(18,36,68,0.7)] text-[#F5F8FF] transition-all",
          size === 'sm' && "h-8 px-3.5 text-xs rounded-[14px]",
          size === 'md' && "h-10 px-5 text-sm rounded-[18px]",
          size === 'lg' && "h-12 px-6 text-base rounded-[20px]",
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

