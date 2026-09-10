import { type HTMLAttributes, forwardRef } from 'react';
import { cn } from '../../utils/cn';


export interface CardProps extends HTMLAttributes<HTMLDivElement> {
  variant?: 'default' | 'interactive' | 'panel' | 'outline' | 'glow';
}

const Card = forwardRef<HTMLDivElement, CardProps>(
  ({ className, variant = 'default', ...props }, ref) => {
    return (
      <div
        ref={ref}
        className={cn(
          "transition-all duration-200",
          variant === 'default' && "ncsa-card p-6",
          variant === 'interactive' && "ncsa-card ncsa-card-interactive p-6 cursor-pointer",
          variant === 'panel' && "ncsa-panel p-4",
          variant === 'glow' && "ncsa-card shadow-[0_16px_40px_-10px_rgba(22,119,255,0.25)] border-[rgba(80,150,255,0.25)] p-6",
          variant === 'outline' && "rounded-[24px] border border-[rgba(100,150,220,0.14)] bg-transparent p-5",
          className
        )}
        {...props}
      />
    );
  }
);
Card.displayName = "Card";

export { Card };

