import type { FC } from 'react';

interface RadialProgressProps {
  value: number; // 0 to 100
  size?: number;
  strokeWidth?: number;
  label?: string;
  sublabel?: string;
  isPrimary?: boolean;
}

export const RadialProgress: FC<RadialProgressProps> = ({
  value,
  size = 170,
  strokeWidth = 14,
  label = 'COMPLIANCE',
  sublabel = 'SCORE',
  isPrimary = true,
}) => {
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const progressOffset = circumference - (value / 100) * circumference;

  return (
    <div className="flex flex-col items-center justify-center relative select-none" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="transform -rotate-90">
        {/* Background Track */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="var(--color-pebble)"
          strokeWidth={strokeWidth}
        />

        {/* Animated / Colored Value Stroke */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={isPrimary ? 'var(--color-signal-blue)' : 'var(--color-slate-gray)'}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={progressOffset}
          strokeLinecap="round"
          className="transition-all duration-1000 ease-out"
        />
      </svg>

      {/* Center Metrics */}
      <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
        <span className={`${isPrimary ? 'text-4xl' : 'text-2xl'} font-bold tracking-tight text-[var(--color-ink-navy)] leading-none`}>
          {value}%
        </span>
        {label && (
          <div className="mt-1 flex flex-col items-center">
            <span className="text-[10px] tracking-wider uppercase text-[var(--color-slate-gray)] font-semibold leading-tight">
              {label}
            </span>
            {sublabel && (
              <span className="text-[10px] tracking-wider uppercase text-[var(--color-slate-gray)] font-semibold leading-tight">
                {sublabel}
              </span>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
