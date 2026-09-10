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
        <defs>
          <linearGradient id={`blue-grad-${isPrimary ? 'primary' : 'secondary'}`} x1="0%" y1="0%" x2="100%" y2="100%">
            {isPrimary ? (
              <>
                <stop offset="0%" stopColor="#2D8CFF" />
                <stop offset="100%" stopColor="#1677FF" />
              </>
            ) : (
              <>
                <stop offset="0%" stopColor="#4AA8FF" />
                <stop offset="100%" stopColor="#2282FA" />
              </>
            )}
          </linearGradient>
          {isPrimary && (
            <filter id="glow-primary" x="-20%" y="-20%" width="140%" height="140%">
              <feDropShadow dx="0" dy="0" stdDeviation="4" floodColor="#1677FF" floodOpacity="0.5" />
            </filter>
          )}
        </defs>

        {/* Background Track */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={isPrimary ? 'rgba(22, 119, 255, 0.18)' : 'rgba(22, 119, 255, 0.14)'}
          strokeWidth={strokeWidth}
        />

        {/* Animated / Colored Value Stroke */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={`url(#blue-grad-${isPrimary ? 'primary' : 'secondary'})`}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={progressOffset}
          strokeLinecap="round"
          filter={isPrimary ? 'url(#glow-primary)' : undefined}
          className="transition-all duration-1000 ease-out"
        />
      </svg>

      {/* Center Metrics */}
      <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
        <span className={`${isPrimary ? 'text-4xl' : 'text-2xl'} font-bold tracking-tight text-[#F5F8FF] leading-none`}>
          {value}%
        </span>
        {label && (
          <div className="mt-1 flex flex-col items-center">
            <span className="text-[10px] tracking-wider uppercase text-[#AAB8D0] font-semibold leading-tight">
              {label}
            </span>
            {sublabel && (
              <span className="text-[10px] tracking-wider uppercase text-[#AAB8D0] font-semibold leading-tight">
                {sublabel}
              </span>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
