import React, { useId } from 'react';
import { cn } from '../../lib/cn';

/**
 * Animated radar mark: range rings, a rotating sweep and a pulsing contact —
 * "finding what sits in the blind spot". Motion stops under prefers-reduced-motion.
 */
export const BrandMark: React.FC<{ className?: string; animated?: boolean }> = ({ className, animated = true }) => {
  const id = useId().replace(/:/g, '');
  return (
    <svg viewBox="0 0 48 48" className={cn('shrink-0', className)} aria-hidden="true">
      <defs>
        <linearGradient id={`${id}-ring`} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="var(--color-accent)" />
          <stop offset="55%" stopColor="var(--color-teal)" />
          <stop offset="100%" stopColor="var(--color-violet)" />
        </linearGradient>
        <radialGradient id={`${id}-sweep`} cx="24" cy="24" r="20" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="var(--color-teal)" stopOpacity="0.05" />
          <stop offset="100%" stopColor="var(--color-teal)" stopOpacity="0.55" />
        </radialGradient>
      </defs>

      <circle cx="24" cy="24" r="21" fill="none" stroke={`url(#${id}-ring)`} strokeWidth="2.5" />
      <circle cx="24" cy="24" r="13.5" fill="none" stroke="var(--color-accent)" strokeOpacity="0.35" strokeWidth="1.2" />
      <circle cx="24" cy="24" r="6.5" fill="none" stroke="var(--color-accent)" strokeOpacity="0.25" strokeWidth="1.2" />

      <g className={animated ? 'bs-sweep' : undefined} style={{ transformOrigin: '24px 24px' }}>
        <path d="M24 24 L24 3 A21 21 0 0 0 5.8 13.5 Z" fill={`url(#${id}-sweep)`} />
        <line x1="24" y1="24" x2="24" y2="3" stroke="var(--color-teal-text)" strokeWidth="1.6" strokeLinecap="round" />
      </g>

      <circle cx="33.5" cy="15" r="2.4" fill="var(--color-pink)" className={animated ? 'bs-blip' : undefined} />
      <circle cx="24" cy="24" r="2.2" fill="var(--color-fg)" />
    </svg>
  );
};

/** The Blindspot mark with its gradient wordmark. */
export const BrandLogo: React.FC<{ size?: 'md' | 'lg' | 'xl'; showWordmark?: boolean; className?: string }> = ({
  size = 'md',
  showWordmark = true,
  className,
}) => {
  const s = {
    md: { mark: 'size-9', text: 'text-xl' },
    lg: { mark: 'size-12', text: 'text-3xl' },
    xl: { mark: 'size-28', text: 'text-6xl' },
  }[size];
  return (
    <span className={cn('inline-flex items-center gap-3', className)}>
      <BrandMark className={s.mark} />
      {showWordmark && <span className={cn('bs-gradient-text font-extrabold tracking-tight', s.text)}>Blindspot</span>}
    </span>
  );
};
