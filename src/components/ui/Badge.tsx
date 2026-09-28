import React from 'react';
import { cn } from '../../lib/cn';

export type Tone = 'neutral' | 'accent' | 'success' | 'warning' | 'danger';

const TONES: Record<Tone, string> = {
  neutral: 'bg-surface-3 text-fg-muted',
  accent: 'bg-accent-soft text-accent-text',
  success: 'bg-success-soft text-success-text',
  warning: 'bg-warning-soft text-warning-text',
  danger: 'bg-danger-soft text-danger-text',
};

interface BadgeProps {
  tone?: Tone;
  mono?: boolean;
  dot?: boolean;
  className?: string;
  title?: string;
  children: React.ReactNode;
}

export const Badge: React.FC<BadgeProps> = ({ tone = 'neutral', mono, dot, className, title, children }) => (
  <span
    title={title}
    className={cn(
      'inline-flex items-center gap-1.5 rounded px-1.5 py-0.5 text-xs font-medium whitespace-nowrap',
      mono && 'font-mono',
      TONES[tone],
      className,
    )}
  >
    {dot && <span className="size-1.5 rounded-full bg-current" />}
    {children}
  </span>
);

/** Maps domain values to a consistent tone across the app. */
export const severityTone = (level?: string): Tone => {
  switch (level) {
    case 'Critical':
      return 'danger';
    case 'High':
      return 'warning';
    case 'Medium':
      return 'accent';
    default:
      return 'neutral';
  }
};

export const outcomeTone = (outcome: string): Tone => {
  switch (outcome) {
    case 'True Positive':
      return 'danger';
    case 'Needs Follow-up':
      return 'warning';
    case 'False Positive':
      return 'neutral';
    default:
      return 'neutral';
  }
};
