import React from 'react';
import type { LucideIcon } from 'lucide-react';
import { cn, mergeDefaults } from '../../lib/cn';
import type { Tone } from './Badge';

/** Text color for a stat's number. Each KPI gets its own color so a row of tiles scans at a glance. */
export const TONE_TEXT: Record<Tone, string> = {
  neutral: 'text-fg',
  accent: 'text-accent-text',
  success: 'text-success-text',
  warning: 'text-warning-text',
  danger: 'text-danger-text',
  violet: 'text-violet-text',
  teal: 'text-teal-text',
  pink: 'text-pink-text',
};

/** Vivid tiles: tinted surface + colored top bar, for headline KPI rows. */
const TONE_VIVID: Record<Tone, { tile: string; bar: string; value: string }> = {
  neutral: { tile: 'border-border bg-surface', bar: 'bg-fg-subtle', value: 'text-fg' },
  accent: { tile: 'border-accent/30 bg-accent-soft', bar: 'bg-accent', value: 'text-accent' },
  success: { tile: 'border-success/30 bg-success-soft', bar: 'bg-success', value: 'text-success' },
  warning: { tile: 'border-warning/30 bg-warning-soft', bar: 'bg-warning', value: 'text-warning' },
  danger: { tile: 'border-danger/30 bg-danger-soft', bar: 'bg-danger', value: 'text-danger' },
  violet: { tile: 'border-violet/30 bg-violet-soft', bar: 'bg-violet', value: 'text-violet' },
  teal: { tile: 'border-teal/30 bg-teal-soft', bar: 'bg-teal', value: 'text-teal' },
  pink: { tile: 'border-pink/30 bg-pink-soft', bar: 'bg-pink', value: 'text-pink' },
};

const TONE_ICON_BG: Record<Tone, string> = {
  neutral: 'bg-surface-3 text-fg-muted',
  accent: 'bg-accent-soft text-accent-text',
  success: 'bg-success-soft text-success-text',
  warning: 'bg-warning-soft text-warning-text',
  danger: 'bg-danger-soft text-danger-text',
  violet: 'bg-violet-soft text-violet-text',
  teal: 'bg-teal-soft text-teal-text',
  pink: 'bg-pink-soft text-pink-text',
};

interface StatProps {
  label: string;
  value: React.ReactNode;
  detail?: React.ReactNode;
  tone?: Tone;
  icon?: LucideIcon;
  /** Tinted tile with a colored bar and a larger number. */
  vivid?: boolean;
  onClick?: () => void;
  className?: string;
}

/** KPI tile. Values must come from real data — never placeholder numbers. */
export const Stat: React.FC<StatProps> = ({ label, value, detail, tone = 'neutral', icon: Icon, vivid, onClick, className }) => {
  const v = TONE_VIVID[tone];
  const body = (
    <>
      {vivid && <span className={cn('absolute inset-x-0 top-0 h-1', v.bar)} />}
      <div className="flex items-center justify-between gap-2">
        <div className="text-[13px] font-medium text-fg-muted">{label}</div>
        {Icon && (
          <span className={cn('flex size-7 items-center justify-center rounded-md', vivid ? cn(v.bar, 'text-white') : TONE_ICON_BG[tone])}>
            <Icon className="size-4" />
          </span>
        )}
      </div>
      <div className={cn('mt-2 font-semibold tracking-tight tabular-nums', vivid ? cn('text-4xl font-bold', v.value) : cn('text-3xl', TONE_TEXT[tone]))}>{value}</div>
      {detail && <div className="mt-1 text-xs text-fg-subtle">{detail}</div>}
    </>
  );
  const base = cn('relative overflow-hidden rounded-lg border p-4 text-left', vivid ? v.tile : 'border-border bg-surface', className);

  if (!onClick) return <div className={base}>{body}</div>;
  return (
    <button type="button" onClick={onClick} className={cn(base, 'w-full transition-colors', vivid ? 'hover:brightness-125' : 'hover:border-border-strong hover:bg-surface-2')}>
      {body}
    </button>
  );
};

/** Thin horizontal progress bar. */
export const Meter: React.FC<{ value: number; tone?: 'accent' | 'success' | 'warning' | 'danger'; className?: string }> = ({
  value,
  tone = 'accent',
  className,
}) => {
  const color = { accent: 'bg-accent', success: 'bg-success', warning: 'bg-warning', danger: 'bg-danger' }[tone];
  return (
    <div className={mergeDefaults('h-1.5 w-full overflow-hidden rounded-full bg-surface-3', className)}>
      <div className={cn('h-full rounded-full', color)} style={{ width: `${Math.max(0, Math.min(100, value))}%` }} />
    </div>
  );
};
