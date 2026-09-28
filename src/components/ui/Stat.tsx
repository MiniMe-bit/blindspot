import React from 'react';
import { cn, mergeDefaults } from '../../lib/cn';

interface StatProps {
  label: string;
  value: React.ReactNode;
  detail?: React.ReactNode;
  onClick?: () => void;
  className?: string;
}

/** KPI tile. Values must come from real data — never placeholder numbers. */
export const Stat: React.FC<StatProps> = ({ label, value, detail, onClick, className }) => {
  const body = (
    <>
      <div className="text-[13px] text-fg-muted">{label}</div>
      <div className="mt-1 text-2xl font-semibold tabular-nums text-fg">{value}</div>
      {detail && <div className="mt-1 text-xs text-fg-subtle">{detail}</div>}
    </>
  );
  const base = cn('rounded-lg border border-border bg-surface p-4 text-left', className);

  if (!onClick) return <div className={base}>{body}</div>;
  return (
    <button type="button" onClick={onClick} className={cn(base, 'w-full transition-colors hover:border-border-strong hover:bg-surface-2')}>
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
