import React from 'react';
import { cn } from '../../lib/cn';

interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  padded?: boolean;
}

export const Card: React.FC<CardProps> = ({ padded = false, className, children, ...rest }) => (
  <div className={cn('rounded-lg border border-border bg-surface', padded && 'p-5', className)} {...rest}>
    {children}
  </div>
);

/** Color of the bar beside a card title. Pages give related cards different tones so they are easy to tell apart. */
export type TitleTone = 'brand' | 'accent' | 'danger' | 'warning' | 'teal' | 'violet' | 'pink' | 'success';

const TITLE_BAR: Record<TitleTone, string> = {
  brand: 'from-accent via-teal to-violet',
  accent: 'from-accent to-violet',
  danger: 'from-danger to-warning',
  warning: 'from-warning to-pink',
  teal: 'from-teal to-accent',
  violet: 'from-violet to-pink',
  pink: 'from-pink to-violet',
  success: 'from-success to-teal',
};

/** Faint wash of the title's color behind a card header. */
const HEADER_WASH: Record<TitleTone, string> = {
  brand: 'from-accent/[0.07]',
  accent: 'from-accent/[0.08]',
  danger: 'from-danger/[0.08]',
  warning: 'from-warning/[0.08]',
  teal: 'from-teal/[0.08]',
  violet: 'from-violet/[0.08]',
  pink: 'from-pink/[0.08]',
  success: 'from-success/[0.08]',
};

/** Card / section title: larger than body text, with a small gradient bar so headings stand out. */
export const CardTitle: React.FC<{ children: React.ReactNode; tone?: TitleTone; className?: string }> = ({ children, tone = 'brand', className }) => (
  <h2 className={cn('flex items-center gap-2.5 text-[17px] font-semibold leading-snug tracking-tight text-fg', className)}>
    <span aria-hidden="true" className={cn('h-5 w-1 shrink-0 rounded-full bg-gradient-to-b', TITLE_BAR[tone])} />
    <span className="min-w-0">{children}</span>
  </h2>
);

interface CardHeaderProps {
  title: React.ReactNode;
  description?: React.ReactNode;
  actions?: React.ReactNode;
  tone?: TitleTone;
  className?: string;
}

export const CardHeader: React.FC<CardHeaderProps> = ({ title, description, actions, tone = 'brand', className }) => (
  <div className={cn('flex items-start justify-between gap-4 rounded-t-lg border-b border-border bg-gradient-to-r to-transparent px-5 py-4', HEADER_WASH[tone], className)}>
    <div className="min-w-0">
      <CardTitle tone={tone}>{title}</CardTitle>
      {description && <p className="mt-1 pl-3.5 text-[13px] text-fg-muted">{description}</p>}
    </div>
    {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
  </div>
);

/** Small uppercase label used above a block of content inside a card. */
export const SectionLabel: React.FC<{ children: React.ReactNode; className?: string }> = ({ children, className }) => (
  <h3 className={cn(!/mb-/.test(className ?? '') && 'mb-2', 'text-xs font-medium uppercase tracking-wide text-fg-subtle', className)}>{children}</h3>
);
