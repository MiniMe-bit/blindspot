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

interface CardHeaderProps {
  title: React.ReactNode;
  description?: React.ReactNode;
  actions?: React.ReactNode;
  className?: string;
}

export const CardHeader: React.FC<CardHeaderProps> = ({ title, description, actions, className }) => (
  <div className={cn('flex items-start justify-between gap-4 border-b border-border px-5 py-4', className)}>
    <div className="min-w-0">
      <h2 className="text-sm font-semibold text-fg">{title}</h2>
      {description && <p className="mt-0.5 text-[13px] text-fg-muted">{description}</p>}
    </div>
    {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
  </div>
);

/** Small uppercase label used above a block of content inside a card. */
export const SectionLabel: React.FC<{ children: React.ReactNode; className?: string }> = ({ children, className }) => (
  <h3 className={cn('mb-2 text-xs font-medium uppercase tracking-wide text-fg-subtle', className)}>{children}</h3>
);
