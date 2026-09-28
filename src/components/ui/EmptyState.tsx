import React from 'react';
import type { LucideIcon } from 'lucide-react';
import { cn } from '../../lib/cn';

interface EmptyStateProps {
  icon?: LucideIcon;
  title: string;
  description?: React.ReactNode;
  action?: React.ReactNode;
  className?: string;
}

export const EmptyState: React.FC<EmptyStateProps> = ({ icon: Icon, title, description, action, className }) => (
  <div className={cn('flex flex-col items-center justify-center px-6 py-12 text-center', className)}>
    {Icon && (
      <div className="mb-3 flex size-10 items-center justify-center rounded-full bg-surface-2 text-fg-subtle">
        <Icon className="size-5" />
      </div>
    )}
    <p className="text-sm font-medium text-fg">{title}</p>
    {description && <p className="mt-1 max-w-sm text-[13px] text-fg-muted">{description}</p>}
    {action && <div className="mt-4">{action}</div>}
  </div>
);
