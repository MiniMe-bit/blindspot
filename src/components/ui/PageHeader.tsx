import React from 'react';

interface PageHeaderProps {
  title: string;
  description?: React.ReactNode;
  actions?: React.ReactNode;
}

/** Standard page title block. Every routed page starts with one. */
export const PageHeader: React.FC<PageHeaderProps> = ({ title, description, actions }) => (
  <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
    <div className="min-w-0">
      <h1 className="text-xl font-semibold tracking-tight text-fg">{title}</h1>
      {description && <p className="mt-1 max-w-2xl text-sm text-fg-muted">{description}</p>}
    </div>
    {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
  </div>
);
