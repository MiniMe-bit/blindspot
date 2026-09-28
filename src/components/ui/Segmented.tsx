import React from 'react';
import { cn } from '../../lib/cn';

interface SegmentedProps<T extends string> {
  value: T;
  onChange: (value: T) => void;
  options: Array<{ value: T; label: React.ReactNode }>;
  size?: 'sm' | 'md';
  ariaLabel?: string;
}

/** A compact single-choice toggle group (filters, view switches). */
export function Segmented<T extends string>({ value, onChange, options, size = 'sm', ariaLabel }: SegmentedProps<T>) {
  return (
    <div role="radiogroup" aria-label={ariaLabel} className="inline-flex rounded-md border border-border bg-canvas p-0.5">
      {options.map((opt) => {
        const active = opt.value === value;
        return (
          <button
            key={opt.value}
            type="button"
            role="radio"
            aria-checked={active}
            onClick={() => onChange(opt.value)}
            className={cn(
              'rounded px-2.5 font-medium whitespace-nowrap transition-colors',
              size === 'sm' ? 'h-7 text-[13px]' : 'h-8 text-sm',
              active ? 'bg-surface-3 text-fg' : 'text-fg-muted hover:text-fg',
            )}
          >
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}
