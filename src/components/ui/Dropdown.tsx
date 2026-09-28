import React, { useEffect, useRef, useState } from 'react';
import { cn } from '../../lib/cn';

interface DropdownProps {
  trigger: (props: { open: boolean; toggle: () => void }) => React.ReactNode;
  align?: 'left' | 'right';
  width?: string;
  children: (close: () => void) => React.ReactNode;
}

/** Click-to-open popover menu that closes on outside click or Escape. */
export const Dropdown: React.FC<DropdownProps> = ({ trigger, align = 'right', width = 'w-64', children }) => {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false);
    document.addEventListener('mousedown', onClick);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onClick);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  return (
    <div ref={ref} className="relative">
      {trigger({ open, toggle: () => setOpen((v) => !v) })}
      {open && (
        <div
          role="menu"
          className={cn(
            'absolute top-full z-40 mt-1.5 overflow-hidden rounded-lg border border-border bg-surface-2 py-1 shadow-xl',
            align === 'right' ? 'right-0' : 'left-0',
            width,
          )}
        >
          {children(() => setOpen(false))}
        </div>
      )}
    </div>
  );
};

interface MenuItemProps {
  onClick: () => void;
  active?: boolean;
  icon?: React.ComponentType<{ className?: string }>;
  children: React.ReactNode;
  hint?: React.ReactNode;
}

export const MenuItem: React.FC<MenuItemProps> = ({ onClick, active, icon: Icon, children, hint }) => (
  <button
    type="button"
    role="menuitem"
    onClick={onClick}
    className={cn(
      'flex w-full items-center gap-2.5 px-3 py-2 text-left text-sm transition-colors hover:bg-surface-3',
      active ? 'text-fg' : 'text-fg-muted hover:text-fg',
    )}
  >
    {Icon && <Icon className="size-4 shrink-0 text-fg-subtle" />}
    <span className="min-w-0 flex-1 truncate">{children}</span>
    {hint && <span className="shrink-0 text-xs text-fg-subtle">{hint}</span>}
  </button>
);

export const MenuLabel: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div className="px-3 pb-1 pt-2 text-xs font-medium text-fg-subtle">{children}</div>
);

export const MenuDivider = () => <div className="my-1 border-t border-border" />;
