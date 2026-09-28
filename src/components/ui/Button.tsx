import React from 'react';
import { Loader2, type LucideIcon } from 'lucide-react';
import { cn } from '../../lib/cn';

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger';
type Size = 'sm' | 'md';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  icon?: LucideIcon;
  iconRight?: LucideIcon;
  loading?: boolean;
}

const VARIANTS: Record<Variant, string> = {
  primary: 'bg-accent text-accent-fg hover:bg-accent-hover border border-transparent',
  secondary: 'bg-surface-2 text-fg hover:bg-surface-3 border border-border',
  ghost: 'bg-transparent text-fg-muted hover:text-fg hover:bg-surface-2 border border-transparent',
  danger: 'bg-transparent text-danger-text hover:bg-danger-soft border border-border',
};

const SIZES: Record<Size, string> = {
  sm: 'h-8 px-3 text-[13px] gap-1.5',
  md: 'h-9 px-3.5 text-sm gap-2',
};

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant = 'secondary', size = 'md', icon: Icon, iconRight: IconRight, loading, className, children, disabled, type = 'button', ...rest }, ref) => (
    <button
      ref={ref}
      type={type}
      disabled={disabled || loading}
      className={cn(
        'inline-flex items-center justify-center rounded-md font-medium whitespace-nowrap transition-colors',
        'disabled:opacity-50 disabled:pointer-events-none',
        VARIANTS[variant],
        SIZES[size],
        className,
      )}
      {...rest}
    >
      {loading ? <Loader2 className="size-4 animate-spin" /> : Icon ? <Icon className="size-4 shrink-0" /> : null}
      {children}
      {IconRight && !loading && <IconRight className="size-4 shrink-0" />}
    </button>
  ),
);
Button.displayName = 'Button';

interface IconButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  icon: LucideIcon;
  label: string;
}

export const IconButton: React.FC<IconButtonProps> = ({ icon: Icon, label, className, type = 'button', ...rest }) => (
  <button
    type={type}
    aria-label={label}
    title={label}
    className={cn(
      'inline-flex size-8 items-center justify-center rounded-md text-fg-muted transition-colors',
      'hover:bg-surface-2 hover:text-fg disabled:opacity-50',
      className,
    )}
    {...rest}
  >
    <Icon className="size-4" />
  </button>
);
