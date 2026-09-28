import React from 'react';
import { mergeDefaults } from '../../lib/cn';

const CONTROL =
  'w-full rounded-md border border-border bg-canvas pl-3 pr-3 text-sm text-fg placeholder:text-fg-subtle ' +
  'transition-colors focus:border-accent focus:outline-none disabled:opacity-60';

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...rest }, ref) => <input ref={ref} className={mergeDefaults(`${CONTROL} h-9`, className)} {...rest} />,
);
Input.displayName = 'Input';

export const Textarea = React.forwardRef<HTMLTextAreaElement, React.TextareaHTMLAttributes<HTMLTextAreaElement>>(
  ({ className, ...rest }, ref) => <textarea ref={ref} className={mergeDefaults(`${CONTROL} py-2 leading-relaxed`, className)} {...rest} />,
);
Textarea.displayName = 'Textarea';

export const Select = React.forwardRef<HTMLSelectElement, React.SelectHTMLAttributes<HTMLSelectElement>>(
  ({ className, children, ...rest }, ref) => (
    <select ref={ref} className={mergeDefaults(mergeDefaults(CONTROL, 'h-9 pr-8'), className)} {...rest}>
      {children}
    </select>
  ),
);
Select.displayName = 'Select';

interface FieldProps {
  label: string;
  htmlFor?: string;
  required?: boolean;
  hint?: React.ReactNode;
  className?: string;
  children: React.ReactNode;
}

export const Field: React.FC<FieldProps> = ({ label, htmlFor, required, hint, className, children }) => (
  <div className={['space-y-1.5', className].filter(Boolean).join(' ')}>
    <label htmlFor={htmlFor} className="block text-[13px] font-medium text-fg-muted">
      {label}
      {required && <span className="ml-0.5 text-danger-text">*</span>}
    </label>
    {children}
    {hint && <p className="text-xs text-fg-subtle">{hint}</p>}
  </div>
);
