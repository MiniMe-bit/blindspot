import React, { useState } from 'react';
import { Check, Copy } from 'lucide-react';
import { cn } from '../../lib/cn';

interface CodeBlockProps {
  code: string;
  label?: string;
  maxHeight?: string;
  className?: string;
}

export const CodeBlock: React.FC<CodeBlockProps> = ({ code, label, maxHeight = 'max-h-80', className }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard can be unavailable (insecure context); fail quietly.
    }
  };

  return (
    <div className={cn('overflow-hidden rounded-md border border-border bg-canvas', className)}>
      <div className="flex items-center justify-between border-b border-border px-3 py-1.5">
        <span className="text-xs font-medium text-fg-subtle">{label ?? 'Query'}</span>
        <button
          type="button"
          onClick={handleCopy}
          className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs text-fg-muted hover:bg-surface-2 hover:text-fg"
        >
          {copied ? <Check className="size-3.5 text-success" /> : <Copy className="size-3.5" />}
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre className={cn('overflow-auto p-3 font-mono text-[12.5px] leading-relaxed text-fg whitespace-pre-wrap', maxHeight)}>
        {code}
      </pre>
    </div>
  );
};
