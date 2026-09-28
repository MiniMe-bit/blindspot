import React, { createContext, useCallback, useContext, useState } from 'react';
import { CheckCircle2, Info, AlertTriangle, X } from 'lucide-react';
import { cn } from '../../lib/cn';

type ToastTone = 'success' | 'info' | 'error';
interface ToastItem {
  id: number;
  message: string;
  tone: ToastTone;
}

const ToastContext = createContext<(message: string, tone?: ToastTone) => void>(() => {});

export const useToast = () => useContext(ToastContext);

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const dismiss = (id: number) => setToasts((prev) => prev.filter((t) => t.id !== id));

  const push = useCallback((message: string, tone: ToastTone = 'success') => {
    const id = Date.now() + Math.random();
    setToasts((prev) => [...prev, { id, message, tone }]);
    setTimeout(() => dismiss(id), 4000);
  }, []);

  return (
    <ToastContext.Provider value={push}>
      {children}
      <div className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-80 flex-col gap-2" aria-live="polite">
        {toasts.map((t) => {
          const Icon = t.tone === 'success' ? CheckCircle2 : t.tone === 'error' ? AlertTriangle : Info;
          return (
            <div
              key={t.id}
              className="pointer-events-auto flex items-start gap-2.5 rounded-lg border border-border bg-surface-2 px-3.5 py-3 text-sm text-fg shadow-xl"
            >
              <Icon
                className={cn(
                  'mt-0.5 size-4 shrink-0',
                  t.tone === 'success' && 'text-success',
                  t.tone === 'error' && 'text-danger',
                  t.tone === 'info' && 'text-accent',
                )}
              />
              <span className="flex-1">{t.message}</span>
              <button type="button" onClick={() => dismiss(t.id)} className="text-fg-subtle hover:text-fg" aria-label="Dismiss">
                <X className="size-4" />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
};
