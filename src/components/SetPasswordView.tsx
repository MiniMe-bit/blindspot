import React, { useState } from 'react';
import { AlertCircle, KeyRound, LogOut } from 'lucide-react';
import { changePassword } from '../services/auth';
import type { SessionUser } from '../app/useWorkspace';
import { BrandLogo } from './ui/BrandLogo';
import { Button, Field, Input } from './ui';

interface SetPasswordViewProps {
  user: SessionUser;
  onDone: (user: SessionUser) => void;
  onSignOut: () => void;
}

/** Shown after signing in with a temporary password (new hunter or admin reset). Nothing else opens until it is changed. */
export const SetPasswordView: React.FC<SetPasswordViewProps> = ({ user, onDone, onSignOut }) => {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const mismatch = confirm.length > 0 && next !== confirm;
  const tooShort = next.length > 0 && next.length < 10;
  const canSave = Boolean(current) && next.length >= 10 && next === confirm && !saving;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSave) return;
    setSaving(true);
    setError(null);
    try {
      onDone(await changePassword(current, next));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not change the password.');
      setSaving(false);
    }
  };

  return (
    <main className="flex min-h-screen items-center justify-center bg-canvas px-4 py-12 text-fg">
      <div className="w-full max-w-md">
        <div className="mb-8 flex flex-col items-center text-center">
          <BrandLogo size="lg" />
          <h1 className="mt-6 text-2xl font-semibold tracking-tight">Set your own password</h1>
          <p className="mt-2 text-sm text-fg-muted">
            Welcome, <span className="font-medium text-fg">{user.name}</span>. You signed in with a temporary password. Choose a new one to continue.
          </p>
        </div>

        <form onSubmit={submit} className="space-y-4 rounded-xl border border-border bg-surface p-6" noValidate>
          {error && (
            <div role="alert" className="flex items-start gap-2 rounded-md bg-danger-soft px-3 py-2.5 text-[13px] text-danger-text">
              <AlertCircle className="mt-0.5 size-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}
          <Field label="Temporary password" htmlFor="sp-current">
            <Input id="sp-current" type="password" autoComplete="current-password" autoFocus value={current} onChange={(e) => setCurrent(e.target.value)} className="h-10" />
          </Field>
          <Field label="New password" htmlFor="sp-new" hint={tooShort ? <span className="text-warning-text">At least 10 characters.</span> : 'At least 10 characters. A passphrase of a few words works well.'}>
            <Input id="sp-new" type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} className="h-10" />
          </Field>
          <Field label="Confirm new password" htmlFor="sp-confirm" hint={mismatch ? <span className="text-danger-text">Passwords don't match.</span> : undefined}>
            <Input id="sp-confirm" type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} className="h-10" />
          </Field>
          <Button type="submit" variant="primary" icon={KeyRound} loading={saving} disabled={!canSave} className="h-10 w-full">
            Save and continue
          </Button>
        </form>

        <button type="button" onClick={onSignOut} className="mx-auto mt-6 flex items-center gap-1.5 text-xs text-fg-subtle hover:text-fg">
          <LogOut className="size-3.5" /> Sign out
        </button>
      </div>
    </main>
  );
};
