import React, { useState } from 'react';
import { AlertCircle, Eye, EyeOff, LogIn } from 'lucide-react';
import { login } from '../services/auth';
import type { SessionUser } from '../app/useWorkspace';
import { BrandLogo } from './ui/BrandLogo';
import { Button, Field, Input } from './ui';

interface LoginViewProps {
  onSignedIn: (user: SessionUser) => void;
  /** Shown when the user was signed out because their session expired. */
  notice?: string;
}

export const LoginView: React.FC<LoginViewProps> = ({ onSignedIn, notice }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      onSignedIn(await login(username, password));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Sign-in failed.');
      setSubmitting(false);
    }
  };

  return (
    <main className="flex min-h-screen items-center justify-center bg-canvas px-4 py-12 text-fg">
      <div className="w-full max-w-md">
        <div className="mb-8 flex flex-col items-center text-center">
          <BrandLogo size="xl" className="flex-col gap-4" />
          <p className="mt-3 text-base text-fg-muted">Find what hides in your clients' blind spots.</p>
          <h1 className="mt-8 text-lg font-semibold tracking-tight">Sign in to your hunting workspace</h1>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4 rounded-xl border border-border bg-surface p-6" noValidate>
          {(error || notice) && (
            <div
              role="alert"
              className={
                error
                  ? 'flex items-start gap-2 rounded-md bg-danger-soft px-3 py-2.5 text-[13px] text-danger-text'
                  : 'flex items-start gap-2 rounded-md bg-surface-2 px-3 py-2.5 text-[13px] text-fg-muted'
              }
            >
              <AlertCircle className="mt-0.5 size-4 shrink-0" />
              <span>{error ?? notice}</span>
            </div>
          )}

          <Field label="Username" htmlFor="username">
            <Input
              id="username"
              name="username"
              autoComplete="username"
              autoFocus
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="e.g. sarah.lin"
              className="h-10"
            />
          </Field>

          <Field label="Password" htmlFor="password">
            <div className="relative">
              <Input
                id="password"
                name="password"
                type={showPassword ? 'text' : 'password'}
                autoComplete="current-password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="h-10 pr-10"
              />
              <button
                type="button"
                onClick={() => setShowPassword((v) => !v)}
                aria-label={showPassword ? 'Hide password' : 'Show password'}
                className="absolute inset-y-0 right-0 flex w-10 items-center justify-center text-fg-subtle hover:text-fg"
              >
                {showPassword ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
              </button>
            </div>
          </Field>

          <Button type="submit" variant="primary" icon={LogIn} loading={submitting} disabled={!username || !password} className="h-10 w-full">
            Sign in
          </Button>
        </form>

        <p className="mt-6 text-center text-xs text-fg-subtle">No account or forgot your password? Ask your hunt lead to create or reset it.</p>
      </div>
    </main>
  );
};
