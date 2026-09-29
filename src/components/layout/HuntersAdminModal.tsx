import React, { useCallback, useEffect, useState } from 'react';
import { AlertCircle, Check, Copy, KeyRound, Lock, LockOpen, UserPlus } from 'lucide-react';
import type { SessionUser } from '../../app/useWorkspace';
import { createHunter, listHunters, resetHunterPassword, unlockHunter, type ManagedHunter } from '../../services/admin';
import { Badge, Button, Field, Input, Modal, Select, useToast } from '../ui';

const ROLES: Array<{ value: SessionUser['role']; label: string }> = [
  { value: 'analyst', label: 'Analyst' },
  { value: 'lead', label: 'Lead' },
  { value: 'admin', label: 'Admin' },
];

const roleTone = (role: string) => (role === 'admin' ? 'violet' : role === 'lead' ? 'accent' : 'neutral');

/** Admin only: add hunters, reset passwords and clear sign-in lockouts. The server enforces the admin role. */
export const HuntersAdminModal: React.FC<{ currentUserId: string; onClose: () => void }> = ({ currentUserId, onClose }) => {
  const toast = useToast();
  const [hunters, setHunters] = useState<ManagedHunter[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [issued, setIssued] = useState<{ name: string; username: string; password: string } | null>(null);
  const [copied, setCopied] = useState(false);

  const [adding, setAdding] = useState(false);
  const [form, setForm] = useState({ name: '', username: '', email: '', role: 'analyst' as SessionUser['role'] });
  const [formError, setFormError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setHunters(await listHunters());
      setLoadError(null);
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : 'Could not load hunters.');
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const showIssued = (name: string, username: string, password: string) => {
    setIssued({ name, username, password });
    setCopied(false);
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    setBusy('create');
    try {
      const { user, temporaryPassword } = await createHunter({ ...form, username: form.username.trim().toLowerCase(), email: form.email.trim() || undefined });
      showIssued(user.name, user.username, temporaryPassword);
      setForm({ name: '', username: '', email: '', role: 'analyst' });
      setAdding(false);
      toast(`${user.name} added.`);
      await load();
    } catch (err) {
      setFormError(err instanceof Error ? err.message : 'Could not add the hunter.');
    } finally {
      setBusy(null);
    }
  };

  const handleReset = async (h: ManagedHunter) => {
    if (!window.confirm(`Reset ${h.name}'s password? They will be signed out everywhere and must set a new password at next sign-in.`)) return;
    setBusy(h.id);
    try {
      const { temporaryPassword } = await resetHunterPassword(h.id);
      showIssued(h.name, h.username, temporaryPassword);
      toast(`Password reset for ${h.name}.`);
      await load();
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Could not reset the password.', 'error');
    } finally {
      setBusy(null);
    }
  };

  const handleUnlock = async (h: ManagedHunter) => {
    setBusy(h.id);
    try {
      await unlockHunter(h.id);
      toast(`${h.name} can sign in again.`);
      await load();
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Could not unlock the account.', 'error');
    } finally {
      setBusy(null);
    }
  };

  const copy = async () => {
    if (!issued) return;
    try {
      await navigator.clipboard.writeText(issued.password);
      setCopied(true);
    } catch {
      // Clipboard unavailable; the password stays visible to copy by hand.
    }
  };

  return (
    <Modal
      open
      onClose={onClose}
      size="xl"
      title="Manage hunters"
      description="Add hunters, reset forgotten passwords and unlock accounts. Temporary passwords must be changed at the next sign-in."
    >
      {issued && (
        <div role="status" className="mb-5 rounded-lg border border-success/40 bg-success-soft p-4">
          <div className="text-[13px] font-semibold text-success-text">
            Temporary password for {issued.name} ({issued.username})
          </div>
          <div className="mt-2 flex items-center gap-2">
            <code className="rounded-md bg-canvas px-3 py-1.5 font-mono text-sm text-fg select-all">{issued.password}</code>
            <Button size="sm" variant="ghost" icon={copied ? Check : Copy} onClick={copy}>
              {copied ? 'Copied' : 'Copy'}
            </Button>
          </div>
          <p className="mt-2 text-xs text-fg-muted">Shown once. Share it privately; they will be asked to choose their own password when they sign in.</p>
        </div>
      )}

      <div className="mb-4 flex items-center justify-between gap-3">
        <h3 className="text-sm font-semibold text-fg">{hunters ? `${hunters.length} hunters` : 'Hunters'}</h3>
        {!adding && (
          <Button size="sm" variant="primary" icon={UserPlus} onClick={() => setAdding(true)}>
            Add hunter
          </Button>
        )}
      </div>

      {adding && (
        <form onSubmit={handleCreate} className="mb-5 space-y-4 rounded-lg border border-border bg-canvas p-4" noValidate>
          {formError && (
            <div role="alert" className="flex items-start gap-2 rounded-md bg-danger-soft px-3 py-2 text-[13px] text-danger-text">
              <AlertCircle className="mt-0.5 size-4 shrink-0" />
              {formError}
            </div>
          )}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <Field label="Full name" htmlFor="ha-name" required>
              <Input id="ha-name" autoFocus value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="e.g. Jane Doe" />
            </Field>
            <Field label="Username" htmlFor="ha-username" required hint="Used to sign in, e.g. jane.doe">
              <Input id="ha-username" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} placeholder="jane.doe" autoComplete="off" />
            </Field>
            <Field label="Email" htmlFor="ha-email" hint="Optional">
              <Input id="ha-email" type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
            </Field>
            <Field label="Role" htmlFor="ha-role">
              <Select id="ha-role" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as SessionUser['role'] })}>
                {ROLES.map((r) => (
                  <option key={r.value} value={r.value}>
                    {r.label}
                  </option>
                ))}
              </Select>
            </Field>
          </div>
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={() => setAdding(false)}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" loading={busy === 'create'} disabled={!form.name.trim() || !form.username.trim()}>
              Add and create temporary password
            </Button>
          </div>
        </form>
      )}

      {loadError ? (
        <p className="text-[13px] text-danger-text">{loadError}</p>
      ) : !hunters ? (
        <p className="text-[13px] text-fg-subtle">Loading…</p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full min-w-[640px] text-left text-[13px]">
            <thead className="border-b border-border bg-surface-2 text-xs text-fg-subtle">
              <tr>
                <th className="px-4 py-2.5 font-medium">Hunter</th>
                <th className="px-4 py-2.5 font-medium">Role</th>
                <th className="px-4 py-2.5 font-medium">Status</th>
                <th className="px-4 py-2.5 text-right font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {hunters.map((h) => {
                const self = h.id === currentUserId;
                return (
                  <tr key={h.id}>
                    <td className="px-4 py-3">
                      <div className="font-medium text-fg">
                        {h.name} {self && <span className="text-xs font-normal text-fg-subtle">(you)</span>}
                      </div>
                      <div className="text-xs text-fg-muted">
                        {h.username}
                        {h.email && ` · ${h.email}`}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <Badge tone={roleTone(h.role)}>{h.role}</Badge>
                    </td>
                    <td className="px-4 py-3">
                      {h.locked ? (
                        <Badge tone="danger">
                          <Lock className="size-3" /> Locked out
                        </Badge>
                      ) : h.mustChangePassword ? (
                        <Badge tone="warning">Temporary password</Badge>
                      ) : (
                        <Badge tone="success">Active</Badge>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex justify-end gap-2">
                        {h.locked && (
                          <Button size="sm" icon={LockOpen} loading={busy === h.id} onClick={() => handleUnlock(h)}>
                            Unlock
                          </Button>
                        )}
                        <Button
                          size="sm"
                          variant="ghost"
                          icon={KeyRound}
                          disabled={self || busy === h.id}
                          title={self ? 'Use Account menu → Change password for your own account' : undefined}
                          onClick={() => handleReset(h)}
                        >
                          Reset password
                        </Button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Modal>
  );
};
