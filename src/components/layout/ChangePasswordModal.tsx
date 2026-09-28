import React, { useState } from 'react';
import { AlertCircle } from 'lucide-react';
import { changePassword } from '../../services/auth';
import { Button, Field, Input, Modal, useToast } from '../ui';

export const ChangePasswordModal: React.FC<{ onClose: () => void }> = ({ onClose }) => {
  const toast = useToast();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const mismatch = confirm.length > 0 && next !== confirm;
  const tooShort = next.length > 0 && next.length < 10;
  const canSave = current && next.length >= 10 && next === confirm && !saving;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSave) return;
    setSaving(true);
    setError(null);
    try {
      await changePassword(current, next);
      toast('Password changed. Use the new password next time you sign in.');
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not change the password.');
      setSaving(false);
    }
  };

  return (
    <Modal
      open
      onClose={onClose}
      size="md"
      title="Change password"
      description="Use at least 10 characters. A passphrase of a few words is easiest to remember."
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" form="change-password-form" loading={saving} disabled={!canSave}>
            Change password
          </Button>
        </>
      }
    >
      <form id="change-password-form" onSubmit={submit} className="space-y-4" noValidate>
        {error && (
          <div role="alert" className="flex items-start gap-2 rounded-md bg-danger-soft px-3 py-2.5 text-[13px] text-danger-text">
            <AlertCircle className="mt-0.5 size-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}
        <Field label="Current password" htmlFor="cp-current">
          <Input id="cp-current" type="password" autoComplete="current-password" autoFocus value={current} onChange={(e) => setCurrent(e.target.value)} />
        </Field>
        <Field label="New password" htmlFor="cp-new" hint={tooShort ? <span className="text-warning-text">At least 10 characters.</span> : undefined}>
          <Input id="cp-new" type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} />
        </Field>
        <Field label="Confirm new password" htmlFor="cp-confirm" hint={mismatch ? <span className="text-danger-text">Passwords don't match.</span> : undefined}>
          <Input id="cp-confirm" type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
        </Field>
      </form>
    </Modal>
  );
};
