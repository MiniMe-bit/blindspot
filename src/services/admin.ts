import type { SessionUser } from '../app/useWorkspace';
import { apiFetch } from './auth';

export interface ManagedHunter extends SessionUser {
  createdAt: string;
  /** Currently locked out after too many failed sign-ins. */
  locked: boolean;
}

export interface TemporaryPasswordResult {
  user: SessionUser;
  temporaryPassword: string;
}

async function call<T>(url: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await apiFetch(url, init?.method === 'POST' ? { ...init, headers: { 'Content-Type': 'application/json' } } : init);
  } catch {
    throw new Error('Cannot reach the Blindspot server.');
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (HTTP ${res.status}).`);
  return data as T;
}

export const listHunters = () => call<{ users: ManagedHunter[] }>('/api/admin/users').then((d) => d.users);

export const createHunter = (input: { username: string; name: string; role: SessionUser['role']; email?: string }) =>
  call<TemporaryPasswordResult>('/api/admin/users', { method: 'POST', body: JSON.stringify(input) });

export const resetHunterPassword = (id: string) =>
  call<TemporaryPasswordResult>(`/api/admin/users/${encodeURIComponent(id)}/reset-password`, { method: 'POST', body: '{}' });

export const unlockHunter = (id: string) => call<{ ok: true }>(`/api/admin/users/${encodeURIComponent(id)}/unlock`, { method: 'POST', body: '{}' });
