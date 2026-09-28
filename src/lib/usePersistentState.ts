import { useEffect, useState } from 'react';

/**
 * Bump when the shape of persisted data or the seed data changes.
 * Old keys are ignored and the workspace reseeds from mock data.
 */
const STORAGE_VERSION = 'v2';
const key = (name: string) => `blindspot.${STORAGE_VERSION}.${name}`;

/**
 * `migrate` upgrades a previously saved value in place (e.g. to backfill new fields) without
 * bumping STORAGE_VERSION, so hunters keep their own reports and edits.
 */
export function usePersistentState<T>(name: string, initial: T | (() => T), migrate?: (saved: T) => T) {
  const [value, setValue] = useState<T>(() => {
    try {
      const raw = localStorage.getItem(key(name));
      if (raw !== null) {
        const saved = JSON.parse(raw) as T;
        return migrate ? migrate(saved) : saved;
      }
    } catch {
      // Corrupt or unavailable storage: fall back to the seed.
    }
    return typeof initial === 'function' ? (initial as () => T)() : initial;
  });

  useEffect(() => {
    try {
      localStorage.setItem(key(name), JSON.stringify(value));
    } catch {
      // Storage full or blocked; state still works in memory.
    }
  }, [name, value]);

  return [value, setValue] as const;
}

/** Remove every persisted Blindspot key (current and legacy versions). */
export function clearPersistedState() {
  try {
    Object.keys(localStorage)
      .filter((k) => k.startsWith('blindspot'))
      .forEach((k) => localStorage.removeItem(k));
  } catch {
    // ignore
  }
}
