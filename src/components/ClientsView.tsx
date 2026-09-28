import React, { useMemo, useState } from 'react';
import { Building2, Search } from 'lucide-react';
import type { ClientOrg } from '../types';
import { useApp } from '../app/AppContext';
import { ClientLogo } from './ui/ClientLogo';
import { Card, EmptyState, Input } from './ui';

const greeting = () => {
  const h = new Date().getHours();
  return h < 12 ? 'Good morning' : h < 18 ? 'Good afternoon' : 'Good evening';
};

/** Landing page after sign-in: every client as a large logo card; picking one opens its workspace. */
export const ClientsView: React.FC = () => {
  const { clients, currentUser, setCurrentClientId, navigate } = useApp();
  const [query, setQuery] = useState('');

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return q ? clients.filter((c) => c.name.toLowerCase().includes(q)) : clients;
  }, [clients, query]);

  const open = (c: ClientOrg) => {
    setCurrentClientId(c.id);
    navigate('overview');
  };

  const firstName = currentUser.name.split(' ')[0];

  return (
    <>
      <div className="mb-10 pt-2">
        <p className="text-sm font-medium text-fg-subtle">{greeting()}</p>
        <h1 className="mt-1 text-4xl font-bold tracking-tight text-fg sm:text-5xl">
          Welcome back, <span className="bs-gradient-text">{firstName}</span>
        </h1>
        <p className="mt-3 text-base text-fg-muted">Choose a client to start hunting.</p>
      </div>

      {clients.length > 6 && (
        <div className="relative mb-6 w-full sm:w-80">
          <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-fg-subtle" />
          <Input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search clients" className="pl-9" aria-label="Search clients" />
        </div>
      )}

      {visible.length === 0 ? (
        <Card>
          <EmptyState icon={Building2} title="No clients match" description={`Nothing matches "${query}".`} />
        </Card>
      ) : (
        <ul className="grid grid-cols-1 gap-5 sm:grid-cols-2 xl:grid-cols-3">
          {visible.map((c) => (
            <li key={c.id}>
              <button
                type="button"
                onClick={() => open(c)}
                className="group flex w-full flex-col items-center rounded-2xl border border-border bg-surface px-6 py-10 text-center transition-all hover:-translate-y-0.5 hover:border-accent/60 hover:bg-surface-2"
              >
                <ClientLogo client={c} size="2xl" className="transition-transform group-hover:scale-105" />
                <span className="mt-6 text-2xl font-semibold tracking-tight text-fg group-hover:text-accent-text">{c.name}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </>
  );
};
