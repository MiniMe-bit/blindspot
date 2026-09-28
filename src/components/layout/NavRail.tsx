import React from 'react';
import { PanelLeftClose, PanelLeftOpen, Building2, X, Lock } from 'lucide-react';
import type { ClientOrg } from '../../types';
import { NAV_SECTIONS, ROUTES, type RouteId } from '../../app/routes';
import { cn } from '../../lib/cn';
import { BrandLogo, BrandMark } from '../ui/BrandLogo';
import { ClientLogo } from '../ui/ClientLogo';

interface NavRailProps {
  current: RouteId;
  onNavigate: (id: RouteId) => void;
  /** The client being worked on, or null before one is picked (client pages are hidden until then). */
  client: ClientOrg | null;
  collapsed: boolean;
  onToggleCollapsed: () => void;
  mobileOpen: boolean;
  onCloseMobile: () => void;
  onOpenClients: () => void;
}

export const NavRail: React.FC<NavRailProps> = ({ current, onNavigate, client, collapsed, onToggleCollapsed, mobileOpen, onCloseMobile, onOpenClients }) => {
  const go = (id: RouteId) => {
    onNavigate(id);
    onCloseMobile();
  };

  const navLink = (id: RouteId, compact: boolean) => {
    const route = ROUTES[id];
    const Icon = route.icon;
    const active = current === id;
    return (
      <a
        href={`#${route.path}`}
        onClick={(e) => {
          e.preventDefault();
          go(id);
        }}
        aria-current={active ? 'page' : undefined}
        title={compact ? route.label : undefined}
        className={cn(
          'group flex items-center gap-2.5 rounded-md text-sm transition-colors',
          compact ? 'h-9 justify-center' : 'h-9 px-2.5',
          active ? 'bg-surface-3 font-medium text-fg' : 'text-fg-muted hover:bg-surface-2 hover:text-fg',
        )}
      >
        <Icon className={cn('size-4 shrink-0', active ? 'text-accent' : 'text-fg-subtle group-hover:text-fg-muted')} />
        {!compact && <span className="truncate">{route.label}</span>}
      </a>
    );
  };

  const content = (isMobile: boolean) => {
    const compact = collapsed && !isMobile;
    return (
      <div className="flex h-full flex-col">
        {/* Brand */}
        <div className={cn('flex h-16 shrink-0 items-center border-b border-border', compact ? 'justify-center px-2' : 'justify-between px-4')}>
          <button type="button" onClick={() => go('clients')} className="flex items-center" title="Blindspot — all clients">
            {compact ? <BrandMark className="size-9" /> : <BrandLogo size="md" />}
          </button>
          {isMobile && (
            <button type="button" onClick={onCloseMobile} className="rounded-md p-1.5 text-fg-muted hover:bg-surface-2 hover:text-fg" aria-label="Close navigation">
              <X className="size-4" />
            </button>
          )}
        </div>

        <nav className="flex-1 overflow-y-auto px-2 py-3" aria-label="Primary">
          <ul>
            <li>{navLink('clients', compact)}</li>
          </ul>

          {client ? (
            <>
              {/* Current client */}
              {compact ? (
                <button type="button" onClick={() => go('overview')} title={client.name} className="mx-auto mt-3 flex justify-center">
                  <ClientLogo client={client} size="sm" />
                </button>
              ) : (
                <div className="mt-3 flex items-center gap-2.5 rounded-lg border border-border bg-canvas px-2.5 py-2">
                  <ClientLogo client={client} size="md" />
                  <div className="min-w-0 flex-1">
                    <div className="text-[11px] font-medium uppercase tracking-wide text-fg-subtle">Client</div>
                    <div className="truncate text-sm font-semibold text-fg">{client.name}</div>
                  </div>
                  <button type="button" onClick={() => go('clients')} className="rounded px-1.5 py-0.5 text-xs text-accent-text hover:bg-surface-2">
                    Change
                  </button>
                </div>
              )}

              {NAV_SECTIONS.map((section, i) => (
                <div key={section.label ?? i} className="mt-4">
                  {section.label && !compact && <div className="mb-1 px-2.5 text-xs font-medium text-fg-subtle">{section.label}</div>}
                  {section.label && compact && <div className="mx-auto mb-2 w-6 border-t border-border" />}
                  <ul className="space-y-0.5">
                    {section.items.map((id) => (
                      <li key={id}>{navLink(id, compact)}</li>
                    ))}
                  </ul>
                </div>
              ))}
            </>
          ) : (
            !compact && (
              <div className="mt-4 rounded-lg border border-dashed border-border px-3 py-3 text-[13px] text-fg-muted">
                <div className="mb-1 flex items-center gap-1.5 font-medium text-fg">
                  <Lock className="size-3.5 text-fg-subtle" /> Pick a client first
                </div>
                Hunts, IOC hunting, reports and coverage open once you choose a client.
              </div>
            )
          )}
        </nav>

        {/* Footer */}
        <div className="shrink-0 space-y-0.5 border-t border-border px-2 py-2">
          <button
            type="button"
            onClick={() => {
              onOpenClients();
              onCloseMobile();
            }}
            title={compact ? 'Clients & telemetry' : undefined}
            className={cn(
              'flex w-full items-center gap-2.5 rounded-md text-sm text-fg-muted transition-colors hover:bg-surface-2 hover:text-fg',
              compact ? 'h-9 justify-center' : 'h-8 px-2.5',
            )}
          >
            <Building2 className="size-4 shrink-0 text-fg-subtle" />
            {!compact && <span>Clients & telemetry</span>}
          </button>
          {!isMobile && (
            <button
              type="button"
              onClick={onToggleCollapsed}
              title={compact ? 'Expand sidebar' : 'Collapse sidebar'}
              className={cn(
                'flex w-full items-center gap-2.5 rounded-md text-sm text-fg-subtle transition-colors hover:bg-surface-2 hover:text-fg',
                compact ? 'h-9 justify-center' : 'h-8 px-2.5',
              )}
            >
              {compact ? <PanelLeftOpen className="size-4" /> : <PanelLeftClose className="size-4" />}
              {!compact && <span>Collapse</span>}
            </button>
          )}
        </div>
      </div>
    );
  };

  return (
    <>
      {/* Desktop rail */}
      <aside
        className={cn(
          'no-print sticky top-0 hidden h-screen shrink-0 border-r border-border bg-surface transition-[width] duration-150 lg:block',
          collapsed ? 'w-16' : 'w-64',
        )}
      >
        {content(false)}
      </aside>

      {/* Mobile drawer */}
      {mobileOpen && (
        <div className="no-print fixed inset-0 z-50 lg:hidden">
          <div className="absolute inset-0 bg-black/60" onClick={onCloseMobile} aria-hidden="true" />
          <aside className="absolute inset-y-0 left-0 w-72 border-r border-border bg-surface shadow-2xl">{content(true)}</aside>
        </div>
      )}
    </>
  );
};
