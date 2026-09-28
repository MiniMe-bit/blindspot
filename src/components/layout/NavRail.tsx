import React from 'react';
import { PanelLeftClose, PanelLeftOpen, Building2, X } from 'lucide-react';
import { NAV_SECTIONS, ROUTES, type RouteId } from '../../app/routes';
import { cn } from '../../lib/cn';

interface NavRailProps {
  current: RouteId;
  onNavigate: (id: RouteId) => void;
  collapsed: boolean;
  onToggleCollapsed: () => void;
  mobileOpen: boolean;
  onCloseMobile: () => void;
  onOpenClients: () => void;
}

export const LogoMark: React.FC<{ className?: string }> = ({ className }) => (
  <svg viewBox="0 0 24 24" fill="none" className={className} aria-hidden="true">
    <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="2" />
    <path d="M12 12 L12 3 A9 9 0 0 1 20.2 8.2 Z" fill="currentColor" />
  </svg>
);

export const NavRail: React.FC<NavRailProps> = ({
  current,
  onNavigate,
  collapsed,
  onToggleCollapsed,
  mobileOpen,
  onCloseMobile,
  onOpenClients,
}) => {
  const go = (id: RouteId) => {
    onNavigate(id);
    onCloseMobile();
  };

  const content = (isMobile: boolean) => {
    const compact = collapsed && !isMobile;
    return (
      <div className="flex h-full flex-col">
        {/* Brand */}
        <div className={cn('flex h-14 shrink-0 items-center border-b border-border', compact ? 'justify-center px-2' : 'justify-between px-4')}>
          <button type="button" onClick={() => go('overview')} className="flex items-center gap-2.5 text-fg" title="Blindspot">
            <LogoMark className="size-5 text-accent" />
            {!compact && <span className="text-[15px] font-semibold tracking-tight">Blindspot</span>}
          </button>
          {isMobile && (
            <button type="button" onClick={onCloseMobile} className="rounded-md p-1.5 text-fg-muted hover:bg-surface-2 hover:text-fg" aria-label="Close navigation">
              <X className="size-4" />
            </button>
          )}
        </div>

        {/* Sections */}
        <nav className="flex-1 overflow-y-auto px-2 py-3" aria-label="Primary">
          {NAV_SECTIONS.map((section, i) => (
            <div key={section.label ?? i} className={cn(i > 0 && 'mt-5')}>
              {section.label && !compact && (
                <div className="mb-1 px-2.5 text-xs font-medium text-fg-subtle">{section.label}</div>
              )}
              {section.label && compact && <div className="mx-auto mb-2 w-6 border-t border-border" />}
              <ul className="space-y-0.5">
                {section.items.map((id) => {
                  const route = ROUTES[id];
                  const Icon = route.icon;
                  const active = current === id;
                  return (
                    <li key={id}>
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
                          compact ? 'h-9 justify-center' : 'h-8 px-2.5',
                          active ? 'bg-surface-3 font-medium text-fg' : 'text-fg-muted hover:bg-surface-2 hover:text-fg',
                        )}
                      >
                        <Icon className={cn('size-4 shrink-0', active ? 'text-accent' : 'text-fg-subtle group-hover:text-fg-muted')} />
                        {!compact && <span className="truncate">{route.label}</span>}
                      </a>
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
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
          collapsed ? 'w-16' : 'w-60',
        )}
      >
        {content(false)}
      </aside>

      {/* Mobile drawer */}
      {mobileOpen && (
        <div className="no-print fixed inset-0 z-50 lg:hidden">
          <div className="absolute inset-0 bg-black/60" onClick={onCloseMobile} aria-hidden="true" />
          <aside className="absolute inset-y-0 left-0 w-64 border-r border-border bg-surface shadow-2xl">{content(true)}</aside>
        </div>
      )}
    </>
  );
};
