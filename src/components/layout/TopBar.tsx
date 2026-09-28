import React from 'react';
import { Menu, ChevronDown, ChevronRight, Check, Settings2, RotateCcw } from 'lucide-react';
import type { ClientOrg, User } from '../../types';
import { ROUTES, sectionOf, type RouteId } from '../../app/routes';
import { Dropdown, MenuDivider, MenuItem, MenuLabel } from '../ui/Dropdown';

interface TopBarProps {
  route: RouteId;
  onOpenMobileNav: () => void;
  clients: ClientOrg[];
  currentClient: ClientOrg;
  onSelectClient: (id: string) => void;
  onManageClients: () => void;
  users: User[];
  currentUser: User;
  onSelectUser: (id: string) => void;
  onResetDemoData: () => void;
}

const initials = (u: User) => u.avatar || u.name.split(' ').map((p) => p[0]).join('').slice(0, 2).toUpperCase();
const capitalize = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

export const TopBar: React.FC<TopBarProps> = ({
  route,
  onOpenMobileNav,
  clients,
  currentClient,
  onSelectClient,
  onManageClients,
  users,
  currentUser,
  onSelectUser,
  onResetDemoData,
}) => {
  const section = sectionOf(route);

  return (
    <header className="no-print sticky top-0 z-30 flex h-14 shrink-0 items-center gap-3 border-b border-border bg-canvas/95 px-4 backdrop-blur sm:px-6">
      <button
        type="button"
        onClick={onOpenMobileNav}
        className="-ml-1 rounded-md p-1.5 text-fg-muted hover:bg-surface-2 hover:text-fg lg:hidden"
        aria-label="Open navigation"
      >
        <Menu className="size-5" />
      </button>

      {/* Breadcrumb */}
      <nav aria-label="Breadcrumb" className="flex min-w-0 items-center gap-1.5 text-sm">
        {section && (
          <>
            <span className="hidden text-fg-subtle sm:inline">{section}</span>
            <ChevronRight className="hidden size-3.5 text-fg-subtle sm:inline" />
          </>
        )}
        <span className="truncate font-medium text-fg">{ROUTES[route].label}</span>
      </nav>

      <div className="ml-auto flex items-center gap-2">
        {/* Client switcher */}
        <Dropdown
          width="w-72"
          trigger={({ open, toggle }) => (
            <button
              type="button"
              onClick={toggle}
              aria-expanded={open}
              className="flex h-9 max-w-[16rem] items-center gap-2 rounded-md border border-border bg-surface px-3 text-sm text-fg transition-colors hover:bg-surface-2"
            >
              <span className="hidden text-fg-subtle sm:inline">Client</span>
              <span className="truncate font-medium">{currentClient.name}</span>
              <ChevronDown className="size-4 shrink-0 text-fg-subtle" />
            </button>
          )}
        >
          {(close) => (
            <>
              <MenuLabel>Switch client</MenuLabel>
              {clients.map((c) => (
                <MenuItem
                  key={c.id}
                  active={c.id === currentClient.id}
                  onClick={() => {
                    onSelectClient(c.id);
                    close();
                  }}
                  hint={c.id === currentClient.id ? <Check className="size-4 text-accent" /> : capitalize(c.industry)}
                >
                  {c.name}
                </MenuItem>
              ))}
              <MenuDivider />
              <MenuItem
                icon={Settings2}
                onClick={() => {
                  onManageClients();
                  close();
                }}
              >
                Manage clients & telemetry
              </MenuItem>
            </>
          )}
        </Dropdown>

        {/* User menu */}
        <Dropdown
          width="w-72"
          trigger={({ open, toggle }) => (
            <button
              type="button"
              onClick={toggle}
              aria-expanded={open}
              aria-label="Account menu"
              className="flex size-9 items-center justify-center rounded-full bg-surface-3 text-xs font-semibold text-fg transition-colors hover:bg-border-strong"
            >
              {initials(currentUser)}
            </button>
          )}
        >
          {(close) => (
            <>
              <div className="border-b border-border px-3 py-2.5">
                <div className="text-sm font-medium text-fg">{currentUser.name}</div>
                <div className="text-xs text-fg-muted">
                  {currentUser.email} · {capitalize(currentUser.role)}
                </div>
              </div>
              <MenuLabel>Switch user (demo)</MenuLabel>
              {users.map((u) => (
                <MenuItem
                  key={u.id}
                  active={u.id === currentUser.id}
                  onClick={() => {
                    onSelectUser(u.id);
                    close();
                  }}
                  hint={u.id === currentUser.id ? <Check className="size-4 text-accent" /> : capitalize(u.role)}
                >
                  {u.name}
                </MenuItem>
              ))}
              <MenuDivider />
              <MenuItem
                icon={RotateCcw}
                onClick={() => {
                  close();
                  if (window.confirm('Reset all demo data? Reports, rules and edits made in this browser will be lost.')) onResetDemoData();
                }}
              >
                Reset demo data
              </MenuItem>
            </>
          )}
        </Dropdown>
      </div>
    </header>
  );
};
