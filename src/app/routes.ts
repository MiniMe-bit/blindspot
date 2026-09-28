import {
  Building2,
  LayoutDashboard,
  Crosshair,
  Radar,
  FileText,
  ShieldCheck,
  Grid3X3,
  Gauge,
  Presentation,
  ScanSearch,
  type LucideIcon,
} from 'lucide-react';

export type RouteId = 'clients' | 'overview' | 'hunts' | 'ioc' | 'intel' | 'reports' | 'detections' | 'coverage' | 'severity' | 'decks';

export interface RouteDef {
  id: RouteId;
  path: string;
  label: string;
  icon: LucideIcon;
}

export const ROUTES: Record<RouteId, RouteDef> = {
  clients: { id: 'clients', path: '/clients', label: 'All clients', icon: Building2 },
  overview: { id: 'overview', path: '/overview', label: 'Client overview', icon: LayoutDashboard },
  hunts: { id: 'hunts', path: '/hunts', label: "What's New", icon: Crosshair },
  ioc: { id: 'ioc', path: '/ioc', label: 'Daily IOC Hunting', icon: ScanSearch },
  intel: { id: 'intel', path: '/intel', label: 'Threat intel', icon: Radar },
  reports: { id: 'reports', path: '/reports', label: 'Hypothesis Record', icon: FileText },
  detections: { id: 'detections', path: '/detections', label: 'Detection rules', icon: ShieldCheck },
  coverage: { id: 'coverage', path: '/coverage', label: 'ATT&CK coverage', icon: Grid3X3 },
  severity: { id: 'severity', path: '/severity', label: 'Severity scoring', icon: Gauge },
  decks: { id: 'decks', path: '/decks', label: 'Executive decks', icon: Presentation },
};

export interface NavSection {
  label?: string;
  items: RouteId[];
}

export const NAV_SECTIONS: NavSection[] = [
  { items: ['overview'] },
  { label: 'Threat Hunting Activities', items: ['reports', 'ioc', 'intel', 'hunts'] },
  { label: 'Detection', items: ['detections', 'coverage'] },
  { label: 'Reporting', items: ['severity', 'decks'] },
];

export const sectionOf = (id: RouteId): string | undefined => NAV_SECTIONS.find((s) => s.items.includes(id))?.label;

/** Hunters land on the client list after signing in. */
export const DEFAULT_ROUTE: RouteId = 'clients';

/** Pages that are not about a single client (no client name in the top bar). */
export const CROSS_CLIENT_ROUTES: RouteId[] = ['clients'];
