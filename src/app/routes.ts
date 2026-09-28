import {
  LayoutDashboard,
  Crosshair,
  Radar,
  FileText,
  ShieldCheck,
  Grid3X3,
  Gauge,
  Presentation,
  type LucideIcon,
} from 'lucide-react';

export type RouteId = 'overview' | 'hunts' | 'intel' | 'reports' | 'detections' | 'coverage' | 'severity' | 'decks';

export interface RouteDef {
  id: RouteId;
  path: string;
  label: string;
  icon: LucideIcon;
}

export const ROUTES: Record<RouteId, RouteDef> = {
  overview: { id: 'overview', path: '/overview', label: 'Overview', icon: LayoutDashboard },
  hunts: { id: 'hunts', path: '/hunts', label: "Today's hunts", icon: Crosshair },
  intel: { id: 'intel', path: '/intel', label: 'Threat intel', icon: Radar },
  reports: { id: 'reports', path: '/reports', label: 'Hunt reports', icon: FileText },
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
  { label: 'Hunting', items: ['hunts', 'intel', 'reports'] },
  { label: 'Detection', items: ['detections', 'coverage'] },
  { label: 'Reporting', items: ['severity', 'decks'] },
];

export const sectionOf = (id: RouteId): string | undefined => NAV_SECTIONS.find((s) => s.items.includes(id))?.label;

export const DEFAULT_ROUTE: RouteId = 'overview';
