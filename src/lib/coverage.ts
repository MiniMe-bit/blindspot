import type { HuntReport } from '../types';
import { MITRE_TACTICS, MITRE_TECHNIQUES } from '../data/mitreAttck';

/** Technique IDs hunted in the given reports. Sub-techniques also count toward their parent. */
export function coveredTechniqueSet(reports: HuntReport[]): Set<string> {
  const set = new Set<string>();
  for (const r of reports) {
    for (const t of r.techniqueIds) {
      set.add(t);
      set.add(t.split('.')[0]);
    }
  }
  return set;
}

export const isCovered = (covered: Set<string>, techniqueId: string) =>
  covered.has(techniqueId) || covered.has(techniqueId.split('.')[0]);

export interface TacticCoverage {
  id: string;
  name: string;
  shortCode: string;
  description: string;
  total: number;
  covered: number;
  percent: number;
}

export function tacticCoverage(covered: Set<string>): TacticCoverage[] {
  return MITRE_TACTICS.map((tac) => {
    const techs = MITRE_TECHNIQUES.filter((t) => t.tactic === tac.name);
    const count = techs.filter((t) => covered.has(t.id)).length;
    return {
      id: tac.id,
      name: tac.name,
      shortCode: tac.shortCode,
      description: tac.description,
      total: techs.length,
      covered: count,
      percent: techs.length ? Math.round((count / techs.length) * 100) : 0,
    };
  });
}

export function coverageSummary(covered: Set<string>) {
  const total = MITRE_TECHNIQUES.length;
  const count = MITRE_TECHNIQUES.filter((t) => covered.has(t.id)).length;
  return { total, covered: count, gaps: total - count, percent: total ? Math.round((count / total) * 100) : 0 };
}

/** True when the client has onboarded a telemetry source that matches the required one (loose name match). */
export const hasTelemetry = (clientSources: string[], required: string) =>
  clientSources.some((s) => s.toLowerCase().includes(required.toLowerCase()) || required.toLowerCase().includes(s.toLowerCase()));

/** ISO week label for today, e.g. "2026-W40 (Sep 28 – Oct 4)". */
export function currentWeekRange(date = new Date()): string {
  const d = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));
  const day = d.getUTCDay() || 7;
  const monday = new Date(d);
  monday.setUTCDate(d.getUTCDate() - day + 1);
  const sunday = new Date(monday);
  sunday.setUTCDate(monday.getUTCDate() + 6);
  const thursday = new Date(d);
  thursday.setUTCDate(d.getUTCDate() + 4 - day);
  const yearStart = new Date(Date.UTC(thursday.getUTCFullYear(), 0, 1));
  const week = Math.ceil(((thursday.getTime() - yearStart.getTime()) / 86400000 + 1) / 7);
  const fmt = (x: Date) => x.toLocaleDateString('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' });
  return `${thursday.getUTCFullYear()}-W${String(week).padStart(2, '0')} (${fmt(monday)} – ${fmt(sunday)})`;
}

export const formatDate = (iso: string) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
};
