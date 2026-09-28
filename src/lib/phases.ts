import type { HuntReport } from '../types';

/** Hunts are grouped into phases of 10: after the 10th hunt of a phase, the next one starts a new phase. */
export const HUNTS_PER_PHASE = 10;

export const phaseCounts = (reports: HuntReport[]) => {
  const counts = new Map<number, number>();
  for (const r of reports) if (r.phase) counts.set(r.phase, (counts.get(r.phase) ?? 0) + 1);
  return counts;
};

/** The phase a new hunt belongs to: the latest phase, or the next one once the latest has 10 hunts. */
export function suggestPhase(reports: HuntReport[]): number {
  const counts = phaseCounts(reports);
  if (!counts.size) return 1;
  const latest = Math.max(...counts.keys());
  return (counts.get(latest) ?? 0) >= HUNTS_PER_PHASE ? latest + 1 : latest;
}

/** Phases offered in the dropdown: every phase used so far plus the next one. */
export function phaseOptions(reports: HuntReport[]): number[] {
  const max = Math.max(suggestPhase(reports), ...phaseCounts(reports).keys(), 1);
  return Array.from({ length: max + 1 }, (_, i) => i + 1);
}
