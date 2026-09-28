import type { TodayHunt } from '../types';
import { DEFAULT_HUNT_SCORE_WEIGHTS, type ScoreWeights } from '../utils/huntScoreCalculator';

export const SCORE_FACTORS: Array<{ key: keyof ScoreWeights; label: string; help: string }> = [
  { key: 'threatRelevance', label: 'Threat relevance', help: 'How relevant the threat is to this client and sector' },
  { key: 'telemetryAvailable', label: 'Telemetry available', help: 'Share of required data sources the client has onboarded' },
  { key: 'detectionGap', label: 'Detection gap', help: 'How little this technique has been hunted or detected' },
  { key: 'recentActivity', label: 'Time since last hunt', help: 'Higher when the technique has not been hunted recently' },
  { key: 'historicalPrevalence', label: 'Historical hit rate', help: 'How often hunts on this technique found true positives' },
];

/** Weighted 0–100 priority. Weights are normalised, so they don't need to sum to 1. */
export function computePriority(hunt: TodayHunt, weights: ScoreWeights = DEFAULT_HUNT_SCORE_WEIGHTS): number {
  const total = SCORE_FACTORS.reduce((acc, f) => acc + weights[f.key], 0) || 1;
  const sum = SCORE_FACTORS.reduce((acc, f) => acc + hunt.aiHuntScore[f.key] * weights[f.key], 0);
  return Math.round(Math.min(100, Math.max(0, sum / total)));
}
