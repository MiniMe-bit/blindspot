import { ClientOrg, HuntReference, NextHuntRecommendation, ThreatHuntReportDocument, TodayHunt } from '../types';
import { LEGACY_SOURCE, SOURCES } from '../lib/huntCatalog';
import { apiFetch } from './auth';

/**
 * AI endpoints may answer with curated fallback content when the model is unavailable.
 * `fallback: true` means the content was NOT generated for this request — the UI must say so.
 */
export interface AiResult<T> {
  data: T;
  fallback: boolean;
}

export async function fetchNextHuntRecommendations(
  client: ClientOrg,
  coveredTechniques: string[],
  uncoveredTechniques: string[]
): Promise<AiResult<NextHuntRecommendation[]>> {
  const res = await apiFetch('/api/ai/recommend-next-hunts', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client, coveredTechniques, uncoveredTechniques }),
  });
  if (!res.ok) throw new Error(`HTTP error ${res.status}`);
  const data = await res.json();
  return { data: data.recommendations || [], fallback: Boolean(data.fallback) };
}

export async function fetchAiDailyHunts(client: ClientOrg): Promise<{ hunts: TodayHunt[]; fallback: boolean }> {
  const res = await apiFetch('/api/ai/generate-daily-hunts', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client }),
  });
  if (!res.ok) throw new Error(`HTTP error ${res.status}`);
  const data = await res.json();
  const hunts: TodayHunt[] = (data.hunts || []).map((h: any, idx: number) => ({
    ...h,
    source: SOURCES.some((s) => s.id === h.source) ? h.source : (LEGACY_SOURCE[h.source] ?? 'Coverage Gap'),
    platformQueries: h.platformQueries && typeof h.platformQueries === 'object' ? h.platformQueries : undefined,
    // Links written by the model are unchecked: the UI labels them so hunters verify before trusting.
    references: Array.isArray(h.references)
      ? h.references
          .filter((r: any) => typeof r?.url === 'string' && r.url.startsWith('https://'))
          .map((r: any): HuntReference => ({ title: String(r.title || r.url), url: r.url, publisher: r.publisher, unverified: true }))
      : undefined,
    id: `ai-gen-${Date.now()}-${idx}`,
    clientId: client.id,
    generatedAt: new Date().toISOString(),
    status: 'queued',
  }));
  return { hunts, fallback: Boolean(data.fallback) };
}

export async function fetchDeckNarrative(
  client: ClientOrg,
  periodLabel: string,
  stats: any,
  coveredCount: number,
  totalTechniques: number,
  truePositiveCount: number
): Promise<
  AiResult<{
    executiveSummary: string;
    topThreatTakeaways: string[];
    criticalBlindSpots: string[];
    nextQuarterRoadmap: string[];
  }>
> {
  const res = await apiFetch('/api/ai/generate-deck-narrative', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client,
      periodLabel,
      stats,
      coveredCount,
      totalTechniques,
      truePositiveCount,
    }),
  });
  if (!res.ok) throw new Error(`HTTP error ${res.status}`);
  const data = await res.json();
  return { data: data.narrative, fallback: Boolean(data.fallback) };
}

export async function fetchSeverityRationale(
  topic: string,
  summary: string,
  factors: any,
  compositeScore: number,
  level: string
): Promise<AiResult<string>> {
  const res = await apiFetch('/api/ai/severity-rationalization', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ topic, summary, factors, compositeScore, level }),
  });
  if (!res.ok) throw new Error(`HTTP error ${res.status}`);
  const data = await res.json();
  return { data: data.rationale || '', fallback: Boolean(data.fallback) };
}

export interface ExtractedHuntReportData {
  hypothesisTitle?: string;
  hypothesisDescription?: string;
  weekRange?: string;
  techniqueIds?: string[];
  dataSources?: string[];
  queryLanguage?: 'KQL' | 'SPL' | 'Sigma' | 'EQL';
  queryText?: string;
  outcome?: 'True Positive' | 'False Positive' | 'No Result' | 'Needs Follow-up';
  notes?: string;
  iocs?: Array<{
    type: 'IP' | 'Domain' | 'Hash' | 'Process' | 'Registry' | 'Account';
    value: string;
    notes?: string;
  }>;
  confidenceScore?: number;
  extractionSummary?: string;
}

export async function parseReportPdf(
  base64Data: string,
  mimeType: string,
  fileName: string
): Promise<ExtractedHuntReportData> {
  const res = await apiFetch('/api/ai/parse-report-pdf', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ base64Data, mimeType, fileName }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data.success) throw new Error(data.error || `Could not read the document (HTTP ${res.status}).`);
  return data.extracted;
}

export async function generateThreatHuntReportDocument(payload: {
  title: string;
  description: string;
  reportDate: string;
  queryContext?: string;
  queries: Array<{ id: string; platform: string; title?: string; code: string; explanation?: string }>;
  huntResults?: string;
  outcome?: string;
  techniqueIds?: string[];
  client?: any;
  hunter?: any;
}): Promise<AiResult<ThreatHuntReportDocument>> {
  const res = await apiFetch('/api/ai/generate-thr-report', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(`HTTP error ${res.status}`);
  const data = await res.json();
  if (!data.success) throw new Error(data.error || 'Failed to generate THR');
  return { data: data.thrDocument, fallback: Boolean(data.fallback) };
}


