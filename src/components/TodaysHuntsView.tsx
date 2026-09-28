import React, { useEffect, useMemo, useState } from 'react';
import { ArrowRight, BookOpen, Crosshair, ExternalLink, Plus, RotateCcw, Search, SlidersHorizontal, Sparkles, X } from 'lucide-react';
import type { HuntPlatform, HuntReference, ReportDraft, TodayHunt, TodayHuntStatus } from '../types';
import { useApp } from '../app/AppContext';
import { fetchAiDailyHunts } from '../services/api';
import { hashParams } from '../lib/useHashRoute';
import { hasTelemetry } from '../lib/coverage';
import { computePriority, SCORE_FACTORS } from '../lib/huntPriority';
import { defaultPlatformFor, platformDef, PLATFORMS, queryFor, sourceDef, SOURCES, type SourceTone } from '../lib/huntCatalog';
import { DEFAULT_HUNT_SCORE_WEIGHTS, type ScoreWeights } from '../utils/huntScoreCalculator';
import { cn } from '../lib/cn';
import {
  Badge,
  Button,
  Card,
  CardTitle,
  CodeBlock,
  EmptyState,
  Input,
  Meter,
  PageHeader,
  SectionLabel,
  Segmented,
  severityTone,
  useToast,
} from './ui';

const STATUS_LABEL: Record<TodayHuntStatus, string> = { queued: 'Queued', 'in-progress': 'In progress', done: 'Done' };

type StatusFilter = 'open' | 'done' | 'all';
type SourceFilter = 'all' | TodayHunt['source'];

const DOT: Record<SourceTone, string> = {
  accent: 'bg-accent',
  danger: 'bg-danger',
  violet: 'bg-violet',
  warning: 'bg-warning',
  teal: 'bg-teal',
  pink: 'bg-pink',
  neutral: 'bg-fg-subtle',
};

/** Report form only knows four languages; other platforms keep the query text and name the platform in notes. */
const REPORT_LANGUAGE: Partial<Record<HuntPlatform, ReportDraft['queryLanguage']>> = {
  defender: 'KQL',
  splunk: 'SPL',
  sigma: 'Sigma',
  elastic: 'EQL',
};

const platformKey = (clientId: string) => `blindspot.ui.huntPlatform.${clientId}`;

function readPlatform(clientId: string): HuntPlatform | null {
  try {
    const v = localStorage.getItem(platformKey(clientId));
    return PLATFORMS.some((p) => p.id === v) ? (v as HuntPlatform) : null;
  } catch {
    return null;
  }
}

const matchesSearch = (h: TodayHunt, q: string) =>
  [h.hypothesisName, h.sourceReference, h.summaryAndRationale, ...h.techniques.flatMap((t) => [t.id, t.name]), ...(h.references ?? []).map((r) => r.title)]
    .join(' ')
    .toLowerCase()
    .includes(q);

export const TodaysHuntsView: React.FC = () => {
  const { currentClient, currentUser, clientHunts, addTodaysHunts, updateTodaysHunt, addHuntReference, startReport } = useApp();
  const toast = useToast();

  const clientPlatform = useMemo(() => defaultPlatformFor(currentClient), [currentClient]);
  const [platform, setPlatformState] = useState<HuntPlatform>(() => readPlatform(currentClient.id) ?? clientPlatform);
  const [selectedId, setSelectedId] = useState<string | null>(() => hashParams().get('id'));
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('open');
  const [sourceFilter, setSourceFilter] = useState<SourceFilter>('all');
  const [search, setSearch] = useState('');
  const [generating, setGenerating] = useState(false);
  const [showWeights, setShowWeights] = useState(false);
  const [weights, setWeights] = useState<ScoreWeights>(DEFAULT_HUNT_SCORE_WEIGHTS);

  const setPlatform = (p: HuntPlatform) => {
    setPlatformState(p);
    try {
      localStorage.setItem(platformKey(currentClient.id), p);
    } catch {
      // Remembering the choice is a convenience only.
    }
  };

  // Hunts matching status + search, before the source filter, so the source bar can show counts.
  const baseHunts = useMemo(() => {
    const q = search.trim().toLowerCase();
    return clientHunts.filter((h) => {
      const status = h.status ?? 'queued';
      if (statusFilter === 'open' && status === 'done') return false;
      if (statusFilter === 'done' && status !== 'done') return false;
      return !q || matchesSearch(h, q);
    });
  }, [clientHunts, statusFilter, search]);

  const sourceCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const h of baseHunts) counts.set(h.source, (counts.get(h.source) ?? 0) + 1);
    return counts;
  }, [baseHunts]);

  const hunts = useMemo(
    () =>
      baseHunts
        .filter((h) => sourceFilter === 'all' || h.source === sourceFilter)
        .map((h) => ({ hunt: h, score: computePriority(h, weights) }))
        .sort((a, b) => b.score - a.score),
    [baseHunts, sourceFilter, weights],
  );

  const active = hunts.find((h) => h.hunt.id === selectedId) ?? hunts[0];

  useEffect(() => {
    if (active && active.hunt.id !== selectedId) setSelectedId(active.hunt.id);
  }, [active, selectedId]);

  const handleGenerate = async () => {
    setGenerating(true);
    try {
      const { hunts: fresh, fallback } = await fetchAiDailyHunts(currentClient);
      if (fresh.length) {
        addTodaysHunts(fresh);
        setSelectedId(fresh[0].id);
        setStatusFilter('open');
        setSourceFilter('all');
        setSearch('');
      }
      toast(
        fallback ? `AI service unavailable — added ${fresh.length} curated hunt ideas instead.` : `Added ${fresh.length} new hunt ideas.`,
        fallback ? 'info' : 'success',
      );
    } catch {
      toast('Could not generate hunts. Check the server connection and try again.', 'error');
    } finally {
      setGenerating(false);
    }
  };

  const setStatus = (hunt: TodayHunt, status: TodayHuntStatus) => updateTodaysHunt({ ...hunt, status });

  const weightsChanged = SCORE_FACTORS.some((f) => weights[f.key] !== DEFAULT_HUNT_SCORE_WEIGHTS[f.key]);
  const filtersActive = sourceFilter !== 'all' || search.trim() !== '' || statusFilter !== 'open';

  return (
    <>
      <PageHeader
        title="What's New"
        description={`New and prioritised hunt ideas for ${currentClient.name}, with ready-to-run queries for your platform.`}
        actions={
          <>
            <Button icon={SlidersHorizontal} onClick={() => setShowWeights((v) => !v)} aria-expanded={showWeights}>
              Scoring weights
            </Button>
            <Button variant="primary" icon={Sparkles} loading={generating} onClick={handleGenerate}>
              Generate ideas
            </Button>
          </>
        }
      />

      {showWeights && (
        <Card padded className="mb-6">
          <div className="mb-4 flex items-start justify-between gap-4">
            <div>
              <CardTitle tone="violet">Priority scoring weights</CardTitle>
              <p className="mt-1 pl-3.5 text-[13px] text-fg-muted">Adjust how much each factor contributes. The queue re-sorts as you change them.</p>
            </div>
            <Button size="sm" variant="ghost" icon={RotateCcw} disabled={!weightsChanged} onClick={() => setWeights(DEFAULT_HUNT_SCORE_WEIGHTS)}>
              Reset
            </Button>
          </div>
          <div className="grid grid-cols-1 gap-x-6 gap-y-4 sm:grid-cols-2 lg:grid-cols-5">
            {SCORE_FACTORS.map((f) => (
              <label key={f.key} className="block" title={f.help}>
                <div className="mb-1.5 flex items-center justify-between text-[13px]">
                  <span className="text-fg-muted">{f.label}</span>
                  <span className="tabular-nums text-fg">{Math.round(weights[f.key] * 100)}%</span>
                </div>
                <input
                  type="range"
                  min={0}
                  max={50}
                  value={Math.round(weights[f.key] * 100)}
                  onChange={(e) => setWeights({ ...weights, [f.key]: Number(e.target.value) / 100 })}
                  className="w-full accent-[var(--color-accent)]"
                />
              </label>
            ))}
          </div>
        </Card>
      )}

      {/* Source + search */}
      <Card className="mb-6 p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <CardTitle tone="accent">What to hunt</CardTitle>
          <div className="flex flex-wrap items-center gap-2">
            <Segmented<StatusFilter>
              ariaLabel="Status"
              value={statusFilter}
              onChange={setStatusFilter}
              options={[
                { value: 'open', label: 'Open' },
                { value: 'done', label: 'Done' },
                { value: 'all', label: 'All' },
              ]}
            />
            <div className="relative w-full sm:w-64">
              <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-fg-subtle" />
              <Input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search hunts, CVEs, T-IDs, malware…"
                className="h-8 pr-8 pl-9 text-[13px]"
                aria-label="Search hunts"
              />
              {search && (
                <button
                  type="button"
                  onClick={() => setSearch('')}
                  aria-label="Clear search"
                  className="absolute inset-y-0 right-0 flex w-8 items-center justify-center text-fg-subtle hover:text-fg"
                >
                  <X className="size-3.5" />
                </button>
              )}
            </div>
          </div>
        </div>

        <div role="radiogroup" aria-label="Hunt source" className="flex flex-wrap gap-2">
          <SourceChip label="All sources" count={baseHunts.length} selected={sourceFilter === 'all'} onClick={() => setSourceFilter('all')} />
          {SOURCES.map((s) => (
            <SourceChip
              key={s.id}
              label={s.label}
              help={s.help}
              dot={DOT[s.tone]}
              count={sourceCounts.get(s.id) ?? 0}
              selected={sourceFilter === s.id}
              onClick={() => setSourceFilter(s.id)}
            />
          ))}
        </div>
      </Card>

      {hunts.length === 0 ? (
        <Card>
          <EmptyState
            icon={Crosshair}
            title={clientHunts.length ? 'No hunts match these filters' : 'No hunt ideas yet'}
            description={
              clientHunts.length
                ? sourceFilter !== 'all'
                  ? `No ${sourceDef(sourceFilter).label} hunts for ${currentClient.name} with the current filters. Generate new ideas or try another source.`
                  : 'Try a different status or search term.'
                : 'Generate a first set of hunt ideas for this client.'
            }
            action={
              <div className="flex flex-wrap justify-center gap-2">
                {filtersActive && clientHunts.length > 0 && (
                  <Button
                    onClick={() => {
                      setSourceFilter('all');
                      setSearch('');
                      setStatusFilter('open');
                    }}
                  >
                    Clear filters
                  </Button>
                )}
                <Button variant="primary" icon={Sparkles} loading={generating} onClick={handleGenerate}>
                  Generate ideas
                </Button>
              </div>
            }
          />
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          {/* Queue */}
          <Card className="self-start lg:col-span-5">
            <div className="flex items-center justify-between border-b border-border px-4 py-2.5 text-xs text-fg-subtle">
              <span>
                {hunts.length} {hunts.length === 1 ? 'hunt' : 'hunts'} · highest priority first
              </span>
              <span>Score</span>
            </div>
            <ul className="divide-y divide-border">
              {hunts.map(({ hunt, score }) => {
                const selected = active?.hunt.id === hunt.id;
                const status = hunt.status ?? 'queued';
                const src = sourceDef(hunt.source);
                const hasQuery = Boolean(queryFor(hunt, platform));
                return (
                  <li key={hunt.id}>
                    <button
                      type="button"
                      onClick={() => setSelectedId(hunt.id)}
                      aria-current={selected}
                      className={cn('relative w-full px-4 py-3.5 text-left transition-colors', selected ? 'bg-surface-2' : 'hover:bg-surface-2/60')}
                    >
                      {selected && <span className="absolute inset-y-2 left-0 w-0.5 rounded-full bg-accent" />}
                      <div className="flex items-center gap-2">
                        <Badge tone={severityTone(hunt.priority)}>{hunt.priority}</Badge>
                        <Badge tone={src.tone}>{src.label}</Badge>
                        <span className={cn('ml-auto shrink-0 text-lg font-semibold tabular-nums', scoreColor(score))} title="Priority score (0–100)">
                          {score}
                        </span>
                      </div>
                      <div className={cn('mt-1.5 line-clamp-2 text-sm', status === 'done' ? 'text-fg-muted line-through' : 'font-medium text-fg')}>
                        {hunt.hypothesisName}
                      </div>
                      <div className="mt-1.5 flex items-center gap-3 text-xs">
                        {status === 'in-progress' && <span className="text-accent-text">In progress</span>}
                        {!hasQuery && <span className="text-fg-subtle">No {platformDef(platform).language} query yet</span>}
                      </div>
                    </button>
                  </li>
                );
              })}
            </ul>
          </Card>

          {/* Detail */}
          {active && (
            <HuntDetail
              key={active.hunt.id}
              hunt={active.hunt}
              score={active.score}
              platform={platform}
              clientPlatform={clientPlatform}
              onPlatform={setPlatform}
              clientTelemetry={currentClient.primaryTelemetry}
              onStatus={setStatus}
              onAddReference={(ref) => {
                addHuntReference(active.hunt.id, { ...ref, addedBy: currentUser.name });
                toast('Reference added to this hunt.');
              }}
              onDraft={startReport}
            />
          )}
        </div>
      )}
    </>
  );
};

const scoreColor = (score: number) => (score >= 85 ? 'text-danger-text' : score >= 70 ? 'text-warning-text' : 'text-accent-text');

const SourceChip: React.FC<{ label: string; count: number; selected: boolean; onClick: () => void; dot?: string; help?: string }> = ({
  label,
  count,
  selected,
  onClick,
  dot,
  help,
}) => (
  <button
    type="button"
    role="radio"
    aria-checked={selected}
    onClick={onClick}
    title={help}
    className={cn(
      'inline-flex h-9 items-center gap-2 rounded-full border px-3.5 text-[13px] font-medium transition-colors',
      selected ? 'border-accent bg-accent-soft text-fg' : 'border-border bg-canvas text-fg-muted hover:border-border-strong hover:text-fg',
      !selected && count === 0 && 'opacity-60',
    )}
  >
    {dot && <span className={cn('size-2 rounded-full', dot)} />}
    {label}
    <span className={cn('rounded-full px-1.5 text-xs tabular-nums', selected ? 'bg-accent text-accent-fg' : 'bg-surface-3 text-fg-muted')}>{count}</span>
  </button>
);

interface HuntDetailProps {
  hunt: TodayHunt;
  score: number;
  platform: HuntPlatform;
  clientPlatform: HuntPlatform;
  onPlatform: (p: HuntPlatform) => void;
  clientTelemetry: string[];
  onStatus: (hunt: TodayHunt, status: TodayHuntStatus) => void;
  onAddReference: (ref: HuntReference) => void;
  onDraft: ReturnType<typeof useApp>['startReport'];
}

const HuntDetail: React.FC<HuntDetailProps> = ({ hunt, score, platform, clientPlatform, onPlatform, clientTelemetry, onStatus, onAddReference, onDraft }) => {
  const status = hunt.status ?? 'queued';
  const src = sourceDef(hunt.source);
  const def = platformDef(platform);
  const query = queryFor(hunt, platform);
  const available = PLATFORMS.filter((p) => queryFor(hunt, p.id));

  const draft = (): ReportDraft => ({
    hypothesisTitle: hunt.hypothesisName,
    hypothesisDescription: hunt.summaryAndRationale,
    techniqueIds: hunt.techniques.map((t) => t.id),
    dataSources: hunt.dataSourcesRequired,
    queryLanguage: query ? REPORT_LANGUAGE[platform] : hunt.suggestedQuery.language,
    queryText: query ?? hunt.suggestedQuery.code,
    notes: `Source: ${src.label} — ${hunt.sourceReference}${query ? `\nQuery platform: ${def.label} (${def.language})` : ''}`,
  });

  return (
    <Card className="lg:col-span-7">
      <div className="border-b border-border px-5 py-4">
        <div className="flex flex-wrap items-center gap-2 text-xs text-fg-subtle">
          <Badge tone={severityTone(hunt.priority)}>{hunt.priority}</Badge>
          <Badge tone={src.tone}>{src.label}</Badge>
          <span className="truncate">{hunt.sourceReference}</span>
        </div>
        <h2 className="mt-2 text-lg font-semibold leading-snug text-fg">{hunt.hypothesisName}</h2>
        <div className="mt-4 flex flex-wrap items-center gap-2">
          <Segmented<TodayHuntStatus>
            ariaLabel="Hunt status"
            value={status}
            onChange={(s) => onStatus(hunt, s)}
            options={(Object.keys(STATUS_LABEL) as TodayHuntStatus[]).map((s) => ({ value: s, label: STATUS_LABEL[s] }))}
          />
          <Button variant="primary" size="sm" iconRight={ArrowRight} className="ml-auto" onClick={() => onDraft(draft())}>
            Start report
          </Button>
        </div>
      </div>

      <div className="space-y-7 px-5 py-5">
        <section>
          <SectionLabel>Why this hunt</SectionLabel>
          <p className="text-sm leading-relaxed text-fg-muted">{hunt.summaryAndRationale}</p>
        </section>

        <section>
          <div className="mb-2 flex flex-wrap items-baseline justify-between gap-2">
            <SectionLabel className="mb-0">Hunt query</SectionLabel>
            <span className="flex items-center gap-1.5 text-xs text-fg-subtle">
              <span className="size-1.5 rounded-full bg-success" /> Client's platform
            </span>
          </div>
          <div className="mb-2 flex flex-wrap gap-1 rounded-lg border border-border bg-canvas p-1" role="tablist" aria-label="Query platform">
            {PLATFORMS.map((p) => {
              const has = Boolean(queryFor(hunt, p.id));
              const selected = p.id === platform;
              return (
                <button
                  key={p.id}
                  type="button"
                  role="tab"
                  aria-selected={selected}
                  onClick={() => onPlatform(p.id)}
                  className={cn(
                    'inline-flex h-8 items-center gap-1.5 rounded-md px-2.5 text-xs font-medium transition-colors',
                    selected ? 'bg-accent-soft text-fg ring-1 ring-accent/50' : 'text-fg-muted hover:bg-surface-2 hover:text-fg',
                    !has && !selected && 'opacity-50',
                  )}
                  title={has ? undefined : `No ${p.language} query for this hunt yet`}
                >
                  {p.id === clientPlatform && <span className="size-1.5 rounded-full bg-success" />}
                  {p.label.replace('Microsoft ', '').replace(' Vision One', '').replace(' Falcon', '')}
                  <span className={cn('text-[11px]', selected ? 'text-accent-text' : 'text-fg-subtle')}>{p.language.replace('Vision One search', 'V1').replace('Sigma YAML', 'YAML')}</span>
                </button>
              );
            })}
          </div>
          {query ? (
            <CodeBlock code={query} label={`${def.label} · ${def.language}`} maxHeight="max-h-96" />
          ) : (
            <div className="rounded-md border border-dashed border-border px-4 py-5 text-center">
              <p className="text-sm text-fg">No {def.label} query for this hunt yet.</p>
              <p className="mt-1 text-[13px] text-fg-muted">
                {available.length
                  ? `Available for: ${available.map((p) => p.label).join(', ')}. The Sigma rule can be converted with sigma-cli / pySigma.`
                  : 'No platform queries are available for this hunt.'}
              </p>
            </div>
          )}
        </section>

        <References hunt={hunt} onAdd={onAddReference} />

        <section>
          <SectionLabel>Techniques</SectionLabel>
          <div className="flex flex-wrap gap-1.5">
            {hunt.techniques.map((t) => (
              <Badge key={t.id} tone="neutral" title={t.tactic}>
                <span className="font-mono">{t.id}</span> {t.name}
              </Badge>
            ))}
          </div>
        </section>

        <section>
          <SectionLabel>Required telemetry</SectionLabel>
          <ul className="space-y-1.5">
            {hunt.dataSourcesRequired.map((ds) => {
              const ok = hasTelemetry(clientTelemetry, ds);
              return (
                <li key={ds} className="flex items-center justify-between gap-3 text-[13px]">
                  <span className="text-fg-muted">{ds}</span>
                  <Badge tone={ok ? 'success' : 'warning'}>{ok ? 'Onboarded' : 'Not onboarded'}</Badge>
                </li>
              );
            })}
          </ul>
        </section>

        <section className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div>
            <SectionLabel>Expected baseline</SectionLabel>
            <p className="text-[13px] leading-relaxed text-fg-muted">{hunt.expectedBaseline}</p>
          </div>
          <div>
            <SectionLabel>What a true positive looks like</SectionLabel>
            <p className="break-words font-mono text-[12.5px] leading-relaxed text-fg-muted">{hunt.truePositiveExample}</p>
          </div>
        </section>

        <section>
          <SectionLabel>
            Priority score · <span className={cn('text-sm font-semibold', scoreColor(score))}>{score}</span>
          </SectionLabel>
          <div className="grid grid-cols-1 gap-x-6 gap-y-2.5 sm:grid-cols-2">
            {SCORE_FACTORS.map((f) => (
              <div key={f.key} title={f.help}>
                <div className="mb-1 flex justify-between text-[13px]">
                  <span className="text-fg-muted">{f.label}</span>
                  <span className="tabular-nums text-fg-subtle">{hunt.aiHuntScore[f.key]}</span>
                </div>
                <Meter value={hunt.aiHuntScore[f.key]} />
              </div>
            ))}
          </div>
        </section>
      </div>
    </Card>
  );
};

const hostOf = (url: string) => {
  try {
    return new URL(url).hostname.replace(/^www\./, '');
  } catch {
    return url;
  }
};

const References: React.FC<{ hunt: TodayHunt; onAdd: (ref: HuntReference) => void }> = ({ hunt, onAdd }) => {
  const refs = hunt.references ?? [];
  const [adding, setAdding] = useState(false);
  const [title, setTitle] = useState('');
  const [url, setUrl] = useState('');
  const [error, setError] = useState<string | null>(null);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    let parsed: URL;
    try {
      parsed = new URL(url.trim());
    } catch {
      setError('Enter a full link, starting with https://');
      return;
    }
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      setError('Only web links (https://) can be added.');
      return;
    }
    if (refs.some((r) => r.url === parsed.href)) {
      setError('This link is already listed.');
      return;
    }
    onAdd({ title: title.trim() || parsed.hostname, url: parsed.href, publisher: parsed.hostname.replace(/^www\./, '') });
    setTitle('');
    setUrl('');
    setError(null);
    setAdding(false);
  };

  return (
    <section>
      <div className="mb-2 flex items-center justify-between gap-3">
        <h3 className="text-xs font-medium uppercase tracking-wide text-fg-subtle">Reference reading</h3>
        {!adding && (
          <Button size="sm" variant="ghost" icon={Plus} onClick={() => setAdding(true)}>
            Add link
          </Button>
        )}
      </div>

      {refs.length === 0 && !adding ? (
        <p className="text-[13px] text-fg-subtle">No reference blogs for this hunt yet. Add one to help the next hunter.</p>
      ) : (
        <ul className="divide-y divide-border overflow-hidden rounded-md border border-border">
          {refs.map((r) => (
            <li key={r.url}>
              <a
                href={r.url}
                target="_blank"
                rel="noopener noreferrer"
                className="group flex items-start gap-3 px-3 py-2.5 transition-colors hover:bg-surface-2"
              >
                <BookOpen className="mt-0.5 size-4 shrink-0 text-fg-subtle" />
                <div className="min-w-0 flex-1">
                  <div className="text-[13px] font-medium text-fg group-hover:text-accent-text">{r.title}</div>
                  <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-fg-subtle">
                    <span>{r.publisher || hostOf(r.url)}</span>
                    {r.addedBy && <span>· added by {r.addedBy}</span>}
                    {r.unverified && (
                      <Badge tone="warning" title="Suggested by the AI generator. Check the link before relying on it.">
                        AI-suggested · unverified
                      </Badge>
                    )}
                  </div>
                </div>
                <ExternalLink className="mt-0.5 size-3.5 shrink-0 text-fg-subtle group-hover:text-fg" aria-label="Opens in a new tab" />
              </a>
            </li>
          ))}
        </ul>
      )}

      {adding && (
        <form onSubmit={submit} className="mt-3 space-y-2 rounded-md border border-border bg-canvas p-3">
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            <Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Title (optional)" aria-label="Reference title" className="h-8 text-[13px]" />
            <Input
              value={url}
              onChange={(e) => {
                setUrl(e.target.value);
                setError(null);
              }}
              placeholder="https://…"
              aria-label="Reference link"
              className="h-8 text-[13px]"
              autoFocus
            />
          </div>
          {error && <p className="text-xs text-danger-text">{error}</p>}
          <div className="flex justify-end gap-2">
            <Button
              size="sm"
              variant="ghost"
              onClick={() => {
                setAdding(false);
                setError(null);
              }}
            >
              Cancel
            </Button>
            <Button size="sm" variant="primary" type="submit" disabled={!url.trim()}>
              Add reference
            </Button>
          </div>
        </form>
      )}
    </section>
  );
};
