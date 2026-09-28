import React, { useEffect, useMemo, useState } from 'react';
import { ArrowRight, Crosshair, RotateCcw, SlidersHorizontal, Sparkles } from 'lucide-react';
import type { TodayHunt, TodayHuntStatus } from '../types';
import { useApp } from '../app/AppContext';
import { fetchAiDailyHunts } from '../services/api';
import { hashParams } from '../lib/useHashRoute';
import { hasTelemetry } from '../lib/coverage';
import { computePriority, SCORE_FACTORS } from '../lib/huntPriority';
import { DEFAULT_HUNT_SCORE_WEIGHTS, type ScoreWeights } from '../utils/huntScoreCalculator';
import { cn } from '../lib/cn';
import {
  Badge,
  Button,
  Card,
  CodeBlock,
  EmptyState,
  Meter,
  PageHeader,
  SectionLabel,
  Segmented,
  Select,
  severityTone,
  useToast,
} from './ui';

const STATUS_LABEL: Record<TodayHuntStatus, string> = { queued: 'Queued', 'in-progress': 'In progress', done: 'Done' };

type StatusFilter = 'open' | 'done' | 'all';

export const TodaysHuntsView: React.FC = () => {
  const { currentClient, clientHunts, addTodaysHunts, updateTodaysHunt, startReport } = useApp();
  const toast = useToast();

  const [selectedId, setSelectedId] = useState<string | null>(() => hashParams().get('id'));
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('open');
  const [sourceFilter, setSourceFilter] = useState('all');
  const [generating, setGenerating] = useState(false);
  const [showWeights, setShowWeights] = useState(false);
  const [weights, setWeights] = useState<ScoreWeights>(DEFAULT_HUNT_SCORE_WEIGHTS);

  const sources = useMemo(() => Array.from(new Set(clientHunts.map((h) => h.source))), [clientHunts]);

  const hunts = useMemo(
    () =>
      clientHunts
        .filter((h) => {
          const status = h.status ?? 'queued';
          if (statusFilter === 'open' && status === 'done') return false;
          if (statusFilter === 'done' && status !== 'done') return false;
          if (sourceFilter !== 'all' && h.source !== sourceFilter) return false;
          return true;
        })
        .map((h) => ({ hunt: h, score: computePriority(h, weights) }))
        .sort((a, b) => b.score - a.score),
    [clientHunts, statusFilter, sourceFilter, weights],
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
      }
      toast(
        fallback
          ? `AI service unavailable — added ${fresh.length} curated hunt ideas instead.`
          : `Added ${fresh.length} new hunt ideas.`,
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

  return (
    <>
      <PageHeader
        title="Today's hunts"
        description={`Prioritised hunt ideas for ${currentClient.name}, drawn from CVEs, active campaigns and coverage gaps.`}
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
              <h2 className="text-sm font-semibold text-fg">Priority scoring weights</h2>
              <p className="mt-0.5 text-[13px] text-fg-muted">Adjust how much each factor contributes. The queue re-sorts as you change them.</p>
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

      <div className="mb-4 flex flex-wrap items-center gap-3">
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
        <Select value={sourceFilter} onChange={(e) => setSourceFilter(e.target.value)} className="h-8 w-auto text-[13px]" aria-label="Source">
          <option value="all">All sources</option>
          {sources.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </Select>
        <span className="ml-auto text-[13px] text-fg-subtle">
          {hunts.length} {hunts.length === 1 ? 'hunt' : 'hunts'}
        </span>
      </div>

      {hunts.length === 0 ? (
        <Card>
          <EmptyState
            icon={Crosshair}
            title={clientHunts.length ? 'No hunts match these filters' : 'No hunt ideas yet'}
            description={clientHunts.length ? 'Try a different status or source.' : 'Generate a first set of hunt ideas for this client.'}
            action={
              !clientHunts.length && (
                <Button variant="primary" icon={Sparkles} loading={generating} onClick={handleGenerate}>
                  Generate ideas
                </Button>
              )
            }
          />
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          {/* Queue */}
          <Card className="self-start lg:col-span-5">
            <ul className="divide-y divide-border">
              {hunts.map(({ hunt, score }) => {
                const selected = active?.hunt.id === hunt.id;
                const status = hunt.status ?? 'queued';
                return (
                  <li key={hunt.id}>
                    <button
                      type="button"
                      onClick={() => setSelectedId(hunt.id)}
                      aria-current={selected}
                      className={cn(
                        'relative w-full px-4 py-3.5 text-left transition-colors',
                        selected ? 'bg-surface-2' : 'hover:bg-surface-2/60',
                      )}
                    >
                      {selected && <span className="absolute inset-y-2 left-0 w-0.5 rounded-full bg-accent" />}
                      <div className="flex items-center gap-2">
                        <Badge tone={severityTone(hunt.priority)}>{hunt.priority}</Badge>
                        <span className="truncate text-xs text-fg-subtle">{hunt.source}</span>
                        <span className="ml-auto shrink-0 text-xs tabular-nums text-fg-muted" title="Priority score">
                          {score}
                        </span>
                      </div>
                      <div className={cn('mt-1.5 line-clamp-2 text-sm', status === 'done' ? 'text-fg-muted line-through' : 'font-medium text-fg')}>
                        {hunt.hypothesisName}
                      </div>
                      {status === 'in-progress' && <div className="mt-1.5 text-xs text-accent-text">In progress</div>}
                    </button>
                  </li>
                );
              })}
            </ul>
          </Card>

          {/* Detail */}
          {active && <HuntDetail hunt={active.hunt} score={active.score} onStatus={setStatus} onDraft={startReport} clientTelemetry={currentClient.primaryTelemetry} />}
        </div>
      )}
    </>
  );
};

interface HuntDetailProps {
  hunt: TodayHunt;
  score: number;
  clientTelemetry: string[];
  onStatus: (hunt: TodayHunt, status: TodayHuntStatus) => void;
  onDraft: ReturnType<typeof useApp>['startReport'];
}

const HuntDetail: React.FC<HuntDetailProps> = ({ hunt, score, clientTelemetry, onStatus, onDraft }) => {
  const status = hunt.status ?? 'queued';

  return (
    <Card className="lg:col-span-7">
      <div className="border-b border-border px-5 py-4">
        <div className="flex flex-wrap items-center gap-2 text-xs text-fg-subtle">
          <Badge tone={severityTone(hunt.priority)}>{hunt.priority}</Badge>
          <span>{hunt.source}</span>
          <span>·</span>
          <span className="truncate">{hunt.sourceReference}</span>
        </div>
        <h2 className="mt-2 text-base font-semibold leading-snug text-fg">{hunt.hypothesisName}</h2>
        <div className="mt-4 flex flex-wrap items-center gap-2">
          <Segmented<TodayHuntStatus>
            ariaLabel="Hunt status"
            value={status}
            onChange={(s) => onStatus(hunt, s)}
            options={(Object.keys(STATUS_LABEL) as TodayHuntStatus[]).map((s) => ({ value: s, label: STATUS_LABEL[s] }))}
          />
          <Button
            variant="primary"
            size="sm"
            iconRight={ArrowRight}
            className="ml-auto"
            onClick={() =>
              onDraft({
                hypothesisTitle: hunt.hypothesisName,
                hypothesisDescription: hunt.summaryAndRationale,
                techniqueIds: hunt.techniques.map((t) => t.id),
                dataSources: hunt.dataSourcesRequired,
                queryLanguage: hunt.suggestedQuery.language,
                queryText: hunt.suggestedQuery.code,
                notes: `Source: ${hunt.source} — ${hunt.sourceReference}`,
              })
            }
          >
            Start report
          </Button>
        </div>
      </div>

      <div className="space-y-6 px-5 py-5">
        <section>
          <SectionLabel>Why this hunt</SectionLabel>
          <p className="text-sm leading-relaxed text-fg-muted">{hunt.summaryAndRationale}</p>
        </section>

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
          <SectionLabel>Priority score · {score}</SectionLabel>
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

        <section>
          <SectionLabel>Suggested query</SectionLabel>
          <CodeBlock code={hunt.suggestedQuery.code} label={hunt.suggestedQuery.language} />
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
      </div>
    </Card>
  );
};
