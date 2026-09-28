import React, { useEffect, useMemo, useState } from 'react';
import { FileText, Lightbulb, Plus, Search } from 'lucide-react';
import type { HuntOutcome, ReportDraft } from '../types';
import { useApp } from '../app/AppContext';
import { hashParams } from '../lib/useHashRoute';
import { formatDate } from '../lib/coverage';
import { HUNTS_PER_PHASE, phaseCounts } from '../lib/phases';
import { cn } from '../lib/cn';
import { Badge, Button, Card, EmptyState, Input, PageHeader, Select, outcomeTone, severityTone } from './ui';
import { ReportForm } from './reports/ReportForm';
import { ReportDetail } from './reports/ReportDetail';
import { NextHuntsModal } from './reports/NextHuntsModal';

const OUTCOMES: HuntOutcome[] = ['True Positive', 'Needs Follow-up', 'False Positive', 'No Result'];

export const ReportsView: React.FC = () => {
  const { clientReports, currentClient, peekReportDraft, clearReportDraft, openThr, navigate } = useApp();

  // A pending draft (from another page) opens the form immediately.
  const [draft, setDraft] = useState<ReportDraft | null>(() => peekReportDraft());
  const [selectedId, setSelectedId] = useState<string | null>(() => hashParams().get('id'));
  const [search, setSearch] = useState('');
  const [outcome, setOutcome] = useState<'all' | HuntOutcome>('all');
  const [phase, setPhase] = useState<'all' | 'none' | number>('all');
  const counts = useMemo(() => phaseCounts(clientReports), [clientReports]);
  const phases = [...counts.keys()].sort((a, b) => a - b);
  const unphased = clientReports.filter((r) => !r.phase).length;
  const [suggestOpen, setSuggestOpen] = useState(false);
  // Remounts the form when a new draft arrives while it is already open.
  const [draftVersion, setDraftVersion] = useState(0);

  useEffect(() => clearReportDraft(), [clearReportDraft]);

  useEffect(() => {
    const onDraft = () => {
      setDraft(peekReportDraft());
      setDraftVersion((v) => v + 1);
      clearReportDraft();
    };
    const onHash = () => {
      const id = hashParams().get('id');
      if (id) {
        setSelectedId(id);
        setDraft(null);
      }
    };
    window.addEventListener('blindspot:report-draft', onDraft);
    window.addEventListener('hashchange', onHash);
    return () => {
      window.removeEventListener('blindspot:report-draft', onDraft);
      window.removeEventListener('hashchange', onHash);
    };
  }, [peekReportDraft, clearReportDraft]);

  const reports = useMemo(() => {
    const q = search.trim().toLowerCase();
    return clientReports
      .filter((r) => outcome === 'all' || r.outcome === outcome)
      .filter((r) => phase === 'all' || (phase === 'none' ? !r.phase : r.phase === phase))
      .filter(
        (r) =>
          !q ||
          [r.hypothesisTitle, r.hypothesisDescription, r.notes, r.analystName, ...r.techniqueIds, ...r.iocs.map((i) => i.value)]
            .join(' ')
            .toLowerCase()
            .includes(q),
      )
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }, [clientReports, search, outcome, phase]);

  const selected = reports.find((r) => r.id === selectedId) ?? reports[0];

  if (draft) {
    return (
      <ReportForm
        key={draftVersion}
        draft={draft}
        onCancel={() => setDraft(null)}
        onSaved={(r) => {
          setDraft(null);
          setSelectedId(r.id);
          navigate('reports', { id: r.id });
        }}
      />
    );
  }

  return (
    <>
      <PageHeader
        title="Hypothesis Record"
        description={`Searchable record of every hunt run for ${currentClient.name}.`}
        actions={
          <>
            <Button icon={Lightbulb} onClick={() => setSuggestOpen(true)}>
              Suggest next hunts
            </Button>
            <Button icon={FileText} onClick={openThr}>
              Create THR
            </Button>
            <Button variant="primary" icon={Plus} onClick={() => setDraft({ hypothesisTitle: '', techniqueIds: [] })}>
              New record
            </Button>
          </>
        }
      />

      {/* Phase progress: 10 hunts per phase */}
      {(phases.length > 0 || unphased > 0) && (
        <div className="mb-4 flex flex-wrap gap-2" role="radiogroup" aria-label="Phase">
          {phases.map((p) => {
            const n = counts.get(p) ?? 0;
            const selected = phase === p;
            return (
              <button
                key={p}
                type="button"
                role="radio"
                aria-checked={selected}
                onClick={() => setPhase(selected ? 'all' : p)}
                className={cn(
                  'min-w-36 rounded-lg border px-3 py-2 text-left transition-colors',
                  selected ? 'border-accent bg-accent-soft' : 'border-border bg-surface hover:border-border-strong',
                )}
              >
                <div className="flex items-baseline justify-between gap-3">
                  <span className="text-[13px] font-semibold text-fg">Phase {p}</span>
                  <span className={cn('text-sm font-bold tabular-nums', n >= HUNTS_PER_PHASE ? 'text-success-text' : 'text-accent-text')}>
                    {n}/{HUNTS_PER_PHASE}
                  </span>
                </div>
                <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-surface-3">
                  <div className={cn('h-full rounded-full', n >= HUNTS_PER_PHASE ? 'bg-success' : 'bg-accent')} style={{ width: `${Math.min(100, (n / HUNTS_PER_PHASE) * 100)}%` }} />
                </div>
              </button>
            );
          })}
          {unphased > 0 && (
            <button
              type="button"
              role="radio"
              aria-checked={phase === 'none'}
              onClick={() => setPhase(phase === 'none' ? 'all' : 'none')}
              title="Records saved before phases were tracked. Open one to assign a phase."
              className={cn(
                'rounded-lg border border-dashed px-3 py-2 text-left text-[13px] transition-colors',
                phase === 'none' ? 'border-accent bg-accent-soft text-fg' : 'border-border text-fg-muted hover:text-fg',
              )}
            >
              <div className="font-semibold">No phase</div>
              <div className="mt-0.5 text-xs">{unphased} record{unphased === 1 ? '' : 's'}</div>
            </button>
          )}
        </div>
      )}

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="relative w-full sm:w-80">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-fg-subtle" />
          <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search title, technique, IOC…" className="h-8 pl-8 text-[13px]" aria-label="Search reports" />
        </div>
        <Select value={outcome} onChange={(e) => setOutcome(e.target.value as 'all' | HuntOutcome)} className="h-8 w-auto text-[13px]" aria-label="Outcome">
          <option value="all">All outcomes</option>
          {OUTCOMES.map((o) => (
            <option key={o}>{o}</option>
          ))}
        </Select>
        <Select
          value={String(phase)}
          onChange={(e) => setPhase(e.target.value === 'all' || e.target.value === 'none' ? e.target.value : Number(e.target.value))}
          className="h-8 w-auto text-[13px]"
          aria-label="Phase"
        >
          <option value="all">All phases</option>
          {phases.map((p) => (
            <option key={p} value={p}>
              Phase {p}
            </option>
          ))}
          {unphased > 0 && <option value="none">No phase</option>}
        </Select>
        <span className="ml-auto text-[13px] text-fg-subtle">
          {reports.length} of {clientReports.length}
        </span>
      </div>

      {reports.length === 0 ? (
        <Card>
          <EmptyState
            icon={FileText}
            title={clientReports.length ? 'No records match' : 'No hypothesis records yet'}
            description={clientReports.length ? 'Try a different search or outcome.' : 'Log the first hunt for this client.'}
            action={
              !clientReports.length && (
                <Button variant="primary" icon={Plus} onClick={() => setDraft({ hypothesisTitle: '', techniqueIds: [] })}>
                  New record
                </Button>
              )
            }
          />
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          <Card className="self-start lg:col-span-5">
            <ul className="divide-y divide-border">
              {reports.map((r) => {
                const active = selected?.id === r.id;
                return (
                  <li key={r.id}>
                    <button
                      type="button"
                      onClick={() => setSelectedId(r.id)}
                      aria-current={active}
                      className={cn('relative w-full px-4 py-3.5 text-left transition-colors', active ? 'bg-surface-2' : 'hover:bg-surface-2/60')}
                    >
                      {active && <span className="absolute inset-y-2 left-0 w-0.5 rounded-full bg-accent" />}
                      <div className="line-clamp-2 text-sm font-medium text-fg">{r.hypothesisTitle}</div>
                      <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                        {r.phase && <Badge tone="violet">Phase {r.phase}</Badge>}
                        <Badge tone={outcomeTone(r.outcome)}>{r.outcome}</Badge>
                        {r.severityScore && <Badge tone={severityTone(r.severityScore.severityLevel)}>{r.severityScore.severityLevel}</Badge>}
                        <span className="text-xs text-fg-subtle">
                          {r.analystName} · {formatDate(r.createdAt)}
                        </span>
                      </div>
                    </button>
                  </li>
                );
              })}
            </ul>
          </Card>
          <div className="lg:col-span-7">{selected && <ReportDetail report={selected} />}</div>
        </div>
      )}

      {suggestOpen && <NextHuntsModal onClose={() => setSuggestOpen(false)} />}
    </>
  );
};
