import React, { useEffect, useMemo, useState } from 'react';
import { FileText, Lightbulb, Plus, Search } from 'lucide-react';
import type { HuntOutcome, ReportDraft } from '../types';
import { useApp } from '../app/AppContext';
import { hashParams } from '../lib/useHashRoute';
import { formatDate } from '../lib/coverage';
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
      .filter(
        (r) =>
          !q ||
          [r.hypothesisTitle, r.hypothesisDescription, r.notes, r.analystName, ...r.techniqueIds, ...r.iocs.map((i) => i.value)]
            .join(' ')
            .toLowerCase()
            .includes(q),
      )
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }, [clientReports, search, outcome]);

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
        title="Hunt reports"
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
              New report
            </Button>
          </>
        }
      />

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
        <span className="ml-auto text-[13px] text-fg-subtle">
          {reports.length} of {clientReports.length}
        </span>
      </div>

      {reports.length === 0 ? (
        <Card>
          <EmptyState
            icon={FileText}
            title={clientReports.length ? 'No reports match' : 'No hunt reports yet'}
            description={clientReports.length ? 'Try a different search or outcome.' : 'Log the first hunt for this client.'}
            action={
              !clientReports.length && (
                <Button variant="primary" icon={Plus} onClick={() => setDraft({ hypothesisTitle: '', techniqueIds: [] })}>
                  New report
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
