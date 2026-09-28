import React, { useMemo, useRef, useState } from 'react';
import { AlertTriangle, ChevronDown, ChevronRight, Download, FileSpreadsheet, Layers, ScanSearch, Search, Siren, Upload, X } from 'lucide-react';
import type { IocHunt } from '../types';
import { useApp } from '../app/AppContext';
import { downloadIocTemplate, FIELD_LABEL, hasResults, isEscalated, parseIocWorkbook, summarise } from '../lib/iocHunts';
import { cn } from '../lib/cn';
import { Badge, Button, Card, CardHeader, CardTitle, CodeBlock, EmptyState, Input, PageHeader, Stat, useToast, type Tone } from './ui';

/** Fixed tone per known category so a category keeps its color across pages and filters. */
const CATEGORY_TONE: Record<string, Tone> = {
  Malware: 'warning',
  Stealer: 'pink',
  Ransomware: 'danger',
  CVE: 'accent',
  ClickFix: 'teal',
  APT: 'violet',
};
const categoryTone = (c: string): Tone => CATEGORY_TONE[c] ?? 'neutral';

interface ImportNotice {
  fileName: string;
  sheetName: string;
  added: number;
  duplicates: number;
  skippedRows: number;
  missingColumns: string[];
}

const PAGE = 30;

export const IocHuntingView: React.FC = () => {
  const { currentClient, clientIocHunts, importIocHunts, removeDemoIocHunts } = useApp();
  const toast = useToast();
  const fileRef = useRef<HTMLInputElement>(null);

  const [uploading, setUploading] = useState(false);
  const [notice, setNotice] = useState<ImportNotice | null>(null);
  const [category, setCategory] = useState<string>('all');
  const [search, setSearch] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);
  const [limit, setLimit] = useState(PAGE);

  const summary = useMemo(() => summarise(clientIocHunts), [clientIocHunts]);
  const demoCount = clientIocHunts.filter((h) => h.origin === 'demo').length;

  const rows = useMemo(() => {
    const q = search.trim().toLowerCase();
    return clientIocHunts
      .filter((h) => category === 'all' || h.category === category)
      .filter((h) => !q || [h.number, h.title, h.description, h.results, h.escalation, h.queries].join(' ').toLowerCase().includes(q))
      .sort((a, b) => (b.date ?? '').localeCompare(a.date ?? '') || b.importedAt.localeCompare(a.importedAt));
  }, [clientIocHunts, category, search]);

  const handleFile = async (file: File) => {
    setUploading(true);
    try {
      const parsed = await parseIocWorkbook(file);
      if (!parsed.rows.length) {
        toast(`No hunt rows found in "${parsed.sheetName}".`, 'error');
        return;
      }
      const result = importIocHunts(parsed.rows);
      setNotice({
        fileName: file.name,
        sheetName: parsed.sheetName,
        added: result.added,
        duplicates: result.duplicates,
        skippedRows: parsed.skippedRows,
        missingColumns: parsed.missingColumns.map((c) => FIELD_LABEL[c]),
      });
      setCategory('all');
      setSearch('');
      toast(result.added ? `Added ${result.added} new IOC hunts.` : 'No new rows — everything in this sheet is already recorded.', result.added ? 'success' : 'info');
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Could not read this file.', 'error');
    } finally {
      setUploading(false);
      if (fileRef.current) fileRef.current.value = '';
    }
  };

  const pct = (n: number) => (summary.total ? `${Math.round((n / summary.total) * 100)}% of hunts` : 'No hunts yet');

  return (
    <>
      <PageHeader
        title="Daily IOC Hunting"
        description={`Threat intel IOC sweeps and CVE exposure checks performed for ${currentClient.name}.`}
        actions={
          <>
            <Button variant="ghost" icon={Download} onClick={() => downloadIocTemplate()}>
              Template
            </Button>
            <Button variant="primary" icon={Upload} loading={uploading} onClick={() => fileRef.current?.click()}>
              Upload latest sheet
            </Button>
            <input
              ref={fileRef}
              type="file"
              accept=".xlsx,.xls,.xlsm,.csv"
              className="hidden"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) handleFile(f);
              }}
            />
          </>
        }
      />

      {notice && (
        <div role="status" className="mb-4 flex items-start gap-3 rounded-lg border border-border bg-surface px-4 py-3 text-[13px]">
          <FileSpreadsheet className="mt-0.5 size-4 shrink-0 text-success" />
          <div className="min-w-0 flex-1 text-fg-muted">
            <span className="font-medium text-fg">{notice.fileName}</span> (sheet “{notice.sheetName}”):{' '}
            <span className="font-semibold text-success-text">{notice.added} new</span>, {notice.duplicates} duplicate{notice.duplicates === 1 ? '' : 's'} skipped
            {notice.skippedRows > 0 && `, ${notice.skippedRows} row${notice.skippedRows === 1 ? '' : 's'} without a title ignored`}.
            {notice.missingColumns.length > 0 && <div className="mt-1 text-xs text-fg-subtle">Columns not in this sheet (left blank): {notice.missingColumns.join(', ')}.</div>}
          </div>
          <button type="button" onClick={() => setNotice(null)} aria-label="Dismiss" className="text-fg-subtle hover:text-fg">
            <X className="size-4" />
          </button>
        </div>
      )}

      {demoCount > 0 && (
        <div className="mb-4 flex flex-wrap items-center gap-3 rounded-lg border border-dashed border-warning/40 bg-warning-soft px-4 py-2.5 text-[13px] text-warning-text">
          <AlertTriangle className="size-4 shrink-0" />
          <span className="flex-1">
            {demoCount} of these rows are demo data. Upload your IOC hunting sheet to add real hunts.
          </span>
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              if (window.confirm(`Remove ${demoCount} demo rows for ${currentClient.name}?`)) removeDemoIocHunts();
            }}
          >
            Remove demo rows
          </Button>
        </div>
      )}

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Threat intel IOC hunts" value={summary.total} tone="accent" icon={ScanSearch} detail={`${summary.categories.length} categories`} />
        <Stat label="Hunts with results" value={summary.withResults} tone="warning" icon={AlertTriangle} detail={pct(summary.withResults)} />
        <Stat label="Escalated" value={summary.escalated} tone="danger" icon={Siren} detail="Task / ServiceNow ID raised" />
        <Stat label="Total queries run" value={summary.totalQueries.toLocaleString()} tone="teal" icon={Layers} detail={summary.total ? `≈${(summary.totalQueries / summary.total).toFixed(1)} per hunt` : '—'} />
      </div>

      <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-5">
        {/* Category weightage */}
        <Card className="lg:col-span-3">
          <CardHeader tone="accent" title="Category weightage" description="Share of IOC hunts per threat category. Click a category to filter the log." />
          {summary.categories.length === 0 ? (
            <EmptyState icon={Layers} title="No categories yet" description="Upload a sheet to see the split." />
          ) : (
            <ul className="space-y-1 px-3 py-3">
              {summary.categories.map((c) => {
                const selected = category === c.name;
                return (
                  <li key={c.name}>
                    <button
                      type="button"
                      onClick={() => setCategory(selected ? 'all' : c.name)}
                      aria-pressed={selected}
                      title={`${c.name}: ${c.count} of ${summary.total} hunts (${c.percent}%)`}
                      className={cn('grid w-full grid-cols-[7rem_1fr_4.5rem] items-center gap-3 rounded-md px-2 py-2 text-left transition-colors', selected ? 'bg-surface-3' : 'hover:bg-surface-2')}
                    >
                      <span className="truncate text-[13px] font-medium text-fg">{c.name}</span>
                      <span className="h-2.5 overflow-hidden rounded-full bg-surface-3">
                        <span className="block h-full rounded-full bg-accent" style={{ width: `${c.percent}%` }} />
                      </span>
                      <span className="text-right text-[13px] tabular-nums">
                        <span className="font-semibold text-fg">{c.percent}%</span> <span className="text-fg-subtle">({c.count})</span>
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </Card>

        {/* Escalations */}
        <Card className="lg:col-span-2">
          <CardHeader tone="danger" title="Escalations" description="Hunts that raised a task or ServiceNow ticket." />
          {summary.escalated === 0 ? (
            <EmptyState icon={Siren} title="Nothing escalated" description="No rows carry an escalation ID." />
          ) : (
            <ul className="max-h-80 divide-y divide-border overflow-y-auto">
              {clientIocHunts
                .filter(isEscalated)
                .sort((a, b) => (b.date ?? '').localeCompare(a.date ?? ''))
                .map((h) => (
                  <li key={h.id} className="px-5 py-3">
                    <div className="flex items-center justify-between gap-2">
                      <Badge tone="danger" mono>
                        {h.escalation}
                      </Badge>
                      <span className="text-xs text-fg-subtle">{h.date}</span>
                    </div>
                    <div className="mt-1.5 line-clamp-2 text-[13px] font-medium text-fg">{h.title}</div>
                    <div className="mt-0.5 text-xs text-fg-muted">{h.results}</div>
                  </li>
                ))}
            </ul>
          )}
        </Card>
      </div>

      {/* Hunt log */}
      <Card className="mt-6">
        <div className="flex flex-col gap-3 border-b border-border px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <CardTitle tone="teal">IOC hunt log</CardTitle>
            <p className="mt-1 pl-3.5 text-[13px] text-fg-muted">
              {rows.length} {rows.length === 1 ? 'hunt' : 'hunts'}
              {category !== 'all' && ` in ${category}`}
            </p>
          </div>
          <div className="relative w-full sm:w-72">
            <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-fg-subtle" />
            <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search title, ticket, query…" className="h-8 pl-9 text-[13px]" aria-label="Search IOC hunts" />
          </div>
        </div>

        <div className="flex flex-wrap gap-2 border-b border-border px-5 py-3" role="radiogroup" aria-label="Threat category">
          {[{ name: 'all', count: summary.total }, ...summary.categories].map((c) => {
            const selected = category === c.name;
            return (
              <button
                key={c.name}
                type="button"
                role="radio"
                aria-checked={selected}
                onClick={() => setCategory(c.name)}
                className={cn(
                  'inline-flex h-8 items-center gap-2 rounded-full border px-3 text-[13px] font-medium transition-colors',
                  selected ? 'border-accent bg-accent-soft text-fg' : 'border-border bg-canvas text-fg-muted hover:text-fg',
                )}
              >
                {c.name === 'all' ? 'All categories' : c.name}
                <span className={cn('rounded-full px-1.5 text-xs tabular-nums', selected ? 'bg-accent text-accent-fg' : 'bg-surface-3')}>{c.count}</span>
              </button>
            );
          })}
        </div>

        {rows.length === 0 ? (
          <EmptyState
            icon={ScanSearch}
            title={clientIocHunts.length ? 'No hunts match' : 'No IOC hunts yet'}
            description={clientIocHunts.length ? 'Try another category or search.' : 'Upload your daily IOC hunting sheet to get started.'}
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[860px] text-left text-[13px]">
              <thead className="border-b border-border text-xs text-fg-subtle">
                <tr>
                  <th className="w-8 px-3 py-2.5" />
                  <th className="px-3 py-2.5 font-medium">#</th>
                  <th className="px-3 py-2.5 font-medium">Date</th>
                  <th className="px-3 py-2.5 font-medium">Title</th>
                  <th className="px-3 py-2.5 font-medium">Category</th>
                  <th className="px-3 py-2.5 text-right font-medium">Queries</th>
                  <th className="px-3 py-2.5 font-medium">Results</th>
                  <th className="px-3 py-2.5 font-medium">Escalation</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {rows.slice(0, limit).map((h) => (
                  <HuntRow key={h.id} hunt={h} open={expanded === h.id} onToggle={() => setExpanded(expanded === h.id ? null : h.id)} />
                ))}
              </tbody>
            </table>
            {rows.length > limit && (
              <div className="border-t border-border px-5 py-3 text-center">
                <Button size="sm" variant="ghost" onClick={() => setLimit((l) => l + PAGE)}>
                  Show more ({rows.length - limit} remaining)
                </Button>
              </div>
            )}
          </div>
        )}
      </Card>
    </>
  );
};

const HuntRow: React.FC<{ hunt: IocHunt; open: boolean; onToggle: () => void }> = ({ hunt: h, open, onToggle }) => {
  const hit = hasResults(h);
  const escalated = isEscalated(h);
  return (
    <>
      <tr className={cn('cursor-pointer align-top transition-colors hover:bg-surface-2', open && 'bg-surface-2')} onClick={onToggle}>
        <td className="px-3 py-3 text-fg-subtle">{open ? <ChevronDown className="size-4" /> : <ChevronRight className="size-4" />}</td>
        <td className="px-3 py-3 tabular-nums text-fg-subtle">{h.number || '—'}</td>
        <td className="px-3 py-3 whitespace-nowrap text-fg-muted">{h.date ?? '—'}</td>
        <td className="max-w-md px-3 py-3">
          <div className="font-medium text-fg">{h.title}</div>
          {h.description && <div className="mt-0.5 line-clamp-1 text-xs text-fg-muted">{h.description}</div>}
        </td>
        <td className="px-3 py-3">
          <Badge tone={categoryTone(h.category)}>{h.category}</Badge>
        </td>
        <td className="px-3 py-3 text-right font-semibold tabular-nums text-fg">{h.queryCount}</td>
        <td className="px-3 py-3">
          <span className={cn('inline-flex items-center gap-1.5', hit ? 'font-medium text-warning-text' : 'text-fg-muted')}>
            <span className={cn('size-1.5 rounded-full', hit ? 'bg-warning' : 'bg-fg-subtle')} />
            {h.results || '—'}
          </span>
        </td>
        <td className="px-3 py-3">{escalated ? <Badge tone="danger" mono>{h.escalation}</Badge> : <span className="text-fg-subtle">—</span>}</td>
      </tr>
      {open && (
        <tr className="bg-surface-2">
          <td />
          <td colSpan={7} className="px-3 pb-4">
            {h.description && <p className="mb-3 text-[13px] leading-relaxed text-fg-muted">{h.description}</p>}
            {h.queries ? <CodeBlock code={h.queries} label={`Queries (${h.queryCount})`} maxHeight="max-h-64" /> : <p className="text-[13px] text-fg-subtle">No queries recorded for this hunt.</p>}
            {h.origin === 'demo' && <p className="mt-2 text-xs text-fg-subtle">Demo row</p>}
          </td>
        </tr>
      )}
    </>
  );
};
