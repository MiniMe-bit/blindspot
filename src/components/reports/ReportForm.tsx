import React, { useRef, useState } from 'react';
import { ArrowLeft, Plus, Trash2, Upload, X } from 'lucide-react';
import type { HuntOutcome, HuntReport, IOC, ReportDraft } from '../../types';
import { useApp } from '../../app/AppContext';
import { ALL_DATA_SOURCES, MITRE_TECHNIQUES } from '../../data/mitreAttck';
import { parseReportPdf } from '../../services/api';
import { currentWeekRange } from '../../lib/coverage';
import { HUNTS_PER_PHASE, phaseCounts, phaseOptions, suggestPhase } from '../../lib/phases';
import { cn } from '../../lib/cn';
import { Badge, Button, Card, CardTitle, Field, Input, Select, Textarea, useToast } from '../ui';

const OUTCOMES: Array<{ value: HuntOutcome; help: string }> = [
  { value: 'True Positive', help: 'Malicious activity confirmed' },
  { value: 'Needs Follow-up', help: 'Suspicious, not yet resolved' },
  { value: 'False Positive', help: 'Hits were benign' },
  { value: 'No Result', help: 'Query returned nothing notable' },
];

const LANGUAGES: HuntReport['queryLanguage'][] = ['KQL', 'SPL', 'Sigma', 'EQL'];
const IOC_TYPES: IOC['type'][] = ['IP', 'Domain', 'Hash', 'Process', 'Registry', 'Account'];

interface ReportFormProps {
  draft: ReportDraft | null;
  onCancel: () => void;
  onSaved: (report: HuntReport) => void;
}

export const ReportForm: React.FC<ReportFormProps> = ({ draft, onCancel, onSaved }) => {
  const { currentClient, currentUser, addReport, clientReports } = useApp();
  const [phase, setPhase] = useState(() => suggestPhase(clientReports));
  const counts = phaseCounts(clientReports);
  const toast = useToast();
  const fileRef = useRef<HTMLInputElement>(null);

  const [weekRange, setWeekRange] = useState(currentWeekRange());
  const [title, setTitle] = useState(draft?.hypothesisTitle ?? '');
  const [description, setDescription] = useState(draft?.hypothesisDescription ?? '');
  const [techniques, setTechniques] = useState<string[]>(draft?.techniqueIds ?? []);
  const [dataSources, setDataSources] = useState<string[]>(draft?.dataSources ?? []);
  const [language, setLanguage] = useState<HuntReport['queryLanguage']>(draft?.queryLanguage ?? 'KQL');
  const [queryText, setQueryText] = useState(draft?.queryText ?? '');
  const [outcome, setOutcome] = useState<HuntOutcome | null>(null);
  const [notes, setNotes] = useState(draft?.notes ?? '');
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [iocType, setIocType] = useState<IOC['type']>('IP');
  const [iocValue, setIocValue] = useState('');
  const [iocNote, setIocNote] = useState('');
  const [importing, setImporting] = useState(false);
  const [submitted, setSubmitted] = useState(false);

  // Data sources: show the catalog plus anything the draft brought in that isn't in it.
  const sourceOptions = Array.from(new Set([...ALL_DATA_SOURCES, ...dataSources]));

  const errors = {
    title: !title.trim() && 'Give the hypothesis a title.',
    description: !description.trim() && 'Describe the hypothesis.',
    techniques: techniques.length === 0 && 'Tag at least one ATT&CK technique.',
    query: !queryText.trim() && 'Add the query you ran.',
    outcome: !outcome && 'Choose an outcome.',
  };
  const hasErrors = Object.values(errors).some(Boolean);

  const handleImport = async (file: File) => {
    setImporting(true);
    try {
      const base64 = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result).split(',')[1] ?? '');
        reader.onerror = () => reject(new Error('Could not read the file.'));
        reader.readAsDataURL(file);
      });
      const x = await parseReportPdf(base64, file.type || 'application/pdf', file.name);
      if (x.hypothesisTitle) setTitle(x.hypothesisTitle);
      if (x.hypothesisDescription) setDescription(x.hypothesisDescription);
      if (x.weekRange) setWeekRange(x.weekRange);
      if (x.techniqueIds?.length) setTechniques(x.techniqueIds);
      if (x.dataSources?.length) setDataSources(x.dataSources);
      if (x.queryLanguage) setLanguage(x.queryLanguage);
      if (x.queryText) setQueryText(x.queryText);
      if (x.outcome) setOutcome(x.outcome);
      if (x.notes) setNotes(x.notes);
      if (x.iocs?.length) setIocs(x.iocs.map((i, idx) => ({ id: `ioc-${Date.now()}-${idx}`, type: i.type, value: i.value, notes: i.notes })));
      toast(`Fields filled from ${file.name}. Review everything before saving.`, 'info');
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Could not import the document.', 'error');
    } finally {
      setImporting(false);
      if (fileRef.current) fileRef.current.value = '';
    }
  };

  const addIoc = () => {
    if (!iocValue.trim()) return;
    setIocs([...iocs, { id: `ioc-${Date.now()}`, type: iocType, value: iocValue.trim(), notes: iocNote.trim() || undefined }]);
    setIocValue('');
    setIocNote('');
  };

  const toggleSource = (ds: string) =>
    setDataSources(dataSources.includes(ds) ? dataSources.filter((d) => d !== ds) : [...dataSources, ds]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitted(true);
    if (hasErrors || !outcome) return;
    const report: HuntReport = {
      id: `hunt-${Date.now()}`,
      clientId: currentClient.id,
      analystId: currentUser.id,
      analystName: currentUser.name,
      weekRange,
      hypothesisTitle: title.trim(),
      hypothesisDescription: description.trim(),
      techniqueIds: techniques,
      dataSources,
      queryLanguage: language,
      queryText,
      outcome,
      notes: notes.trim(),
      iocs,
      createdAt: new Date().toISOString(),
      phase,
    };
    addReport(report);
    toast('Hypothesis record saved.');
    onSaved(report);
  };

  const err = (key: keyof typeof errors) => (submitted && errors[key] ? <p className="text-xs text-danger-text">{errors[key]}</p> : null);

  return (
    <form onSubmit={handleSubmit} noValidate>
      <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <button type="button" onClick={onCancel} className="mb-2 inline-flex items-center gap-1 text-[13px] text-fg-muted hover:text-fg">
            <ArrowLeft className="size-3.5" /> Hypothesis Record
          </button>
          <h1 className="text-xl font-semibold tracking-tight text-fg">New hypothesis record</h1>
          <p className="mt-1 text-sm text-fg-muted">
            {currentClient.name} · {currentUser.name}
          </p>
        </div>
        <div className="flex gap-2">
          <input
            ref={fileRef}
            type="file"
            accept=".pdf,.txt,.md,application/pdf,text/plain,text/markdown"
            className="hidden"
            onChange={(e) => e.target.files?.[0] && handleImport(e.target.files[0])}
          />
          <Button icon={Upload} loading={importing} onClick={() => fileRef.current?.click()} title="Use AI to fill the form from an existing report (PDF, Markdown or text)">
            Import from document
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          <Card padded className="space-y-5">
            <CardTitle tone="accent">Hypothesis</CardTitle>
            <Field label="Phase" htmlFor="rf-phase" required hint={`Each phase holds ${HUNTS_PER_PHASE} hunts. Phase ${phase} has ${counts.get(phase) ?? 0} of ${HUNTS_PER_PHASE} so far.`}>
              <Select id="rf-phase" value={phase} onChange={(e) => setPhase(Number(e.target.value))} className="sm:w-60">
                {phaseOptions(clientReports).map((p) => (
                  <option key={p} value={p}>
                    Phase {p} ({counts.get(p) ?? 0}/{HUNTS_PER_PHASE}){(counts.get(p) ?? 0) >= HUNTS_PER_PHASE ? ' — full' : ''}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Title" htmlFor="rf-title" required>
              <Input id="rf-title" value={title} onChange={(e) => setTitle(e.target.value)} placeholder="e.g. LSASS memory access via comsvcs.dll MiniDump" />
              {err('title')}
            </Field>
            <Field label="Description" htmlFor="rf-desc" required hint="What is the adversary trying to do, and why does it matter for this client?">
              <Textarea id="rf-desc" rows={4} value={description} onChange={(e) => setDescription(e.target.value)} />
              {err('description')}
            </Field>
            <Field label="ATT&CK techniques" required>
              {techniques.length > 0 && (
                <div className="mb-2 flex flex-wrap gap-1.5">
                  {techniques.map((id) => {
                    const t = MITRE_TECHNIQUES.find((x) => x.id === id);
                    return (
                      <Badge key={id} tone="accent">
                        <span className="font-mono">{id}</span>
                        {t && <span className="max-w-[16rem] truncate">{t.name}</span>}
                        <button type="button" onClick={() => setTechniques(techniques.filter((x) => x !== id))} aria-label={`Remove ${id}`} className="hover:text-fg">
                          <X className="size-3" />
                        </button>
                      </Badge>
                    );
                  })}
                </div>
              )}
              <Select
                value=""
                aria-label="Add technique"
                onChange={(e) => e.target.value && !techniques.includes(e.target.value) && setTechniques([...techniques, e.target.value])}
              >
                <option value="">Add a technique…</option>
                {MITRE_TECHNIQUES.filter((t) => !techniques.includes(t.id)).map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.id} · {t.name} ({t.tactic})
                  </option>
                ))}
              </Select>
              {err('techniques')}
            </Field>
          </Card>

          <Card padded className="space-y-5">
            <CardTitle tone="teal">Query</CardTitle>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-4">
              <Field label="Language" htmlFor="rf-lang">
                <Select id="rf-lang" value={language} onChange={(e) => setLanguage(e.target.value as HuntReport['queryLanguage'])}>
                  {LANGUAGES.map((l) => (
                    <option key={l}>{l}</option>
                  ))}
                </Select>
              </Field>
            </div>
            <Field label="Query" htmlFor="rf-query" required>
              <Textarea id="rf-query" rows={7} value={queryText} onChange={(e) => setQueryText(e.target.value)} className="font-mono text-[12.5px]" spellCheck={false} />
              {err('query')}
            </Field>
            <Field label="Data sources used">
              <div className="grid max-h-44 grid-cols-1 gap-x-4 gap-y-1.5 overflow-y-auto rounded-md border border-border bg-canvas p-3 sm:grid-cols-2">
                {sourceOptions.map((ds) => (
                  <label key={ds} className="flex cursor-pointer items-center gap-2 text-[13px] text-fg-muted">
                    <input type="checkbox" checked={dataSources.includes(ds)} onChange={() => toggleSource(ds)} className="accent-accent" />
                    <span className="truncate">{ds}</span>
                  </label>
                ))}
              </div>
            </Field>
          </Card>

          <Card padded className="space-y-5">
            <CardTitle tone="danger">Findings</CardTitle>
            <Field label="Outcome" required>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                {OUTCOMES.map((o) => (
                  <button
                    key={o.value}
                    type="button"
                    onClick={() => setOutcome(o.value)}
                    aria-pressed={outcome === o.value}
                    className={cn(
                      'rounded-md border px-3 py-2.5 text-left transition-colors',
                      outcome === o.value ? 'border-accent bg-accent-soft' : 'border-border bg-canvas hover:border-border-strong',
                    )}
                  >
                    <div className="text-sm font-medium text-fg">{o.value}</div>
                    <div className="text-xs text-fg-muted">{o.help}</div>
                  </button>
                ))}
              </div>
              {err('outcome')}
            </Field>
            <Field label="Notes" htmlFor="rf-notes" hint="Affected hosts, containment actions, tuning or allow-listing recommendations.">
              <Textarea id="rf-notes" rows={4} value={notes} onChange={(e) => setNotes(e.target.value)} />
            </Field>

            <Field label="Indicators of compromise">
              {iocs.length > 0 && (
                <ul className="mb-2 divide-y divide-border rounded-md border border-border">
                  {iocs.map((i) => (
                    <li key={i.id} className="flex items-center gap-3 px-3 py-2 text-[13px]">
                      <Badge>{i.type}</Badge>
                      <span className="min-w-0 flex-1 truncate font-mono text-fg">{i.value}</span>
                      {i.notes && <span className="hidden truncate text-fg-subtle sm:inline">{i.notes}</span>}
                      <button type="button" onClick={() => setIocs(iocs.filter((x) => x.id !== i.id))} aria-label="Remove indicator" className="text-fg-subtle hover:text-danger-text">
                        <Trash2 className="size-4" />
                      </button>
                    </li>
                  ))}
                </ul>
              )}
              <div className="flex flex-col gap-2 sm:flex-row">
                <Select value={iocType} onChange={(e) => setIocType(e.target.value as IOC['type'])} className="sm:w-32" aria-label="Indicator type">
                  {IOC_TYPES.map((t) => (
                    <option key={t}>{t}</option>
                  ))}
                </Select>
                <Input
                  value={iocValue}
                  onChange={(e) => setIocValue(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      e.preventDefault();
                      addIoc();
                    }
                  }}
                  placeholder="Value"
                  className="font-mono"
                  aria-label="Indicator value"
                />
                <Input value={iocNote} onChange={(e) => setIocNote(e.target.value)} placeholder="Context (optional)" aria-label="Indicator context" />
                <Button icon={Plus} onClick={addIoc} disabled={!iocValue.trim()}>
                  Add
                </Button>
              </div>
            </Field>
          </Card>
        </div>

        {/* Sticky summary / submit */}
        <div className="lg:sticky lg:top-20 lg:self-start">
          <Card padded className="space-y-4">
            <Field label="Week" htmlFor="rf-week">
              <Input id="rf-week" value={weekRange} onChange={(e) => setWeekRange(e.target.value)} />
            </Field>
            <dl className="space-y-2 text-[13px]">
              <div className="flex justify-between">
                <dt className="text-fg-muted">Techniques</dt>
                <dd className="text-fg">{techniques.length}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-fg-muted">Data sources</dt>
                <dd className="text-fg">{dataSources.length}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-fg-muted">Indicators</dt>
                <dd className="text-fg">{iocs.length}</dd>
              </div>
            </dl>
            {submitted && hasErrors && <p className="text-xs text-danger-text">Fix the highlighted fields to save.</p>}
            <div className="flex flex-col gap-2">
              <Button type="submit" variant="primary">
                Save record
              </Button>
              <Button variant="ghost" onClick={onCancel}>
                Cancel
              </Button>
            </div>
          </Card>
        </div>
      </div>
    </form>
  );
};
