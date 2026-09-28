import React, { useMemo, useState } from 'react';
import { Copy, Save, Sparkles } from 'lucide-react';
import type { SeverityFactors, SeverityScoreRecord } from '../types';
import { useApp } from '../app/AppContext';
import { calculateSeverityScore, FACTOR_WEIGHTS, generateSeverityRationale } from '../utils/severityCalculator';
import { fetchSeverityRationale } from '../services/api';
import { hashParams } from '../lib/useHashRoute';
import { cn } from '../lib/cn';
import { Badge, Button, Card, Field, Input, Meter, PageHeader, SectionLabel, Select, Textarea, severityTone, useToast } from './ui';

type Level = 'Low' | 'Medium' | 'High' | 'Critical';

interface FactorDef {
  key: keyof SeverityFactors;
  label: string;
  max: number;
  options: Array<{ value: string; label: string; help: string }>;
}

const LEVELS: Level[] = ['Low', 'Medium', 'High', 'Critical'];

const FACTORS: FactorDef[] = [
  {
    key: 'businessImpact',
    label: 'Business impact',
    max: FACTOR_WEIGHTS.businessImpact * 100,
    options: LEVELS.map((l, i) => ({ value: l, label: l, help: ['Isolated test/dev', 'Departmental system', 'Core database / IP', 'Domain controller / EHR'][i] })),
  },
  {
    key: 'threatStage',
    label: 'Attacker progression',
    max: FACTOR_WEIGHTS.threatStage * 100,
    options: [
      { value: 'Reconnaissance', label: 'Recon', help: 'Scanning, footprinting' },
      { value: 'Initial Access', label: 'Initial access', help: 'Phishing, edge exploit' },
      { value: 'Execution/Persistence', label: 'Execution', help: 'Payload, persistence' },
      { value: 'Lateral Movement/Credential Access', label: 'Lateral / creds', help: 'LSASS, pivoting' },
      { value: 'Impact/Exfiltration', label: 'Impact', help: 'Ransomware, exfil' },
    ],
  },
  {
    key: 'detectionConfidence',
    label: 'Detection confidence',
    max: FACTOR_WEIGHTS.detectionConfidence * 100,
    options: LEVELS.map((l, i) => ({ value: l, label: l, help: ['Noisy heuristic', 'Needs validation', 'High-fidelity behaviour', 'Deterministic proof'][i] })),
  },
  {
    key: 'exploitability',
    label: 'Exploitability',
    max: FACTOR_WEIGHTS.exploitability * 100,
    options: LEVELS.map((l, i) => ({ value: l, label: l, help: ['Theoretical', 'PoC, auth required', 'Exploited in the wild', 'CISA KEV / wormable'][i] })),
  },
];

const POINTS_KEY: Record<keyof SeverityFactors, keyof SeverityScoreRecord['factorBreakdown']> = {
  businessImpact: 'businessImpactPoints',
  threatStage: 'threatStagePoints',
  detectionConfidence: 'detectionConfidencePoints',
  exploitability: 'exploitabilityPoints',
};

export const SeverityScoringView: React.FC = () => {
  const { currentClient, clientReports, attachSeverity, navigate } = useApp();
  const toast = useToast();

  const initialReport = clientReports.find((r) => r.id === hashParams().get('report'));
  const [reportId, setReportId] = useState(initialReport?.id ?? '');
  const [topic, setTopic] = useState(initialReport?.hypothesisTitle ?? '');
  const [summary, setSummary] = useState(initialReport?.notes ?? '');
  const [factors, setFactors] = useState<SeverityFactors>(
    initialReport?.severityScore?.factors ?? {
      businessImpact: 'Medium',
      threatStage: 'Initial Access',
      detectionConfidence: 'Medium',
      exploitability: 'Medium',
    },
  );
  const [rationale, setRationale] = useState(initialReport?.severityScore?.rationale ?? '');
  const [rationaleFallback, setRationaleFallback] = useState(false);
  const [loadingAi, setLoadingAi] = useState(false);

  const { compositeScore, severityLevel, factorBreakdown } = calculateSeverityScore(factors);
  const autoRationale = generateSeverityRationale(topic || 'this finding', factors, compositeScore, severityLevel);
  const scored = useMemo(() => clientReports.filter((r) => r.severityScore), [clientReports]);

  const pickReport = (id: string) => {
    setReportId(id);
    const r = clientReports.find((x) => x.id === id);
    if (!r) return;
    setTopic(r.hypothesisTitle);
    setSummary(r.notes);
    if (r.severityScore) {
      setFactors(r.severityScore.factors);
      setRationale(r.severityScore.rationale ?? '');
    } else {
      setRationale('');
    }
  };

  const generateRationale = async () => {
    setLoadingAi(true);
    try {
      const res = await fetchSeverityRationale(topic, summary, factors, compositeScore, severityLevel);
      setRationale(res.data || autoRationale);
      setRationaleFallback(res.fallback);
    } catch {
      toast('Could not reach the AI service. The template rationale is shown instead.', 'error');
      setRationale(autoRationale);
      setRationaleFallback(true);
    } finally {
      setLoadingAi(false);
    }
  };

  const save = () => {
    if (!reportId) return;
    const record: SeverityScoreRecord = {
      id: `sev-${Date.now()}`,
      huntReportId: reportId,
      clientId: currentClient.id,
      topic,
      summary,
      query: clientReports.find((r) => r.id === reportId)?.queryText ?? '',
      factors,
      compositeScore,
      severityLevel,
      factorBreakdown,
      rationale: rationale || autoRationale,
      createdAt: new Date().toISOString(),
    };
    attachSeverity(reportId, record);
    toast(`Severity ${severityLevel} (${compositeScore}) saved to the report.`);
  };

  const copySummary = async () => {
    const text = [
      `Severity: ${severityLevel} (${compositeScore}/100) — ${topic}`,
      ...FACTORS.map((f) => `- ${f.label}: ${factors[f.key]} (${factorBreakdown[POINTS_KEY[f.key]]} pts)`),
      '',
      rationale || autoRationale,
    ].join('\n');
    try {
      await navigator.clipboard.writeText(text);
      toast('Summary copied.');
    } catch {
      toast('Clipboard unavailable.', 'error');
    }
  };

  return (
    <>
      <PageHeader
        title="Severity scoring"
        description="Score a finding on four weighted factors and attach the result to its hunt report."
      />

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        <div className="space-y-6 lg:col-span-7">
          <Card padded className="space-y-4">
            <Field label="Hunt report" htmlFor="sv-report" hint="The score is saved on this report.">
              <Select id="sv-report" value={reportId} onChange={(e) => pickReport(e.target.value)}>
                <option value="">Select a report…</option>
                {clientReports.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.hypothesisTitle} {r.severityScore ? `(scored ${r.severityScore.compositeScore})` : ''}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Finding" htmlFor="sv-topic">
              <Input id="sv-topic" value={topic} onChange={(e) => setTopic(e.target.value)} placeholder="e.g. LSASS dump on domain controller" />
            </Field>
            <Field label="Context" htmlFor="sv-summary">
              <Textarea id="sv-summary" rows={3} value={summary} onChange={(e) => setSummary(e.target.value)} placeholder="Affected assets and how far the attacker got." />
            </Field>
          </Card>

          <Card padded className="space-y-6">
            {FACTORS.map((f) => (
              <fieldset key={f.key}>
                <legend className="mb-2 flex w-full items-center justify-between text-[13px]">
                  <span className="font-medium text-fg">
                    {f.label} <span className="font-normal text-fg-subtle">· {Math.round(f.max)}% weight</span>
                  </span>
                  <span className="tabular-nums text-fg-muted">
                    {factorBreakdown[POINTS_KEY[f.key]]} / {Math.round(f.max)}
                  </span>
                </legend>
                <div className={cn('grid gap-2', f.options.length === 5 ? 'grid-cols-2 sm:grid-cols-5' : 'grid-cols-2 sm:grid-cols-4')}>
                  {f.options.map((o) => {
                    const active = factors[f.key] === o.value;
                    return (
                      <button
                        key={o.value}
                        type="button"
                        aria-pressed={active}
                        onClick={() => setFactors({ ...factors, [f.key]: o.value } as SeverityFactors)}
                        className={cn(
                          'rounded-md border px-2.5 py-2 text-left transition-colors',
                          active ? 'border-accent bg-accent-soft' : 'border-border bg-canvas hover:border-border-strong',
                        )}
                      >
                        <div className="text-[13px] font-medium text-fg">{o.label}</div>
                        <div className="truncate text-xs text-fg-subtle">{o.help}</div>
                      </button>
                    );
                  })}
                </div>
              </fieldset>
            ))}
          </Card>
        </div>

        <div className="space-y-6 lg:col-span-5">
          <Card padded className="space-y-5 lg:sticky lg:top-20">
            <div className="flex items-center justify-between">
              <span className="text-[13px] text-fg-muted">Composite score</span>
              <Badge tone={severityTone(severityLevel)}>{severityLevel}</Badge>
            </div>
            <div>
              <div className="flex items-baseline gap-1.5">
                <span className="text-5xl font-semibold tabular-nums text-fg">{compositeScore}</span>
                <span className="text-sm text-fg-subtle">/ 100</span>
              </div>
              <Meter
                value={compositeScore}
                tone={severityLevel === 'Critical' ? 'danger' : severityLevel === 'High' ? 'warning' : 'accent'}
                className="mt-3"
              />
              <div className="mt-1.5 flex justify-between text-xs text-fg-subtle">
                <span>Low</span>
                <span>Medium 45</span>
                <span>High 68</span>
                <span>Critical 85</span>
              </div>
            </div>

            <div>
              <div className="mb-2 flex items-center justify-between">
                <SectionLabel className="mb-0">Rationale</SectionLabel>
                <Button size="sm" variant="ghost" icon={Sparkles} loading={loadingAi} onClick={generateRationale} disabled={!topic.trim()}>
                  Draft with AI
                </Button>
              </div>
              <Textarea rows={5} value={rationale} onChange={(e) => setRationale(e.target.value)} placeholder={autoRationale} className="text-[13px]" />
              {rationaleFallback && <p className="mt-1.5 text-xs text-fg-subtle">AI unavailable — template text shown. Edit before saving.</p>}
            </div>

            <div className="flex gap-2">
              <Button icon={Copy} onClick={copySummary} className="flex-1">
                Copy summary
              </Button>
              <Button variant="primary" icon={Save} onClick={save} disabled={!reportId} className="flex-1" title={reportId ? undefined : 'Select a hunt report first'}>
                Save to report
              </Button>
            </div>
            {!reportId && <p className="-mt-2 text-xs text-fg-subtle">Select a hunt report to save this score.</p>}
          </Card>

          <Card>
            <div className="border-b border-border px-5 py-3 text-sm font-semibold text-fg">Scored reports ({scored.length})</div>
            {scored.length === 0 ? (
              <p className="px-5 py-6 text-center text-[13px] text-fg-muted">No reports scored yet.</p>
            ) : (
              <ul className="max-h-72 divide-y divide-border overflow-y-auto">
                {scored.map((r) => (
                  <li key={r.id}>
                    <button
                      type="button"
                      onClick={() => navigate('reports', { id: r.id })}
                      className="flex w-full items-center justify-between gap-3 px-5 py-2.5 text-left hover:bg-surface-2"
                    >
                      <span className="truncate text-[13px] text-fg">{r.hypothesisTitle}</span>
                      <Badge tone={severityTone(r.severityScore!.severityLevel)}>{r.severityScore!.compositeScore}</Badge>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>
      </div>
    </>
  );
};
