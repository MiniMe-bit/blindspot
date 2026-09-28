import React, { useMemo, useState } from 'react';
import { ChevronDown, Download, Plus, Search, ShieldCheck } from 'lucide-react';
import type { DetectionPlatform, DetectionRule, DetectionRuleStatus } from '../types';
import { useApp } from '../app/AppContext';
import { hashParams } from '../lib/useHashRoute';
import { formatDate } from '../lib/coverage';
import { cn } from '../lib/cn';
import { Badge, Button, Card, CodeBlock, EmptyState, Field, Input, Modal, PageHeader, SectionLabel, Select, Stat, Textarea, severityTone, useToast, type Tone } from './ui';

const PLATFORMS: DetectionPlatform[] = [
  'Microsoft Sentinel (KQL)',
  'Splunk Enterprise (SPL)',
  'CrowdStrike Falcon (LQL)',
  'SentinelOne (Deep Visibility)',
  'Trend Micro Vision One',
  'Sigma (Generic)',
  'Elasticsearch (EQL)',
];

const STATUSES: DetectionRuleStatus[] = ['Testing / Staging', 'Pending Client Review', 'Production Active', 'Tuning Needed', 'Deprecated'];

const STATUS_TONE: Record<DetectionRuleStatus, Tone> = {
  'Production Active': 'success',
  'Testing / Staging': 'accent',
  'Pending Client Review': 'warning',
  'Tuning Needed': 'danger',
  Deprecated: 'neutral',
};

const SEVERITIES: DetectionRule['severity'][] = ['Critical', 'High', 'Medium', 'Low'];

export const DetectionsView: React.FC = () => {
  const { currentClient, clientRules, updateRule } = useApp();
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState<'all' | DetectionRuleStatus>('all');
  const [platform, setPlatform] = useState<'all' | DetectionPlatform>('all');
  // A freshly created rule arrives with no id param; open the newest one by default.
  const [expanded, setExpanded] = useState<string | null>(() => hashParams().get('id') ?? clientRules[0]?.id ?? null);
  const [creating, setCreating] = useState(false);

  const counts = useMemo(() => {
    const by = (s: DetectionRuleStatus) => clientRules.filter((r) => r.status === s).length;
    return { prod: by('Production Active'), testing: by('Testing / Staging'), review: by('Pending Client Review'), tuning: by('Tuning Needed') };
  }, [clientRules]);

  const rules = useMemo(() => {
    const q = search.trim().toLowerCase();
    return clientRules.filter((r) => {
      if (status !== 'all' && r.status !== status) return false;
      if (platform !== 'all' && r.platform !== platform) return false;
      if (!q) return true;
      return [r.ruleName, r.description, r.huntHypothesisTitle, ...r.techniqueIds].join(' ').toLowerCase().includes(q);
    });
  }, [clientRules, search, status, platform]);

  const exportRules = () => {
    const blob = new Blob([JSON.stringify(clientRules, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${currentClient.name.toLowerCase().replace(/\s+/g, '-')}-detection-rules.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <>
      <PageHeader
        title="Detection rules"
        description="Hunts promoted to detection logic for this client, tracked from testing to production."
        actions={
          <>
            <Button icon={Download} onClick={exportRules} disabled={!clientRules.length}>
              Export JSON
            </Button>
            <Button variant="primary" icon={Plus} onClick={() => setCreating(true)}>
              New rule
            </Button>
          </>
        }
      />

      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="In production" value={counts.prod} onClick={() => setStatus('Production Active')} />
        <Stat label="Testing / staging" value={counts.testing} onClick={() => setStatus('Testing / Staging')} />
        <Stat label="Awaiting client review" value={counts.review} onClick={() => setStatus('Pending Client Review')} />
        <Stat label="Needs tuning" value={counts.tuning} onClick={() => setStatus('Tuning Needed')} />
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="relative w-full sm:w-72">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-fg-subtle" />
          <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search rules or techniques…" className="h-8 pl-8 text-[13px]" aria-label="Search rules" />
        </div>
        <Select value={status} onChange={(e) => setStatus(e.target.value as 'all' | DetectionRuleStatus)} className="h-8 w-auto text-[13px]" aria-label="Status">
          <option value="all">All statuses</option>
          {STATUSES.map((s) => (
            <option key={s}>{s}</option>
          ))}
        </Select>
        <Select value={platform} onChange={(e) => setPlatform(e.target.value as 'all' | DetectionPlatform)} className="h-8 w-auto text-[13px]" aria-label="Platform">
          <option value="all">All platforms</option>
          {PLATFORMS.map((p) => (
            <option key={p}>{p}</option>
          ))}
        </Select>
        <span className="ml-auto text-[13px] text-fg-subtle">
          {rules.length} of {clientRules.length}
        </span>
      </div>

      <Card>
        {rules.length === 0 ? (
          <EmptyState
            icon={ShieldCheck}
            title={clientRules.length ? 'No rules match' : 'No detection rules yet'}
            description={
              clientRules.length ? 'Try a different filter.' : 'Promote a hunt report from Hunt reports, or add a rule manually.'
            }
            action={
              !clientRules.length && (
                <Button variant="primary" icon={Plus} onClick={() => setCreating(true)}>
                  New rule
                </Button>
              )
            }
          />
        ) : (
          <ul className="divide-y divide-border">
            {rules.map((rule) => {
              const open = expanded === rule.id;
              return (
                <li key={rule.id}>
                  <div className="flex items-center gap-3 px-5 py-3.5">
                    <button
                      type="button"
                      onClick={() => setExpanded(open ? null : rule.id)}
                      aria-expanded={open}
                      className="flex min-w-0 flex-1 items-center gap-3 text-left"
                    >
                      <ChevronDown className={cn('size-4 shrink-0 text-fg-subtle transition-transform', !open && '-rotate-90')} />
                      <div className="min-w-0">
                        <div className="truncate text-sm font-medium text-fg">{rule.ruleName}</div>
                        <div className="mt-0.5 truncate text-xs text-fg-subtle">
                          {rule.platform} · <span className="font-mono">{rule.techniqueIds.join(', ')}</span>
                        </div>
                      </div>
                    </button>
                    <span className="hidden sm:block">
                      <Badge tone={severityTone(rule.severity)}>{rule.severity}</Badge>
                    </span>
                    <Select
                      value={rule.status}
                      onChange={(e) => updateRule({ ...rule, status: e.target.value as DetectionRuleStatus })}
                      className="h-8 w-44 shrink-0 text-[13px]"
                      aria-label={`Status of ${rule.ruleName}`}
                    >
                      {STATUSES.map((s) => (
                        <option key={s}>{s}</option>
                      ))}
                    </Select>
                    <span className="hidden w-20 md:block">
                      <Badge tone={STATUS_TONE[rule.status]} dot>
                        {rule.status === 'Production Active' ? 'Live' : rule.status === 'Deprecated' ? 'Off' : 'Not live'}
                      </Badge>
                    </span>
                  </div>

                  {open && (
                    <div className="space-y-5 border-t border-border bg-canvas/40 px-5 py-5 sm:pl-12">
                      {rule.description && <p className="text-sm leading-relaxed text-fg-muted">{rule.description}</p>}
                      <dl className="grid grid-cols-2 gap-4 text-[13px] lg:grid-cols-4">
                        <Meta label="Origin hunt" value={rule.huntHypothesisTitle} />
                        <Meta label="Target environment" value={rule.targetEnvironment} />
                        <Meta label="Client approver" value={rule.clientApprover} />
                        <Meta label="Created" value={`${formatDate(rule.sentDate)} by ${rule.deployedBy}`} />
                        <Meta label="Tactics" value={rule.tactics.join(', ')} />
                        <Meta label="Data sources" value={rule.targetDataSources.join(', ')} />
                        <Meta label="Alerts (recorded)" value={String(rule.totalAlertsTriggered)} />
                        <Meta label="False-positive rate (recorded)" value={`${rule.falsePositiveRatePct}%`} />
                      </dl>
                      <CodeBlock code={rule.queryLogic} label={rule.platform} />
                      {rule.tuningNotes && (
                        <div>
                          <SectionLabel>Tuning notes</SectionLabel>
                          <p className="text-[13px] text-fg-muted">{rule.tuningNotes}</p>
                        </div>
                      )}
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </Card>

      {creating && <NewRuleModal onClose={() => setCreating(false)} onCreated={(id) => setExpanded(id)} />}
    </>
  );
};

const Meta: React.FC<{ label: string; value?: string }> = ({ label, value }) => (
  <div className="min-w-0">
    <dt className="text-xs text-fg-subtle">{label}</dt>
    <dd className="mt-0.5 break-words text-fg">{value?.trim() ? value : '—'}</dd>
  </div>
);

const LANG_TO_PLATFORM: Record<string, DetectionPlatform> = {
  KQL: 'Microsoft Sentinel (KQL)',
  SPL: 'Splunk Enterprise (SPL)',
  Sigma: 'Sigma (Generic)',
  EQL: 'Elasticsearch (EQL)',
};

const NewRuleModal: React.FC<{ onClose: () => void; onCreated: (id: string) => void }> = ({ onClose, onCreated }) => {
  const { currentClient, currentUser, clientReports, addRule } = useApp();
  const toast = useToast();

  const [originId, setOriginId] = useState('');
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [platform, setPlatform] = useState<DetectionPlatform>(PLATFORMS[0]);
  const [severity, setSeverity] = useState<DetectionRule['severity']>('High');
  const [status, setStatus] = useState<DetectionRuleStatus>('Testing / Staging');
  const [query, setQuery] = useState('');
  const [techniques, setTechniques] = useState('');
  const [tactics, setTactics] = useState('');
  const [environment, setEnvironment] = useState('');
  const [approver, setApprover] = useState('');
  const [tuning, setTuning] = useState('');
  const [submitted, setSubmitted] = useState(false);

  const pickOrigin = (id: string) => {
    setOriginId(id);
    const r = clientReports.find((x) => x.id === id);
    if (!r) return;
    setName(r.hypothesisTitle.slice(0, 80));
    setDescription(r.hypothesisDescription);
    setQuery(r.queryText);
    setTechniques(r.techniqueIds.join(', '));
    setPlatform(LANG_TO_PLATFORM[r.queryLanguage] ?? PLATFORMS[0]);
  };

  const valid = name.trim() && query.trim();

  const save = () => {
    setSubmitted(true);
    if (!valid) return;
    const split = (s: string) => s.split(',').map((x) => x.trim()).filter(Boolean);
    const origin = clientReports.find((r) => r.id === originId);
    const rule: DetectionRule = {
      id: `det-rule-${Date.now()}`,
      clientId: currentClient.id,
      huntReportId: origin?.id,
      huntHypothesisTitle: origin?.hypothesisTitle ?? '',
      ruleName: name.trim(),
      description: description.trim(),
      platform,
      severity,
      status,
      techniqueIds: split(techniques),
      tactics: split(tactics),
      queryLogic: query,
      targetDataSources: origin?.dataSources ?? [],
      targetEnvironment: environment.trim(),
      deployedBy: currentUser.name,
      sentDate: new Date().toISOString(),
      totalAlertsTriggered: 0,
      falsePositiveRatePct: 0,
      tuningNotes: tuning.trim() || undefined,
      clientApprover: approver.trim(),
    };
    addRule(rule);
    toast(`Rule "${rule.ruleName}" saved.`);
    onCreated(rule.id);
    onClose();
  };

  return (
    <Modal
      open
      onClose={onClose}
      size="lg"
      title="New detection rule"
      description="Records the rule in Blindspot. Deploy it to the client's SIEM/EDR through your normal change process."
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" onClick={save}>
            Save rule
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label="Start from a hunt report" htmlFor="nr-origin" hint="Optional. Prefills name, description, query and techniques.">
          <Select id="nr-origin" value={originId} onChange={(e) => pickOrigin(e.target.value)}>
            <option value="">None — write from scratch</option>
            {clientReports.map((r) => (
              <option key={r.id} value={r.id}>
                {r.hypothesisTitle}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Rule name" htmlFor="nr-name" required>
          <Input id="nr-name" value={name} onChange={(e) => setName(e.target.value)} />
          {submitted && !name.trim() && <p className="text-xs text-danger-text">Name the rule.</p>}
        </Field>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <Field label="Platform" htmlFor="nr-platform">
            <Select id="nr-platform" value={platform} onChange={(e) => setPlatform(e.target.value as DetectionPlatform)}>
              {PLATFORMS.map((p) => (
                <option key={p}>{p}</option>
              ))}
            </Select>
          </Field>
          <Field label="Severity" htmlFor="nr-sev">
            <Select id="nr-sev" value={severity} onChange={(e) => setSeverity(e.target.value as DetectionRule['severity'])}>
              {SEVERITIES.map((s) => (
                <option key={s}>{s}</option>
              ))}
            </Select>
          </Field>
          <Field label="Status" htmlFor="nr-status">
            <Select id="nr-status" value={status} onChange={(e) => setStatus(e.target.value as DetectionRuleStatus)}>
              {STATUSES.map((s) => (
                <option key={s}>{s}</option>
              ))}
            </Select>
          </Field>
        </div>
        <Field label="Description" htmlFor="nr-desc">
          <Textarea id="nr-desc" rows={2} value={description} onChange={(e) => setDescription(e.target.value)} />
        </Field>
        <Field label="Detection logic" htmlFor="nr-query" required>
          <Textarea id="nr-query" rows={6} value={query} onChange={(e) => setQuery(e.target.value)} className="font-mono text-[12.5px]" spellCheck={false} />
          {submitted && !query.trim() && <p className="text-xs text-danger-text">Add the detection logic.</p>}
        </Field>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Field label="Techniques" htmlFor="nr-tech" hint="Comma-separated, e.g. T1003.001, T1059.001">
            <Input id="nr-tech" value={techniques} onChange={(e) => setTechniques(e.target.value)} className="font-mono" />
          </Field>
          <Field label="Tactics" htmlFor="nr-tactics" hint="Comma-separated">
            <Input id="nr-tactics" value={tactics} onChange={(e) => setTactics(e.target.value)} />
          </Field>
          <Field label="Target environment" htmlFor="nr-env">
            <Input id="nr-env" value={environment} onChange={(e) => setEnvironment(e.target.value)} placeholder="e.g. Sentinel workspace ws-prod-01" />
          </Field>
          <Field label="Client approver" htmlFor="nr-approver">
            <Input id="nr-approver" value={approver} onChange={(e) => setApprover(e.target.value)} />
          </Field>
        </div>
        <Field label="Tuning notes" htmlFor="nr-tuning">
          <Input id="nr-tuning" value={tuning} onChange={(e) => setTuning(e.target.value)} placeholder="Allow-listed processes, thresholds…" />
        </Field>
      </div>
    </Modal>
  );
};
