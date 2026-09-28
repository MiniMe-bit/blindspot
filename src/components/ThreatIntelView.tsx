import React, { useMemo, useState } from 'react';
import { ExternalLink, FileText, Radar, Search, ShieldCheck } from 'lucide-react';
import type { DetectionPlatform, SectorThreatIntel } from '../types';
import { useApp } from '../app/AppContext';
import { SECTOR_THREAT_INTEL } from '../data/mockData';
import { hashParams } from '../lib/useHashRoute';
import { coveredTechniqueSet, hasTelemetry, isCovered } from '../lib/coverage';
import { Badge, Button, Card, CodeBlock, EmptyState, Input, Modal, PageHeader, SectionLabel, Segmented, Select } from './ui';

type PlatformKey = 'kql' | 'splunk' | 'sigma' | 'fql' | 'sentinelone' | 'trendmicro' | 'elastic';

const PLATFORMS: Array<{ key: PlatformKey; label: string; rulePlatform: DetectionPlatform }> = [
  { key: 'kql', label: 'Sentinel (KQL)', rulePlatform: 'Microsoft Sentinel (KQL)' },
  { key: 'splunk', label: 'Splunk (SPL)', rulePlatform: 'Splunk Enterprise (SPL)' },
  { key: 'sigma', label: 'Sigma', rulePlatform: 'Sigma (Generic)' },
  { key: 'fql', label: 'CrowdStrike', rulePlatform: 'CrowdStrike Falcon (LQL)' },
  { key: 'sentinelone', label: 'SentinelOne', rulePlatform: 'SentinelOne (Deep Visibility)' },
  { key: 'trendmicro', label: 'Trend Vision One', rulePlatform: 'Trend Micro Vision One' },
  { key: 'elastic', label: 'Elastic', rulePlatform: 'Elasticsearch (EQL)' },
];

const SECTORS = ['healthcare', 'finance', 'retail', 'energy', 'technology', 'defense'];

/** Only platforms with a dedicated query are offered; the generic package query is shown as the default. */
const platformQueries = (intel: SectorThreatIntel) => {
  const pq = intel.suggestedHuntPackage.platformQueries ?? {};
  const available = PLATFORMS.filter((p) => Boolean((pq as Record<string, string | undefined>)[p.key]));
  return available;
};

export const ThreatIntelView: React.FC = () => {
  const { currentClient, clientReports } = useApp();
  const [scope, setScope] = useState<'client' | 'all'>('client');
  const [sector, setSector] = useState('all');
  const [query, setQuery] = useState('');
  const [openId, setOpenId] = useState<string | null>(() => hashParams().get('id'));

  const covered = useMemo(() => coveredTechniqueSet(clientReports), [clientReports]);

  const items = useMemo(() => {
    const q = query.trim().toLowerCase();
    return SECTOR_THREAT_INTEL.filter((i) => {
      if (scope === 'client' && !i.sectors.includes(currentClient.industry)) return false;
      if (scope === 'all' && sector !== 'all' && !i.sectors.includes(sector)) return false;
      if (!q) return true;
      return [i.title, i.summary, ...i.threatActors, ...i.targetedCountries, ...(i.cvesObserved ?? []), ...i.primaryTTPs.map((t) => `${t.id} ${t.name}`)]
        .join(' ')
        .toLowerCase()
        .includes(q);
    });
  }, [scope, sector, query, currentClient.industry]);

  const openItem = SECTOR_THREAT_INTEL.find((i) => i.id === openId) ?? null;

  return (
    <>
      <PageHeader
        title="Threat intel"
        description="Curated advisories by sector, mapped to ATT&CK techniques, with ready-to-adapt hunt queries."
      />

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <Segmented<'client' | 'all'>
          ariaLabel="Scope"
          value={scope}
          onChange={setScope}
          options={[
            { value: 'client', label: <span className="capitalize">{currentClient.industry}</span> },
            { value: 'all', label: 'All sectors' },
          ]}
        />
        {scope === 'all' && (
          <Select value={sector} onChange={(e) => setSector(e.target.value)} className="h-8 w-auto text-[13px] capitalize" aria-label="Sector">
            <option value="all">Any sector</option>
            {SECTORS.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </Select>
        )}
        <div className="relative ml-auto w-full sm:w-72">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-fg-subtle" />
          <Input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Actor, CVE, technique…" className="h-8 pl-8 text-[13px]" aria-label="Search intel" />
        </div>
      </div>

      {items.length === 0 ? (
        <Card>
          <EmptyState icon={Radar} title="No advisories match" description="Try another sector or clear the search." />
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {items.map((intel) => {
            const gaps = intel.primaryTTPs.filter((t) => !isCovered(covered, t.id)).length;
            return (
              <Card key={intel.id} className="flex flex-col">
                <button type="button" onClick={() => setOpenId(intel.id)} className="flex flex-1 flex-col p-5 text-left transition-colors hover:bg-surface-2/50">
                  <div className="flex flex-wrap items-center gap-2 text-xs text-fg-subtle">
                    <Badge tone={intel.urgency === 'Critical' ? 'danger' : 'warning'}>{intel.urgency}</Badge>
                    <span>{intel.publishedDate}</span>
                    {intel.sourcePublisher && (
                      <>
                        <span>·</span>
                        <span>{intel.sourcePublisher}</span>
                      </>
                    )}
                  </div>
                  <h3 className="mt-2 text-sm font-semibold leading-snug text-fg">{intel.title}</h3>
                  <p className="mt-1.5 line-clamp-3 text-[13px] leading-relaxed text-fg-muted">{intel.summary}</p>
                  <div className="mt-auto flex flex-wrap items-center gap-x-4 gap-y-1 pt-4 text-xs text-fg-subtle">
                    <span className="truncate">Actors: {intel.threatActors.slice(0, 3).join(', ')}</span>
                    <span className={gaps ? 'text-warning-text' : 'text-success-text'}>
                      {gaps ? `${gaps} of ${intel.primaryTTPs.length} techniques not hunted` : 'All techniques hunted'}
                    </span>
                  </div>
                </button>
              </Card>
            );
          })}
        </div>
      )}

      {openItem && <IntelDetail intel={openItem} covered={covered} onClose={() => setOpenId(null)} />}
    </>
  );
};

const IntelDetail: React.FC<{ intel: SectorThreatIntel; covered: Set<string>; onClose: () => void }> = ({ intel, covered, onClose }) => {
  const { currentClient, startReport, sendToDetections } = useApp();
  const options = platformQueries(intel);
  const [platform, setPlatform] = useState<PlatformKey | 'default'>(options[0]?.key ?? 'default');

  const pkg = intel.suggestedHuntPackage;
  const selected = PLATFORMS.find((p) => p.key === platform);
  const code =
    platform === 'default' ? pkg.queryCode : ((pkg.platformQueries as Record<string, string | undefined> | undefined)?.[platform] ?? pkg.queryCode);
  const languageLabel = selected?.label ?? pkg.queryLanguage;
  const rulePlatform: DetectionPlatform =
    selected?.rulePlatform ?? (pkg.queryLanguage === 'SPL' ? 'Splunk Enterprise (SPL)' : pkg.queryLanguage === 'Sigma' ? 'Sigma (Generic)' : 'Microsoft Sentinel (KQL)');

  return (
    <Modal
      open
      onClose={onClose}
      size="xl"
      title={intel.title}
      description={
        <span className="flex flex-wrap items-center gap-2">
          <Badge tone={intel.urgency === 'Critical' ? 'danger' : 'warning'}>{intel.urgency}</Badge>
          <span>{intel.publishedDate}</span>
          {intel.sourcePublisher && <span>· {intel.sourcePublisher}</span>}
          {intel.sourceUrl && (
            <a href={intel.sourceUrl} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-accent-text hover:underline">
              Source <ExternalLink className="size-3" />
            </a>
          )}
        </span>
      }
      footer={
        <>
          <Button
            icon={ShieldCheck}
            onClick={() =>
              sendToDetections({
                ruleName: `${intel.primaryTTPs[0]?.id ?? 'INTEL'} – ${pkg.hypothesisTitle}`.slice(0, 80),
                queryLogic: code,
                techniqueIds: intel.primaryTTPs.map((t) => t.id),
                tactics: Array.from(new Set(intel.primaryTTPs.map((t) => t.tactic))),
                description: pkg.hypothesisTitle,
                platform: rulePlatform,
              })
            }
          >
            Add as detection rule
          </Button>
          <Button
            variant="primary"
            icon={FileText}
            onClick={() =>
              startReport({
                hypothesisTitle: pkg.hypothesisTitle,
                hypothesisDescription: pkg.description,
                techniqueIds: intel.primaryTTPs.map((t) => t.id),
                dataSources: pkg.requiredDataSources,
                queryLanguage: pkg.queryLanguage,
                queryText: code,
                notes: `Intel: ${intel.title} (${intel.sourcePublisher ?? intel.sourceAttribution}). Actors: ${intel.threatActors.join(', ')}.`,
              })
            }
          >
            Start hunt report
          </Button>
        </>
      }
    >
      <div className="space-y-6">
        <p className="text-sm leading-relaxed text-fg-muted">{intel.summary}</p>

        <div className="grid grid-cols-1 gap-4 text-[13px] sm:grid-cols-2">
          <div>
            <SectionLabel>Threat actors</SectionLabel>
            <p className="text-fg">{intel.threatActors.join(', ')}</p>
          </div>
          <div>
            <SectionLabel>Targeted countries</SectionLabel>
            <p className="text-fg">{intel.targetedCountries.join(', ')}</p>
          </div>
          {intel.cvesObserved && intel.cvesObserved.length > 0 && (
            <div className="sm:col-span-2">
              <SectionLabel>CVEs observed</SectionLabel>
              <div className="flex flex-wrap gap-1.5">
                {intel.cvesObserved.map((c) => (
                  <Badge key={c} mono>
                    {c}
                  </Badge>
                ))}
              </div>
            </div>
          )}
        </div>

        <div>
          <SectionLabel>Techniques · coverage for {currentClient.name}</SectionLabel>
          <ul className="divide-y divide-border rounded-md border border-border">
            {intel.primaryTTPs.map((t) => {
              const ok = isCovered(covered, t.id);
              return (
                <li key={t.id} className="flex items-center justify-between gap-3 px-3 py-2 text-[13px]">
                  <span className="min-w-0 truncate">
                    <span className="font-mono text-fg">{t.id}</span> <span className="text-fg-muted">{t.name}</span>
                  </span>
                  <Badge tone={ok ? 'success' : 'warning'}>{ok ? 'Hunted' : 'Not hunted'}</Badge>
                </li>
              );
            })}
          </ul>
        </div>

        <div>
          <SectionLabel>Required telemetry</SectionLabel>
          <ul className="space-y-1.5">
            {pkg.requiredDataSources.map((ds) => {
              const ok = hasTelemetry(currentClient.primaryTelemetry, ds);
              return (
                <li key={ds} className="flex items-center justify-between gap-3 text-[13px]">
                  <span className="text-fg-muted">{ds}</span>
                  <Badge tone={ok ? 'success' : 'warning'}>{ok ? 'Onboarded' : 'Not onboarded'}</Badge>
                </li>
              );
            })}
          </ul>
        </div>

        <div>
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <SectionLabel className="mb-0">Hunt query</SectionLabel>
            {options.length > 0 && (
              <Select value={platform} onChange={(e) => setPlatform(e.target.value as PlatformKey)} className="h-8 w-auto text-[13px]" aria-label="Query platform">
                {options.map((p) => (
                  <option key={p.key} value={p.key}>
                    {p.label}
                  </option>
                ))}
              </Select>
            )}
          </div>
          <CodeBlock code={code} label={languageLabel} />
          <p className="mt-2 text-xs text-fg-subtle">
            Starting point only — validate field names and tune for the client environment before running.
          </p>
        </div>

        <div>
          <SectionLabel>Indicator pattern</SectionLabel>
          <p className="break-words font-mono text-[12.5px] text-fg-muted">{pkg.logPattern}</p>
        </div>
      </div>
    </Modal>
  );
};
