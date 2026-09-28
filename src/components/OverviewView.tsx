import React, { useMemo } from 'react';
import { ArrowLeft, ArrowRight, FileText, Plus, ShieldAlert, Crosshair, Radar, Target, Grid3X3, ShieldCheck } from 'lucide-react';
import { useApp } from '../app/AppContext';
import { SECTOR_THREAT_INTEL } from '../data/mockData';
import { coveredTechniqueSet, coverageSummary, formatDate } from '../lib/coverage';
import { computePriority } from '../lib/huntPriority';
import { sourceDef } from '../lib/huntCatalog';
import { Badge, Button, Card, CardHeader, EmptyState, Stat, outcomeTone, severityTone } from './ui';
import { ClientLogo } from './ui/ClientLogo';
import { TacticCoverage } from './overview/TacticCoverage';

const SEVERITY_RANK: Record<string, number> = { Critical: 3, High: 2, Medium: 1, Low: 0 };

export const OverviewView: React.FC = () => {
  const { currentClient, clientReports, clientHunts, clientRules, navigate, startReport, openThr } = useApp();

  const covered = useMemo(() => coveredTechniqueSet(clientReports), [clientReports]);
  const coverage = coverageSummary(covered);

  const total = clientReports.length;
  const tpCount = clientReports.filter((r) => r.outcome === 'True Positive').length;
  const tpRate = total ? Math.round((tpCount / total) * 100) : 0;
  const last30 = clientReports.filter((r) => Date.now() - new Date(r.createdAt).getTime() < 30 * 86400000).length;
  const prodRules = clientRules.filter((r) => r.status === 'Production Active').length;

  // Findings worth attention: scored High/Critical, or unscored true positives / follow-ups.
  const findings = useMemo(
    () =>
      clientReports
        .filter(
          (r) =>
            (r.severityScore && SEVERITY_RANK[r.severityScore.severityLevel] >= 2) ||
            (!r.severityScore && (r.outcome === 'True Positive' || r.outcome === 'Needs Follow-up')),
        )
        .sort((a, b) => (b.severityScore?.compositeScore ?? 0) - (a.severityScore?.compositeScore ?? 0))
        .slice(0, 5),
    [clientReports],
  );

  const queue = useMemo(
    () =>
      clientHunts
        .filter((h) => h.status !== 'done')
        .sort((a, b) => computePriority(b) - computePriority(a))
        .slice(0, 4),
    [clientHunts],
  );

  const intel = useMemo(() => SECTOR_THREAT_INTEL.filter((i) => i.sectors.includes(currentClient.industry)).slice(0, 3), [currentClient.industry]);

  return (
    <>
      <button
        type="button"
        onClick={() => navigate('clients')}
        className="mb-4 inline-flex items-center gap-1.5 text-[13px] text-fg-muted hover:text-fg"
      >
        <ArrowLeft className="size-4" /> All clients
      </button>

      {/* Client profile */}
      <Card className="mb-6">
        <div className="flex flex-col gap-5 p-5 sm:flex-row sm:items-start">
          <ClientLogo client={currentClient} size="lg" />
          <div className="min-w-0 flex-1">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
              <div className="min-w-0">
                <h1 className="text-2xl font-semibold tracking-tight text-fg">{currentClient.name}</h1>
                <p className="mt-1 text-sm text-fg-muted">
                  <span className="capitalize">{currentClient.industry}</span> · {currentClient.threatProfile.riskTolerance} risk tolerance
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <Button icon={FileText} onClick={openThr}>
                  Create THR
                </Button>
                <Button variant="primary" icon={Plus} onClick={() => startReport()}>
                  New hypothesis record
                </Button>
              </div>
            </div>
            <p className="mt-3 max-w-3xl text-sm leading-relaxed text-fg-muted">{currentClient.description}</p>
            <dl className="mt-4 grid grid-cols-1 gap-4 text-[13px] md:grid-cols-3">
              <ProfileList label="Telemetry onboarded" items={currentClient.primaryTelemetry} />
              <ProfileList label="Known adversaries" items={currentClient.threatProfile.primaryAdversaries} />
              <ProfileList label="Crown jewels" items={currentClient.threatProfile.topTargetedAssets} />
            </dl>
          </div>
        </div>
      </Card>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat vivid label="Hunts logged" value={total} tone="accent" icon={Crosshair} detail={`${last30} in the last 30 days`} onClick={() => navigate('reports')} />
        <Stat
          vivid
          label="True positives"
          value={tpCount}
          tone="danger"
          icon={Target}
          detail={total ? `${tpRate}% of hunts` : 'No hunts yet'}
          onClick={() => navigate('reports')}
        />
        <Stat
          vivid
          label="ATT&CK coverage"
          value={`${coverage.percent}%`}
          tone="violet"
          icon={Grid3X3}
          detail={`${coverage.covered} of ${coverage.total} techniques hunted`}
          onClick={() => navigate('coverage')}
        />
        <Stat
          vivid
          label="Detection rules"
          value={clientRules.length}
          tone="teal"
          icon={ShieldCheck}
          detail={`${prodRules} in production`}
          onClick={() => navigate('detections')}
        />
      </div>

      <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          {/* Findings */}
          <Card>
            <CardHeader
              tone="danger"
              title="Findings needing attention"
              description="High or critical severity, and unscored true positives or follow-ups."
              actions={
                <Button size="sm" variant="ghost" iconRight={ArrowRight} onClick={() => navigate('reports')}>
                  All records
                </Button>
              }
            />
            {findings.length === 0 ? (
              <EmptyState icon={ShieldAlert} title="Nothing needs attention" description="No high-severity findings for this client." />
            ) : (
              <ul className="divide-y divide-border">
                {findings.map((r) => (
                  <li key={r.id}>
                    <button
                      type="button"
                      onClick={() => navigate('reports', { id: r.id })}
                      className="flex w-full items-start gap-4 px-5 py-3.5 text-left transition-colors hover:bg-surface-2"
                    >
                      <div className="min-w-0 flex-1">
                        <div className="truncate text-sm font-medium text-fg">{r.hypothesisTitle}</div>
                        <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-fg-muted">
                          <span>{r.analystName}</span>
                          <span className="text-fg-subtle">·</span>
                          <span>{formatDate(r.createdAt)}</span>
                          <span className="text-fg-subtle">·</span>
                          <span className="font-mono">{r.techniqueIds.slice(0, 3).join(', ')}</span>
                        </div>
                      </div>
                      <div className="flex shrink-0 flex-col items-end gap-1">
                        {r.severityScore ? (
                          <Badge tone={severityTone(r.severityScore.severityLevel)}>
                            {r.severityScore.severityLevel} · {r.severityScore.compositeScore}
                          </Badge>
                        ) : (
                          <Badge tone="neutral">Not scored</Badge>
                        )}
                        <Badge tone={outcomeTone(r.outcome)}>{r.outcome}</Badge>
                      </div>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          {/* Coverage by tactic */}
          <TacticCoverage covered={covered} onStartHunt={startReport} onOpenCoverage={() => navigate('coverage')} />
        </div>

        <div className="space-y-6">
          {/* Hunt queue */}
          <Card>
            <CardHeader
              tone="teal"
              title="Hunt queue"
              actions={
                <Button size="sm" variant="ghost" iconRight={ArrowRight} onClick={() => navigate('hunts')}>
                  Open
                </Button>
              }
            />
            {queue.length === 0 ? (
              <EmptyState icon={Crosshair} title="Queue is empty" description="Generate new hunt ideas from What's New." />
            ) : (
              <ul className="divide-y divide-border">
                {queue.map((h) => (
                  <li key={h.id}>
                    <button
                      type="button"
                      onClick={() => navigate('hunts', { id: h.id })}
                      className="w-full px-5 py-3 text-left transition-colors hover:bg-surface-2"
                    >
                      <div className="flex items-center gap-2">
                        <Badge tone={severityTone(h.priority)}>{h.priority}</Badge>
                        <Badge tone={sourceDef(h.source).tone}>{sourceDef(h.source).label}</Badge>
                      </div>
                      <div className="mt-1.5 line-clamp-2 text-[13px] font-medium text-fg">{h.hypothesisName}</div>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          {/* Threat intelligence for the client's sector */}
          <Card>
            <CardHeader
              tone="pink"
              title="Threat Intelligence [TTP Hunts]"
              description={
                <>
                  Sector: <span className="font-medium capitalize text-fg">{currentClient.industry}</span>
                </>
              }
              actions={
                <Button size="sm" variant="ghost" iconRight={ArrowRight} onClick={() => navigate('intel')}>
                  All intel
                </Button>
              }
            />
            {intel.length === 0 ? (
              <EmptyState icon={Radar} title="No threat intelligence" description={`No TTP advisories tagged for the ${currentClient.industry} sector.`} />
            ) : (
              <ul className="divide-y divide-border">
                {intel.map((i) => (
                  <li key={i.id}>
                    <button
                      type="button"
                      onClick={() => navigate('intel', { id: i.id })}
                      className="w-full px-5 py-3 text-left transition-colors hover:bg-surface-2"
                    >
                      <div className="flex items-center gap-2 text-xs text-fg-subtle">
                        <Badge tone={i.urgency === 'Critical' ? 'danger' : 'warning'}>{i.urgency}</Badge>
                        <span>{i.publishedDate}</span>
                      </div>
                      <div className="mt-1.5 line-clamp-2 text-[13px] font-medium text-fg">{i.title}</div>
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

const ProfileList: React.FC<{ label: string; items: string[] }> = ({ label, items }) => (
  <div>
    <dt className="mb-1.5 text-xs font-medium uppercase tracking-wide text-fg-subtle">{label}</dt>
    <dd className="flex flex-wrap gap-1.5">
      {items.length ? items.map((i) => <Badge key={i}>{i}</Badge>) : <span className="text-fg-subtle">None recorded</span>}
    </dd>
  </div>
);
