import React, { useMemo } from 'react';
import { ArrowRight, FileText, Plus, ShieldAlert, Crosshair, Radar } from 'lucide-react';
import { useApp } from '../app/AppContext';
import { SECTOR_THREAT_INTEL } from '../data/mockData';
import { coveredTechniqueSet, coverageSummary, formatDate, tacticCoverage } from '../lib/coverage';
import { computePriority } from '../lib/huntPriority';
import { Badge, Button, Card, CardHeader, EmptyState, Meter, PageHeader, Stat, outcomeTone, severityTone } from './ui';

const SEVERITY_RANK: Record<string, number> = { Critical: 3, High: 2, Medium: 1, Low: 0 };

export const OverviewView: React.FC = () => {
  const { currentClient, clientReports, clientHunts, clientRules, navigate, startReport, openThr } = useApp();

  const covered = useMemo(() => coveredTechniqueSet(clientReports), [clientReports]);
  const coverage = coverageSummary(covered);
  const tactics = useMemo(() => tacticCoverage(covered), [covered]);

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
      <PageHeader
        title="Overview"
        description={
          <>
            {currentClient.name} · <span className="capitalize">{currentClient.industry}</span> · {currentClient.threatProfile.riskTolerance} risk
            tolerance
          </>
        }
        actions={
          <>
            <Button icon={FileText} onClick={openThr}>
              Create THR
            </Button>
            <Button variant="primary" icon={Plus} onClick={() => startReport()}>
              New hunt report
            </Button>
          </>
        }
      />

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Hunts logged" value={total} detail={`${last30} in the last 30 days`} onClick={() => navigate('reports')} />
        <Stat label="True positives" value={tpCount} detail={total ? `${tpRate}% of hunts` : 'No hunts yet'} onClick={() => navigate('reports')} />
        <Stat
          label="ATT&CK coverage"
          value={`${coverage.percent}%`}
          detail={`${coverage.covered} of ${coverage.total} techniques hunted`}
          onClick={() => navigate('coverage')}
        />
        <Stat
          label="Detection rules"
          value={clientRules.length}
          detail={`${prodRules} in production`}
          onClick={() => navigate('detections')}
        />
      </div>

      <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          {/* Findings */}
          <Card>
            <CardHeader
              title="Findings needing attention"
              description="High or critical severity, and unscored true positives or follow-ups."
              actions={
                <Button size="sm" variant="ghost" iconRight={ArrowRight} onClick={() => navigate('reports')}>
                  All reports
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
          <Card>
            <CardHeader
              title="Coverage by tactic"
              description={`${coverage.covered} of ${coverage.total} catalog techniques have at least one hunt.`}
              actions={
                <Button size="sm" variant="ghost" iconRight={ArrowRight} onClick={() => navigate('coverage')}>
                  Coverage
                </Button>
              }
            />
            <div className="grid grid-cols-1 gap-x-8 gap-y-3 px-5 py-4 sm:grid-cols-2">
              {tactics.map((t) => (
                <div key={t.id} className="min-w-0">
                  <div className="mb-1 flex items-center justify-between gap-2 text-[13px]">
                    <span className="truncate text-fg-muted">{t.name}</span>
                    <span className="shrink-0 tabular-nums text-fg-subtle">
                      {t.covered}/{t.total}
                    </span>
                  </div>
                  <Meter value={t.percent} tone={t.covered === 0 ? 'warning' : 'accent'} />
                </div>
              ))}
            </div>
          </Card>
        </div>

        <div className="space-y-6">
          {/* Hunt queue */}
          <Card>
            <CardHeader
              title="Hunt queue"
              actions={
                <Button size="sm" variant="ghost" iconRight={ArrowRight} onClick={() => navigate('hunts')}>
                  Open
                </Button>
              }
            />
            {queue.length === 0 ? (
              <EmptyState icon={Crosshair} title="Queue is empty" description="Generate new hunt ideas from Today's hunts." />
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
                        <span className="truncate text-xs text-fg-subtle">{h.source}</span>
                      </div>
                      <div className="mt-1.5 line-clamp-2 text-[13px] font-medium text-fg">{h.hypothesisName}</div>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          {/* Sector intel */}
          <Card>
            <CardHeader
              title="Sector intel"
              description={<span className="capitalize">{currentClient.industry}</span>}
              actions={
                <Button size="sm" variant="ghost" iconRight={ArrowRight} onClick={() => navigate('intel')}>
                  All intel
                </Button>
              }
            />
            {intel.length === 0 ? (
              <EmptyState icon={Radar} title="No sector intel" description="No advisories tagged for this industry." />
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
