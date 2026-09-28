import React, { useState, useEffect } from 'react';
import { DeckSlide, GeneratedDeck } from '../types';
import { MITRE_TACTICS, MITRE_TECHNIQUES } from '../data/mitreAttck';
import { fetchDeckNarrative } from '../services/api';
import { useApp } from '../app/AppContext';
import { isEscalated, summarise } from '../lib/iocHunts';
import { exportDeckPptx } from '../lib/deckPptx';
import { Button, PageHeader, Segmented, useToast } from './ui';
import {
  Sparkles,
  FileDown,
  ChevronLeft,
  ChevronRight,
  Maximize2,
  Minimize2,
  CheckCircle2,
  ShieldAlert,
} from 'lucide-react';

const now = new Date();
const QUARTER_LABEL = `Q${Math.floor(now.getMonth() / 3) + 1} ${now.getFullYear()}`;
const MONTH_LABEL = now.toLocaleDateString('en-US', { month: 'long', year: 'numeric' });

export const DeckGeneratorView: React.FC = () => {
  const { currentClient, clientReports, clientIocHunts } = useApp();
  const [exporting, setExporting] = useState(false);
  const toast = useToast();
  const [periodType, setPeriodType] = useState<'monthly' | 'quarterly'>('quarterly');
  const [periodLabel, setPeriodLabel] = useState(`${QUARTER_LABEL} threat hunting briefing`);
  const [activeSlideIndex, setActiveSlideIndex] = useState(0);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [deck, setDeck] = useState<GeneratedDeck | null>(null);
  const totalHunts = clientReports.length;
  const truePositives = clientReports.filter((r) => r.outcome === 'True Positive');
  const tpCount = truePositives.length;
  const tpRate = totalHunts > 0 ? `${Math.round((tpCount / totalHunts) * 100)}%` : '0%';

  // Technique calculations
  const coveredTechniqueIds = new Set<string>();
  clientReports.forEach((r) => {
    r.techniqueIds.forEach((t) => {
      coveredTechniqueIds.add(t);
      coveredTechniqueIds.add(t.split('.')[0]);
    });
  });
  const coveredCount = MITRE_TECHNIQUES.filter((t) => coveredTechniqueIds.has(t.id)).length;
  const totalTechniques = MITRE_TECHNIQUES.length;
  const uncoveredCount = totalTechniques - coveredCount;

  // Severity metrics
  const criticalHunts = clientReports.filter((r) => r.severityScore?.severityLevel === 'Critical');
  const highHunts = clientReports.filter((r) => r.severityScore?.severityLevel === 'High');
  const mediumHunts = clientReports.filter((r) => r.severityScore?.severityLevel === 'Medium');

  // Daily IOC hunts in the deck period (rows without a date are included).
  const periodStart = periodType === 'monthly'
    ? new Date(now.getFullYear(), now.getMonth(), 1)
    : new Date(now.getFullYear(), Math.floor(now.getMonth() / 3) * 3, 1);
  const periodIoc = clientIocHunts.filter((h) => !h.date || new Date(h.date) >= periodStart);
  const iocSummary = summarise(periodIoc);

  // Build default or AI-driven slides
  const buildDeck = (narrative?: {
    executiveSummary: string;
    topThreatTakeaways: string[];
    criticalBlindSpots: string[];
    nextQuarterRoadmap: string[];
  }): GeneratedDeck => {
    // Data-only draft: every statement is derived from recorded reports. Analysts edit/extend before sharing.
    const uncoveredTactics = MITRE_TACTICS.filter(
      (tac) => !MITRE_TECHNIQUES.some((t) => t.tactic === tac.name && coveredTechniqueIds.has(t.id)),
    ).map((t) => t.name);
    const followUps = clientReports.filter((r) => r.outcome === 'Needs Follow-up').length;
    const defaultNarrative = {
      executiveSummary: `${totalHunts} hypothesis-driven hunts were recorded for ${currentClient.name} this period. ${tpCount} returned confirmed true positives (${tpRate} of hunts) and ${followUps} need follow-up. Hunting has covered ${coveredCount} of ${totalTechniques} catalog ATT&CK techniques.`,
      topThreatTakeaways: [
        `${tpCount} confirmed true positive${tpCount === 1 ? '' : 's'} across ${totalHunts} hunts.`,
        `${criticalHunts.length} critical and ${highHunts.length} high severity findings scored.`,
        `${coveredCount} ATT&CK techniques hunted to date.`,
      ],
      criticalBlindSpots: [
        `${uncoveredCount} catalog techniques have not been hunted.`,
        uncoveredTactics.length
          ? `Tactics with no hunts: ${uncoveredTactics.join(', ')}.`
          : 'Every ATT&CK tactic has at least one hunt.',
      ],
      nextQuarterRoadmap: [
        uncoveredTactics.length ? `Run first hunts for ${uncoveredTactics.slice(0, 2).join(' and ')}.` : 'Deepen coverage of partially hunted tactics.',
        followUps ? `Close out ${followUps} open follow-up finding${followUps === 1 ? '' : 's'}.` : 'Promote validated hunt queries to detection rules.',
        'Review telemetry gaps with the client and onboard missing data sources.',
      ],
    };

    const finalNarrative = narrative || defaultNarrative;

    const slides: DeckSlide[] = [
      // Slide 1: Title
      {
        id: 'slide-1',
        title: 'Executive Threat Hunting Report',
        subtitle: `${currentClient.name} · ${periodLabel}`,
        type: 'title',
        content: {
          clientName: currentClient.name,
          industry: currentClient.industry.toUpperCase(),
          date: MONTH_LABEL,
          preparedBy: 'Threat Hunting Team',
        }
      },
      // Slide 2: Executive Summary
      {
        id: 'slide-2',
        title: 'Executive Overview & Strategic Threat Posture',
        subtitle: 'Leadership briefing on verified coverage, proactive defense, and risk mitigation',
        type: 'executive_summary',
        content: {
          summary: finalNarrative.executiveSummary,
          takeaways: finalNarrative.topThreatTakeaways,
        }
      },
      // Slide 3: KPI Performance
      {
        id: 'slide-3',
        title: 'Threat Hunting Operations & Detection Outcomes',
        subtitle: 'Quantitative metrics of investigations executed and threat validation rates',
        type: 'kpi_performance',
        content: {
          totalHunts,
          followUps: clientReports.filter((r) => r.outcome === 'Needs Follow-up').length,
          tpCount,
          tpRate,
          breakdown: {
            truePositives: tpCount,
            falsePositives: clientReports.filter((r) => r.outcome === 'False Positive').length,
            noResults: clientReports.filter((r) => r.outcome === 'No Result').length,
            needsFollowUp: clientReports.filter((r) => r.outcome === 'Needs Follow-up').length,
          }
        }
      },
      // Daily threat intel IOC hunting
      {
        id: 'slide-ioc',
        title: 'Daily Threat Intel IOC Hunting',
        subtitle: 'IOC sweeps and CVE exposure checks performed against your environment',
        type: 'ioc_hunting',
        content: {
          ...iocSummary,
          periodNote: periodType === 'monthly' ? MONTH_LABEL : QUARTER_LABEL,
          escalations: periodIoc
            .filter(isEscalated)
            .sort((a, b) => (b.date ?? '').localeCompare(a.date ?? ''))
            .map((h) => ({ date: h.date, title: h.title, escalation: h.escalation, results: h.results })),
        },
      },
      // Slide 4: MITRE Heatmap & Matrix Coverage
      {
        id: 'slide-4',
        title: 'MITRE ATT&CK® Enterprise Matrix Coverage',
        subtitle: `${coveredCount} of ${totalTechniques} techniques verified against active adversary TTPs`,
        type: 'mitre_coverage_heatmap',
        content: {
          coveredCount,
          totalTechniques,
          percent: Math.round((coveredCount / totalTechniques) * 100),
          tacticsSummary: MITRE_TACTICS.map((tac) => {
            const inTac = MITRE_TECHNIQUES.filter((t) => t.tactic === tac.name);
            const cov = inTac.filter((t) => coveredTechniqueIds.has(t.id)).length;
            return {
              name: tac.name,
              code: tac.shortCode,
              covered: cov,
              total: inTac.length,
            };
          })
        }
      },
      // Slide 5: Findings & Severity Distribution
      {
        id: 'slide-5',
        title: 'Intercepted Threats & Severity Breakdown',
        subtitle: 'Validated true positive findings prioritized by the 4-factor SOC severity model',
        type: 'severity_distribution',
        content: {
          criticalCount: criticalHunts.length,
          highCount: highHunts.length,
          mediumCount: mediumHunts.length,
          findings: clientReports.filter((r) => r.outcome === 'True Positive' || (r.severityScore && r.severityScore.compositeScore >= 70)).slice(0, 3),
        }
      },
      // Slide 6: Blind Spots & High-Risk Gaps
      {
        id: 'slide-6',
        title: 'Identified Blind Spots & Attack Surface Gaps',
        subtitle: 'Techniques with highest residual risk and absent telemetry feeds',
        type: 'blind_spots',
        content: {
          gaps: finalNarrative.criticalBlindSpots,
          uncoveredTechniqueSamples: MITRE_TECHNIQUES.filter((t) => !coveredTechniqueIds.has(t.id)).slice(0, 4),
        }
      },
      // Slide 7: Strategic Roadmap
      {
        id: 'slide-7',
        title: 'Strategic Threat Hunting Roadmap & Next Steps',
        subtitle: 'Planned hunting campaigns, telemetry expansion, and engineering handoffs',
        type: 'strategic_roadmap',
        content: {
          roadmap: finalNarrative.nextQuarterRoadmap,
        }
      }
    ];

    return {
      id: `deck-${Date.now()}`,
      clientId: currentClient.id,
      clientName: currentClient.name,
      industry: currentClient.industry,
      periodType,
      periodLabel,
      dateRange: periodType === 'quarterly' ? QUARTER_LABEL : MONTH_LABEL,
      generatedAt: new Date().toISOString(),
      generatedBy: 'Blindspot',
      narrativeSummary: finalNarrative.executiveSummary,
      slides,
    };
  };

  useEffect(() => {
    setDeck(buildDeck());
  }, [currentClient.id, periodLabel, clientIocHunts]);

  const handleGenerateAiDeck = async () => {
    setGenerating(true);
    try {
      const res = await fetchDeckNarrative(currentClient, periodLabel, { totalHunts, tpRate }, coveredCount, totalTechniques, tpCount);
      if (res.fallback) {
        // The server's canned narrative isn't about this client; keep the data-only draft.
        toast('AI service unavailable — the deck keeps the data-only narrative.', 'info');
        return;
      }
      setDeck(buildDeck(res.data));
      setActiveSlideIndex(0);
      toast('Narrative drafted with AI. Review it before sharing.');
    } catch {
      toast('Could not reach the AI service.', 'error');
    } finally {
      setGenerating(false);
    }
  };

  const handleExport = async () => {
    if (!deck) return;
    setExporting(true);
    try {
      await exportDeckPptx(deck, currentClient);
      toast('PowerPoint deck downloaded.');
    } catch {
      toast('Could not build the PowerPoint file.', 'error');
    } finally {
      setExporting(false);
    }
  };

  const currentSlide = deck?.slides[activeSlideIndex];

  return (
    <div className="space-y-6">
      <div className="no-print">
        <PageHeader
          title="Executive decks"
          description="A briefing deck built from this client's recorded hunts, findings and coverage."
          actions={
            <>
              <Segmented<'monthly' | 'quarterly'>
                ariaLabel="Period"
                size="md"
                value={periodType}
                onChange={(p) => {
                  setPeriodType(p);
                  setPeriodLabel(p === 'monthly' ? `${MONTH_LABEL} threat hunting briefing` : `${QUARTER_LABEL} threat hunting briefing`);
                }}
                options={[
                  { value: 'monthly', label: 'Monthly' },
                  { value: 'quarterly', label: 'Quarterly' },
                ]}
              />
              <Button icon={Sparkles} loading={generating} onClick={handleGenerateAiDeck}>
                Draft narrative with AI
              </Button>
              <Button variant="primary" icon={FileDown} loading={exporting} onClick={handleExport}>
                Export PowerPoint
              </Button>
            </>
          }
        />
      </div>

      {/* Main Slide Deck Stage */}
      {deck && currentSlide && (
        <div className={`space-y-4 ${isFullscreen ? 'fixed inset-0 z-50 bg-slate-950 p-8 flex flex-col justify-between overflow-y-auto' : ''}`}>
          {/* Deck Presenter Box */}
          <div className="bg-surface border border-border rounded-lg p-8 sm:p-12 min-h-[500px] flex flex-col justify-between relative">
            {/* Slide Header */}
            <div className="flex items-start justify-between border-b border-slate-800/80 pb-4">
              <div>
                <span className="text-[11px] font-mono uppercase tracking-widest text-cyan-400 font-semibold">
                  {currentClient.name} · {periodLabel}
                </span>
                <h2 className="text-2xl font-bold text-white tracking-tight mt-1">{currentSlide.title}</h2>
                <p className="text-xs text-slate-400 mt-0.5">{currentSlide.subtitle}</p>
              </div>

              <div className="no-print flex items-center gap-2">
                <span className="text-xs font-mono text-slate-500">
                  Slide {activeSlideIndex + 1} of {deck.slides.length}
                </span>
                <button
                  onClick={() => setIsFullscreen(!isFullscreen)}
                  className="p-1.5 text-slate-400 hover:text-white rounded hover:bg-slate-800"
                  title="Toggle Fullscreen Presentation Mode"
                >
                  {isFullscreen ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Slide Body by Type */}
            <div className="py-6 flex-1 flex flex-col justify-center">
              {/* Type: Title Slide */}
              {currentSlide.type === 'title' && (
                <div className="text-center py-12 space-y-6 max-w-2xl mx-auto">
                  <div className="w-14 h-14 rounded-xl bg-accent-soft flex items-center justify-center mx-auto">
                    <ShieldAlert className="w-7 h-7 text-accent" />
                  </div>
                  <div>
                    <h1 className="text-3xl font-extrabold text-white tracking-tight sm:text-4xl">
                      {currentClient.name}
                    </h1>
                    <p className="text-lg text-cyan-300 font-mono mt-2 font-medium">
                      {periodLabel}
                    </p>
                  </div>
                  <div className="pt-4 border-t border-slate-800/80 text-xs text-slate-400 flex justify-center gap-6 font-mono">
                    <span>Sector: {currentClient.industry.toUpperCase()}</span>
                    <span>·</span>
                    <span>{currentSlide.content.date}</span>
                    <span>·</span>
                    <span>Prepared by {currentSlide.content.preparedBy}</span>
                  </div>
                </div>
              )}

              {/* Type: Executive Summary */}
              {currentSlide.type === 'executive_summary' && (
                <div className="space-y-6 max-w-4xl">
                  <div className="bg-slate-950/80 border border-slate-800/80 rounded-lg p-5">
                    <p className="text-sm text-slate-200 leading-relaxed font-normal">
                      {currentSlide.content.summary}
                    </p>
                  </div>

                  <div>
                    <h4 className="text-xs font-bold text-cyan-400 uppercase tracking-wider mb-3">
                      Key takeaways
                    </h4>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                      {currentSlide.content.takeaways.map((point: string, i: number) => (
                        <div key={i} className="bg-slate-950/60 border border-slate-800 p-3.5 rounded-lg space-y-1.5">
                          <div className="flex items-center gap-1.5 text-xs font-bold text-white">
                            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                            <span>Finding 0{i + 1}</span>
                          </div>
                          <p className="text-xs text-slate-300 leading-relaxed">{point}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* Type: KPI Performance */}
              {currentSlide.type === 'kpi_performance' && (
                <div className="space-y-6">
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                    <div className="bg-slate-950 p-5 rounded-lg border border-slate-800 text-center space-y-1">
                      <div className="text-xs font-semibold text-slate-400 uppercase">Hypotheses Tested</div>
                      <div className="text-4xl font-bold font-mono text-white tabular-nums">
                        {currentSlide.content.totalHunts}
                      </div>
                      <div className="text-[11px] text-slate-500">Structured investigations</div>
                    </div>
                    <div className="bg-slate-950 p-5 rounded-lg border border-slate-800 text-center space-y-1">
                      <div className="text-xs font-semibold text-slate-400 uppercase">Open follow-ups</div>
                      <div className="text-4xl font-bold font-mono text-cyan-300 tabular-nums">
                        {currentSlide.content.followUps}
                      </div>
                      <div className="text-[11px] text-slate-500">Findings still being worked</div>
                    </div>
                    <div className="bg-slate-950 p-5 rounded-lg border border-slate-800 text-center space-y-1">
                      <div className="text-xs font-semibold text-slate-400 uppercase">True Positives</div>
                      <div className="text-4xl font-bold font-mono text-emerald-400 tabular-nums">
                        {currentSlide.content.tpCount}
                      </div>
                      <div className="text-[11px] text-slate-500">Confirmed malicious activity</div>
                    </div>
                    <div className="bg-slate-950 p-5 rounded-lg border border-slate-800 text-center space-y-1">
                      <div className="text-xs font-semibold text-slate-400 uppercase">Hit Rate</div>
                      <div className="text-4xl font-bold font-mono text-white tabular-nums">
                        {currentSlide.content.tpRate}
                      </div>
                      <div className="text-[11px] text-slate-500">True positives / hunts</div>
                    </div>
                  </div>

                  <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 flex items-center justify-between text-xs">
                    <span className="text-slate-400 font-medium">Outcome Distribution:</span>
                    <div className="flex items-center gap-6 font-mono text-xs">
                      <span className="text-emerald-400">TP: {currentSlide.content.breakdown.truePositives}</span>
                      <span className="text-amber-400">FP: {currentSlide.content.breakdown.falsePositives}</span>
                      <span className="text-slate-400">No Result: {currentSlide.content.breakdown.noResults}</span>
                      <span className="text-cyan-400">Follow-up: {currentSlide.content.breakdown.needsFollowUp}</span>
                    </div>
                  </div>
                </div>
              )}

              {/* Type: Daily IOC hunting */}
              {currentSlide.type === 'ioc_hunting' && (
                <div className="space-y-5">
                  <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                    {[
                      { label: 'IOC hunts performed', value: currentSlide.content.total, color: 'text-fg' },
                      { label: 'Hunts with results', value: currentSlide.content.withResults, color: 'text-warning-text' },
                      { label: 'Escalated', value: currentSlide.content.escalated, color: 'text-danger-text' },
                      { label: 'Queries run', value: currentSlide.content.totalQueries, color: 'text-teal-text' },
                    ].map((k) => (
                      <div key={k.label} className="space-y-1 rounded-lg border border-border bg-canvas p-5 text-center">
                        <div className="text-xs font-semibold uppercase text-fg-muted">{k.label}</div>
                        <div className={`text-4xl font-bold tabular-nums ${k.color}`}>{k.value}</div>
                      </div>
                    ))}
                  </div>
                  <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                    <div className="rounded-lg border border-border bg-canvas p-4">
                      <div className="mb-3 text-xs font-semibold uppercase text-fg-muted">Threat category weightage</div>
                      {currentSlide.content.categories.length === 0 && <p className="text-xs text-fg-subtle">No IOC hunts recorded this period.</p>}
                      <ul className="space-y-2">
                        {currentSlide.content.categories.slice(0, 8).map((c: any) => (
                          <li key={c.name} className="grid grid-cols-[6rem_1fr_3.5rem] items-center gap-2 text-xs">
                            <span className="truncate text-fg">{c.name}</span>
                            <span className="h-2 overflow-hidden rounded-full bg-surface-3">
                              <span className="block h-full rounded-full bg-accent" style={{ width: `${c.percent}%` }} />
                            </span>
                            <span className="text-right tabular-nums text-fg-muted">{c.percent}%</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                    <div className="rounded-lg border border-border bg-canvas p-4">
                      <div className="mb-3 text-xs font-semibold uppercase text-fg-muted">Escalations</div>
                      {currentSlide.content.escalations.length === 0 ? (
                        <p className="text-xs text-fg-subtle">No IOC hunts were escalated this period.</p>
                      ) : (
                        <ul className="space-y-2 text-xs">
                          {currentSlide.content.escalations.slice(0, 6).map((e: any) => (
                            <li key={e.escalation + e.title} className="flex items-start justify-between gap-3">
                              <span className="text-fg">{e.title}</span>
                              <span className="shrink-0 font-mono text-danger-text">{e.escalation}</span>
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {/* Type: MITRE Coverage Heatmap */}
              {currentSlide.type === 'mitre_coverage_heatmap' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between text-xs bg-slate-950 p-3 rounded border border-slate-800">
                    <span className="font-semibold text-slate-300">
                      Enterprise ATT&CK Coverage: {currentSlide.content.coveredCount} / {currentSlide.content.totalTechniques} Techniques ({currentSlide.content.percent}%)
                    </span>
                    <div className="w-48 bg-slate-800 h-2 rounded overflow-hidden">
                      <div style={{ width: `${currentSlide.content.percent}%` }} className="bg-cyan-500 h-full" />
                    </div>
                  </div>

                  {/* Tactics Coverage Grid */}
                  <div className="grid grid-cols-2 sm:grid-cols-7 gap-2 text-xs">
                    {currentSlide.content.tacticsSummary.map((tac: any) => (
                      <div key={tac.code} className="bg-slate-950 p-2.5 rounded border border-slate-800/80 space-y-1">
                        <div className="flex justify-between font-mono text-[10px] text-slate-400">
                          <span>{tac.code}</span>
                          <span className={tac.covered > 0 ? 'text-cyan-400 font-bold' : 'text-slate-600'}>
                            {tac.covered}/{tac.total}
                          </span>
                        </div>
                        <div className="font-medium text-slate-200 truncate text-[11px]">{tac.name}</div>
                        <div className="w-full bg-slate-800 h-1 rounded overflow-hidden mt-1">
                          <div style={{ width: `${(tac.covered / (tac.total || 1)) * 100}%` }} className="bg-cyan-500 h-full" />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Type: Severity Distribution */}
              {currentSlide.type === 'severity_distribution' && (
                <div className="space-y-4">
                  <div className="grid grid-cols-3 gap-4 text-center">
                    <div className="bg-rose-950/40 border border-rose-800 p-4 rounded-lg">
                      <div className="text-xs font-semibold text-rose-300 uppercase">Critical Severity</div>
                      <div className="text-3xl font-bold font-mono text-rose-400 mt-1">{currentSlide.content.criticalCount}</div>
                    </div>
                    <div className="bg-amber-950/40 border border-amber-800 p-4 rounded-lg">
                      <div className="text-xs font-semibold text-amber-300 uppercase">High Severity</div>
                      <div className="text-3xl font-bold font-mono text-amber-400 mt-1">{currentSlide.content.highCount}</div>
                    </div>
                    <div className="bg-cyan-950/40 border border-cyan-800 p-4 rounded-lg">
                      <div className="text-xs font-semibold text-cyan-300 uppercase">Medium Severity</div>
                      <div className="text-3xl font-bold font-mono text-cyan-400 mt-1">{currentSlide.content.mediumCount}</div>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div className="text-xs font-bold text-slate-400 uppercase tracking-wider">
                      Featured Threat Finding Case Studies
                    </div>
                    {currentSlide.content.findings.map((f: any) => (
                      <div key={f.id} className="bg-slate-950 p-3 rounded border border-slate-800 flex justify-between items-center text-xs">
                        <div>
                          <div className="font-semibold text-white">{f.hypothesisTitle}</div>
                          <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                            {f.weekRange} · {f.techniqueIds.join(', ')}
                          </div>
                        </div>
                        {f.severityScore && (
                          <span className="font-mono text-rose-400 font-bold px-2 py-0.5 rounded bg-rose-950 border border-rose-900">
                            {f.severityScore.compositeScore}/100 ({f.severityScore.severityLevel})
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Type: Blind Spots */}
              {currentSlide.type === 'blind_spots' && (
                <div className="space-y-5">
                  <div className="bg-rose-950/20 border border-rose-800/40 p-4 rounded-lg space-y-2">
                    <h4 className="text-xs font-bold text-rose-300 uppercase tracking-wider flex items-center gap-1.5">
                      <ShieldAlert className="w-4 h-4 text-rose-400" />
                      <span>Executive Risk: Uncovered Adversary TTPs</span>
                    </h4>
                    <ul className="space-y-2 text-xs text-slate-200">
                      {currentSlide.content.gaps.map((gap: string, idx: number) => (
                        <li key={idx} className="flex items-start gap-2">
                          <span className="text-rose-400 font-bold">›</span>
                          <span>{gap}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div>
                    <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">
                      Priority Matrix Blind Spots for Immediate Focus
                    </h4>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                      {currentSlide.content.uncoveredTechniqueSamples.map((tech: any) => (
                        <div key={tech.id} className="bg-slate-950 p-2.5 rounded border border-slate-800">
                          <div className="flex justify-between font-mono text-[10px] text-cyan-400">
                            <span>{tech.id}</span>
                            <span className="text-slate-400">{tech.tactic}</span>
                          </div>
                          <div className="font-semibold text-white mt-0.5">{tech.name}</div>
                          <div className="text-[11px] text-slate-400 truncate mt-1">{tech.description}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* Type: Strategic Roadmap */}
              {currentSlide.type === 'strategic_roadmap' && (
                <div className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {currentSlide.content.roadmap.map((item: string, idx: number) => (
                      <div key={idx} className="bg-slate-950 p-4 rounded-lg border border-slate-800 space-y-2">
                        <div className="flex items-center gap-2 font-mono text-cyan-400 font-bold text-xs">
                          <span className="w-5 h-5 rounded-full bg-cyan-950 border border-cyan-800 flex items-center justify-center text-[10px]">
                            {idx + 1}
                          </span>
                          <span>PHASE 0{idx + 1}</span>
                        </div>
                        <p className="text-xs text-slate-200 leading-relaxed">{item}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Slide Footer */}
            <div className="border-t border-slate-800/80 pt-3 flex items-center justify-between text-[11px] text-slate-500 font-mono">
              <span>Confidential</span>
              <span>{currentClient.name}</span>
            </div>
          </div>

          {/* Slide Deck Navigation Bar (hidden in print) */}
          <div className="no-print flex items-center justify-between bg-slate-900 border border-slate-800 rounded-lg p-3">
            <button
              onClick={() => setActiveSlideIndex(Math.max(0, activeSlideIndex - 1))}
              disabled={activeSlideIndex === 0}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-semibold text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 disabled:opacity-40 cursor-pointer"
            >
              <ChevronLeft className="w-4 h-4" />
              <span>Previous Slide</span>
            </button>

            {/* Slide Thumbnail dots */}
            <div className="flex items-center gap-1.5 overflow-x-auto px-2">
              {deck.slides.map((s, idx) => (
                <button
                  key={s.id}
                  onClick={() => setActiveSlideIndex(idx)}
                  className={`px-2.5 py-1 rounded text-[11px] font-mono transition-colors cursor-pointer ${
                    activeSlideIndex === idx
                      ? 'bg-cyan-600 text-white font-bold'
                      : 'bg-slate-800/60 text-slate-400 hover:bg-slate-800'
                  }`}
                >
                  {idx + 1}
                </button>
              ))}
            </div>

            <button
              onClick={() => setActiveSlideIndex(Math.min(deck.slides.length - 1, activeSlideIndex + 1))}
              disabled={activeSlideIndex === deck.slides.length - 1}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-semibold text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 disabled:opacity-40 cursor-pointer"
            >
              <span>Next Slide</span>
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

    </div>
  );
};
