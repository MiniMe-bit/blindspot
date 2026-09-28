import React, { useState, useMemo } from 'react';
import { ClientOrg, HuntReport, MitreTechnique, TodayHunt, SectorThreatIntel, DetectionPlatform } from '../types';
import { MITRE_TACTICS, MITRE_TECHNIQUES } from '../data/mitreAttck';
import { SECTOR_THREAT_INTEL } from '../data/mockData';
import { 
  Target, 
  Terminal, 
  CheckCircle2, 
  ShieldAlert, 
  ShieldCheck,
  ArrowUpRight, 
  Layers, 
  Sparkles, 
  ExternalLink,
  PlusCircle,
  FileSpreadsheet,
  AlertTriangle,
  Calendar,
  Search,
  Check,
  Zap,
  Filter,
  Activity,
  Play,
  Copy,
  ChevronDown,
  ChevronUp,
  X,
  Radar,
  Globe,
  Crosshair,
  Building,
  FileCode,
  FileText
} from 'lucide-react';

interface DashboardViewProps {
  currentClient: ClientOrg;
  reports: HuntReport[];
  todaysHunts: TodayHunt[];
  onNavigateTab: (tab: string) => void;
  onOpenMitreModal: (technique?: MitreTechnique) => void;
  onSelectTechniqueForHunt: (techId: string) => void;
  onDraftReportWithPackage?: (pkg: { hypothesisTitle: string; queryText: string; techniqueIds: string[]; notes: string }) => void;
  onDeployDetectionRule?: (ruleData: { ruleName: string; queryLogic: string; techniqueIds: string[]; platform: any; description: string; tactics: string[] }) => void;
  onOpenCreateTHR?: () => void;
}

// Pre-defined adversary campaigns for interactive attack chain simulation
const ADVERSARY_SCENARIOS = [
  {
    id: 'none',
    name: 'Standard Coverage View',
    description: 'Shows all enterprise techniques across the 14 MITRE tactics.',
    techniques: [] as string[],
  },
  {
    id: 'ransomware',
    name: 'BlackCat / ALPHV Ransomware Chain',
    description: 'Initial access via phishing, LSASS dumping, defense evasion via shadow copy deletion, data exfil.',
    techniques: ['T1566.001', 'T1059.001', 'T1003.001', 'T1490', 'T1048.002'],
  },
  {
    id: 'apt29',
    name: 'APT29 / Cozy Bear (Cloud & Identity Exfil)',
    description: 'Spearphishing tokens, OAuth credential abuse, PowerShell execution, cloud storage staging.',
    techniques: ['T1566.002', 'T1059.001', 'T1078.004', 'T1098', 'T1567.002'],
  },
  {
    id: 'volt_typhoon',
    name: 'Volt Typhoon (Living-off-the-Land)',
    description: 'Stealthy living-off-the-land binaries (LOLBins), WMI execution, NTDS.dit theft, network discovery.',
    techniques: ['T1047', 'T1059.001', 'T1003.003', 'T1018', 'T1087.002'],
  },
  {
    id: 'scattered_spider',
    name: 'Scattered Spider (MFA Fatigue & Okta Bypass)',
    description: 'SMS social engineering, MFA bombing, Azure AD privilege escalation, session hijacking.',
    techniques: ['T1621', 'T1078.004', 'T1556', 'T1098.001'],
  },
];

export const DashboardView: React.FC<DashboardViewProps> = ({
  currentClient,
  reports,
  todaysHunts,
  onNavigateTab,
  onOpenMitreModal,
  onSelectTechniqueForHunt,
  onDraftReportWithPackage,
  onDeployDetectionRule,
  onOpenCreateTHR,
}) => {
  // Interactive State
  const [timeRange, setTimeRange] = useState<'all' | '30d' | '7d'>('all');
  const [activeKpiFilter, setActiveKpiFilter] = useState<'all' | 'TP' | 'FP' | 'NoResult' | 'FollowUp'>('all');
  
  // Simplified MITRE Section State
  const [selectedTacticId, setSelectedTacticId] = useState<string>('all');
  const [matrixCoverageFilter, setMatrixCoverageFilter] = useState<'all' | 'gaps' | 'covered'>('all');
  const [matrixSearch, setMatrixSearch] = useState<string>('');
  const [activeScenarioId, setActiveScenarioId] = useState<string>('none');
  const [inspectedTechnique, setInspectedTechnique] = useState<MitreTechnique | null>(null);

  // Instant Gap Audit State
  const [isAuditingGaps, setIsAuditingGaps] = useState(false);
  const [gapAuditResult, setGapAuditResult] = useState<string | null>(null);

  // Telemetry Analytics Drawer State (triggered by KPI 2 click)
  const [showTelemetryModal, setShowTelemetryModal] = useState(false);

  // Expanded finding cards state
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);
  const [copiedQueryId, setCopiedQueryId] = useState<string | null>(null);

  // Simulated Telemetry Query Run State
  const [simulatingHuntId, setSimulatingHuntId] = useState<string | null>(null);
  const [simulatedLogs, setSimulatedLogs] = useState<{ [huntId: string]: string }>({});

  // Sector Threat Intel State (Replaces bottom raw technique cards with sector intel)
  const [selectedSector, setSelectedSector] = useState<string>('all');
  const [sectorSearch, setSectorSearch] = useState<string>('');
  const [selectedIntelForHunt, setSelectedIntelForHunt] = useState<SectorThreatIntel | null>(null);
  const [simulatingIntelId, setSimulatingIntelId] = useState<string | null>(null);
  const [simulatedIntelLogs, setSimulatedIntelLogs] = useState<{ [id: string]: string }>({});
  const [copiedIntelQueryId, setCopiedIntelQueryId] = useState<string | null>(null);
  const [selectedQueryPlatform, setSelectedQueryPlatform] = useState<
    'kql' | 'fql' | 'sigma' | 'sentinelone' | 'trendmicro' | 'splunk' | 'elastic'
  >('kql');

  const getIntelQueryForPlatform = (intel: SectorThreatIntel, platformKey: string): string => {
    if (intel.suggestedHuntPackage.platformQueries) {
      const customQuery = (intel.suggestedHuntPackage.platformQueries as any)[platformKey];
      if (customQuery) return customQuery;
    }
    return intel.suggestedHuntPackage.queryCode;
  };

  // Filter reports for current client and timeframe
  const clientReports = useMemo(() => {
    let list = reports.filter((r) => r.clientId === currentClient.id);
    if (timeRange === '7d') {
      const cutoff = new Date();
      cutoff.setDate(cutoff.getDate() - 7);
      list = list.filter((r) => new Date(r.createdAt) >= cutoff);
    } else if (timeRange === '30d') {
      const cutoff = new Date();
      cutoff.setDate(cutoff.getDate() - 30);
      list = list.filter((r) => new Date(r.createdAt) >= cutoff);
    }
    return list;
  }, [reports, currentClient.id, timeRange]);

  const clientTodaysHunts = todaysHunts.filter((h) => h.clientId === currentClient.id);

  // Compute KPIs
  const totalHunts = clientReports.length;
  const totalQueriesExecuted = clientReports.reduce(
    (acc, r) => acc + (r.queryText.split('\n\n').length || 1) + 2, 
    0
  );
  
  const truePositives = clientReports.filter((r) => r.outcome === 'True Positive');
  const falsePositives = clientReports.filter((r) => r.outcome === 'False Positive');
  const noResults = clientReports.filter((r) => r.outcome === 'No Result');
  const needsFollowUp = clientReports.filter((r) => r.outcome === 'Needs Follow-up');

  const tpCount = truePositives.length;
  const tpRate = totalHunts > 0 ? Math.round((tpCount / totalHunts) * 100) : 0;

  // Covered MITRE techniques calculation
  const coveredTechniqueIds = useMemo(() => {
    const set = new Set<string>();
    clientReports.forEach((r) => {
      r.techniqueIds.forEach((t) => {
        set.add(t);
        set.add(t.split('.')[0]);
      });
    });
    return set;
  }, [clientReports]);

  const totalCatalogTechniques = MITRE_TECHNIQUES.length;
  const coveredCount = MITRE_TECHNIQUES.filter((t) => coveredTechniqueIds.has(t.id)).length;
  const coveragePercent = Math.round((coveredCount / totalCatalogTechniques) * 100);
  const uncoveredCount = totalCatalogTechniques - coveredCount;

  // Active scenario details
  const activeScenario = useMemo(() => {
    return ADVERSARY_SCENARIOS.find((s) => s.id === activeScenarioId) || ADVERSARY_SCENARIOS[0];
  }, [activeScenarioId]);

  // Techniques filtered for simplified MITRE section
  const displayedTechniques = useMemo(() => {
    return MITRE_TECHNIQUES.filter((tech) => {
      // Scenario filter
      if (activeScenario.id !== 'none') {
        const inScenario = activeScenario.techniques.some(
          (tId) => tech.id === tId || tech.id.startsWith(tId) || tId.startsWith(tech.id)
        );
        if (!inScenario) return false;
      }

      // Tactic filter
      if (selectedTacticId !== 'all' && tech.tacticId !== selectedTacticId && tech.tactic !== selectedTacticId) {
        return false;
      }

      // Coverage filter
      const isCovered = coveredTechniqueIds.has(tech.id);
      if (matrixCoverageFilter === 'covered' && !isCovered) return false;
      if (matrixCoverageFilter === 'gaps' && isCovered) return false;

      // Search query
      if (matrixSearch.trim()) {
        const query = matrixSearch.toLowerCase();
        const matchesId = tech.id.toLowerCase().includes(query);
        const matchesName = tech.name.toLowerCase().includes(query);
        const matchesTactic = tech.tactic.toLowerCase().includes(query);
        if (!matchesId && !matchesName && !matchesTactic) return false;
      }
      return true;
    });
  }, [selectedTacticId, matrixCoverageFilter, matrixSearch, coveredTechniqueIds, activeScenario]);

  // Stored Severity Findings
  const severeFindings = useMemo(() => {
    let findings = clientReports.filter(
      (r) => r.severityScore && (r.severityScore.severityLevel === 'Critical' || r.severityScore.severityLevel === 'High')
    );
    if (activeKpiFilter === 'TP') {
      findings = findings.filter((r) => r.outcome === 'True Positive');
    } else if (activeKpiFilter === 'FP') {
      findings = findings.filter((r) => r.outcome === 'False Positive');
    } else if (activeKpiFilter === 'FollowUp') {
      findings = findings.filter((r) => r.outcome === 'Needs Follow-up');
    }
    return findings;
  }, [clientReports, activeKpiFilter]);

  // Instant Gap Audit Handler
  const handleRunGapAudit = () => {
    setIsAuditingGaps(true);
    setGapAuditResult(null);
    setTimeout(() => {
      const topGapTechniques = MITRE_TECHNIQUES.filter((t) => !coveredTechniqueIds.has(t.id)).slice(0, 3);
      setGapAuditResult(
        `Critical Blind Spot Identified: ${topGapTechniques.map((t) => `${t.id} (${t.name})`).join(', ')}. Recommended immediate hunt creation.`
      );
      setIsAuditingGaps(false);
    }, 700);
  };

  const handleCopyQuery = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedQueryId(id);
    setTimeout(() => setCopiedQueryId(null), 2000);
  };

  const handleSimulateHunt = (huntId: string) => {
    setSimulatingHuntId(huntId);
    setTimeout(() => {
      setSimulatedLogs((prev) => ({
        ...prev,
        [huntId]: `[2026-09-25 14:40:12 UTC] 3,420 endpoints scanned. Found 2 anomalous process executions on WORKSTATION-402 (PID: 8812) matching pattern.`,
      }));
      setSimulatingHuntId(null);
    }, 900);
  };

  // Filtered Sector Threat Intel Feed
  const displayedSectorIntels = useMemo(() => {
    return SECTOR_THREAT_INTEL.filter((intel) => {
      if (selectedSector !== 'all' && !intel.sectors.includes(selectedSector)) {
        return false;
      }
      if (sectorSearch.trim()) {
        const query = sectorSearch.toLowerCase();
        const matchTitle = intel.title.toLowerCase().includes(query);
        const matchActors = intel.threatActors.some((a) => a.toLowerCase().includes(query));
        const matchCountries = intel.targetedCountries.some((c) => c.toLowerCase().includes(query));
        const matchSummary = intel.summary.toLowerCase().includes(query);
        const matchCves = intel.cvesObserved?.some((cve) => cve.toLowerCase().includes(query));
        const matchTTPs = intel.primaryTTPs.some((t) => t.id.toLowerCase().includes(query) || t.name.toLowerCase().includes(query));
        if (!matchTitle && !matchActors && !matchCountries && !matchSummary && !matchCves && !matchTTPs) {
          return false;
        }
      }
      return true;
    });
  }, [selectedSector, sectorSearch]);

  const handleSimulateIntelHunt = (intelId: string) => {
    setSimulatingIntelId(intelId);
    setTimeout(() => {
      const now = new Date().toISOString().replace('T', ' ').slice(0, 19);
      setSimulatedIntelLogs((prev) => ({
        ...prev,
        [intelId]: `[${now} UTC] Simulated hunt query dispatched against ${currentClient.name} telemetry lakes. Evaluated 4,120 endpoint events over last 72h: 0 active intrusions matching IOC/TTP pattern — Telemetry baseline healthy.`,
      }));
      setSimulatingIntelId(null);
    }, 850);
  };

  const handleCopyIntelQuery = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedIntelQueryId(id);
    setTimeout(() => setCopiedIntelQueryId(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Top Banner: Client Info + Interactive Timeframe Selector */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2 flex-wrap">
              <h1 className="text-xl font-bold text-white tracking-tight">{currentClient.name}</h1>
              <span className="text-[11px] text-cyan-300 font-mono font-medium px-2 py-0.5 rounded bg-cyan-950/70 border border-cyan-800/40 uppercase">
                {currentClient.industry}
              </span>
              <span className="text-[11px] text-slate-400 font-mono">
                Risk Tolerance: <strong className="text-slate-200">{currentClient.threatProfile.riskTolerance}</strong>
              </span>
            </div>
            <p className="text-xs text-slate-300 max-w-3xl leading-relaxed">
              {currentClient.description}
            </p>
          </div>

          {/* Interactive Controls & Quick Actions */}
          <div className="flex items-center gap-2 shrink-0 flex-wrap">
            {/* Timeframe Filter Buttons */}
            <div className="flex items-center bg-slate-950 border border-slate-800 rounded-md p-1 text-xs">
              <Calendar className="w-3.5 h-3.5 text-slate-400 ml-1 mr-1.5" />
              {[
                { id: 'all', label: 'All Time' },
                { id: '30d', label: '30 Days' },
                { id: '7d', label: '7 Days' },
              ].map((btn) => (
                <button
                  key={btn.id}
                  onClick={() => setTimeRange(btn.id as any)}
                  className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors cursor-pointer ${
                    timeRange === btn.id
                      ? 'bg-slate-800 text-cyan-300 font-semibold shadow-sm'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {btn.label}
                </button>
              ))}
            </div>

            <button
              onClick={() => onNavigateTab('reports')}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-md bg-cyan-600 hover:bg-cyan-500 text-white transition-colors shadow-sm cursor-pointer"
            >
              <PlusCircle className="w-3.5 h-3.5" />
              <span>Log Hunt Report</span>
            </button>
            {onOpenCreateTHR && (
              <button
                onClick={onOpenCreateTHR}
                className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-bold rounded-md bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white transition-all shadow-sm cursor-pointer hover:scale-[1.02]"
                title="Create standardized 12-section Threat Hunt Report"
              >
                <FileText className="w-3.5 h-3.5" />
                <span>Create THR</span>
              </button>
            )}
            <button
              onClick={() => onNavigateTab('decks')}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-md bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors cursor-pointer"
            >
              <FileSpreadsheet className="w-3.5 h-3.5 text-cyan-400" />
              <span>Generate Deck</span>
            </button>
          </div>
        </div>

        {/* Telemetry Feeds & Threat Actors */}
        <div className="mt-4 pt-3 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-y-2 gap-x-4 text-xs text-slate-400">
          <div className="flex flex-wrap items-center gap-4">
            <div className="flex items-center gap-1.5">
              <span className="text-slate-500 font-medium">Telemetry Sources:</span>
              <span className="text-slate-300 font-mono text-[11px]">
                {currentClient.primaryTelemetry.slice(0, 3).join(', ')}
                {currentClient.primaryTelemetry.length > 3 && ` +${currentClient.primaryTelemetry.length - 3} more`}
              </span>
            </div>
            <span className="text-slate-700">|</span>
            <div className="flex items-center gap-1.5">
              <span className="text-slate-500 font-medium">Adversary Profiles:</span>
              <span className="text-amber-300/90 font-mono text-[11px]">
                {currentClient.threatProfile.primaryAdversaries.join(', ')}
              </span>
            </div>
          </div>

          {/* Quick Gap Scan Button */}
          <button
            onClick={handleRunGapAudit}
            disabled={isAuditingGaps}
            className="flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-mono text-cyan-300 bg-cyan-950/60 hover:bg-cyan-900/60 border border-cyan-800/60 rounded cursor-pointer transition-colors"
          >
            <Zap className={`w-3.5 h-3.5 ${isAuditingGaps ? 'animate-spin text-cyan-400' : 'text-cyan-400'}`} />
            <span>{isAuditingGaps ? 'Auditing Matrix...' : 'Scan Priority Gaps'}</span>
          </button>
        </div>

        {/* Gap Audit Alert banner */}
        {gapAuditResult && (
          <div className="mt-3 p-2.5 bg-amber-950/50 border border-amber-800/60 rounded-md text-xs text-amber-200 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
              <span>{gapAuditResult}</span>
            </div>
            <button
              onClick={() => {
                const firstGap = MITRE_TECHNIQUES.find((t) => !coveredTechniqueIds.has(t.id));
                if (firstGap) onSelectTechniqueForHunt(firstGap.id);
              }}
              className="px-2 py-0.5 bg-amber-600 hover:bg-amber-500 text-white rounded font-semibold text-[11px] shrink-0 cursor-pointer"
            >
              Draft Hunt Now →
            </button>
          </div>
        )}
      </div>

      {/* KPI Tiles (Interactive: click to filter findings or view telemetry analytics) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* KPI 1: Hypotheses Tested (Interactive reset) */}
        <div 
          onClick={() => setActiveKpiFilter('all')}
          className={`bg-slate-900/80 border rounded-lg p-4 transition-all cursor-pointer select-none ${
            activeKpiFilter === 'all' ? 'border-cyan-500/80 ring-1 ring-cyan-500/30 shadow-[0_0_12px_rgba(6,182,212,0.1)]' : 'border-slate-800 hover:border-slate-700'
          }`}
          title="Click to reset filters"
        >
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium uppercase tracking-wider">Hypotheses Tested</span>
            <Target className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span style={{ fontSize: '42px', color: '#3ccb0a' }} className="font-bold font-mono tabular-nums leading-tight">{totalHunts}</span>
            <span className="text-xs text-slate-400 font-mono">
              ({timeRange === 'all' ? 'all-time' : timeRange})
            </span>
          </div>
          <p className="text-[11px] text-slate-400 mt-2">
            Click to view all findings without filters
          </p>
        </div>

        {/* KPI 2: Queries Executed (Interactive telemetry breakdown modal) */}
        <div 
          onClick={() => setShowTelemetryModal(true)}
          className="bg-slate-900/80 border border-slate-800 hover:border-blue-500/60 rounded-lg p-4 transition-all cursor-pointer select-none group"
          title="Click to inspect query telemetry breakdown"
        >
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium uppercase tracking-wider">Queries Executed</span>
            <Terminal className="w-4 h-4 text-blue-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="flex items-baseline gap-2">
            <span style={{ fontSize: '42px', color: '#4a5cd5' }} className="font-bold font-mono tabular-nums leading-tight">{totalQueriesExecuted}</span>
            <span className="text-xs text-slate-400 font-mono">unified production hunts</span>
          </div>
          <div className="flex items-center justify-between text-[11px] text-blue-400 mt-2 font-medium">
            <span>Inspect query metrics</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </div>
        </div>

        {/* KPI 3: True Positive Detections (Interactive click-to-filter) */}
        <div 
          onClick={() => setActiveKpiFilter(activeKpiFilter === 'TP' ? 'all' : 'TP')}
          className={`bg-slate-900/80 border rounded-lg p-4 transition-all cursor-pointer select-none ${
            activeKpiFilter === 'TP' ? 'border-emerald-500 ring-1 ring-emerald-500/30 shadow-[0_0_12px_rgba(16,185,129,0.15)]' : 'border-slate-800 hover:border-emerald-500/60'
          }`}
          title="Click to isolate True Positive alerts"
        >
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium uppercase tracking-wider">True Positive Detections</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span style={{ fontSize: '42px' }} className="font-bold font-mono text-emerald-400 tabular-nums leading-tight">{tpCount}</span>
            <span className="text-xs font-mono text-slate-300">
              ({tpRate}% hit rate)
            </span>
          </div>
          <div className="w-full bg-slate-800 h-1.5 rounded-full mt-2 overflow-hidden flex">
            <div style={{ width: `${tpRate}%` }} className="bg-emerald-500 h-full" title={`TP: ${tpCount}`} />
            <div style={{ width: `${(falsePositives.length / (totalHunts || 1)) * 100}%` }} className="bg-amber-500 h-full" title={`FP: ${falsePositives.length}`} />
            <div style={{ width: `${(noResults.length / (totalHunts || 1)) * 100}%` }} className="bg-slate-600 h-full" title={`No Result: ${noResults.length}`} />
          </div>
          <p className="text-[11px] text-emerald-400/90 mt-2 font-medium">
            {activeKpiFilter === 'TP' ? '✓ Filtering feed to True Positives' : 'Click to filter findings to True Positives'}
          </p>
        </div>

        {/* KPI 4: MITRE Coverage (Interactive toggle to gaps) */}
        <div 
          onClick={() => {
            setMatrixCoverageFilter(matrixCoverageFilter === 'gaps' ? 'all' : 'gaps');
            const el = document.getElementById('mitre-coverage-section');
            if (el) el.scrollIntoView({ behavior: 'smooth' });
          }}
          className={`bg-slate-900/80 border rounded-lg p-4 transition-all cursor-pointer group select-none ${
            matrixCoverageFilter === 'gaps' ? 'border-rose-500/80 ring-1 ring-rose-500/30' : 'border-slate-800 hover:border-cyan-500/60'
          }`}
          title="Click to highlight Blind Spots in the matrix"
        >
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium uppercase tracking-wider">ATT&CK Matrix Coverage</span>
            <Layers className="w-4 h-4 text-cyan-400 group-hover:translate-x-0.5 transition-transform" />
          </div>
          <div className="flex items-baseline gap-2">
            <span style={{ fontSize: '42px' }} className="font-bold font-mono text-cyan-300 tabular-nums leading-tight">{coveredCount}</span>
            <span style={{ fontSize: '15px' }} className="text-slate-400 font-mono leading-tight">
              / {totalCatalogTechniques} ({coveragePercent}%)
            </span>
          </div>
          <div className="w-full bg-slate-800 h-1.5 rounded-full mt-2 overflow-hidden flex">
            <div style={{ width: `${coveragePercent}%` }} className="bg-cyan-500 h-full" />
            <div style={{ width: `${100 - coveragePercent}%` }} className="bg-slate-700 h-full" />
          </div>
          <div className="flex justify-between text-[11px] mt-2">
            <span className="text-cyan-400 font-medium">{coveredCount} Covered</span>
            <span className="text-rose-400 font-medium flex items-center">
              {uncoveredCount} Gaps {matrixCoverageFilter === 'gaps' ? '(Active Filter)' : '→'}
            </span>
          </div>
        </div>
      </div>

      {/* SIMPLIFIED & INTERACTIVE: MITRE ATT&CK Enterprise Coverage Section */}
      <section 
        id="mitre-coverage-section" 
        className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4 shadow-sm"
      >
        {/* Section Header: Simplified title, quick status pills, search & actions */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
          <div>
            <div className="flex items-center gap-2.5 flex-wrap">
              <h2 className="text-base font-bold text-white tracking-tight">MITRE ATT&CK® Enterprise Coverage</h2>
              <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/70 px-2 py-0.5 rounded border border-cyan-800/40">
                STIX v2.1
              </span>
              <span className="text-xs font-mono text-slate-400">
                • {coveredCount} of {totalCatalogTechniques} techniques covered ({coveragePercent}%)
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Streamlined 14-tactic overview. Click any tactic or threat scenario to expose client coverage gaps.
            </p>
          </div>

          {/* Quick Filter & Search Bar */}
          <div className="flex items-center gap-2 flex-wrap">
            {/* Search Input */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5" />
              <input
                type="text"
                placeholder="Search technique (e.g. LSASS, T1059)..."
                value={matrixSearch}
                onChange={(e) => setMatrixSearch(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded-md pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 w-52 sm:w-60"
              />
              {matrixSearch && (
                <button
                  onClick={() => setMatrixSearch('')}
                  className="absolute right-2 top-2 text-slate-400 hover:text-slate-200"
                >
                  <X className="w-3 h-3" />
                </button>
              )}
            </div>

            {/* Quick Status Filter Pills */}
            <div style={{ fontSize: '33px' }} className="flex items-center bg-slate-950 border border-slate-800 rounded-md p-0.5">
              {[
                { id: 'all', label: `All (${totalCatalogTechniques})` },
                { id: 'gaps', label: `Blind Spots (${uncoveredCount})` },
                { id: 'covered', label: `Covered (${coveredCount})` },
              ].map((f) => (
                <button
                  key={f.id}
                  onClick={() => setMatrixCoverageFilter(f.id as any)}
                  className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors cursor-pointer ${
                    matrixCoverageFilter === f.id
                      ? f.id === 'gaps' 
                        ? 'bg-rose-950/80 text-rose-300 font-semibold border border-rose-800/40' 
                        : 'bg-slate-800 text-cyan-300 font-semibold shadow-sm'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {f.label}
                </button>
              ))}
            </div>

            <button
              onClick={() => onOpenMitreModal()}
              className="text-cyan-400 hover:text-cyan-300 text-xs font-semibold flex items-center gap-1.5 px-3 py-1.5 bg-slate-950 border border-slate-800 hover:border-cyan-800/60 rounded-md transition-colors cursor-pointer"
            >
              <span>Full Matrix Explorer</span>
              <ExternalLink className="w-3 h-3" />
            </button>
          </div>
        </div>

        {/* INTERACTIVE FEATURE: Adversary Threat Chain Simulator */}
        <div className="bg-slate-950/70 border border-slate-800/90 rounded-lg p-3 text-xs flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 rounded bg-cyan-950 flex items-center justify-center text-cyan-400 border border-cyan-800/60 shrink-0">
              <Radar className="w-3.5 h-3.5 animate-pulse" />
            </div>
            <div>
              <span className="font-semibold text-slate-200">Threat Campaign Simulator:</span>
              <span className="text-slate-400 ml-1.5">
                Highlight adversary-specific attack paths to audit kill-chain coverage.
              </span>
            </div>
          </div>

          <div className="flex items-center gap-1.5 overflow-x-auto scrollbar-none pb-1 md:pb-0">
            {ADVERSARY_SCENARIOS.map((s) => {
              const isSelected = activeScenarioId === s.id;
              return (
                <button
                  key={s.id}
                  onClick={() => setActiveScenarioId(s.id)}
                  className={`px-2.5 py-1 rounded text-[11px] font-mono whitespace-nowrap transition-all cursor-pointer border ${
                    isSelected
                      ? 'bg-cyan-950 text-cyan-200 border-cyan-500 font-bold shadow-[0_0_10px_rgba(6,182,212,0.2)]'
                      : 'bg-slate-900 text-slate-400 hover:text-slate-200 border-slate-800'
                  }`}
                >
                  {s.id === 'none' ? 'Default View' : s.name.split(' (')[0]}
                </button>
              );
            })}
          </div>
        </div>

        {/* Active Scenario Alert Banner if simulated */}
        {activeScenario.id !== 'none' && (
          <div className="p-3 bg-cyan-950/40 border border-cyan-800/60 rounded-md text-xs text-cyan-200 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <span className="font-bold text-white">{activeScenario.name}: </span>
              <span className="text-cyan-300/90">{activeScenario.description}</span>
            </div>
            <button
              onClick={() => setActiveScenarioId('none')}
              className="text-xs text-cyan-400 hover:underline shrink-0 font-medium cursor-pointer"
            >
              Reset to Full View ✕
            </button>
          </div>
        )}

        {/* SIMPLIFIED 14-TACTIC PROGRESS STRIP */}
        <div className="space-y-1.5">
          <div className="flex items-center justify-between text-[11px] text-slate-400 px-0.5">
            <span className="font-medium">Filter by MITRE Tactic ({MITRE_TACTICS.length}):</span>
            {selectedTacticId !== 'all' && (
              <button
                onClick={() => setSelectedTacticId('all')}
                className="text-cyan-400 hover:underline cursor-pointer"
              >
                Clear tactic filter
              </button>
            )}
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-7 gap-1.5 text-xs">
            {/* All Tactics Reset Button */}
            <button
              onClick={() => setSelectedTacticId('all')}
              className={`p-2 rounded text-left transition-colors border cursor-pointer ${
                selectedTacticId === 'all'
                  ? 'bg-slate-800 text-cyan-300 border-cyan-700/80 font-bold'
                  : 'bg-slate-950 text-slate-400 hover:text-slate-200 border-slate-800'
              }`}
            >
              <div className="font-mono text-[10px] text-slate-500">ALL</div>
              <div className="truncate font-semibold text-[11px] text-white">All Tactics</div>
              <div className="text-[10px] font-mono text-cyan-400 mt-1">
                {coveredCount}/{totalCatalogTechniques}
              </div>
            </button>

            {/* 14 Individual Tactics Cards */}
            {MITRE_TACTICS.map((tac) => {
              const tacTechs = MITRE_TECHNIQUES.filter((t) => t.tactic === tac.name);
              const cov = tacTechs.filter((t) => coveredTechniqueIds.has(t.id)).length;
              const isSelected = selectedTacticId === tac.id || selectedTacticId === tac.name;
              const pct = tacTechs.length > 0 ? Math.round((cov / tacTechs.length) * 100) : 0;

              return (
                <button
                  key={tac.id}
                  onClick={() => setSelectedTacticId(isSelected ? 'all' : tac.name)}
                  className={`p-2 rounded text-left transition-colors border cursor-pointer relative overflow-hidden ${
                    isSelected
                      ? 'bg-cyan-950/80 text-cyan-200 border-cyan-500 font-bold shadow-sm'
                      : 'bg-slate-950 text-slate-400 hover:text-slate-200 border-slate-800'
                  }`}
                  title={`${tac.name} (${cov}/${tacTechs.length} covered)`}
                >
                  <div className="flex items-center justify-between font-mono text-[9px] text-slate-500">
                    <span>{tac.shortCode}</span>
                    <span className={cov > 0 ? 'text-cyan-400 font-bold' : 'text-slate-600'}>
                      {cov}/{tacTechs.length}
                    </span>
                  </div>
                  <div className="truncate font-medium text-[11px] text-slate-200 mt-0.5">
                    {tac.name.replace('Enterprise', '')}
                  </div>
                  {/* Miniature progress bar */}
                  <div className="w-full bg-slate-800 h-1 rounded-full mt-1.5 overflow-hidden">
                    <div 
                      style={{ width: `${pct}%` }} 
                      className={`h-full ${cov > 0 ? 'bg-cyan-400' : 'bg-transparent'}`} 
                    />
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* SECTOR-BASED THREAT INTELLIGENCE & ACTIONABLE DAILY HUNTS */}
        <div className="pt-4 border-t border-slate-800 space-y-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <Globe className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-bold text-white tracking-tight">
                  Sector Threat Intelligence & Active Campaigns
                </h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/60 font-semibold">
                  Actionable Hunting Feeds
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Curated intelligence by industry vertical. Review targeted countries, active threat actors, and launch instant TTP hunts today.
              </p>
            </div>

            {/* Quick Filter to Client Sector */}
            <div className="flex items-center gap-2 flex-wrap">
              <button
                onClick={() => setSelectedSector(selectedSector === currentClient.industry ? 'all' : currentClient.industry)}
                className={`px-2.5 py-1 text-xs font-mono rounded border flex items-center gap-1.5 cursor-pointer transition-colors ${
                  selectedSector === currentClient.industry
                    ? 'bg-cyan-950 text-cyan-200 border-cyan-500 font-bold'
                    : 'bg-slate-950 text-slate-300 hover:text-white border-slate-800'
                }`}
                title={`Filter to active client sector: ${currentClient.industry}`}
              >
                <Zap className="w-3 h-3 text-cyan-400" />
                <span>Client Sector: {currentClient.industry.toUpperCase()}</span>
              </button>

              <div className="relative">
                <Search className="w-3 h-3 text-slate-400 absolute left-2.5 top-2.5" />
                <input
                  type="text"
                  placeholder="Search intel by actor, country, or CVE..."
                  value={sectorSearch}
                  onChange={(e) => setSectorSearch(e.target.value)}
                  className="bg-slate-950 border border-slate-800 rounded pl-7 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 w-48 sm:w-56"
                />
                {sectorSearch && (
                  <button
                    onClick={() => setSectorSearch('')}
                    className="absolute right-2 top-2 text-slate-400 hover:text-slate-200"
                  >
                    <X className="w-3 h-3" />
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Sector Filter Chips */}
          <div className="flex items-center gap-1.5 overflow-x-auto pb-1 scrollbar-none text-xs">
            {[
              { id: 'all', label: 'All Sectors' },
              { id: 'healthcare', label: 'Healthcare & Pharma' },
              { id: 'retail', label: 'Retail & E-commerce' },
              { id: 'finance', label: 'Financial Services' },
              { id: 'energy', label: 'Energy & Utilities' },
              { id: 'technology', label: 'Technology & SaaS' },
              { id: 'defense', label: 'Defense & Aerospace' },
            ].map((sec) => (
              <button
                key={sec.id}
                onClick={() => setSelectedSector(sec.id)}
                className={`px-3 py-1 rounded text-xs whitespace-nowrap transition-colors cursor-pointer border ${
                  selectedSector === sec.id
                    ? 'bg-cyan-950 text-cyan-200 border-cyan-500 font-semibold shadow-sm'
                    : 'bg-slate-950 text-slate-400 hover:text-slate-200 border-slate-800'
                }`}
              >
                {sec.label}
              </button>
            ))}
          </div>

          {/* Sector Intel Advisory Cards Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {displayedSectorIntels.map((intel) => {
              const matchesClientSector = intel.sectors.includes(currentClient.industry);

              return (
                <div
                  key={intel.id}
                  className={`bg-slate-950/80 border rounded-lg p-4 space-y-3.5 transition-all relative ${
                    matchesClientSector
                      ? 'border-cyan-800/80 shadow-[0_0_15px_rgba(6,182,212,0.06)]'
                      : 'border-slate-800/90 hover:border-slate-700'
                  }`}
                >
                  {/* Top Bar: Urgency, Sector Tag, Attribution, Publisher Link */}
                  <div className="flex items-center justify-between gap-2 flex-wrap text-[11px] font-mono">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        intel.urgency === 'Critical'
                          ? 'bg-rose-950 text-rose-300 border border-rose-800'
                          : 'bg-amber-950 text-amber-300 border border-amber-800'
                      }`}>
                        {intel.urgency} Advisory
                      </span>

                      {intel.sourcePublisher && (
                        <span className="px-2 py-0.5 rounded bg-cyan-950/90 text-cyan-300 border border-cyan-700/80 text-[10px] font-bold flex items-center gap-1">
                          <span>{intel.sourcePublisher}</span>
                          {intel.sourceUrl && (
                            <a
                              href={intel.sourceUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              onClick={(e) => e.stopPropagation()}
                              className="text-cyan-400 hover:text-white"
                              title={`Open verified article on ${intel.sourcePublisher}`}
                            >
                              <ExternalLink className="w-2.5 h-2.5" />
                            </a>
                          )}
                        </span>
                      )}

                      {intel.sectors.slice(0, 2).map((s) => (
                        <span
                          key={s}
                          className="px-2 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-800 text-[10px] uppercase font-semibold"
                        >
                          {s}
                        </span>
                      ))}

                      {matchesClientSector && (
                        <span className="px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-700/60 text-[9px] font-semibold">
                          ★ Client Vertical
                        </span>
                      )}
                    </div>

                    <span className="text-slate-500 text-[10px]">
                      {intel.publishedDate}
                    </span>
                  </div>

                  {/* Title & Narrative */}
                  <div>
                    <h4 className="text-sm font-bold text-white tracking-tight leading-snug">
                      {intel.title}
                    </h4>
                    <p className="text-xs text-slate-300 mt-1.5 leading-relaxed">
                      {intel.summary}
                    </p>
                  </div>

                  {/* Threat Context Details: Targeted Countries & Threat Actors */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs bg-slate-900/80 p-2.5 rounded border border-slate-800/80 font-mono">
                    <div className="space-y-0.5">
                      <div className="flex items-center gap-1 text-[10px] text-slate-400 uppercase">
                        <Globe className="w-3 h-3 text-cyan-400" />
                        <span>Targeted Countries:</span>
                      </div>
                      <div className="text-slate-200 text-[11px] truncate" title={intel.targetedCountries.join(', ')}>
                        {intel.targetedCountries.join(', ')}
                      </div>
                    </div>

                    <div className="space-y-0.5">
                      <div className="flex items-center gap-1 text-[10px] text-slate-400 uppercase">
                        <Crosshair className="w-3 h-3 text-rose-400" />
                        <span>Threat Actors:</span>
                      </div>
                      <div className="text-amber-300 text-[11px] truncate font-semibold" title={intel.threatActors.join(', ')}>
                        {intel.threatActors.join(', ')}
                      </div>
                    </div>
                  </div>

                  {/* Observed CVEs / Entry Vectors */}
                  {intel.cvesObserved && intel.cvesObserved.length > 0 && (
                    <div className="flex items-center gap-2 text-xs">
                      <span className="text-[10px] font-mono text-slate-500 uppercase">Observed Vectors:</span>
                      <div className="flex flex-wrap gap-1">
                        {intel.cvesObserved.map((cve) => (
                          <span
                            key={cve}
                            className="px-2 py-0.5 rounded bg-slate-900 text-rose-300 border border-rose-900/60 font-mono text-[10px]"
                          >
                            {cve}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Primary Observed TTPs with Client Coverage Indicator */}
                  <div className="space-y-1.5 pt-1">
                    <span className="text-[10px] font-mono text-slate-500 uppercase">Primary MITRE ATT&CK TTPs:</span>
                    <div className="flex flex-wrap gap-1.5">
                      {intel.primaryTTPs.map((ttp) => {
                        const isCovered = coveredTechniqueIds.has(ttp.id) || coveredTechniqueIds.has(ttp.id.split('.')[0]);

                        return (
                          <button
                            key={ttp.id}
                            onClick={() => onSelectTechniqueForHunt(ttp.id)}
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-medium flex items-center gap-1 cursor-pointer transition-colors ${
                              isCovered
                                ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/80 hover:border-emerald-600'
                                : 'bg-slate-900 text-amber-300 border border-amber-800/60 hover:border-amber-600'
                            }`}
                            title={`Click to draft hunt for ${ttp.id} (${ttp.name})`}
                          >
                            <span>{ttp.id}</span>
                            <span className="text-[9px] text-slate-400">({ttp.name.slice(0, 14)})</span>
                            <span className={isCovered ? 'text-emerald-400' : 'text-amber-400'}>
                              {isCovered ? '✓' : '⚠'}
                            </span>
                          </button>
                        );
                      })}
                    </div>
                  </div>

                  {/* MULTI-PLATFORM QUERY ACTIONS */}
                  <div className="pt-2 border-t border-slate-800/80 space-y-2">
                    <div className="flex items-center justify-between flex-wrap gap-2 text-xs">
                      <div className="flex items-center gap-1 flex-wrap text-[10px] font-mono text-slate-400">
                        <span className="text-slate-500 font-semibold">Queries:</span>
                        {['Sigma', 'FQL', 'KQL', 'S1', 'Trend', 'Splunk', 'Elastic'].map((p) => (
                          <span key={p} className="px-1.5 py-0.2 rounded bg-slate-900 border border-slate-800 text-slate-300">
                            {p}
                          </span>
                        ))}
                      </div>

                      <button
                        onClick={() => {
                          setSelectedIntelForHunt(intel);
                          setSelectedQueryPlatform('kql');
                        }}
                        className="px-3.5 py-1.5 bg-gradient-to-r from-cyan-600 via-teal-600 to-emerald-600 hover:from-cyan-500 hover:to-emerald-500 text-white font-bold text-xs rounded-md shadow flex items-center gap-1.5 cursor-pointer transition-all hover:scale-[1.02]"
                      >
                        <Crosshair className="w-3.5 h-3.5" />
                        <span>Inspect Intel & Multi-Platform Queries →</span>
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}

            {displayedSectorIntels.length === 0 && (
              <div className="col-span-full py-12 text-center text-xs text-slate-400 bg-slate-950 rounded-lg border border-slate-800">
                No threat intelligence matched current search or sector filters.
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Two Column Section: Findings & AI Today's Hunt Pulse */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Findings Feed (Interactive KPI filter aware) */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              <h3 className="text-sm font-bold text-white">
                {activeKpiFilter === 'TP'
                  ? 'Confirmed True Positive Intrusions'
                  : 'Critical & High Severity Findings'}
              </h3>
            </div>
            {activeKpiFilter !== 'all' && (
              <button
                onClick={() => setActiveKpiFilter('all')}
                className="text-xs text-slate-400 hover:text-white underline cursor-pointer"
              >
                Clear Filter ({activeKpiFilter})
              </button>
            )}
          </div>

          <div className="space-y-3">
            {severeFindings.length > 0 ? (
              severeFindings.map((report) => {
                const isExpanded = expandedFindingId === report.id;
                return (
                  <div
                    key={report.id}
                    className="bg-slate-950/80 border border-slate-800 rounded p-3.5 space-y-2 hover:border-slate-700 transition-colors"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <h4 className="text-xs font-semibold text-white">{report.hypothesisTitle}</h4>
                        <div className="flex items-center gap-2 text-[11px] text-slate-400 mt-1">
                          <span>Analyst: {report.analystName}</span>
                          <span aria-hidden="true">·</span>
                          <span>{report.weekRange}</span>
                          <span aria-hidden="true">·</span>
                          <span className="font-mono text-cyan-400">{report.techniqueIds.join(', ')}</span>
                        </div>
                      </div>
                      {report.severityScore && (
                        <div className="shrink-0 text-right">
                          <span className={`px-2 py-0.5 text-[10px] font-mono font-bold rounded ${
                            report.severityScore.severityLevel === 'Critical'
                              ? 'bg-rose-950 text-rose-300 border border-rose-800'
                              : 'bg-amber-950 text-amber-300 border border-amber-800'
                          }`}>
                            {report.severityScore.severityLevel} ({report.severityScore.compositeScore}/100)
                          </span>
                        </div>
                      )}
                    </div>
                    <p className="text-xs text-slate-300 line-clamp-2">
                      {report.notes}
                    </p>

                    {/* Interactive Expander: Detection Query & IOCs */}
                    <div className="pt-1.5 border-t border-slate-800/60 flex items-center justify-between text-[11px]">
                      <button
                        onClick={() => setExpandedFindingId(isExpanded ? null : report.id)}
                        className="text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1 cursor-pointer"
                      >
                        {isExpanded ? 'Hide Detection Logic' : 'Inspect Detection Query'}
                        {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                      </button>

                      {report.iocs.length > 0 && (
                        <span className="font-mono text-amber-300/80 text-[10px]">
                          {report.iocs.length} IOC{report.iocs.length > 1 ? 's' : ''} detected
                        </span>
                      )}
                    </div>

                    {isExpanded && (
                      <div className="mt-2 p-2.5 bg-slate-900 border border-slate-800 rounded space-y-2 text-xs">
                        <div className="flex items-center justify-between">
                          <span className="text-[10px] font-mono text-slate-400 uppercase">Detection Query:</span>
                          <button
                            onClick={() => handleCopyQuery(report.id, report.queryText)}
                            className="text-[10px] font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer"
                          >
                            {copiedQueryId === report.id ? (
                              <>
                                <Check className="w-3 h-3 text-emerald-400" />
                                <span>Copied!</span>
                              </>
                            ) : (
                              <>
                                <Copy className="w-3 h-3" />
                                <span>Copy Query</span>
                              </>
                            )}
                          </button>
                        </div>
                        <pre className="font-mono text-[11px] bg-slate-950 p-2 rounded text-cyan-200 overflow-x-auto whitespace-pre-wrap border border-slate-800/80">
                          {report.queryText}
                        </pre>

                        {report.iocs.length > 0 && (
                          <div className="space-y-1">
                            <span className="text-[10px] font-mono text-slate-400 uppercase">Associated IOCs:</span>
                            <div className="flex flex-wrap gap-1.5">
                              {report.iocs.map((ioc) => (
                                <span
                                  key={ioc.id}
                                  className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 border border-amber-800/50 text-amber-300"
                                >
                                  {ioc.type}: {ioc.value}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })
            ) : (
              <div className="py-8 text-center text-xs text-slate-500">
                No findings matching current filter criteria.
              </div>
            )}
          </div>
        </div>

        {/* Right: Daily Shortlist Highlight with Interactive Simulation */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-white">AI-Driven Daily Hunt Shortlist</h3>
            </div>
            <button
              onClick={() => onNavigateTab('todays-hunts')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-medium cursor-pointer"
            >
              View Full Shortlist ({clientTodaysHunts.length}) →
            </button>
          </div>

          <div className="space-y-3">
            {clientTodaysHunts.slice(0, 2).map((hunt) => (
              <div
                key={hunt.id}
                className="bg-slate-950/80 border border-slate-800 rounded p-3.5 space-y-2.5 hover:border-cyan-500/40 transition-colors"
              >
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <span className="text-[10px] font-mono uppercase tracking-wider text-cyan-400 bg-cyan-950/80 px-1.5 py-0.5 rounded border border-cyan-800/40">
                      {hunt.source}: {hunt.sourceReference}
                    </span>
                    <h4 className="text-xs font-semibold text-white mt-1.5">{hunt.hypothesisName}</h4>
                  </div>
                  <div className="text-right shrink-0">
                    <span className="text-xs font-mono font-bold text-cyan-300">
                      Priority {hunt.aiHuntScore.priorityScore}/100
                    </span>
                    <div className="text-[10px] text-slate-500 font-mono">AI Hunt Score</div>
                  </div>
                </div>

                <p className="text-xs text-slate-300 line-clamp-2">
                  {hunt.summaryAndRationale}
                </p>

                {/* Simulated Telemetry output if run */}
                {simulatedLogs[hunt.id] && (
                  <div className="p-2 bg-slate-900 border border-slate-800 rounded font-mono text-[10px] text-emerald-300">
                    {simulatedLogs[hunt.id]}
                  </div>
                )}

                <div className="flex items-center justify-between text-xs pt-2 border-t border-slate-800/60">
                  <span className="text-[11px] text-slate-400">
                    Telemetry: {hunt.dataSourcesRequired.slice(0, 2).join(', ')}
                  </span>
                  
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleSimulateHunt(hunt.id)}
                      disabled={simulatingHuntId === hunt.id}
                      className="px-2 py-0.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-[11px] font-medium flex items-center gap-1 cursor-pointer"
                    >
                      <Play className={`w-3 h-3 text-cyan-400 ${simulatingHuntId === hunt.id ? 'animate-spin' : ''}`} />
                      <span>{simulatingHuntId === hunt.id ? 'Simulating...' : 'Test Telemetry'}</span>
                    </button>
                    <button
                      onClick={() => onNavigateTab('todays-hunts')}
                      className="text-cyan-400 hover:text-cyan-300 text-xs font-medium cursor-pointer"
                    >
                      Investigate →
                    </button>
                  </div>
                </div>
              </div>
            ))}

            {clientTodaysHunts.length === 0 && (
              <div className="py-8 text-center text-xs text-slate-500">
                No active daily hunts generated. Click above to produce fresh daily hunts.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* QUICK TECHNIQUE INSPECT DRAWER / MODAL */}
      {inspectedTechnique && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex justify-end">
          <div className="bg-slate-900 border-l border-slate-800 w-full max-w-md h-full overflow-y-auto p-6 space-y-5 animate-in slide-in-from-right duration-200">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div>
                <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/80 px-2 py-0.5 rounded border border-cyan-800/60">
                  {inspectedTechnique.id}
                </span>
                <h3 className="text-base font-bold text-white mt-1">{inspectedTechnique.name}</h3>
                <p className="text-xs text-slate-400 font-mono">{inspectedTechnique.tactic}</p>
              </div>
              <button
                onClick={() => setInspectedTechnique(null)}
                className="text-slate-400 hover:text-white p-1 rounded-md bg-slate-800 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Technique Description */}
            <div className="space-y-1">
              <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">Description:</span>
              <p className="text-xs text-slate-300 leading-relaxed bg-slate-950 p-3 rounded border border-slate-800/80">
                {inspectedTechnique.description}
              </p>
            </div>

            {/* Telemetry Status for Current Client */}
            <div className="space-y-2">
              <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">Required Telemetry:</span>
              <div className="space-y-1.5">
                {inspectedTechnique.dataSources.map((ds) => {
                  const hasTelemetry = currentClient.primaryTelemetry.some((clientSource) =>
                    ds.toLowerCase().includes(clientSource.toLowerCase()) ||
                    clientSource.toLowerCase().includes(ds.toLowerCase())
                  );

                  return (
                    <div
                      key={ds}
                      className="flex items-center justify-between p-2 rounded bg-slate-950 border border-slate-800 text-xs"
                    >
                      <span className="text-slate-300">{ds}</span>
                      <span className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded ${
                        hasTelemetry 
                          ? 'bg-emerald-950 text-emerald-300 border border-emerald-800/60'
                          : 'bg-amber-950 text-amber-300 border border-amber-800/60'
                      }`}>
                        {hasTelemetry ? '✓ Onboarded' : '⚠ Gap'}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Client Coverage Status */}
            <div className="p-3 bg-slate-950 rounded border border-slate-800 space-y-1">
              <div className="text-[11px] font-mono text-slate-400 uppercase">Coverage Status for {currentClient.name}:</div>
              <div className="text-xs font-semibold">
                {coveredTechniqueIds.has(inspectedTechnique.id) ? (
                  <span className="text-emerald-400">✓ Hunted and covered in client reports</span>
                ) : (
                  <span className="text-rose-400">⚠ Uncovered blind spot — recommend hunt execution</span>
                )}
              </div>
            </div>

            {/* Action Buttons */}
            <div className="pt-3 border-t border-slate-800 flex gap-2">
              <button
                onClick={() => {
                  onSelectTechniqueForHunt(inspectedTechnique.id);
                  setInspectedTechnique(null);
                }}
                className="flex-1 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-md text-xs font-bold transition-colors cursor-pointer text-center"
              >
                Draft Hypothesis Hunt Now →
              </button>
              <button
                onClick={() => {
                  onOpenMitreModal(inspectedTechnique);
                  setInspectedTechnique(null);
                }}
                className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-md text-xs font-semibold border border-slate-700 transition-colors cursor-pointer"
              >
                Matrix Explorer
              </button>
            </div>
          </div>
        </div>
      )}

      {/* TELEMETRY ANALYTICS MODAL (Opened from KPI 2) */}
      {showTelemetryModal && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-lg max-w-lg w-full p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Terminal className="w-5 h-5 text-blue-400" />
                <h3 className="text-base font-bold text-white">Detection Query Telemetry Center</h3>
              </div>
              <button
                onClick={() => setShowTelemetryModal(false)}
                className="text-slate-400 hover:text-white p-1 rounded bg-slate-800 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-xs text-slate-300">
              Breakdown of search logic and queries dispatched across client data lakes and SIEM connectors.
            </p>

            <div className="grid grid-cols-3 gap-2 text-center">
              <div className="bg-slate-950 p-3 rounded border border-slate-800">
                <div className="text-[10px] font-mono text-slate-400">Total Dispatched</div>
                <div className="text-xl font-bold font-mono text-white mt-1">{totalQueriesExecuted}</div>
              </div>
              <div className="bg-slate-950 p-3 rounded border border-slate-800">
                <div className="text-[10px] font-mono text-slate-400">Mean Latency</div>
                <div className="text-xl font-bold font-mono text-cyan-400 mt-1">420ms</div>
              </div>
              <div className="bg-slate-950 p-3 rounded border border-slate-800">
                <div className="text-[10px] font-mono text-slate-400">Endpoints Scanned</div>
                <div className="text-xl font-bold font-mono text-emerald-400 mt-1">12,850</div>
              </div>
            </div>

            <div className="space-y-2">
              <div className="text-xs font-semibold text-slate-200">Query Engine Distribution:</div>
              <div className="space-y-1.5 text-xs font-mono">
                <div className="flex justify-between text-slate-300">
                  <span>Standard Production Hunt Logic</span>
                  <span className="text-cyan-400">100% Standardized</span>
                </div>
                <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                  <div className="bg-gradient-to-r from-cyan-500 to-blue-500 h-full w-full" />
                </div>
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setShowTelemetryModal(false)}
                className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-medium cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ACTIONABLE TTP HUNT PACKAGE MODAL */}
      {selectedIntelForHunt && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl w-full max-w-3xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden animate-in fade-in duration-150">
            {/* Modal Header */}
            <div className="flex items-start justify-between px-6 py-4 border-b border-slate-800 bg-slate-950">
              <div className="space-y-1.5">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                    selectedIntelForHunt.urgency === 'Critical'
                      ? 'bg-rose-950 text-rose-300 border border-rose-800'
                      : 'bg-amber-950 text-amber-300 border border-amber-800'
                  }`}>
                    {selectedIntelForHunt.urgency} Advisory Hunt
                  </span>

                  {selectedIntelForHunt.sourcePublisher && (
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-800/80 font-bold flex items-center gap-1">
                      <span>Publisher: {selectedIntelForHunt.sourcePublisher}</span>
                      {selectedIntelForHunt.sourceUrl && (
                        <a
                          href={selectedIntelForHunt.sourceUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-cyan-400 hover:text-white"
                          title="Open original threat intel article"
                        >
                          <ExternalLink className="w-2.5 h-2.5" />
                        </a>
                      )}
                    </span>
                  )}

                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-800 uppercase font-semibold">
                    {selectedIntelForHunt.sectors.join(', ')}
                  </span>
                  <span className="text-slate-500 text-[10px] font-mono">
                    {selectedIntelForHunt.publishedDate}
                  </span>
                </div>
                <h3 className="text-base font-bold text-white tracking-tight leading-snug">
                  {selectedIntelForHunt.suggestedHuntPackage.hypothesisTitle}
                </h3>
              </div>
              <button
                onClick={() => setSelectedIntelForHunt(null)}
                className="text-slate-400 hover:text-white p-1 rounded bg-slate-800 cursor-pointer ml-3 shrink-0"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Content */}
            <div className="p-6 overflow-y-auto space-y-4 text-xs">
              {/* Intel Advisory Context */}
              <div className="bg-slate-950/90 p-3.5 rounded-lg border border-slate-800 space-y-2">
                <div className="text-[11px] font-mono text-cyan-400 uppercase font-bold flex items-center gap-1.5">
                  <Radar className="w-3.5 h-3.5" />
                  <span>Threat Campaign Intelligence Context:</span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {selectedIntelForHunt.summary}
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-2 border-t border-slate-800/80 text-[11px] font-mono">
                  <div>
                    <span className="text-slate-500">Targeted Countries: </span>
                    <span className="text-slate-200">{selectedIntelForHunt.targetedCountries.join(', ')}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Active Actors: </span>
                    <span className="text-amber-300 font-semibold">{selectedIntelForHunt.threatActors.join(', ')}</span>
                  </div>
                </div>
              </div>

              {/* Mapped Techniques */}
              <div className="space-y-1.5">
                <span className="text-[10px] font-mono text-slate-400 uppercase font-semibold">
                  TTPs Included in this Hunt Package:
                </span>
                <div className="flex flex-wrap gap-2">
                  {selectedIntelForHunt.primaryTTPs.map((t) => {
                    const isCovered = coveredTechniqueIds.has(t.id);
                    return (
                      <div
                        key={t.id}
                        className={`px-2.5 py-1 rounded text-[11px] font-mono border flex items-center gap-1.5 ${
                          isCovered
                            ? 'bg-emerald-950/60 border-emerald-800/70 text-emerald-300'
                            : 'bg-slate-950 border-amber-800/60 text-amber-300'
                        }`}
                      >
                        <span className="font-bold">{t.id}</span>
                        <span className="text-slate-400">({t.name})</span>
                        <span className={`text-[10px] font-semibold px-1 rounded ${isCovered ? 'bg-emerald-900/60 text-emerald-300' : 'bg-amber-900/60 text-amber-300'}`}>
                          {isCovered ? 'Covered' : 'Blind Spot'}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Telemetry Checklist */}
              <div className="space-y-1.5">
                <span className="text-[10px] font-mono text-slate-400 uppercase font-semibold">
                  Client Telemetry Alignment ({currentClient.name}):
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {selectedIntelForHunt.suggestedHuntPackage.requiredDataSources.map((ds) => {
                    const hasTelemetry = currentClient.primaryTelemetry.some((clientSource) =>
                      ds.toLowerCase().includes(clientSource.toLowerCase()) ||
                      clientSource.toLowerCase().includes(ds.toLowerCase())
                    );

                    return (
                      <div
                        key={ds}
                        className="flex items-center justify-between p-2 rounded bg-slate-950 border border-slate-800 text-xs"
                      >
                        <span className="text-slate-300 font-mono text-[11px]">{ds}</span>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                          hasTelemetry
                            ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                            : 'bg-amber-950 text-amber-300 border border-amber-800'
                        }`}>
                          {hasTelemetry ? '✓ Active' : '⚠ Missing Gap'}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* MULTI-PLATFORM QUERY SELECTOR & CODE BOX */}
              <div className="space-y-2.5 bg-slate-950 p-4 rounded-lg border border-slate-800">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-2.5">
                  <div className="flex items-center gap-2 flex-wrap">
                    <FileCode className="w-4 h-4 text-cyan-400" />
                    <span className="font-mono text-xs text-white font-bold uppercase tracking-wider">
                      Multi-Platform Threat Detection Queries
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/60 font-semibold">
                      7 Platforms Available
                    </span>
                  </div>

                  <button
                    onClick={() => handleCopyIntelQuery(`${selectedIntelForHunt.id}-${selectedQueryPlatform}`, getIntelQueryForPlatform(selectedIntelForHunt, selectedQueryPlatform))}
                    className="px-2.5 py-1 text-[11px] font-mono text-cyan-300 hover:text-cyan-200 bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-800/80 rounded flex items-center gap-1.5 cursor-pointer transition-colors self-start sm:self-auto"
                  >
                    {copiedIntelQueryId === `${selectedIntelForHunt.id}-${selectedQueryPlatform}` ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        <span>Copied {selectedQueryPlatform.toUpperCase()}!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copy {selectedQueryPlatform.toUpperCase()} Query</span>
                      </>
                    )}
                  </button>
                </div>

                {/* Platform Selector Tabs */}
                <div className="flex items-center gap-1.5 flex-wrap">
                  {[
                    { id: 'sigma', name: 'Sigma Rule', badge: 'YAML' },
                    { id: 'fql', name: 'CrowdStrike (FQL)', badge: 'Falcon' },
                    { id: 'kql', name: 'Microsoft Sentinel', badge: 'KQL' },
                    { id: 'sentinelone', name: 'SentinelOne', badge: 'S1QL' },
                    { id: 'trendmicro', name: 'Trend Micro Vision One', badge: 'XDR' },
                    { id: 'splunk', name: 'Splunk', badge: 'SPL' },
                    { id: 'elastic', name: 'Elastic', badge: 'EQL' },
                  ].map((plat) => (
                    <button
                      key={plat.id}
                      onClick={() => setSelectedQueryPlatform(plat.id as any)}
                      className={`px-2.5 py-1 rounded text-[11px] font-mono transition-colors cursor-pointer border flex items-center gap-1.5 ${
                        selectedQueryPlatform === plat.id
                          ? 'bg-cyan-950 text-cyan-200 border-cyan-400 font-bold shadow-[0_0_10px_rgba(6,182,212,0.25)]'
                          : 'bg-slate-900 text-slate-400 hover:text-slate-200 border-slate-800 hover:border-slate-700'
                      }`}
                    >
                      <span>{plat.name}</span>
                      <span className="text-[9px] opacity-70">({plat.badge})</span>
                    </button>
                  ))}
                </div>

                {/* Active Platform Query Code */}
                <pre className="p-3.5 bg-slate-900/90 rounded text-cyan-200 font-mono text-[11px] overflow-x-auto whitespace-pre-wrap border border-slate-800 leading-relaxed max-h-72 scrollbar-thin">
                  {getIntelQueryForPlatform(selectedIntelForHunt, selectedQueryPlatform)}
                </pre>

                {/* Expected Log Pattern */}
                <div className="text-[11px] text-slate-400 pt-1 font-mono">
                  <span className="text-slate-500 uppercase">Expected Indicator Pattern: </span>
                  <span className="text-slate-300">{selectedIntelForHunt.suggestedHuntPackage.logPattern}</span>
                </div>
              </div>

              {/* Simulation Result Output */}
              {simulatedIntelLogs[selectedIntelForHunt.id] && (
                <div className="p-3 bg-emerald-950/40 border border-emerald-800/70 rounded-md font-mono text-xs text-emerald-200 flex items-start gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  <span>{simulatedIntelLogs[selectedIntelForHunt.id]}</span>
                </div>
              )}
            </div>

            {/* Modal Actions */}
            <div className="px-6 py-4 border-t border-slate-800 bg-slate-950 flex flex-col sm:flex-row items-center justify-between gap-3">
              <button
                onClick={() => handleSimulateIntelHunt(selectedIntelForHunt.id)}
                disabled={simulatingIntelId === selectedIntelForHunt.id}
                className="w-full sm:w-auto px-3.5 py-2 text-xs font-mono font-medium rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 flex items-center justify-center gap-2 cursor-pointer transition-colors"
              >
                <Play className={`w-3.5 h-3.5 text-cyan-400 ${simulatingIntelId === selectedIntelForHunt.id ? 'animate-spin' : ''}`} />
                <span>{simulatingIntelId === selectedIntelForHunt.id ? 'Scanning Client Logs...' : 'Test Telemetry Simulation'}</span>
              </button>

              <div className="flex items-center gap-2 w-full sm:w-auto justify-end flex-wrap">
                <button
                  onClick={() => {
                    const intel = selectedIntelForHunt;
                    const query = getIntelQueryForPlatform(intel, selectedQueryPlatform);
                    setSelectedIntelForHunt(null);
                    if (onDraftReportWithPackage) {
                      onDraftReportWithPackage({
                        hypothesisTitle: intel.suggestedHuntPackage.hypothesisTitle,
                        queryText: query,
                        techniqueIds: intel.primaryTTPs.map((t) => t.id),
                        notes: `Intel Source: ${intel.sourcePublisher || intel.sourceAttribution}. Platform: ${selectedQueryPlatform.toUpperCase()}. Context: ${intel.summary}. Threat Actors: ${intel.threatActors.join(', ')}.`,
                      });
                    } else {
                      onSelectTechniqueForHunt(intel.primaryTTPs[0]?.id || 'T1059.001');
                    }
                  }}
                  className="px-3.5 py-2 text-xs font-semibold rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 flex items-center gap-1.5 cursor-pointer"
                >
                  <PlusCircle className="w-3.5 h-3.5" />
                  <span>Log as {selectedQueryPlatform.toUpperCase()} Hunt</span>
                </button>

                <button
                  onClick={() => {
                    const intel = selectedIntelForHunt;
                    const query = getIntelQueryForPlatform(intel, selectedQueryPlatform);
                    setSelectedIntelForHunt(null);
                    
                    const platformMapping: Record<string, DetectionPlatform> = {
                      kql: 'Microsoft Sentinel (KQL)',
                      fql: 'CrowdStrike Falcon (LQL)',
                      sigma: 'Sigma (Generic)',
                      sentinelone: 'SentinelOne (Deep Visibility)',
                      trendmicro: 'Trend Micro Vision One',
                      splunk: 'Splunk Enterprise (SPL)',
                      elastic: 'Elasticsearch (EQL)',
                    };

                    const chosenPlatform = platformMapping[selectedQueryPlatform] || 'Microsoft Sentinel (KQL)';

                    if (onDeployDetectionRule) {
                      onDeployDetectionRule({
                        ruleName: `RULE-${intel.primaryTTPs[0]?.id || 'T1000'}-${intel.threatActors[0]?.slice(0, 10).replace(/[^a-zA-Z0-9]/g, '-').toUpperCase() || 'INTEL'}-${selectedQueryPlatform.toUpperCase()}`,
                        queryLogic: query,
                        techniqueIds: intel.primaryTTPs.map((t) => t.id),
                        tactics: intel.primaryTTPs.map((t) => t.tactic),
                        description: `Continuous detection rule generated from ${intel.sourcePublisher || 'Threat Intel'}: ${intel.title}`,
                        platform: chosenPlatform,
                      });
                    }
                    onNavigateTab('detection-coverage');
                  }}
                  className="px-4 py-2 text-xs font-bold rounded bg-cyan-600 hover:bg-cyan-500 text-white flex items-center gap-1.5 shadow-sm cursor-pointer"
                >
                  <ShieldCheck className="w-4 h-4" />
                  <span>Send as {selectedQueryPlatform.toUpperCase()} Detection Rule →</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
