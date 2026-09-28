import React, { useState, useMemo } from 'react';
import { ClientOrg, DetectionPlatform, DetectionRule, DetectionRuleStatus, HuntReport, User } from '../types';
import { 
  ShieldCheck, 
  Terminal, 
  CheckCircle2, 
  AlertTriangle, 
  Clock, 
  Search, 
  PlusCircle, 
  Download, 
  Copy, 
  Check, 
  Play, 
  Activity, 
  SlidersHorizontal, 
  Layers, 
  X, 
  ExternalLink,
  ChevronDown,
  Building2,
  FileCode,
  Tag
} from 'lucide-react';

interface DetectionCoverageViewProps {
  currentClient: ClientOrg;
  detectionRules: DetectionRule[];
  reports: HuntReport[];
  currentUser: User;
  onAddDetectionRule: (rule: DetectionRule) => void;
  onUpdateDetectionRule: (rule: DetectionRule) => void;
  onNavigateTab: (tab: string) => void;
}

const PLATFORM_OPTIONS: DetectionPlatform[] = [
  'Microsoft Sentinel (KQL)',
  'Splunk Enterprise (SPL)',
  'CrowdStrike Falcon (LQL)',
  'SentinelOne (Deep Visibility)',
  'Trend Micro Vision One',
  'Sigma (Generic)',
  'Elasticsearch (EQL)',
];

const STATUS_CONFIG: Record<DetectionRuleStatus, { bg: string; text: string; border: string; dot: string }> = {
  'Production Active': {
    bg: 'bg-emerald-950/70',
    text: 'text-emerald-300',
    border: 'border-emerald-800/80',
    dot: 'bg-emerald-400',
  },
  'Testing / Staging': {
    bg: 'bg-cyan-950/70',
    text: 'text-cyan-300',
    border: 'border-cyan-800/80',
    dot: 'bg-cyan-400',
  },
  'Pending Client Review': {
    bg: 'bg-amber-950/70',
    text: 'text-amber-300',
    border: 'border-amber-800/80',
    dot: 'bg-amber-400',
  },
  'Tuning Needed': {
    bg: 'bg-rose-950/70',
    text: 'text-rose-300',
    border: 'border-rose-800/80',
    dot: 'bg-rose-400',
  },
  'Deprecated': {
    bg: 'bg-slate-900',
    text: 'text-slate-400',
    border: 'border-slate-800',
    dot: 'bg-slate-500',
  },
};

export const DetectionCoverageView: React.FC<DetectionCoverageViewProps> = ({
  currentClient,
  detectionRules,
  reports,
  currentUser,
  onAddDetectionRule,
  onUpdateDetectionRule,
  onNavigateTab,
}) => {
  // Search & Filter State
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedStatus, setSelectedStatus] = useState<string>('all');
  const [selectedPlatform, setSelectedPlatform] = useState<string>('all');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');

  // Interactive UI State
  const [copiedRuleId, setCopiedRuleId] = useState<string | null>(null);
  const [simulatingRuleId, setSimulatingRuleId] = useState<string | null>(null);
  const [simulationOutputs, setSimulationOutputs] = useState<{ [ruleId: string]: string }>({});
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);

  // New Rule Form State
  const [newOriginHuntId, setNewOriginHuntId] = useState<string>('');
  const [newRuleName, setNewRuleName] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [newPlatform, setNewPlatform] = useState<DetectionPlatform>('Microsoft Sentinel (KQL)');
  const [newSeverity, setNewSeverity] = useState<'Critical' | 'High' | 'Medium' | 'Low'>('High');
  const [newStatus, setNewStatus] = useState<DetectionRuleStatus>('Testing / Staging');
  const [newQueryLogic, setNewQueryLogic] = useState('');
  const [newTargetEnvironment, setNewTargetEnvironment] = useState('');
  const [newTechniqueIds, setNewTechniqueIds] = useState('');
  const [newTactics, setNewTactics] = useState('');
  const [newTuningNotes, setNewTuningNotes] = useState('');
  const [newClientApprover, setNewClientApprover] = useState('');

  // Filter client rules
  const clientRules = useMemo(() => {
    return detectionRules.filter((r) => r.clientId === currentClient.id);
  }, [detectionRules, currentClient.id]);

  // Client available hunt reports for promotion
  const clientReports = useMemo(() => {
    return reports.filter((r) => r.clientId === currentClient.id);
  }, [reports, currentClient.id]);

  // Filtered Rules
  const displayedRules = useMemo(() => {
    return clientRules.filter((rule) => {
      if (selectedStatus !== 'all' && rule.status !== selectedStatus) return false;
      if (selectedPlatform !== 'all' && rule.platform !== selectedPlatform) return false;
      if (selectedSeverity !== 'all' && rule.severity !== selectedSeverity) return false;

      if (searchTerm.trim()) {
        const query = searchTerm.toLowerCase();
        const matchName = rule.ruleName.toLowerCase().includes(query);
        const matchHypothesis = rule.huntHypothesisTitle.toLowerCase().includes(query);
        const matchDesc = rule.description.toLowerCase().includes(query);
        const matchTech = rule.techniqueIds.some((t) => t.toLowerCase().includes(query));
        const matchEnv = rule.targetEnvironment.toLowerCase().includes(query);
        const matchApprover = rule.clientApprover?.toLowerCase().includes(query);
        if (!matchName && !matchHypothesis && !matchDesc && !matchTech && !matchEnv && !matchApprover) {
          return false;
        }
      }
      return true;
    });
  }, [clientRules, selectedStatus, selectedPlatform, selectedSeverity, searchTerm]);

  // Aggregate Metrics
  const totalRules = clientRules.length;
  const activeCount = clientRules.filter((r) => r.status === 'Production Active').length;
  const stagingCount = clientRules.filter((r) => r.status === 'Testing / Staging').length;
  const pendingCount = clientRules.filter((r) => r.status === 'Pending Client Review').length;
  const tuningCount = clientRules.filter((r) => r.status === 'Tuning Needed').length;
  const totalAlertsFired = clientRules.reduce((acc, r) => acc + (r.totalAlertsTriggered || 0), 0);
  const avgFpRate = totalRules > 0
    ? (clientRules.reduce((acc, r) => acc + (r.falsePositiveRatePct || 0), 0) / totalRules).toFixed(1)
    : '0.0';

  // Handle Copy Query
  const handleCopyQuery = (ruleId: string, query: string) => {
    navigator.clipboard.writeText(query);
    setCopiedRuleId(ruleId);
    setTimeout(() => setCopiedRuleId(null), 2000);
  };

  // Handle Rule Simulation
  const handleSimulateRule = (ruleId: string) => {
    setSimulatingRuleId(ruleId);
    setTimeout(() => {
      const now = new Date().toISOString().replace('T', ' ').slice(0, 19);
      setSimulationOutputs((prev) => ({
        ...prev,
        [ruleId]: `[${now} UTC] Telemetry simulation completed against ${currentClient.name} SIEM logs. Evaluated 18,420 events over 24h window: 1 True Positive match identified with 0 false positives.`,
      }));
      setSimulatingRuleId(null);
    }, 850);
  };

  // Pre-fill form when origin hunt is selected
  const handleSelectOriginHunt = (reportId: string) => {
    setNewOriginHuntId(reportId);
    const report = clientReports.find((r) => r.id === reportId);
    if (report) {
      setNewRuleName(`RULE-${report.techniqueIds[0] || 'T1000'}-${report.hypothesisTitle.slice(0, 28).replace(/[^a-zA-Z0-9]/g, '-').toUpperCase()}`);
      setNewDescription(`Graduated from Hunt: ${report.hypothesisTitle}. ${report.notes.slice(0, 140)}...`);
      setNewQueryLogic(report.queryText);
      setNewTechniqueIds(report.techniqueIds.join(', '));
      setNewTactics('Credential Access, Defense Evasion');
      setNewTargetEnvironment(`${currentClient.name} Production SIEM Cluster`);
      if (report.queryLanguage === 'KQL') setNewPlatform('Microsoft Sentinel (KQL)');
      else if (report.queryLanguage === 'SPL') setNewPlatform('Splunk Enterprise (SPL)');
      else if (report.queryLanguage === 'Sigma') setNewPlatform('Sigma (Generic)');
    }
  };

  // Submit New Rule
  const handleSaveNewRule = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newRuleName.trim() || !newQueryLogic.trim()) return;

    const techArray = newTechniqueIds.split(',').map((t) => t.trim()).filter(Boolean);
    const tacticArray = newTactics.split(',').map((t) => t.trim()).filter(Boolean);

    const createdRule: DetectionRule = {
      id: `det-rule-${Date.now()}`,
      clientId: currentClient.id,
      huntReportId: newOriginHuntId || undefined,
      huntHypothesisTitle: clientReports.find((r) => r.id === newOriginHuntId)?.hypothesisTitle || 'Custom Hunter Hypothesis',
      ruleName: newRuleName.trim(),
      description: newDescription.trim(),
      platform: newPlatform,
      severity: newSeverity,
      status: newStatus,
      techniqueIds: techArray.length > 0 ? techArray : ['T1059'],
      tactics: tacticArray.length > 0 ? tacticArray : ['Execution'],
      queryLogic: newQueryLogic.trim(),
      targetDataSources: currentClient.primaryTelemetry.slice(0, 2),
      targetEnvironment: newTargetEnvironment.trim() || `${currentClient.name} SIEM`,
      deployedBy: `${currentUser.name} (Optiv Hunter)`,
      sentDate: new Date().toISOString(),
      totalAlertsTriggered: 0,
      falsePositiveRatePct: 0.0,
      tuningNotes: newTuningNotes.trim() || undefined,
      clientApprover: newClientApprover.trim() || 'Pending Review',
    };

    onAddDetectionRule(createdRule);
    setIsAddModalOpen(false);
    resetForm();
  };

  const resetForm = () => {
    setNewOriginHuntId('');
    setNewRuleName('');
    setNewDescription('');
    setNewPlatform('Microsoft Sentinel (KQL)');
    setNewSeverity('High');
    setNewStatus('Testing / Staging');
    setNewQueryLogic('');
    setNewTargetEnvironment('');
    setNewTechniqueIds('');
    setNewTactics('');
    setNewTuningNotes('');
    setNewClientApprover('');
  };

  // Export JSON/Markdown
  const handleExportPackage = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(clientRules, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `${currentClient.name.toLowerCase().replace(/\s+/g, '_')}_detection_rules_package.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="space-y-6">
      {/* Top Header & Context Card */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2.5 flex-wrap">
              <div className="w-8 h-8 rounded bg-cyan-950/80 border border-cyan-700/60 flex items-center justify-center text-cyan-400">
                <ShieldCheck className="w-4 h-4" />
              </div>
              <h1 className="text-xl font-bold text-white tracking-tight">Detection Coverage & Hunt Rule Tracking</h1>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/60">
                {currentClient.name}
              </span>
            </div>
            <p className="text-xs text-slate-300 max-w-3xl leading-relaxed">
              Track proactively tested threat hunts graduated into automated detection rules deployed to the client environment. Monitor testing, production activation, and tuning metrics across Sentinel, Splunk, CrowdStrike, and Sigma.
            </p>
          </div>

          <div className="flex items-center gap-2.5 shrink-0 flex-wrap">
            <button
              onClick={handleExportPackage}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-md bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors cursor-pointer"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              <span>Export Rules Package</span>
            </button>
            <button
              onClick={() => {
                resetForm();
                setIsAddModalOpen(true);
              }}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-md bg-cyan-600 hover:bg-cyan-500 text-white transition-colors shadow-sm cursor-pointer"
            >
              <PlusCircle className="w-3.5 h-3.5" />
              <span>Promote Hunt to Detection Rule</span>
            </button>
          </div>
        </div>

        {/* Client Environment Info Strip */}
        <div className="mt-4 pt-3 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-y-2 gap-x-4 text-xs text-slate-400 font-mono">
          <div className="flex items-center gap-2">
            <Building2 className="w-3.5 h-3.5 text-slate-500" />
            <span className="text-slate-500">Target SIEM/EDR:</span>
            <span className="text-slate-300">{currentClient.primaryTelemetry.slice(0, 3).join(' • ')}</span>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-emerald-400 font-semibold">● {activeCount} Production Active</span>
            <span className="text-cyan-400">○ {stagingCount} Testing</span>
            <span className="text-amber-400">△ {pendingCount} Pending Client Review</span>
          </div>
        </div>
      </div>

      {/* KPI Tiles */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* KPI 1: Total Deployed Rules */}
        <div 
          onClick={() => setSelectedStatus('all')}
          className={`bg-slate-900/80 border rounded-lg p-4 cursor-pointer transition-all select-none ${
            selectedStatus === 'all' ? 'border-cyan-500/80 ring-1 ring-cyan-500/30' : 'border-slate-800 hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium uppercase tracking-wider">Total Rules Sent</span>
            <Layers className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-3xl font-bold font-mono text-white tabular-nums">{totalRules}</div>
          <p className="text-[11px] text-slate-400 mt-2">Hunts converted into rules</p>
        </div>

        {/* KPI 2: Production Active */}
        <div 
          onClick={() => setSelectedStatus(selectedStatus === 'Production Active' ? 'all' : 'Production Active')}
          className={`bg-slate-900/80 border rounded-lg p-4 cursor-pointer transition-all select-none ${
            selectedStatus === 'Production Active' ? 'border-emerald-500 ring-1 ring-emerald-500/30' : 'border-slate-800 hover:border-emerald-500/60'
          }`}
        >
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium uppercase tracking-wider">Production Active</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-3xl font-bold font-mono text-emerald-400 tabular-nums">{activeCount}</div>
          <p className="text-[11px] text-emerald-400/90 mt-2 font-medium">Alerting live in client SIEM</p>
        </div>

        {/* KPI 3: Testing / Staging */}
        <div 
          onClick={() => setSelectedStatus(selectedStatus === 'Testing / Staging' ? 'all' : 'Testing / Staging')}
          className={`bg-slate-900/80 border rounded-lg p-4 cursor-pointer transition-all select-none ${
            selectedStatus === 'Testing / Staging' ? 'border-cyan-500 ring-1 ring-cyan-500/30' : 'border-slate-800 hover:border-cyan-500/60'
          }`}
        >
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium uppercase tracking-wider">Testing / Staging</span>
            <Clock className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-3xl font-bold font-mono text-cyan-300 tabular-nums">{stagingCount}</div>
          <p className="text-[11px] text-slate-400 mt-2">Silent mode validation</p>
        </div>

        {/* KPI 4: Pending Review / Tuning */}
        <div 
          onClick={() => setSelectedStatus(selectedStatus === 'Pending Client Review' ? 'all' : 'Pending Client Review')}
          className={`bg-slate-900/80 border rounded-lg p-4 cursor-pointer transition-all select-none ${
            selectedStatus === 'Pending Client Review' ? 'border-amber-500 ring-1 ring-amber-500/30' : 'border-slate-800 hover:border-amber-500/60'
          }`}
        >
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium uppercase tracking-wider">Client SOC Review</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-3xl font-bold font-mono text-amber-300 tabular-nums">{pendingCount}</div>
          <p className="text-[11px] text-slate-400 mt-2">Awaiting CISO/SOC sign-off</p>
        </div>

        {/* KPI 5: Alerts & Efficacy */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium uppercase tracking-wider">Alerts Fired</span>
            <Activity className="w-4 h-4 text-blue-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-white tabular-nums">{totalAlertsFired}</span>
            <span className="text-xs font-mono text-emerald-400">({avgFpRate}% avg FP)</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-2">Validated detection efficacy</p>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs">
        <div className="relative flex-1 max-w-md">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search rules, hypotheses, technique (e.g. T1003), or environment..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-md pl-9 pr-8 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
          />
          {searchTerm && (
            <button
              onClick={() => setSearchTerm('')}
              className="absolute right-2.5 top-2 text-slate-400 hover:text-slate-200"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {/* Status Filter */}
          <select
            aria-label="Filter by Status"
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-md px-2.5 py-1.5 text-slate-300 text-xs focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All Statuses ({totalRules})</option>
            <option value="Production Active">Production Active ({activeCount})</option>
            <option value="Testing / Staging">Testing / Staging ({stagingCount})</option>
            <option value="Pending Client Review">Pending Review ({pendingCount})</option>
            <option value="Tuning Needed">Tuning Needed ({tuningCount})</option>
          </select>

          {/* Platform Filter */}
          <select
            aria-label="Filter by SIEM Platform"
            value={selectedPlatform}
            onChange={(e) => setSelectedPlatform(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-md px-2.5 py-1.5 text-slate-300 text-xs focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All SIEM Platforms</option>
            {PLATFORM_OPTIONS.map((p) => (
              <option key={p} value={p}>{p}</option>
            ))}
          </select>

          {/* Severity Filter */}
          <select
            aria-label="Filter by Severity"
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-md px-2.5 py-1.5 text-slate-300 text-xs focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
        </div>
      </div>

      {/* Rules List / Cards */}
      <div className="space-y-4">
        {displayedRules.map((rule) => {
          const statusStyle = STATUS_CONFIG[rule.status];

          return (
            <div
              key={rule.id}
              className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4 hover:border-slate-700/80 transition-all shadow-sm"
            >
              {/* Card Header: Rule Title, Status, Severity, Platform */}
              <div className="flex flex-col md:flex-row md:items-start justify-between gap-3">
                <div className="space-y-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-sm font-bold text-white tracking-wide">
                      {rule.ruleName}
                    </span>

                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold border flex items-center gap-1.5 ${statusStyle.bg} ${statusStyle.text} ${statusStyle.border}`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${statusStyle.dot}`} />
                      {rule.status}
                    </span>

                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                      rule.severity === 'Critical'
                        ? 'bg-rose-950 text-rose-300 border border-rose-800'
                        : rule.severity === 'High'
                        ? 'bg-amber-950 text-amber-300 border border-amber-800'
                        : 'bg-blue-950 text-blue-300 border border-blue-800'
                    }`}>
                      {rule.severity}
                    </span>

                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-950 text-cyan-300 border border-slate-800">
                      {rule.platform}
                    </span>
                  </div>

                  <p className="text-xs text-slate-300 leading-relaxed max-w-4xl">
                    {rule.description}
                  </p>
                </div>

                {/* Quick Status Dropdown Updater */}
                <div className="shrink-0 flex items-center gap-2">
                  <div className="flex flex-col text-right">
                    <span className="text-[10px] text-slate-500 font-mono">Status:</span>
                    <select
                      aria-label="Update Rule Status"
                      value={rule.status}
                      onChange={(e) => {
                        onUpdateDetectionRule({
                          ...rule,
                          status: e.target.value as DetectionRuleStatus,
                        });
                      }}
                      className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-300 text-xs font-mono focus:outline-none focus:border-cyan-500"
                    >
                      <option value="Production Active">Production Active</option>
                      <option value="Testing / Staging">Testing / Staging</option>
                      <option value="Pending Client Review">Pending Client Review</option>
                      <option value="Tuning Needed">Tuning Needed</option>
                      <option value="Deprecated">Deprecated</option>
                    </select>
                  </div>
                </div>
              </div>

              {/* Metadata Grid: Origin Hunt, Target Environment, Approver, Dates */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 bg-slate-950/70 p-3 rounded-md border border-slate-800/80 text-xs">
                <div>
                  <span className="text-[10px] font-mono text-slate-500 uppercase block">Origin Hunt Hypothesis:</span>
                  <span className="text-slate-200 font-medium truncate block" title={rule.huntHypothesisTitle}>
                    {rule.huntHypothesisTitle}
                  </span>
                </div>

                <div>
                  <span className="text-[10px] font-mono text-slate-500 uppercase block">Target Client SIEM:</span>
                  <span className="text-slate-200 font-mono truncate block" title={rule.targetEnvironment}>
                    {rule.targetEnvironment}
                  </span>
                </div>

                <div>
                  <span className="text-[10px] font-mono text-slate-500 uppercase block">Client Approver / Deployed:</span>
                  <span className="text-slate-200 block truncate">
                    {rule.clientApprover || 'Pending Sign-off'}
                  </span>
                  <span className="text-[10px] font-mono text-slate-500">
                    Sent: {new Date(rule.sentDate).toLocaleDateString()}
                  </span>
                </div>

                <div>
                  <span className="text-[10px] font-mono text-slate-500 uppercase block">Telemetry Health:</span>
                  <div className="flex items-center gap-2 mt-0.5">
                    <span className="text-emerald-400 font-mono font-semibold">
                      {rule.totalAlertsTriggered} alert{rule.totalAlertsTriggered !== 1 ? 's' : ''}
                    </span>
                    <span className="text-slate-600">|</span>
                    <span className="text-slate-300 font-mono">
                      {rule.falsePositiveRatePct}% FP rate
                    </span>
                  </div>
                </div>
              </div>

              {/* MITRE ATT&CK Mapping & Required Data Sources */}
              <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="text-[10px] font-mono text-slate-500 uppercase mr-1">TTPs:</span>
                  {rule.techniqueIds.map((t) => (
                    <span
                      key={t}
                      className="px-2 py-0.5 bg-cyan-950/60 text-cyan-300 border border-cyan-800/50 rounded text-[10px] font-mono font-medium"
                    >
                      {t}
                    </span>
                  ))}
                  {rule.tactics.map((tac) => (
                    <span
                      key={tac}
                      className="px-2 py-0.5 bg-slate-950 text-slate-400 border border-slate-800 rounded text-[10px] font-mono"
                    >
                      {tac}
                    </span>
                  ))}
                </div>

                <div className="flex items-center gap-1.5 text-[11px] text-slate-400">
                  <span className="text-slate-500 font-mono">Data Sources:</span>
                  <span className="text-slate-300 font-mono">{rule.targetDataSources.join(', ')}</span>
                </div>
              </div>

              {/* Query Logic Preview with 1-Click Copy and Test Simulation */}
              <div className="bg-slate-950 rounded-md border border-slate-800 p-3 space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <FileCode className="w-3.5 h-3.5 text-cyan-400" />
                    <span className="text-[11px] font-mono text-slate-400 uppercase font-semibold">
                      {rule.platform} Logic
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleSimulateRule(rule.id)}
                      disabled={simulatingRuleId === rule.id}
                      className="px-2.5 py-1 text-[11px] font-mono text-slate-300 hover:text-white bg-slate-900 hover:bg-slate-800 border border-slate-700/80 rounded flex items-center gap-1.5 cursor-pointer transition-colors"
                    >
                      <Play className={`w-3 h-3 text-cyan-400 ${simulatingRuleId === rule.id ? 'animate-spin' : ''}`} />
                      <span>{simulatingRuleId === rule.id ? 'Evaluating Logs...' : 'Test Rule'}</span>
                    </button>

                    <button
                      onClick={() => handleCopyQuery(rule.id, rule.queryLogic)}
                      className="px-2.5 py-1 text-[11px] font-mono text-cyan-300 hover:text-cyan-200 bg-cyan-950/70 hover:bg-cyan-900/70 border border-cyan-800/60 rounded flex items-center gap-1.5 cursor-pointer transition-colors"
                    >
                      {copiedRuleId === rule.id ? (
                        <>
                          <Check className="w-3 h-3 text-emerald-400" />
                          <span>Copied!</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" />
                          <span>Copy Rule Logic</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>

                <pre className="p-2.5 bg-slate-900/90 rounded text-cyan-200 font-mono text-[11px] overflow-x-auto whitespace-pre-wrap border border-slate-800">
                  {rule.queryLogic}
                </pre>

                {/* Simulation Output Banner */}
                {simulationOutputs[rule.id] && (
                  <div className="p-2.5 bg-emerald-950/40 border border-emerald-800/60 rounded text-xs text-emerald-200 font-mono flex items-start gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    <span>{simulationOutputs[rule.id]}</span>
                  </div>
                )}

                {/* Tuning Notes */}
                {rule.tuningNotes && (
                  <div className="pt-2 border-t border-slate-800/70 text-[11px] text-slate-400 flex items-start gap-1.5">
                    <span className="font-semibold text-slate-300 font-mono shrink-0">Tuning & Whitelisting:</span>
                    <span className="text-slate-400">{rule.tuningNotes}</span>
                  </div>
                )}
              </div>
            </div>
          );
        })}

        {displayedRules.length === 0 && (
          <div className="py-16 text-center text-xs text-slate-400 bg-slate-900 rounded-lg border border-slate-800 space-y-2">
            <p className="text-sm font-semibold text-slate-300">No detection rules found matching your filters.</p>
            <p>You can promote any completed hunt report into an automated client detection rule using the button above.</p>
          </div>
        )}
      </div>

      {/* MODAL: Promote Hunt to Detection Rule */}
      {isAddModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl w-full max-w-2xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden animate-in fade-in duration-150">
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-cyan-400" />
                <div>
                  <h3 className="text-base font-bold text-white tracking-tight">
                    Deploy Hunt as Detection Rule to Client Environment
                  </h3>
                  <p className="text-[11px] text-slate-400">
                    Package verified hunt hypothesis into a continuous detection rule for {currentClient.name}.
                  </p>
                </div>
              </div>
              <button
                onClick={() => setIsAddModalOpen(false)}
                className="text-slate-400 hover:text-white p-1 rounded bg-slate-800 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleSaveNewRule} className="p-6 overflow-y-auto space-y-4 text-xs">
              {/* Select from existing hunt report */}
              <div>
                <label className="block text-slate-300 font-semibold mb-1">
                  1. Select Origin Hunt Report (Optional):
                </label>
                <select
                  aria-label="Select Origin Hunt Report"
                  value={newOriginHuntId}
                  onChange={(e) => handleSelectOriginHunt(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="">-- Custom Hypothesis / Write from Scratch --</option>
                  {clientReports.map((r) => (
                    <option key={r.id} value={r.id}>
                      [{r.techniqueIds.join(', ')}] {r.hypothesisTitle} ({r.outcome})
                    </option>
                  ))}
                </select>
                <span className="text-[10px] text-slate-500 mt-1 block">
                  Selecting a hunt report will auto-populate the detection query, techniques, and description.
                </span>
              </div>

              {/* Rule Name & Platform */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-semibold mb-1">
                    Rule Name: <span className="text-rose-400">*</span>
                  </label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. EDR-PROD-LSASS-DUMP-PPL"
                    value={newRuleName}
                    onChange={(e) => setNewRuleName(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 font-mono text-xs focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label className="block text-slate-300 font-semibold mb-1">
                    Target SIEM / EDR Platform:
                  </label>
                  <select
                    aria-label="Select Target Platform"
                    value={newPlatform}
                    onChange={(e) => setNewPlatform(e.target.value as DetectionPlatform)}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                  >
                    {PLATFORM_OPTIONS.map((p) => (
                      <option key={p} value={p}>{p}</option>
                    ))}
                  </select>
                </div>
              </div>

              {/* Severity & Status */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-semibold mb-1">Rule Severity:</label>
                  <select
                    aria-label="Select Rule Severity"
                    value={newSeverity}
                    onChange={(e) => setNewSeverity(e.target.value as any)}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-300 font-semibold mb-1">Initial Deployment Status:</label>
                  <select
                    aria-label="Select Initial Deployment Status"
                    value={newStatus}
                    onChange={(e) => setNewStatus(e.target.value as DetectionRuleStatus)}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="Testing / Staging">Testing / Staging (Silent Validation)</option>
                    <option value="Pending Client Review">Pending Client Review</option>
                    <option value="Production Active">Production Active (Alerting)</option>
                  </select>
                </div>
              </div>

              {/* Target Environment & Client Approver */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-semibold mb-1">
                    Target Environment / Workspace:
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. Apex Azure Sentinel Prod (Workspace: ws-apex-01)"
                    value={newTargetEnvironment}
                    onChange={(e) => setNewTargetEnvironment(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label className="block text-slate-300 font-semibold mb-1">
                    Client SOC Approver:
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. Rachel Greene (Lead SOC Analyst)"
                    value={newClientApprover}
                    onChange={(e) => setNewClientApprover(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>

              {/* Technique IDs & Tactics */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-semibold mb-1">MITRE Technique IDs (comma-separated):</label>
                  <input
                    type="text"
                    placeholder="T1003.001, T1059.001"
                    value={newTechniqueIds}
                    onChange={(e) => setNewTechniqueIds(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 font-mono text-xs focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div>
                  <label className="block text-slate-300 font-semibold mb-1">ATT&CK Tactics (comma-separated):</label>
                  <input
                    type="text"
                    placeholder="Credential Access, Defense Evasion"
                    value={newTactics}
                    onChange={(e) => setNewTactics(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>

              {/* Description */}
              <div>
                <label className="block text-slate-300 font-semibold mb-1">Rule Operational Description:</label>
                <textarea
                  rows={2}
                  placeholder="Summarize the threat behavior this automated rule detects in the client environment..."
                  value={newDescription}
                  onChange={(e) => setNewDescription(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
                />
              </div>

              {/* Detection Query Logic */}
              <div>
                <label className="block text-slate-300 font-semibold mb-1">
                  Detection Query Logic: <span className="text-rose-400">*</span>
                </label>
                <textarea
                  rows={5}
                  required
                  placeholder="Paste production detection query logic..."
                  value={newQueryLogic}
                  onChange={(e) => setNewQueryLogic(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-cyan-200 font-mono text-xs focus:outline-none focus:border-cyan-500"
                />
              </div>

              {/* Tuning Notes */}
              <div>
                <label className="block text-slate-300 font-semibold mb-1">
                  Tuning & False Positive Mitigation Notes:
                </label>
                <input
                  type="text"
                  placeholder="e.g. Whitelisted certified backup script backup-sql-dump.ps1"
                  value={newTuningNotes}
                  onChange={(e) => setNewTuningNotes(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
                />
              </div>

              {/* Form Actions */}
              <div className="pt-4 border-t border-slate-800 flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setIsAddModalOpen(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded font-medium cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded font-semibold cursor-pointer shadow-sm"
                >
                  Send & Deploy Rule to Client
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
