import React, { useState } from 'react';
import { ClientOrg, User, HuntOutcome, ThreatHuntQueryItem, ThreatHuntReportDocument, HuntReport } from '../types';
import { MITRE_TECHNIQUES } from '../data/mitreAttck';
import { generateThreatHuntReportDocument } from '../services/api';
import { downloadThreatHuntDoc, printThreatHuntPdf } from '../utils/thrExporter';
import {
  X,
  Sparkles,
  FileText,
  Plus,
  Trash2,
  Download,
  Printer,
  Save,
  Check,
  Code,
  Terminal,
  Layers,
  Calendar,
  AlertTriangle,
  BookOpen,
  Eye,
  Edit3,
} from 'lucide-react';

interface CreateTHRModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentClient: ClientOrg;
  currentUser: User;
  onSaveReport: (report: HuntReport) => void;
}

export const CreateTHRModal: React.FC<CreateTHRModalProps> = ({
  isOpen,
  onClose,
  currentClient,
  currentUser,
  onSaveReport,
}) => {
  // Step 1 Form States
  const todayStr = new Date().toISOString().split('T')[0];
  const [reportDate, setReportDate] = useState<string>(todayStr);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [queryContext, setQueryContext] = useState('');
  const [outcome, setOutcome] = useState<HuntOutcome>('No Result');
  const [huntResults, setHuntResults] = useState('');
  const [selectedTechniques, setSelectedTechniques] = useState<string[]>(['T1059.001']);
  const [dataSources, setDataSources] = useState<string[]>(
    currentClient.primaryTelemetry.slice(0, 3)
  );

  // Multiple Queries State
  const [queries, setQueries] = useState<ThreatHuntQueryItem[]>([
    {
      id: 'q-1',
      platform: 'KQL',
      title: 'Primary EDR Process Execution Query',
      code: `DeviceProcessEvents\n| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe")\n| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "downloadstring", "invoke-expression")\n| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName`,
      explanation: 'Detects base64 encoded or dynamic memory download strings in script interpreters.',
    },
  ]);

  // Mode: 'input' or 'preview'
  const [activeStep, setActiveStep] = useState<'input' | 'preview'>('input');
  const [isGenerating, setIsGenerating] = useState(false);
  const [generationError, setGenerationError] = useState<string | null>(null);
  const [isTemplate, setIsTemplate] = useState(false);
  const [savedSuccess, setSavedSuccess] = useState(false);

  // Generated THR Document (12-section standard)
  const [thrDocument, setThrDocument] = useState<ThreatHuntReportDocument | null>(null);

  // Add Query
  const handleAddQuery = () => {
    const newId = `q-${Date.now()}-${queries.length + 1}`;
    setQueries([
      ...queries,
      {
        id: newId,
        platform: 'KQL',
        title: `Secondary Query #${queries.length + 1}`,
        code: `// Insert secondary hunt query logic here\n`,
        explanation: 'Searches for related indicators or correlation telemetry.',
      },
    ]);
  };

  // Remove Query
  const handleRemoveQuery = (id: string) => {
    if (queries.length <= 1) return;
    setQueries(queries.filter((q) => q.id !== id));
  };

  // Update Query
  const handleUpdateQuery = (id: string, field: keyof ThreatHuntQueryItem, val: string) => {
    setQueries(
      queries.map((q) => (q.id === id ? { ...q, [field]: val } : q))
    );
  };

  // Toggle Technique
  const handleToggleTechnique = (techId: string) => {
    if (selectedTechniques.includes(techId)) {
      if (selectedTechniques.length > 1) {
        setSelectedTechniques(selectedTechniques.filter((t) => t !== techId));
      }
    } else {
      setSelectedTechniques([...selectedTechniques, techId]);
    }
  };

  // Load Preset Sample
  const handleLoadSample = (sampleType: 'dcsync' | 'ransomware' | 'fido2') => {
    if (sampleType === 'dcsync') {
      setTitle('Active Directory DCSync Replication Rights Abuse via Non-DC Principal');
      setDescription(
        'Adversaries leveraging compromised administrative credentials or misconfigured Access Control Entries (ACEs) to query DS-Replication-Get-Changes-All permissions against Domain Controllers using DRSUAPI remote procedure calls.'
      );
      setReportDate(todayStr);
      setOutcome('True Positive');
      setSelectedTechniques(['T1003.006', 'T1078.002', 'T1069.002']);
      setQueryContext(
        'Windows Security Event 4662 (Directory Service Access) and 4624 (Logon) from tier-0 domain controller security logs.'
      );
      setHuntResults(
        'Analyzed 450,000 Event 4662 records over past 30 days. Discovered 1 unauthorized workstation (10.14.88.22, host WS-FIN-ADM02) requesting GUID {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} without a domain controller computer account.'
      );
      setQueries([
        {
          id: 'q-dc-1',
          platform: 'SPL',
          title: 'Event 4662 DRSUAPI GUID Search (Splunk)',
          code: `index=wineventlog EventCode=4662 (AccessMask=0x100 OR AccessMask=0x10)\n| where match(Properties, "(?i)(\\{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2\\}|\\{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2\\})")\n| search NOT (SubjectUserName="*$")\n| stats count by _time, SubjectUserName, Computer, ObjectName`,
          explanation:
            'Identifies DCSync DS-Replication rights requests originating from user accounts rather than authorized machine accounts ending in $.',
        },
        {
          id: 'q-dc-2',
          platform: 'KQL',
          title: 'Microsoft Sentinel DC Directory Service Audit (KQL)',
          code: `SecurityEvent\n| where EventID == 4662\n| where ObjectServer == "DS"\n| where Properties has_any ("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")\n| where SubjectAccount !endswith "$"\n| project TimeGenerated, Computer, SubjectAccount, SubjectDomainName, Activity`,
          explanation: 'Correlates DRSUAPI GUID access with non-machine SubjectAccount identity.',
        },
      ]);
    } else if (sampleType === 'ransomware') {
      setTitle('Ransomware Pre-Encryption Inhibit Recovery & Volume Shadow Destruction');
      setDescription(
        '2026 ransomware operators (Qilin, RansomHub) utilize automated command-line scripts to delete Volume Shadow Copies and stop EDR endpoint agents immediately prior to encrypting clinical databases.'
      );
      setReportDate(todayStr);
      setOutcome('No Result');
      setSelectedTechniques(['T1490', 'T1562.001', 'T1059.003']);
      setQueryContext(
        'Endpoint process telemetry across all Windows medical servers, testing for vssadmin and driver unloading utilities.'
      );
      setHuntResults(
        'Scanned all 2,800 active endpoints over 14 days. Zero executions of "vssadmin delete shadows" or "bcdedit /set ignoreallfailures". All shadow copy creation tasks were validated as authorized Veeam backup schedules.'
      );
      setQueries([
        {
          id: 'q-vss-1',
          platform: 'KQL',
          title: 'Volume Shadow Deletion & Recovery Inhibition (KQL)',
          code: `DeviceProcessEvents\n| where FileName in~ ("vssadmin.exe", "wmic.exe", "wbadmin.exe", "bcdedit.exe")\n| where ProcessCommandLine has_any ("delete shadows", "shadowcopy delete", "resize shadowstorage", "recoveryenabled no", "bootstatuspolicy ignoreallfailures")\n| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName`,
          explanation: 'Flags explicit attempts to destroy backup snapshots and disable Windows boot recovery.',
        },
      ]);
    } else {
      setTitle('Fast-Follow Helpdesk Voice-Phishing (Vishing) & Rogue FIDO2 Token Enrollment');
      setDescription(
        'Adversaries impersonating corporate helpdesk personnel to deceive employees into approving MFA push fatigue notifications, followed by instantaneous enrollment of unauthorized FIDO2 hardware tokens.'
      );
      setReportDate(todayStr);
      setOutcome('Needs Follow-up');
      setSelectedTechniques(['T1098.001', 'T1078.004', 'T1621']);
      setQueryContext(
        'Okta SystemLog, Entra ID Sign-in logs, and User MFA Factor registration events.'
      );
      setHuntResults(
        'Observed 2 instances of user.mfa.factor.activate initiated from residential IP subnets outside corporate geographical allowances within 5 minutes of a password reset request.'
      );
      setQueries([
        {
          id: 'q-mfa-1',
          platform: 'SPL',
          title: 'Okta High-Risk Token Activation Spanning Geography (Splunk)',
          code: `index=okta eventType IN ("user.account.reset_password", "user.mfa.factor.activate", "user.session.start")\n| transaction actor.alternateId maxspan=20m\n| where match(client.geographicalContext.country, "(?i)(unknown|russia|nigeria)") OR client.userAgent LIKE "%Headless%"\n| table _time, actor.alternateId, eventType, client.ipAddress, client.userAgent, target.displayName`,
          explanation: 'Correlates rapid factor activation across non-standard foreign IP geographical context.',
        },
      ]);
    }
  };

  // Generate with AI
  const handleGenerateTHR = async () => {
    if (!title.trim()) {
      setGenerationError('Please provide a Hypothesis Name (Title) before generating.');
      return;
    }
    setIsGenerating(true);
    setGenerationError(null);

    try {
      const { data: generated, fallback } = await generateThreatHuntReportDocument({
        title: title.trim(),
        description: description.trim() || 'Proactive hunt hypothesis investigation.',
        reportDate,
        queryContext: queryContext.trim() || 'Telemetry analysis across environment.',
        queries,
        huntResults: huntResults.trim() || 'Investigation concluded without confirmed adversary presence.',
        outcome,
        techniqueIds: selectedTechniques,
        client: currentClient,
        hunter: currentUser,
      });

      setThrDocument(generated);
      setIsTemplate(fallback);
      setActiveStep('preview');
    } catch (err: any) {
      setGenerationError(err.message || 'Failed to generate Threat Hunt Report with AI intelligence.');
    } finally {
      setIsGenerating(false);
    }
  };

  // Save to System
  const handleSaveToSystem = () => {
    if (!thrDocument) return;

    const newReport: HuntReport = {
      id: `thr-${Date.now()}`,
      clientId: currentClient.id,
      analystId: currentUser.id,
      analystName: currentUser.name,
      weekRange: `THR (${thrDocument.reportDate || reportDate})`,
      hypothesisTitle: thrDocument.hypothesisName || title,
      hypothesisDescription: thrDocument.executiveSummary || description,
      techniqueIds: selectedTechniques,
      dataSources: dataSources,
      queryLanguage: (queries[0]?.platform === 'SPL' ? 'SPL' : queries[0]?.platform === 'Sigma' ? 'Sigma' : 'KQL') as any,
      queryText: queries.map((q) => `// [${q.platform}] ${q.title || 'Query'}\n${q.code}`).join('\n\n'),
      outcome: outcome,
      notes: `THR Official Report: ${thrDocument.purpose}\n\nKey Analysis:\n${thrDocument.analysis}\n\nRecommendations:\n${thrDocument.recommendation}`,
      iocs: [],
      createdAt: new Date().toISOString(),
      isTHR: true,
      reportDate: thrDocument.reportDate || reportDate,
      thrDocument: thrDocument,
    };

    onSaveReport(newReport);
    setSavedSuccess(true);
    setTimeout(() => {
      setSavedSuccess(false);
      onClose();
    }, 1200);
  };

  // Download Word DOC
  const handleDownloadDoc = () => {
    if (!thrDocument) return;
    downloadThreatHuntDoc(thrDocument, currentClient.name, currentUser.name, outcome);
  };

  // Print / Save as PDF
  const handlePrintPdf = () => {
    if (!thrDocument) return;
    printThreatHuntPdf(thrDocument, currentClient.name, currentUser.name, outcome);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 overflow-y-auto">
      <div className="bg-slate-900 border border-slate-700 rounded-xl w-full max-w-5xl max-h-[92vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Modal Top Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400">
              <FileText className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-white tracking-tight">
                  Create Threat Hunt Report (THR)
                </h2>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-300 border border-emerald-800/80 font-bold uppercase">
                  12-Section Format
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Client: <strong className="text-white">{currentClient.name}</strong> · Hunter:{' '}
                <span className="text-emerald-400">{currentUser.name}</span>
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* View Mode Switcher */}
            {thrDocument && (
              <div className="flex items-center bg-slate-900 border border-slate-800 rounded-lg p-0.5 text-xs">
                <button
                  onClick={() => setActiveStep('input')}
                  className={`px-3 py-1 rounded-md transition-colors cursor-pointer flex items-center gap-1.5 ${
                    activeStep === 'input'
                      ? 'bg-slate-800 text-white font-semibold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Edit3 className="w-3.5 h-3.5" />
                  <span>Hunter Inputs</span>
                </button>
                <button
                  onClick={() => setActiveStep('preview')}
                  className={`px-3 py-1 rounded-md transition-colors cursor-pointer flex items-center gap-1.5 ${
                    activeStep === 'preview'
                      ? 'bg-emerald-600 text-white font-semibold shadow-sm'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Eye className="w-3.5 h-3.5" />
                  <span>THR Report View</span>
                </button>
              </div>
            )}

            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Modal Body Container */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6 scrollbar-thin">
          {generationError && (
            <div className="p-3 bg-rose-950/70 border border-rose-800 rounded-lg flex items-center justify-between text-xs text-rose-200">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                <span>{generationError}</span>
              </div>
              <button
                onClick={() => setGenerationError(null)}
                className="text-rose-400 hover:text-rose-200 font-bold"
              >
                Dismiss
              </button>
            </div>
          )}

          {activeStep === 'input' ? (
            /* ========================================================= */
            /* STEP 1: HUNTER INPUTS FORM                                */
            /* ========================================================= */
            <div className="space-y-5 text-xs">
              {/* Presets Bar */}
              <div className="bg-slate-950/80 p-3 rounded-lg border border-slate-800 flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-2 text-slate-300 font-medium">
                  <BookOpen className="w-4 h-4 text-cyan-400" />
                  <span>Quick Load Realistic 2026 Hunt Blueprints:</span>
                </div>
                <div className="flex items-center gap-2 flex-wrap">
                  <button
                    onClick={() => handleLoadSample('dcsync')}
                    className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-cyan-300 font-mono text-[11px] cursor-pointer"
                  >
                    DCSync Replication Rights
                  </button>
                  <button
                    onClick={() => handleLoadSample('ransomware')}
                    className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-emerald-300 font-mono text-[11px] cursor-pointer"
                  >
                    Ransomware Inhibit Recovery
                  </button>
                  <button
                    onClick={() => handleLoadSample('fido2')}
                    className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 font-mono text-[11px] cursor-pointer"
                  >
                    Rogue FIDO2 Token Reset
                  </button>
                </div>
              </div>

              {/* Row 1: Date, Outcome, Client */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div>
                  <label className="block text-slate-300 font-semibold mb-1 flex items-center gap-1.5">
                    <Calendar className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Hunt Record Date *</span>
                  </label>
                  <input
                    type="date"
                    value={reportDate}
                    onChange={(e) => setReportDate(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-100 font-mono text-xs focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label className="block text-slate-300 font-semibold mb-1">
                    Investigation Outcome *
                  </label>
                  <select
                    value={outcome}
                    onChange={(e) => setOutcome(e.target.value as HuntOutcome)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-100 text-xs focus:outline-none focus:border-cyan-500"
                  >
                    <option value="True Positive">True Positive (Confirmed Threat / IOCs)</option>
                    <option value="False Positive">False Positive (Benign / Misconfig)</option>
                    <option value="No Result">No Result (Hypothesis Refuted / Negative)</option>
                    <option value="Needs Follow-up">Needs Follow-up (Inconclusive)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-300 font-semibold mb-1">
                    Client Organization
                  </label>
                  <input
                    type="text"
                    disabled
                    value={currentClient.name}
                    className="w-full bg-slate-950/60 border border-slate-800/60 rounded-lg px-3 py-2 text-slate-400 text-xs font-medium cursor-not-allowed"
                  />
                </div>
              </div>

              {/* Row 2: Hypothesis Name (Title) */}
              <div>
                <label className="block text-slate-300 font-semibold mb-1">
                  Hypothesis Name (Title) *
                </label>
                <input
                  type="text"
                  placeholder="e.g., Credential Access: DCSync Replication Rights via Misconfigured Service Principal"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-100 font-semibold text-xs focus:outline-none focus:border-cyan-500"
                />
              </div>

              {/* Row 3: Threat Description */}
              <div>
                <label className="block text-slate-300 font-semibold mb-1">
                  Description & Threat Trigger Context *
                </label>
                <textarea
                  rows={2}
                  placeholder="Describe the suspected threat, attacker objective, zero-day CVE, or threat intel triggering this hunt..."
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 text-xs focus:outline-none focus:border-cyan-500 leading-relaxed"
                />
              </div>

              {/* MITRE ATT&CK Techniques Badges */}
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="text-slate-300 font-semibold flex items-center gap-1.5">
                    <Layers className="w-3.5 h-3.5 text-cyan-400" />
                    <span>MITRE ATT&CK Techniques ({selectedTechniques.length} tagged)</span>
                  </label>
                  <span className="text-[11px] text-slate-500">
                    Click techniques to tag or untag
                  </span>
                </div>
                <div className="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto p-2 bg-slate-950 rounded-lg border border-slate-800 scrollbar-thin">
                  {MITRE_TECHNIQUES.slice(0, 24).map((tech) => {
                    const isSelected = selectedTechniques.includes(tech.id);
                    return (
                      <button
                        key={tech.id}
                        type="button"
                        onClick={() => handleToggleTechnique(tech.id)}
                        className={`px-2 py-0.5 rounded font-mono text-[10px] cursor-pointer transition-colors border ${
                          isSelected
                            ? 'bg-cyan-950 text-cyan-300 border-cyan-500 font-bold'
                            : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-slate-200'
                        }`}
                      >
                        {tech.id} - {tech.name}
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Row 4: Query Context */}
              <div>
                <label className="block text-slate-300 font-semibold mb-1">
                  Query Context & Baseline Assumptions
                </label>
                <input
                  type="text"
                  placeholder="e.g., EDR Process Creation logs (Event 4688 / Sysmon 1) across all clinical servers; excluding authorized backup service accounts."
                  value={queryContext}
                  onChange={(e) => setQueryContext(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
                />
              </div>

              {/* MULTIPLE QUERIES SECTION */}
              <div className="space-y-3 pt-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-emerald-400" />
                    <span className="font-semibold text-slate-200 text-xs uppercase tracking-wider">
                      Hunt Queries ({queries.length} Included)
                    </span>
                  </div>
                  <button
                    type="button"
                    onClick={handleAddQuery}
                    className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-emerald-300 border border-slate-700 text-xs font-semibold cursor-pointer transition-colors"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    <span>+ Add Another Query</span>
                  </button>
                </div>

                <div className="space-y-3">
                  {queries.map((q, idx) => (
                    <div
                      key={q.id}
                      className="bg-slate-950 p-3.5 rounded-lg border border-slate-800 space-y-2.5 relative group"
                    >
                      <div className="flex items-center justify-between gap-2 flex-wrap">
                        <div className="flex items-center gap-2 flex-1">
                          <span className="font-mono text-[11px] font-bold text-slate-400">
                            Query #{idx + 1}
                          </span>
                          <select
                            value={q.platform}
                            onChange={(e) => handleUpdateQuery(q.id, 'platform', e.target.value)}
                            className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-slate-200 font-mono text-[11px] focus:outline-none focus:border-cyan-500"
                          >
                            <option value="KQL">Microsoft Sentinel (KQL)</option>
                            <option value="SPL">Splunk (SPL)</option>
                            <option value="Sigma">Sigma (Generic YAML)</option>
                            <option value="EQL">Elasticsearch (EQL)</option>
                            <option value="CrowdStrike (FQL)">CrowdStrike (FQL)</option>
                            <option value="SentinelOne (S1QL)">SentinelOne (S1QL)</option>
                            <option value="Trend Micro Vision One">Trend Micro Vision One</option>
                            <option value="Other">Other / Custom</option>
                          </select>
                          <input
                            type="text"
                            placeholder="Query Title or Objective (optional)"
                            value={q.title || ''}
                            onChange={(e) => handleUpdateQuery(q.id, 'title', e.target.value)}
                            className="flex-1 bg-slate-900 border border-slate-700 rounded px-2 py-1 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
                          />
                        </div>

                        {queries.length > 1 && (
                          <button
                            type="button"
                            onClick={() => handleRemoveQuery(q.id)}
                            className="p-1 text-slate-500 hover:text-rose-400 rounded transition-colors cursor-pointer"
                            title="Remove this query"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>

                      {/* Code Area */}
                      <div>
                        <textarea
                          rows={4}
                          value={q.code}
                          onChange={(e) => handleUpdateQuery(q.id, 'code', e.target.value)}
                          placeholder="Paste query syntax here..."
                          className="w-full bg-slate-900 border border-slate-800 rounded p-2.5 font-mono text-cyan-200 text-[11px] focus:outline-none focus:border-cyan-500 leading-relaxed"
                        />
                      </div>

                      {/* Explanation */}
                      <div>
                        <input
                          type="text"
                          value={q.explanation || ''}
                          onChange={(e) => handleUpdateQuery(q.id, 'explanation', e.target.value)}
                          placeholder="Query Explanation: What is this query designed to find in the logs?"
                          className="w-full bg-slate-900/60 border border-slate-800 rounded px-2.5 py-1.5 text-slate-300 text-xs focus:outline-none focus:border-cyan-500"
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Hunt Results Documented */}
              <div>
                <label className="block text-slate-300 font-semibold mb-1">
                  Hunt Results & Observations (Findings from execution)
                </label>
                <textarea
                  rows={2}
                  placeholder="Document findings: number of matching hits, endpoints investigated, evidence collected, or confirmation of negative baseline..."
                  value={huntResults}
                  onChange={(e) => setHuntResults(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 text-xs focus:outline-none focus:border-cyan-500 leading-relaxed"
                />
              </div>

              {/* Generate Button Bar */}
              <div className="pt-3 border-t border-slate-800 flex items-center justify-between">
                <span className="text-slate-500 text-[11px]">
                  Blindspot AI will synthesize your inputs into the official 12-section Threat Hunt
                  Report format.
                </span>

                <button
                  type="button"
                  disabled={isGenerating || !title.trim()}
                  onClick={handleGenerateTHR}
                  className="px-5 py-2.5 rounded-lg bg-accent hover:bg-accent-hover text-white font-semibold text-sm flex items-center gap-2 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <Sparkles className="w-4 h-4" />
                  <span>{isGenerating ? 'Synthesizing THR Sections...' : 'Generate Report from Intelligence →'}</span>
                </button>
              </div>
            </div>
          ) : (
            /* ========================================================= */
            /* STEP 2: GENERATED 12-SECTION THR REPORT PREVIEW & EDIT     */
            /* ========================================================= */
            thrDocument && (
              <div className="space-y-6 text-xs animate-in fade-in duration-150">
                {/* Top Action Ribbon */}
                <div className="bg-slate-950 p-4 rounded-xl border border-emerald-800/80 flex flex-wrap items-center justify-between gap-3 shadow-md">
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center font-bold">
                      ✓
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-white text-sm">
                          {isTemplate ? 'Template draft (AI unavailable)' : 'Draft generated'}
                        </span>
                        <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-[10px] font-mono font-bold">
                          {outcome}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400">
                        {isTemplate
                          ? 'The AI service could not be reached, so sections contain generic template text. Rewrite them before saving or exporting.'
                          : `Date: ${thrDocument.reportDate} · ${currentClient.name} · Review and edit every section before saving.`}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 flex-wrap">
                    <button
                      onClick={handleDownloadDoc}
                      className="px-3.5 py-2 rounded-lg bg-blue-700 hover:bg-blue-600 text-white font-semibold text-xs flex items-center gap-1.5 shadow-sm cursor-pointer transition-colors"
                      title="Download as Microsoft Word compatible .doc file"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>Download DOC (.doc)</span>
                    </button>

                    <button
                      onClick={handlePrintPdf}
                      className="px-3.5 py-2 rounded-lg bg-rose-700 hover:bg-rose-600 text-white font-semibold text-xs flex items-center gap-1.5 shadow-sm cursor-pointer transition-colors"
                      title="Print or Save as PDF"
                    >
                      <Printer className="w-3.5 h-3.5" />
                      <span>Download / Print PDF</span>
                    </button>

                    <button
                      onClick={handleSaveToSystem}
                      className="px-4 py-2 rounded-lg bg-accent hover:bg-accent-hover text-white font-semibold text-sm flex items-center gap-1.5 transition-colors"
                    >
                      {savedSuccess ? (
                        <>
                          <Check className="w-4 h-4 text-white" />
                          <span>Saved to Knowledge Base!</span>
                        </>
                      ) : (
                        <>
                          <Save className="w-4 h-4" />
                          <span>Save to Knowledge Base</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>

                {/* THE 12 SECTIONS RENDERING */}
                <div className="bg-slate-950 p-6 rounded-xl border border-slate-800 space-y-6">
                  {/* Hypothesis Name Banner */}
                  <div className="border-b border-slate-800 pb-4">
                    <span className="text-[10px] font-mono text-cyan-400 font-bold uppercase tracking-widest">
                      THREAT HUNT REPORT · &lt;Hypothesis Name&gt;
                    </span>
                    <h1 className="text-xl font-bold text-white mt-1 leading-snug">
                      {thrDocument.hypothesisName}
                    </h1>
                    <div className="flex items-center gap-3 text-slate-400 text-xs mt-2 font-mono">
                      <span>Date: {thrDocument.reportDate}</span>
                      <span>·</span>
                      <span>Client: {currentClient.name}</span>
                      <span>·</span>
                      <span>Analyst: {currentUser.name}</span>
                      <span>·</span>
                      <span className="text-emerald-400 font-bold">Outcome: {outcome}</span>
                    </div>
                  </div>

                  {/* 1. Executive Summary */}
                  <section className="space-y-1.5">
                    <h3 className="text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                      <span>1. Executive Summary</span>
                    </h3>
                    <p className="text-slate-200 leading-relaxed bg-slate-900/60 p-3.5 rounded-lg border border-slate-800/80">
                      {thrDocument.executiveSummary}
                    </p>
                  </section>

                  {/* 2. Purpose */}
                  <section className="space-y-1.5">
                    <h3 className="text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                      <span>2. Purpose</span>
                    </h3>
                    <p className="text-slate-200 leading-relaxed bg-slate-900/60 p-3.5 rounded-lg border border-slate-800/80">
                      {thrDocument.purpose}
                    </p>
                  </section>

                  {/* 3. MITRE Information */}
                  <section className="space-y-1.5">
                    <h3 className="text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                      <span>3. MITRE Information</span>
                    </h3>
                    <div className="text-slate-200 leading-relaxed bg-cyan-950/20 p-3.5 rounded-lg border border-cyan-800/40 whitespace-pre-wrap font-sans">
                      {thrDocument.mitreInformation}
                    </div>
                  </section>

                  {/* 4. High-Level Overview of Hunt Methodology */}
                  <section className="space-y-1.5">
                    <h3 className="text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                      <span>4. High-Level Overview of Hunt Methodology</span>
                    </h3>
                    <div className="text-slate-200 leading-relaxed bg-slate-900/60 p-3.5 rounded-lg border border-slate-800/80 whitespace-pre-wrap">
                      {thrDocument.huntMethodology}
                    </div>
                  </section>

                  {/* 5. Potential Detection Ideas & Hunting Thoughts */}
                  <section className="space-y-1.5">
                    <h3 className="text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                      <span>5. Potential Detection Ideas & Hunting Thoughts</span>
                    </h3>
                    <div className="text-slate-200 leading-relaxed bg-slate-900/60 p-3.5 rounded-lg border border-slate-800/80 whitespace-pre-wrap">
                      {thrDocument.potentialDetectionIdeas}
                    </div>
                  </section>

                  {/* 6. Hunt Query (Multi-Query Display) */}
                  <section className="space-y-2">
                    <div className="flex items-center justify-between">
                      <h3 className="text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                        <Code className="w-4 h-4 text-emerald-400" />
                        <span>6. Hunt Query ({thrDocument.huntQueries.length} Executed)</span>
                      </h3>
                    </div>

                    <div className="space-y-3">
                      {thrDocument.huntQueries.map((q, idx) => (
                        <div
                          key={q.id || idx}
                          className="bg-slate-900/90 rounded-lg border border-slate-800 overflow-hidden"
                        >
                          <div className="px-3 py-2 bg-slate-900 border-b border-slate-800 flex items-center justify-between text-xs">
                            <span className="font-semibold text-slate-200">
                              Query #{idx + 1}: {q.title || 'Telemetry Execution'}
                            </span>
                            <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 font-mono text-[10px] font-bold border border-cyan-800/60">
                              {q.platform}
                            </span>
                          </div>
                          <pre className="p-3 text-[11px] font-mono text-cyan-200 overflow-x-auto whitespace-pre-wrap bg-slate-950/80">
                            {q.code}
                          </pre>
                          {q.explanation && (
                            <div className="px-3 py-2 bg-slate-900/60 border-t border-slate-800/80 text-[11px] text-slate-400">
                              <span className="font-semibold text-slate-300">Target Intent: </span>
                              {q.explanation}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </section>

                  {/* 7. Hunt Results */}
                  <section className="space-y-1.5">
                    <h3 className="text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                      <span>7. Hunt Results</span>
                    </h3>
                    <p className="text-slate-200 leading-relaxed bg-slate-900/60 p-3.5 rounded-lg border border-slate-800/80">
                      {thrDocument.huntResults}
                    </p>
                  </section>

                  {/* 8. Analysis */}
                  <section className="space-y-1.5">
                    <h3 className="text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                      <span>8. Analysis</span>
                    </h3>
                    <p className="text-slate-200 leading-relaxed bg-slate-900/60 p-3.5 rounded-lg border border-slate-800/80">
                      {thrDocument.analysis}
                    </p>
                  </section>

                  {/* 9. Risk */}
                  <section className="space-y-1.5">
                    <h3 className="text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                      <span>9. Risk</span>
                    </h3>
                    <p className="text-slate-200 leading-relaxed bg-slate-900/60 p-3.5 rounded-lg border border-slate-800/80">
                      {thrDocument.risk}
                    </p>
                  </section>

                  {/* 10. Impact */}
                  <section className="space-y-1.5">
                    <h3 className="text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                      <span>10. Impact</span>
                    </h3>
                    <p className="text-slate-200 leading-relaxed bg-slate-900/60 p-3.5 rounded-lg border border-slate-800/80">
                      {thrDocument.impact}
                    </p>
                  </section>

                  {/* 11. Recommendation */}
                  <section className="space-y-1.5">
                    <h3 className="text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                      <span>11. Recommendation</span>
                    </h3>
                    <div className="text-slate-200 leading-relaxed bg-slate-900/60 p-3.5 rounded-lg border border-slate-800/80 whitespace-pre-wrap">
                      {thrDocument.recommendation}
                    </div>
                  </section>

                  {/* 12. References */}
                  <section className="space-y-1.5">
                    <h3 className="text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                      <span>12. References</span>
                    </h3>
                    <ul className="list-disc list-inside text-slate-300 bg-slate-900/60 p-3.5 rounded-lg border border-slate-800/80 space-y-1">
                      {thrDocument.references && thrDocument.references.length > 0 ? (
                        thrDocument.references.map((ref, idx) => (
                          <li key={idx} className="leading-relaxed">
                            {ref}
                          </li>
                        ))
                      ) : (
                        <li>MITRE ATT&CK Enterprise Matrix</li>
                      )}
                    </ul>
                  </section>
                </div>
              </div>
            )
          )}
        </div>

        {/* Modal Bottom Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-slate-950 flex items-center justify-between text-xs">
          <div className="flex items-center gap-2 text-slate-500 font-mono text-[11px]">
            <span>Blindspot THR Engine</span>
            <span>·</span>
            <span>Client: {currentClient.name}</span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              className="px-3.5 py-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer"
            >
              Close
            </button>
            {thrDocument && activeStep === 'preview' && (
              <button
                onClick={handleSaveToSystem}
                className="px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs flex items-center gap-1.5 shadow cursor-pointer transition-colors"
              >
                <Save className="w-3.5 h-3.5" />
                <span>Save to Knowledge Base</span>
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
