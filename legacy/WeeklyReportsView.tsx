import React, { useState } from 'react';
import { 
  ClientOrg, 
  HuntOutcome, 
  HuntReport, 
  IOC, 
  NextHuntRecommendation, 
  User,
  ThreatHuntReportDocument
} from '../types';
import { ALL_DATA_SOURCES, MITRE_TECHNIQUES } from '../data/mitreAttck';
import { fetchNextHuntRecommendations, parseReportPdf } from '../services/api';
import { downloadThreatHuntDoc, printThreatHuntPdf } from '../utils/thrExporter';
import { 
  Plus, 
  Search, 
  Sparkles, 
  CheckCircle2, 
  XCircle, 
  HelpCircle, 
  Clock, 
  Copy, 
  Check, 
  ChevronDown, 
  ChevronUp, 
  Tag, 
  ShieldAlert, 
  Filter,
  Terminal,
  Loader2,
  Trash2,
  UploadCloud,
  FileText,
  FileCheck2,
  AlertTriangle,
  RefreshCw,
  FileCode,
  Play,
  ShieldCheck,
  Download,
  Printer
} from 'lucide-react';

interface WeeklyReportsViewProps {
  currentClient: ClientOrg;
  currentUser: User;
  reports: HuntReport[];
  onAddReport: (report: HuntReport) => void;
  onOpenSeverityModalForReport?: (reportId: string) => void;
  preselectedTechnique?: string;
  onClearPreselectedTechnique?: () => void;
  onOpenCreateTHR?: () => void;
}

export const WeeklyReportsView: React.FC<WeeklyReportsViewProps> = ({
  currentClient,
  currentUser,
  reports,
  onAddReport,
  preselectedTechnique,
  onClearPreselectedTechnique,
  onOpenCreateTHR,
}) => {
  // Tabs: 'archive' (Knowledge Base) vs 'log' (Create Report)
  const [activeTab, setActiveTab] = useState<'archive' | 'log'>('archive');
  
  // Knowledge Base Search & Filter State
  const [searchTerm, setSearchTerm] = useState('');
  const [outcomeFilter, setOutcomeFilter] = useState<string>('all');
  const [selectedReportId, setSelectedReportId] = useState<string | null>(null);
  const [copiedQueryId, setCopiedQueryId] = useState<string | null>(null);

  // AI Recommendation Engine state
  const [recommendations, setRecommendations] = useState<NextHuntRecommendation[]>([]);
  const [loadingAi, setLoadingAi] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);

  // Form State for Logging New Hunt
  const [weekRange, setWeekRange] = useState('2026-W39 (Sep 21 - Sep 27)');
  const [hypothesisTitle, setHypothesisTitle] = useState('');
  const [hypothesisDescription, setHypothesisDescription] = useState('');
  const [selectedTechniques, setSelectedTechniques] = useState<string[]>(
    preselectedTechnique ? [preselectedTechnique] : ['T1059.001']
  );
  const [selectedDataSources, setSelectedDataSources] = useState<string[]>([
    'EDR Process Creation',
    'Windows Event 4688 / Sysmon 1',
  ]);
  const [queryLanguage, setQueryLanguage] = useState<'KQL' | 'SPL' | 'Sigma' | 'EQL'>('KQL');
  const [queryText, setQueryText] = useState(
    `DeviceProcessEvents\n| where FileName in~ ("powershell.exe", "pwsh.exe")\n| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "downloadstring")\n| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine`
  );

  // Report Format Selector & Detection State
  const [selectedUploadFormat, setSelectedUploadFormat] = useState<string>('auto');
  const [detectedFormatBadge, setDetectedFormatBadge] = useState<{
    label: string;
    confidence: number;
  } | null>(null);

  const detectFormatFromFileAndContent = (fileName: string, content: string) => {
    const ext = fileName.toLowerCase().split('.').pop() || '';
    if (ext === 'pdf') {
      return { format: 'PDF', label: 'PDF Threat Intelligence Report (.pdf)', confidence: 99 };
    }
    if (ext === 'json') {
      return { format: 'JSON', label: 'JSON Structured Hunt Export (.json)', confidence: 98 };
    }
    if (ext === 'md' || ext === 'markdown') {
      return { format: 'Markdown', label: 'Markdown Hunt Playbook (.md)', confidence: 97 };
    }
    if (ext === 'yml' || ext === 'yaml') {
      return { format: 'EDR', label: 'EDR / SIEM Detection Rule (.yaml)', confidence: 96 };
    }
    if (ext === 'csv') {
      return { format: 'CSV', label: 'CSV Incident Telemetry Dump (.csv)', confidence: 95 };
    }
    const lower = content.toLowerCase();
    if (lower.includes('{') && lower.includes('}') && (lower.includes('hypothesis') || lower.includes('mitre'))) {
      return { format: 'JSON', label: 'JSON Structured Hunt Export', confidence: 94 };
    }
    if (lower.includes('# ') || lower.includes('## ') || lower.includes('**')) {
      return { format: 'Markdown', label: 'Markdown Playbook Document', confidence: 92 };
    }
    return { format: 'PDF', label: 'PDF / Text Threat Report', confidence: 90 };
  };
  const [outcome, setOutcome] = useState<HuntOutcome>('No Result');
  const [notes, setNotes] = useState('');
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [newIocType, setNewIocType] = useState<IOC['type']>('IP');
  const [newIocValue, setNewIocValue] = useState('');
  const [newIocNotes, setNewIocNotes] = useState('');

  // PDF Document Ingestion & Extraction State
  const [isExtractingPdf, setIsExtractingPdf] = useState(false);
  const [extractedInfo, setExtractedInfo] = useState<{
    fileName: string;
    summary: string;
    confidenceScore: number;
  } | null>(null);
  const [pdfUploadError, setPdfUploadError] = useState<string | null>(null);
  const [isDraggingFile, setIsDraggingFile] = useState(false);
  const fileInputRef = React.useRef<HTMLInputElement>(null);

  // Interactive Query Tester & IOC Reputation State
  const [isTestingQuery, setIsTestingQuery] = useState(false);
  const [queryTestResult, setQueryTestResult] = useState<{
    status: 'valid' | 'warning';
    matches: number;
    latencyMs: number;
    endpointsChecked: number;
  } | null>(null);

  const [isScanningIocs, setIsScanningIocs] = useState(false);
  const [scannedIocs, setScannedIocs] = useState<Record<string, { verdict: string; score: number }>>({});

  const handleRunQueryTest = () => {
    setIsTestingQuery(true);
    setQueryTestResult(null);
    setTimeout(() => {
      setIsTestingQuery(false);
      setQueryTestResult({
        status: 'valid',
        matches: outcome === 'True Positive' ? 4 : outcome === 'No Result' ? 0 : 8,
        latencyMs: 290,
        endpointsChecked: 1840,
      });
    }, 700);
  };

  const handleScanIocs = () => {
    setIsScanningIocs(true);
    setTimeout(() => {
      setIsScanningIocs(false);
      const res: Record<string, { verdict: string; score: number }> = {};
      iocs.forEach((ioc) => {
        res[ioc.id] = {
          verdict: ioc.type === 'IP' ? 'Malicious C2 Node' : ioc.type === 'Hash' ? 'Trojan/Locker' : 'Suspicious Artifact',
          score: Math.floor(Math.random() * 15) + 85,
        };
      });
      setScannedIocs(res);
    }, 700);
  };

  // Process uploaded PDF file
  const processPdfFile = async (file: File) => {
    setIsExtractingPdf(true);
    setPdfUploadError(null);
    try {
      const reader = new FileReader();
      reader.onload = async () => {
        try {
          const result = reader.result as string;
          const base64Data = result.split(',')[1] || result;
          const mimeType = file.type || 'application/pdf';

          const extracted = await parseReportPdf(base64Data, mimeType, file.name);

          if (extracted.hypothesisTitle) setHypothesisTitle(extracted.hypothesisTitle);
          if (extracted.hypothesisDescription) setHypothesisDescription(extracted.hypothesisDescription);
          if (extracted.weekRange) setWeekRange(extracted.weekRange);
          if (extracted.techniqueIds && extracted.techniqueIds.length > 0) {
            setSelectedTechniques(extracted.techniqueIds);
          }
          if (extracted.dataSources && extracted.dataSources.length > 0) {
            setSelectedDataSources(extracted.dataSources);
          }
          const detected = detectFormatFromFileAndContent(file.name, extracted.queryText || extracted.notes || '');
          if (selectedUploadFormat === 'auto') {
            setDetectedFormatBadge({
              label: detected.label,
              confidence: detected.confidence,
            });
          } else {
            const formatLabels: Record<string, string> = {
              PDF: 'PDF Threat Intelligence Report (.pdf)',
              Markdown: 'Markdown / Text Playbook (.md)',
              JSON: 'JSON Structured Hunt Export (.json)',
              EDR: 'EDR / SIEM Detection Rule (.yaml)',
              CSV: 'CSV Incident Telemetry Dump (.csv)',
            };
            setDetectedFormatBadge({
              label: formatLabels[selectedUploadFormat] || selectedUploadFormat,
              confidence: 100,
            });
          }

          if (extracted.queryText) setQueryText(extracted.queryText);
          if (extracted.outcome) setOutcome(extracted.outcome);
          if (extracted.notes) setNotes(extracted.notes);
          if (extracted.iocs && Array.isArray(extracted.iocs)) {
            setIocs(
              extracted.iocs.map((ioc, idx) => ({
                id: `ioc-pdf-${Date.now()}-${idx}`,
                type: ioc.type || 'IP',
                value: ioc.value || '',
                notes: ioc.notes,
              }))
            );
          }

          setExtractedInfo({
            fileName: file.name,
            summary: extracted.extractionSummary || 'Threat hunting details successfully extracted from report.',
            confidenceScore: extracted.confidenceScore || 94,
          });
        } catch (err: any) {
          console.error('Error during AI report extraction:', err);
          setPdfUploadError(err.message || 'Failed to extract report data from document.');
        } finally {
          setIsExtractingPdf(false);
        }
      };
      reader.onerror = () => {
        setPdfUploadError('Failed to read document from disk.');
        setIsExtractingPdf(false);
      };
      reader.readAsDataURL(file);
    } catch (err: any) {
      setPdfUploadError(err.message || 'Error processing file');
      setIsExtractingPdf(false);
    }
  };

  const handleFileSelected = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      processPdfFile(file);
    }
  };

  const handleDropFile = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDraggingFile(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      processPdfFile(file);
    }
  };

  // Sample report generator for fast testing
  const handleLoadSamplePdfReport = async (sampleType: 'lsass' | 'ransomware' | 'okta') => {
    setIsExtractingPdf(true);
    setPdfUploadError(null);

    let sampleName = '';
    let sampleContent = '';

    if (sampleType === 'lsass') {
      sampleName = 'Incident_Hunt_Report_ApexHealth_LSASS_T1003.pdf';
      sampleContent = `THREAT HUNTING INVESTIGATION REPORT
CLIENT: ${currentClient.name}
DATE: 2026-09-22 (Week 39)
HUNTER: ${currentUser.name}

HYPOTHESIS: Suspicious Process Memory Access against LSASS via Native MiniDump API
DESCRIPTION: Adversaries attempting ransomware deployment or domain persistence utilize living-off-the-land techniques (such as comsvcs.dll MiniDump or procdump) to extract cleartext passwords and Kerberos tickets from lsass.exe process memory.

TECHNIQUES IDENTIFIED:
- T1003.001: OS Credential Dumping - LSASS Memory
- T1059.001: PowerShell Execution
- T1003: OS Credential Dumping

DATA SOURCES:
- EDR Process Creation
- Windows Event 4688 / Sysmon 1
- Sysmon Event 10

DETECTION LOGIC (KQL):
DeviceProcessEvents
| where FileName in~ ("rundll32.exe", "procdump.exe")
| where ProcessCommandLine has_any ("comsvcs.dll", "MiniDump", "#24", "lsass")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName

OUTCOME: True Positive
OBSERVATIONS & CONTAINMENT:
Anomalous rundll32 invocation observed on workstation RAD-092. Malicious dump output written to C:\\Windows\\Temp\\lsass.dmp. Endpoint disconnected and credentials revoked.

INDICATORS OF COMPROMISE (IOCs):
- Process: procdump64.exe (Dropped in C:\\Windows\\Temp)
- IP: 192.168.42.118 (Internal jump host)
- Account: svc-pacs-viewer (Compromised service account)
- Hash: d41d8cd98f00b204e9800998ecf8427e (Suspicious launcher)`;
    } else if (sampleType === 'ransomware') {
      sampleName = 'Threat_Hunt_Report_BlackCat_VSS_Recovery_Inhibition.pdf';
      sampleContent = `WEEKLY THREAT HUNT REPORT
CLIENT: ${currentClient.name}
INVESTIGATION: Ransomware Pre-Encryption Inhibiting System Recovery via VSS Shadow Deletion
DATE RANGE: 2026-W39 (Sep 21 - Sep 27)
ANALYST: ${currentUser.name}

HYPOTHESIS: Adversaries prior to bulk ransomware locking execute command-line utilities (vssadmin, bcdedit, wbadmin) to delete shadow copies and prevent automated Windows recovery.
MITRE ATT&CK: T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery)
TELEMETRY: EDR Process Creation, Windows Event 4688 / Sysmon 1

QUERY (KQL):
DeviceProcessEvents
| where ProcessCommandLine has_any ("vssadmin delete shadows", "wbadmin delete catalog", "bcdedit /set {default} bootstatuspolicy ignoreallfailures")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine

OUTCOME: True Positive
NOTES: Detected automated recovery destruction commands initiated from batch file staged in Public user directory. Terminated before ransomware payload initiated.
IOCs:
- IP: 45.154.255.19 (C2 Staging Host)
- Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 (Payload locker)`;
    } else {
      sampleName = 'Threat_Hunt_Report_ScatterSpider_Okta_Session_Hijack.pdf';
      sampleContent = `HYPOTHESIS HUNT REPORT
CLIENT: ${currentClient.name}
TOPIC: Okta Session Token Hijacking via SIM-Swap & Helpdesk Social Engineering
WEEK: 2026-W39 (Sep 21 - Sep 27)
LEAD: ${currentUser.name}

HYPOTHESIS: UNC3944 actors target corporate employees with vishing/SIM swap to hijack IdP session tokens and bypass MFA.
MITRE TECHNIQUES: T1078.004 (Cloud Accounts), T1566.002 (Spearphishing Link)
DATA SOURCES: Identity Broker Logs (Okta, Entra), Proxy / Web Gateway Logs

QUERY (SPL):
index=okta eventType="user.session.start"
| where client.geographicalContext.country!="United States"
| table _time, actor.alternateId, client.ipAddress, debugContext.debugData.pushNotificationStatus

OUTCOME: True Positive
NOTES: Identified concurrent sessions in Singapore and residential IP in California within 15 minutes of each other. Session revoked.
IOCs:
- IP: 198.51.100.73 (Residential Proxy)
- Account: d.chen@vanguardcapital.com (Targeted Trader)`;
    }

    const base64 = btoa(unescape(encodeURIComponent(sampleContent)));
    try {
      const extracted = await parseReportPdf(base64, 'text/plain', sampleName);
      if (extracted.hypothesisTitle) setHypothesisTitle(extracted.hypothesisTitle);
      if (extracted.hypothesisDescription) setHypothesisDescription(extracted.hypothesisDescription);
      if (extracted.weekRange) setWeekRange(extracted.weekRange);
      if (extracted.techniqueIds && extracted.techniqueIds.length > 0) {
        setSelectedTechniques(extracted.techniqueIds);
      }
      if (extracted.dataSources && extracted.dataSources.length > 0) {
        setSelectedDataSources(extracted.dataSources);
      }
      if (sampleType === 'lsass') {
        setSelectedUploadFormat('PDF');
        setDetectedFormatBadge({ label: 'PDF Threat Intelligence Report (.pdf)', confidence: 99 });
      } else if (sampleType === 'ransomware') {
        setSelectedUploadFormat('Markdown');
        setDetectedFormatBadge({ label: 'Markdown Hunt Playbook (.md)', confidence: 98 });
      } else {
        setSelectedUploadFormat('JSON');
        setDetectedFormatBadge({ label: 'JSON Structured Hunt Export (.json)', confidence: 97 });
      }

      if (extracted.queryText) setQueryText(extracted.queryText);
      if (extracted.outcome) setOutcome(extracted.outcome);
      if (extracted.notes) setNotes(extracted.notes);
      if (extracted.iocs && Array.isArray(extracted.iocs)) {
        setIocs(
          extracted.iocs.map((ioc, idx) => ({
            id: `ioc-sample-${Date.now()}-${idx}`,
            type: ioc.type || 'IP',
            value: ioc.value || '',
            notes: ioc.notes,
          }))
        );
      }

      setExtractedInfo({
        fileName: sampleName,
        summary: extracted.extractionSummary || 'Report fields extracted successfully.',
        confidenceScore: extracted.confidenceScore || 95,
      });
    } catch (err: any) {
      setPdfUploadError(err.message || 'Failed to extract sample report');
    } finally {
      setIsExtractingPdf(false);
    }
  };

  const handleClearExtracted = () => {
    setExtractedInfo(null);
    setPdfUploadError(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  // Filter reports by client
  const clientReports = reports.filter((r) => r.clientId === currentClient.id);

  // Filtered knowledge base reports
  const filteredReports = clientReports.filter((report) => {
    const matchesOutcome = outcomeFilter === 'all' || report.outcome === outcomeFilter;
    const term = searchTerm.toLowerCase();
    const matchesSearch =
      !searchTerm ||
      report.hypothesisTitle.toLowerCase().includes(term) ||
      report.hypothesisDescription.toLowerCase().includes(term) ||
      report.techniqueIds.some((t) => t.toLowerCase().includes(term)) ||
      report.notes.toLowerCase().includes(term) ||
      report.iocs.some((i) => i.value.toLowerCase().includes(term));
    return matchesOutcome && matchesSearch;
  });

  // Calculate covered technique IDs for AI engine
  const coveredTechniqueIds = Array.from(
    new Set(clientReports.flatMap((r) => r.techniqueIds))
  );
  const uncoveredTechniques = MITRE_TECHNIQUES
    .filter((t) => !coveredTechniqueIds.includes(t.id))
    .map((t) => `${t.id} - ${t.name}`);

  // Fetch AI recommendations
  const handleTriggerRecommendations = async () => {
    setLoadingAi(true);
    setAiError(null);
    try {
      const recs = await fetchNextHuntRecommendations(
        currentClient,
        coveredTechniqueIds,
        uncoveredTechniques
      );
      setRecommendations(recs);
    } catch (err: any) {
      setAiError('Failed to fetch recommendations from AI engine.');
    } finally {
      setLoadingAi(false);
    }
  };

  // Pre-load recommendations on mount or when client changes if empty
  React.useEffect(() => {
    if (recommendations.length === 0) {
      handleTriggerRecommendations();
    }
  }, [currentClient.id]);

  // Handle preselected technique change
  React.useEffect(() => {
    if (preselectedTechnique) {
      setActiveTab('log');
      setSelectedTechniques([preselectedTechnique]);
      const foundTech = MITRE_TECHNIQUES.find((t) => t.id === preselectedTechnique);
      if (foundTech) {
        setHypothesisTitle(`Adversary Abuse of ${foundTech.name} (${foundTech.id})`);
        setHypothesisDescription(foundTech.description);
        if (foundTech.sampleQuery) {
          setQueryLanguage(foundTech.sampleQuery.language);
          setQueryText(foundTech.sampleQuery.query);
        }
      }
    }
  }, [preselectedTechnique]);

  const handleAddIoc = () => {
    if (!newIocValue.trim()) return;
    setIocs([
      ...iocs,
      {
        id: `ioc-${Date.now()}`,
        type: newIocType,
        value: newIocValue.trim(),
        notes: newIocNotes.trim() || undefined,
      },
    ]);
    setNewIocValue('');
    setNewIocNotes('');
  };

  const handleRemoveIoc = (id: string) => {
    setIocs(iocs.filter((i) => i.id !== id));
  };

  const handleAdoptRecommendation = (rec: NextHuntRecommendation) => {
    setActiveTab('log');
    setSelectedTechniques([rec.techniqueId]);
    setHypothesisTitle(`Adversary TTP: ${rec.techniqueName} (${rec.techniqueId})`);
    setHypothesisDescription(rec.suggestedHypothesis);
    setSelectedDataSources(rec.requiredDataSources);
    const tech = MITRE_TECHNIQUES.find((t) => t.id === rec.techniqueId);
    if (tech?.sampleQuery) {
      setQueryLanguage(tech.sampleQuery.language);
      setQueryText(tech.sampleQuery.query);
    }
  };

  const handleSubmitReport = (e: React.FormEvent) => {
    e.preventDefault();
    if (!hypothesisTitle.trim()) return;

    const newReport: HuntReport = {
      id: `hunt-${Date.now()}`,
      clientId: currentClient.id,
      analystId: currentUser.id,
      analystName: currentUser.name,
      weekRange,
      hypothesisTitle,
      hypothesisDescription,
      techniqueIds: selectedTechniques,
      dataSources: selectedDataSources,
      queryLanguage,
      queryText,
      outcome,
      notes,
      iocs,
      createdAt: new Date().toISOString(),
    };

    onAddReport(newReport);
    // Reset form and view archive
    setActiveTab('archive');
    setSelectedReportId(newReport.id);
    if (onClearPreselectedTechnique) onClearPreselectedTechnique();
  };

  const handleCopyQuery = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedQueryId(id);
    setTimeout(() => setCopiedQueryId(null), 2000);
  };

  const getThrDocForReport = (report: HuntReport): ThreatHuntReportDocument => {
    if (report.thrDocument) return report.thrDocument;
    return {
      hypothesisName: report.hypothesisTitle,
      reportDate: report.reportDate || report.createdAt.split('T')[0] || '2026-09-28',
      executiveSummary: report.hypothesisDescription,
      purpose: `Validate presence of adversary tradecraft matching techniques ${report.techniqueIds.join(', ')} across ${currentClient.name}'s telemetry.`,
      mitreInformation: `Mapped Techniques: ${report.techniqueIds.join(', ')}. Monitored telemetry data sources: ${report.dataSources.join(', ')}.`,
      huntMethodology: `Hypothesis-driven telemetry analytics applied over ${report.dataSources.join(', ')} telemetry.`,
      potentialDetectionIdeas: `Behavioral analytics and detection rules targeting anomalous patterns of ${report.techniqueIds.join(', ')}.`,
      huntQueries: [
        {
          id: 'q-1',
          platform: (report.queryLanguage || 'KQL') as any,
          title: 'Production Telemetry Hunt Query',
          code: report.queryText,
          explanation: 'Executed query searching for anomalous process execution or persistence indicators.',
        },
      ],
      huntResults: report.notes || 'Threat hunting query executed across production endpoints.',
      analysis: `Campaign investigation completed with outcome "${report.outcome}". Analyzed process genealogy and baseline telemetry.`,
      risk: report.outcome === 'True Positive' ? 'Elevated threat risk requiring immediate containment.' : 'Low residual risk verified by clean baseline observation.',
      impact: `Evaluated impact for ${currentClient.name} operations, data integrity, and compliance.`,
      recommendation: 'Incorporate validated query logic into continuous SOC scheduled detection analytics.',
      references: report.techniqueIds.map((t) => `https://attack.mitre.org/techniques/${t}`),
    };
  };

  return (
    <div className="space-y-6">
      {/* Header and Subnav Tabs */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">Weekly Hypothesis Hunt Reports</h1>
          <p className="text-xs text-slate-400 mt-1">
            Structured threat hunting logs and searchable team knowledge base for <span className="text-slate-200 font-semibold">{currentClient.name}</span>.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {/* Segmented Control */}
          <div className="flex items-center bg-slate-900 border border-slate-800 rounded-lg p-1 text-xs">
            <button
              onClick={() => setActiveTab('archive')}
              className={`px-3 py-1.5 rounded-md font-medium transition-colors cursor-pointer ${
                activeTab === 'archive'
                  ? 'bg-slate-800 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Hunt Knowledge Base ({clientReports.length})
            </button>
            <button
              onClick={() => setActiveTab('log')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md font-medium transition-colors cursor-pointer ${
                activeTab === 'log'
                  ? 'bg-cyan-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Log Hunt Report</span>
            </button>
            {onOpenCreateTHR && (
              <button
                onClick={onOpenCreateTHR}
                className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-md font-bold bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white transition-all shadow-sm cursor-pointer hover:scale-[1.02]"
                title="Create standardized 12-section Threat Hunt Report"
              >
                <FileText className="w-3.5 h-3.5" />
                <span>Create THR</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Main Content Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Main Active Tab (Knowledge Base or New Report Form) */}
        <div className="lg:col-span-2 space-y-4">
          {activeTab === 'archive' ? (
            /* KNOWLEDGE BASE VIEW */
            <div className="space-y-4">
              {/* Search & Filters */}
              <div className="bg-slate-900 border border-slate-800 rounded-lg p-3.5 space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="relative flex-1">
                    <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                    <input
                      type="text"
                      placeholder="Search hypotheses, techniques (T1059), queries, or IOCs..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-md pl-9 pr-4 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
                    />
                  </div>

                  <div className="flex items-center gap-1.5 overflow-x-auto text-xs">
                    <span className="text-slate-500 font-medium text-[11px] shrink-0">Outcome:</span>
                    {['all', 'True Positive', 'False Positive', 'No Result', 'Needs Follow-up'].map((opt) => (
                      <button
                        key={opt}
                        onClick={() => setOutcomeFilter(opt)}
                        className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors cursor-pointer shrink-0 ${
                          outcomeFilter === opt
                            ? 'bg-slate-800 text-cyan-300 border border-slate-700 font-semibold'
                            : 'text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        {opt === 'all' ? 'All Outcomes' : opt}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              {/* Reports List */}
              <div className="space-y-3">
                {filteredReports.length > 0 ? (
                  filteredReports.map((report) => {
                    const isExpanded = selectedReportId === report.id;
                    const outcomeColors = {
                      'True Positive': 'text-emerald-400 bg-emerald-950/60 border-emerald-800/60',
                      'False Positive': 'text-amber-400 bg-amber-950/60 border-amber-800/60',
                      'No Result': 'text-slate-400 bg-slate-900 border-slate-800',
                      'Needs Follow-up': 'text-cyan-400 bg-cyan-950/60 border-cyan-800/60',
                    }[report.outcome];

                    return (
                      <div
                        key={report.id}
                        className={`bg-slate-900/90 border rounded-lg transition-all ${
                          isExpanded ? 'border-cyan-500/50 shadow-md' : 'border-slate-800 hover:border-slate-700'
                        }`}
                      >
                        {/* Header bar */}
                        <div
                          onClick={() => setSelectedReportId(isExpanded ? null : report.id)}
                          className="p-4 cursor-pointer flex items-start justify-between gap-3 select-none"
                        >
                          <div className="space-y-1.5 flex-1">
                            <div className="flex flex-wrap items-center gap-2 text-[11px]">
                              <span className={`px-2 py-0.5 rounded font-mono font-medium border ${outcomeColors}`}>
                                {report.outcome}
                              </span>
                              {(report.isTHR || report.thrDocument) && (
                                <span className="px-2 py-0.5 rounded font-mono text-[10px] font-bold bg-emerald-950/80 text-emerald-300 border border-emerald-800/80 flex items-center gap-1">
                                  <FileText className="w-2.5 h-2.5" />
                                  <span>THR Document</span>
                                </span>
                              )}
                              <span className="text-slate-400">{report.weekRange}</span>
                              <span className="text-slate-600">·</span>
                              <span className="text-slate-300 font-medium">Analyst: {report.analystName}</span>
                              {report.severityScore && (
                                <>
                                  <span className="text-slate-600">·</span>
                                  <span className="font-mono text-rose-400 font-semibold">
                                    Severity: {report.severityScore.compositeScore}/100 ({report.severityScore.severityLevel})
                                  </span>
                                </>
                              )}
                            </div>

                            <h3 className="text-sm font-semibold text-white leading-snug">
                              {report.hypothesisTitle}
                            </h3>

                            <div className="flex flex-wrap items-center gap-1.5 pt-1">
                              {report.techniqueIds.map((tid) => (
                                <span
                                  key={tid}
                                  className="text-[10px] font-mono text-cyan-300 bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800"
                                >
                                  {tid}
                                </span>
                              ))}
                              <span className="text-[11px] text-slate-500 ml-2">
                                Data: {report.dataSources.slice(0, 2).join(', ')}
                                {report.dataSources.length > 2 && ` +${report.dataSources.length - 2}`}
                              </span>
                            </div>
                          </div>

                          <div className="flex items-center gap-2 shrink-0 pt-1 text-slate-400">
                            {report.iocs.length > 0 && (
                              <span className="text-[10px] font-mono text-amber-400 bg-amber-950/60 px-1.5 py-0.5 rounded border border-amber-800/40">
                                {report.iocs.length} IOC{report.iocs.length > 1 ? 's' : ''}
                              </span>
                            )}
                            {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                          </div>
                        </div>

                        {/* Expanded Deep Dive Details */}
                        {isExpanded && (
                          <div className="px-4 pb-4 pt-2 border-t border-slate-800/80 space-y-4 text-xs">
                            {/* Hypothesis Description */}
                            <div>
                              <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1">
                                Hypothesis Description & Threat Context
                              </div>
                              <p className="text-slate-300 leading-relaxed bg-slate-950/60 p-3 rounded border border-slate-800/60">
                                {report.hypothesisDescription}
                              </p>
                            </div>

                            {/* Query Used with Copy */}
                            <div>
                              <div className="flex items-center justify-between mb-1.5">
                                <span className="text-[11px] font-semibold text-slate-300 uppercase tracking-wider font-mono flex items-center gap-1.5">
                                  <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                                  <span>Production Hunt Query Logic</span>
                                </span>
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    handleCopyQuery(report.id, report.queryText);
                                  }}
                                  className="flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300 font-medium cursor-pointer"
                                >
                                  {copiedQueryId === report.id ? (
                                    <>
                                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                                      <span className="text-emerald-400">Copied!</span>
                                    </>
                                  ) : (
                                    <>
                                      <Copy className="w-3.5 h-3.5" />
                                      <span>Copy Query</span>
                                    </>
                                  )}
                                </button>
                              </div>
                              <pre className="bg-slate-950 p-3 rounded-md text-[11px] text-cyan-200 font-mono overflow-x-auto border border-slate-800/80 leading-relaxed scrollbar-thin">
                                {report.queryText}
                              </pre>
                            </div>

                            {/* Findings & Notes */}
                            <div>
                              <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1">
                                Investigation Outcome Notes
                              </div>
                              <p className="text-slate-300 leading-relaxed bg-slate-950/60 p-3 rounded border border-slate-800/60">
                                {report.notes || 'No analyst notes recorded.'}
                              </p>
                            </div>

                            {/* IOCs Table */}
                            {report.iocs.length > 0 && (
                              <div>
                                <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                                  Indicators of Compromise (IOCs)
                                </div>
                                <div className="border border-slate-800 rounded overflow-hidden">
                                  <table className="w-full text-left text-[11px]">
                                    <thead className="bg-slate-950 font-mono text-slate-400 border-b border-slate-800">
                                      <tr>
                                        <th className="p-2">Type</th>
                                        <th className="p-2">Indicator Value</th>
                                        <th className="p-2">Context / Notes</th>
                                      </tr>
                                    </thead>
                                    <tbody className="divide-y divide-slate-800/60 font-mono text-slate-300">
                                      {report.iocs.map((ioc) => (
                                        <tr key={ioc.id} className="hover:bg-slate-800/30">
                                          <td className="p-2 text-cyan-400 font-semibold">{ioc.type}</td>
                                          <td className="p-2 select-all">{ioc.value}</td>
                                          <td className="p-2 text-slate-400 font-sans">{ioc.notes || '—'}</td>
                                        </tr>
                                      ))}
                                    </tbody>
                                  </table>
                                </div>
                              </div>
                            )}

                            {/* Linked Severity Record */}
                            {report.severityScore && (
                              <div className="bg-slate-950/90 border border-slate-800 p-3 rounded space-y-2">
                                <div className="flex items-center justify-between text-[11px]">
                                  <span className="font-semibold text-slate-300 uppercase tracking-wider">
                                    Stored SOC Severity Assessment
                                  </span>
                                  <span className="font-mono font-bold text-rose-400">
                                    Composite Score: {report.severityScore.compositeScore}/100 ({report.severityScore.severityLevel})
                                  </span>
                                </div>
                                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[10px] font-mono text-slate-400">
                                  <div className="bg-slate-900 p-1.5 rounded">
                                    Impact: <strong className="text-white">{report.severityScore.factors.businessImpact}</strong> ({report.severityScore.factorBreakdown.businessImpactPoints} pts)
                                  </div>
                                  <div className="bg-slate-900 p-1.5 rounded">
                                    Stage: <strong className="text-white">{report.severityScore.factors.threatStage}</strong> ({report.severityScore.factorBreakdown.threatStagePoints} pts)
                                  </div>
                                  <div className="bg-slate-900 p-1.5 rounded">
                                    Confidence: <strong className="text-white">{report.severityScore.factors.detectionConfidence}</strong> ({report.severityScore.factorBreakdown.detectionConfidencePoints} pts)
                                  </div>
                                  <div className="bg-slate-900 p-1.5 rounded">
                                    Exploit: <strong className="text-white">{report.severityScore.factors.exploitability}</strong> ({report.severityScore.factorBreakdown.exploitabilityPoints} pts)
                                  </div>
                                </div>
                              </div>
                            )}

                            {/* Threat Hunt Report (THR) 12 Sections Viewer */}
                            {report.thrDocument && (
                              <div className="bg-slate-950 p-4 rounded-lg border border-emerald-900/60 space-y-3.5 mt-2">
                                <div className="flex items-center justify-between border-b border-slate-800 pb-2 flex-wrap gap-2">
                                  <span className="font-mono text-xs text-emerald-400 font-bold uppercase tracking-wider flex items-center gap-1.5">
                                    <FileText className="w-3.5 h-3.5" />
                                    <span>Official 12-Section Threat Hunt Report (THR)</span>
                                  </span>
                                  <span className="text-[10px] font-mono text-slate-400">
                                    Date: {report.thrDocument.reportDate || report.reportDate || '2026-09-28'}
                                  </span>
                                </div>

                                <div className="space-y-2.5 text-xs">
                                  <div>
                                    <span className="font-semibold text-cyan-400 uppercase text-[10px]">1. Executive Summary:</span>
                                    <p className="text-slate-300 mt-0.5 leading-relaxed bg-slate-900/60 p-2.5 rounded border border-slate-800/80">{report.thrDocument.executiveSummary}</p>
                                  </div>

                                  <div>
                                    <span className="font-semibold text-cyan-400 uppercase text-[10px]">2. Purpose:</span>
                                    <p className="text-slate-300 mt-0.5 leading-relaxed bg-slate-900/60 p-2.5 rounded border border-slate-800/80">{report.thrDocument.purpose}</p>
                                  </div>

                                  <div>
                                    <span className="font-semibold text-cyan-400 uppercase text-[10px]">3. MITRE Information:</span>
                                    <div className="text-slate-300 mt-0.5 leading-relaxed bg-slate-900/60 p-2.5 rounded border border-slate-800/80 whitespace-pre-wrap">{report.thrDocument.mitreInformation}</div>
                                  </div>

                                  <div>
                                    <span className="font-semibold text-cyan-400 uppercase text-[10px]">4. High-Level Methodology:</span>
                                    <div className="text-slate-300 mt-0.5 leading-relaxed bg-slate-900/60 p-2.5 rounded border border-slate-800/80 whitespace-pre-wrap">{report.thrDocument.huntMethodology}</div>
                                  </div>

                                  <div>
                                    <span className="font-semibold text-cyan-400 uppercase text-[10px]">5. Potential Detection Ideas & Hunting Thoughts:</span>
                                    <div className="text-slate-300 mt-0.5 leading-relaxed bg-slate-900/60 p-2.5 rounded border border-slate-800/80 whitespace-pre-wrap">{report.thrDocument.potentialDetectionIdeas}</div>
                                  </div>

                                  <div>
                                    <span className="font-semibold text-cyan-400 uppercase text-[10px]">7. Hunt Results:</span>
                                    <p className="text-slate-300 mt-0.5 leading-relaxed bg-slate-900/60 p-2.5 rounded border border-slate-800/80">{report.thrDocument.huntResults}</p>
                                  </div>

                                  <div>
                                    <span className="font-semibold text-cyan-400 uppercase text-[10px]">8. Analysis:</span>
                                    <p className="text-slate-300 mt-0.5 leading-relaxed bg-slate-900/60 p-2.5 rounded border border-slate-800/80">{report.thrDocument.analysis}</p>
                                  </div>

                                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                                    <div>
                                      <span className="font-semibold text-amber-400 uppercase text-[10px]">9. Risk:</span>
                                      <p className="text-slate-300 mt-0.5 leading-relaxed bg-slate-900/60 p-2.5 rounded border border-slate-800/80">{report.thrDocument.risk}</p>
                                    </div>
                                    <div>
                                      <span className="font-semibold text-rose-400 uppercase text-[10px]">10. Impact:</span>
                                      <p className="text-slate-300 mt-0.5 leading-relaxed bg-slate-900/60 p-2.5 rounded border border-slate-800/80">{report.thrDocument.impact}</p>
                                    </div>
                                  </div>

                                  <div>
                                    <span className="font-semibold text-emerald-400 uppercase text-[10px]">11. Recommendation:</span>
                                    <div className="text-slate-300 mt-0.5 leading-relaxed bg-slate-900/60 p-2.5 rounded border border-slate-800/80 whitespace-pre-wrap">{report.thrDocument.recommendation}</div>
                                  </div>

                                  {report.thrDocument.references && report.thrDocument.references.length > 0 && (
                                    <div>
                                      <span className="font-semibold text-slate-400 uppercase text-[10px]">12. References:</span>
                                      <ul className="list-disc list-inside text-slate-400 mt-0.5 space-y-0.5 bg-slate-900/60 p-2 rounded border border-slate-800/80 text-[11px]">
                                        {report.thrDocument.references.map((ref, idx) => (
                                          <li key={idx}>{ref}</li>
                                        ))}
                                      </ul>
                                    </div>
                                  )}
                                </div>
                              </div>
                            )}

                            {/* Export Action Bar for DOC / PDF */}
                            <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between flex-wrap gap-2">
                              <span className="text-[11px] text-slate-500 font-mono">
                                Record ID: {report.id} · Stored in Hunt Database
                              </span>
                              <div className="flex items-center gap-2">
                                <button
                                  type="button"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    const thrDoc = getThrDocForReport(report);
                                    downloadThreatHuntDoc(thrDoc, currentClient.name, report.analystName, report.outcome);
                                  }}
                                  className="px-3 py-1.5 rounded bg-blue-900/70 hover:bg-blue-800 border border-blue-700/80 text-blue-200 text-xs font-semibold flex items-center gap-1.5 cursor-pointer transition-colors"
                                  title="Download report in Microsoft Word .doc format"
                                >
                                  <Download className="w-3.5 h-3.5" />
                                  <span>Download DOC (.doc)</span>
                                </button>
                                <button
                                  type="button"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    const thrDoc = getThrDocForReport(report);
                                    printThreatHuntPdf(thrDoc, currentClient.name, report.analystName, report.outcome);
                                  }}
                                  className="px-3 py-1.5 rounded bg-rose-900/70 hover:bg-rose-800 border border-rose-700/80 text-rose-200 text-xs font-semibold flex items-center gap-1.5 cursor-pointer transition-colors"
                                  title="Download / Print as PDF"
                                >
                                  <Printer className="w-3.5 h-3.5" />
                                  <span>Download / Print PDF</span>
                                </button>
                              </div>
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })
                ) : (
                  <div className="bg-slate-900 border border-slate-800 rounded-lg p-12 text-center space-y-3">
                    <HelpCircle className="w-8 h-8 text-slate-600 mx-auto" />
                    <h3 className="text-sm font-semibold text-slate-300">No hunt reports match your criteria</h3>
                    <p className="text-xs text-slate-500 max-w-sm mx-auto">
                      Try broadening your search term or switch to the Log Hunt tab to submit your first hypothesis investigation.
                    </p>
                    <button
                      onClick={() => setActiveTab('log')}
                      className="px-3 py-1.5 text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white rounded-md cursor-pointer"
                    >
                      Log New Report Now
                    </button>
                  </div>
                )}
              </div>
            </div>
          ) : (
            /* LOG NEW HUNT REPORT FORM */
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
              <form onSubmit={handleSubmitReport} className="space-y-5">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-cyan-400" />
                    <span>Hypothesis Hunt Submission Form</span>
                  </h2>
                  <span className="text-[11px] text-slate-400 font-mono">
                    Client: <strong className="text-cyan-300">{currentClient.name}</strong>
                  </span>
                </div>

                {/* AI PDF / Document Upload Dropzone (Section 4.1 Feature) */}
                <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <UploadCloud className="w-4 h-4 text-cyan-400" />
                      <span className="text-xs font-bold text-white uppercase tracking-wider">
                        AI Report Ingestion: Upload Threat Hunt Document (PDF)
                      </span>
                    </div>
                    <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/80 px-2 py-0.5 rounded border border-cyan-800/40">
                      Auto-Extract Fields
                    </span>
                  </div>

                  <p className="text-xs text-slate-400 leading-relaxed">
                    Upload an existing weekly hunt report or investigation PDF. Blindspot AI will automatically parse the document, extract the hypothesis narrative, tag MITRE ATT&CK techniques, extract detection queries, outcome, and indicators of compromise (IOCs).
                  </p>

                  {/* Report Format Selection / Detection Controls */}
                  <div className="bg-[#0b0f19] p-3 rounded-lg border border-[#1e293b] space-y-2.5">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <span className="text-[11px] font-mono text-slate-300 font-semibold uppercase flex items-center gap-1.5">
                        <Tag className="w-3.5 h-3.5 text-cyan-400" />
                        <span>Select or Detect Report Format:</span>
                      </span>
                      <div className="flex items-center gap-1.5 flex-wrap">
                        {[
                          { id: 'auto', label: '⚡ Auto-Detect Format' },
                          { id: 'PDF', label: '📄 PDF Report' },
                          { id: 'Markdown', label: '📋 Markdown / TXT' },
                          { id: 'JSON', label: '📦 JSON Export' },
                          { id: 'EDR', label: '🛡️ EDR / SIEM Package' },
                          { id: 'CSV', label: '📊 CSV Dump' },
                        ].map((fmt) => (
                          <button
                            key={fmt.id}
                            type="button"
                            onClick={() => {
                              setSelectedUploadFormat(fmt.id);
                              if (fmt.id !== 'auto') {
                                setDetectedFormatBadge({
                                  label: fmt.label,
                                  confidence: 100,
                                });
                              }
                            }}
                            className={`px-2.5 py-1 rounded text-[10px] font-mono transition-colors cursor-pointer border ${
                              selectedUploadFormat === fmt.id
                                ? 'bg-cyan-950 text-cyan-200 border-cyan-500 font-bold shadow-sm'
                                : 'bg-[#0f172a] text-slate-400 hover:text-slate-200 border-slate-800'
                            }`}
                          >
                            {fmt.label}
                          </button>
                        ))}
                      </div>
                    </div>

                    {detectedFormatBadge && (
                      <div className="flex items-center justify-between text-[11px] font-mono text-emerald-300 bg-emerald-950/40 p-2.5 rounded border border-emerald-800/60">
                        <div className="flex items-center gap-2">
                          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                          <span>Detected & Applied Report Format: <strong>{detectedFormatBadge.label}</strong></span>
                        </div>
                        <span className="text-slate-400 text-[10px] bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                          {detectedFormatBadge.confidence}% Confidence
                        </span>
                      </div>
                    )}
                  </div>

                  {/* Hidden File Input */}
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".pdf,.txt,.md,.json,application/pdf"
                    onChange={handleFileSelected}
                    className="hidden"
                  />

                  {/* Upload Drag/Drop Box */}
                  {!extractedInfo && !isExtractingPdf && (
                    <div
                      onDragOver={(e) => {
                        e.preventDefault();
                        setIsDraggingFile(true);
                      }}
                      onDragLeave={() => setIsDraggingFile(false)}
                      onDrop={handleDropFile}
                      onClick={() => fileInputRef.current?.click()}
                      className={`border-2 border-dashed rounded-lg p-5 text-center transition-all cursor-pointer ${
                        isDraggingFile
                          ? 'border-cyan-400 bg-cyan-950/30'
                          : 'border-slate-800 hover:border-cyan-500/50 bg-slate-900/40 hover:bg-slate-900/80'
                      }`}
                    >
                      <div className="flex flex-col items-center gap-2">
                        <div className="w-9 h-9 rounded-full bg-cyan-950/80 border border-cyan-800/60 flex items-center justify-center text-cyan-400">
                          <UploadCloud className="w-5 h-5" />
                        </div>
                        <div>
                          <span className="text-xs font-semibold text-slate-200">
                            Click to upload PDF report or drag and drop document
                          </span>
                          <p className="text-[11px] text-slate-500 mt-0.5">
                            Supports PDF (.pdf), Markdown (.md), or plain text reports up to 25MB
                          </p>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Loading / Extraction in Progress State */}
                  {isExtractingPdf && (
                    <div className="border border-cyan-500/50 bg-cyan-950/20 rounded-lg p-5 text-center space-y-2.5">
                      <div className="flex items-center justify-center gap-2">
                        <Loader2 className="w-4 h-4 text-cyan-400 animate-spin" />
                        <span className="text-xs font-bold text-white font-mono uppercase tracking-wider">
                          Parsing Document with Gemini 3.8 Flash...
                        </span>
                      </div>
                      <p className="text-[11px] text-cyan-300/80 max-w-md mx-auto">
                        Reading PDF tokens, mapping adversary behaviors to MITRE ATT&CK STIX taxonomy, parsing detection queries and carving out indicators of compromise...
                      </p>
                      <div className="w-48 bg-slate-800 h-1.5 rounded-full mx-auto overflow-hidden">
                        <div className="bg-gradient-to-r from-cyan-500 to-blue-500 h-full w-2/3 animate-pulse rounded-full" />
                      </div>
                    </div>
                  )}

                  {/* Error State */}
                  {pdfUploadError && (
                    <div className="bg-rose-950/50 border border-rose-800 rounded-lg p-3 flex items-start gap-2.5 text-xs text-rose-300">
                      <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                      <div className="flex-1">
                        <span className="font-semibold block">Extraction Notice:</span>
                        <span>{pdfUploadError}</span>
                      </div>
                      <button
                        type="button"
                        onClick={() => setPdfUploadError(null)}
                        className="text-rose-400 hover:text-white text-xs font-mono"
                      >
                        Dismiss
                      </button>
                    </div>
                  )}

                  {/* Extracted Confirmation Banner */}
                  {extractedInfo && !isExtractingPdf && (
                    <div className="bg-emerald-950/40 border border-emerald-800/80 rounded-lg p-3.5 space-y-2">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <FileCheck2 className="w-4 h-4 text-emerald-400" />
                          <span className="text-xs font-bold text-emerald-300 font-mono truncate max-w-md">
                            Successfully Extracted from: {extractedInfo.fileName}
                          </span>
                          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-emerald-900 text-emerald-200">
                            {extractedInfo.confidenceScore}% Confidence
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() => fileInputRef.current?.click()}
                            className="text-[11px] text-cyan-400 hover:text-cyan-300 font-semibold cursor-pointer"
                          >
                            Upload Different PDF
                          </button>
                          <span className="text-slate-600">·</span>
                          <button
                            type="button"
                            onClick={handleClearExtracted}
                            className="text-[11px] text-slate-400 hover:text-rose-300 cursor-pointer"
                          >
                            Clear
                          </button>
                        </div>
                      </div>
                      <p className="text-[11px] text-slate-300 leading-relaxed">
                        {extractedInfo.summary} All fields below have been automatically populated. You can review, modify, or add notes before submitting.
                      </p>
                    </div>
                  )}

                  {/* Quick Sample Report Buttons by Format */}
                  <div className="pt-2 border-t border-slate-800/60 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
                    <span className="text-[11px] text-slate-400">
                      Need a sample report to test format detection?
                    </span>
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <button
                        type="button"
                        disabled={isExtractingPdf}
                        onClick={() => handleLoadSamplePdfReport('lsass')}
                        className="px-2.5 py-1 rounded text-[10px] font-mono bg-[#0b0f19] hover:bg-[#131d31] text-slate-300 border border-slate-800 hover:border-cyan-500/50 cursor-pointer disabled:opacity-50 flex items-center gap-1 transition-colors"
                      >
                        <span>📄 [PDF]</span>
                        <span>LSASS Memory Dump.pdf</span>
                      </button>
                      <button
                        type="button"
                        disabled={isExtractingPdf}
                        onClick={() => handleLoadSamplePdfReport('ransomware')}
                        className="px-2.5 py-1 rounded text-[10px] font-mono bg-[#0b0f19] hover:bg-[#131d31] text-slate-300 border border-slate-800 hover:border-cyan-500/50 cursor-pointer disabled:opacity-50 flex items-center gap-1 transition-colors"
                      >
                        <span>📋 [Markdown]</span>
                        <span>BlackCat VSS Recovery.md</span>
                      </button>
                      <button
                        type="button"
                        disabled={isExtractingPdf}
                        onClick={() => handleLoadSamplePdfReport('okta')}
                        className="px-2.5 py-1 rounded text-[10px] font-mono bg-[#0b0f19] hover:bg-[#131d31] text-slate-300 border border-slate-800 hover:border-cyan-500/50 cursor-pointer disabled:opacity-50 flex items-center gap-1 transition-colors"
                      >
                        <span>📦 [JSON]</span>
                        <span>Okta SIM-Swap Hijack.json</span>
                      </button>
                    </div>
                  </div>
                </div>

                {/* Week Range & Analyst */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                  <div>
                    <label className="block text-slate-400 font-medium mb-1">Investigation Week Range</label>
                    <input
                      type="text"
                      value={weekRange}
                      onChange={(e) => setWeekRange(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-white focus:outline-none focus:border-cyan-500 font-mono"
                      required
                    />
                  </div>
                  <div>
                    <label className="block text-slate-400 font-medium mb-1">Lead Hunter</label>
                    <input
                      type="text"
                      value={currentUser.name}
                      disabled
                      className="w-full bg-slate-950/60 border border-slate-800 rounded px-3 py-2 text-slate-400 cursor-not-allowed"
                    />
                  </div>
                </div>

                {/* Hypothesis Title */}
                <div>
                  <label className="block text-xs text-slate-400 font-medium mb-1">
                    Hypothesis Title <span className="text-rose-400">*</span>
                  </label>
                  <input
                    type="text"
                    placeholder="e.g., Suspicious LSASS Memory Dump via Native MiniDump API"
                    value={hypothesisTitle}
                    onChange={(e) => setHypothesisTitle(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-medium"
                    required
                  />
                </div>

                {/* Hypothesis Description */}
                <div>
                  <label className="block text-xs text-slate-400 font-medium mb-1">
                    Hypothesis Rationale & Threat Narrative <span className="text-rose-400">*</span>
                  </label>
                  <textarea
                    rows={3}
                    placeholder="Explain what the adversary is trying to accomplish, which threat actors use this TTP, and why this is dangerous for this client..."
                    value={hypothesisDescription}
                    onChange={(e) => setHypothesisDescription(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
                    required
                  />
                </div>

                {/* MITRE ATT&CK Techniques Multi-Picker */}
                <div>
                  <label className="block text-xs text-slate-400 font-medium mb-1">
                    MITRE ATT&CK® Techniques Tagged <span className="text-rose-400">*</span>
                  </label>
                  <div className="flex flex-wrap gap-1.5 p-2 bg-slate-950 border border-slate-800 rounded mb-2 min-h-[38px]">
                    {selectedTechniques.map((tid) => {
                      const tech = MITRE_TECHNIQUES.find((t) => t.id === tid);
                      return (
                        <span
                          key={tid}
                          className="flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono bg-cyan-950 text-cyan-300 border border-cyan-800/60"
                        >
                          <span>{tid} {tech ? `(${tech.name})` : ''}</span>
                          <button
                            type="button"
                            onClick={() => setSelectedTechniques(selectedTechniques.filter((t) => t !== tid))}
                            className="text-cyan-400 hover:text-white"
                          >
                            ×
                          </button>
                        </span>
                      );
                    })}
                  </div>

                  <select
                    aria-label="Add MITRE Technique Tag"
                    onChange={(e) => {
                      if (e.target.value && !selectedTechniques.includes(e.target.value)) {
                        setSelectedTechniques([...selectedTechniques, e.target.value]);
                      }
                    }}
                    value=""
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="" disabled>+ Add Technique Tag from MITRE ATT&CK Catalog...</option>
                    {MITRE_TECHNIQUES.map((tech) => (
                      <option key={tech.id} value={tech.id} className="bg-slate-900 text-white">
                        {tech.id} - {tech.name} [{tech.tactic}]
                      </option>
                    ))}
                  </select>
                </div>

                {/* Data Sources Checkboxes */}
                <div>
                  <label className="block text-xs text-slate-400 font-medium mb-1.5">
                    Data Sources Used in Hunt
                  </label>
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 p-3 bg-slate-950 border border-slate-800 rounded max-h-36 overflow-y-auto scrollbar-thin text-xs">
                    {ALL_DATA_SOURCES.map((ds) => {
                      const checked = selectedDataSources.includes(ds);
                      return (
                        <label key={ds} className="flex items-center gap-2 cursor-pointer select-none text-slate-300">
                          <input
                            type="checkbox"
                            checked={checked}
                            onChange={() => {
                              setSelectedDataSources(
                                checked
                                  ? selectedDataSources.filter((d) => d !== ds)
                                  : [...selectedDataSources, ds]
                              );
                            }}
                            className="rounded bg-slate-900 border-slate-700 text-cyan-500 focus:ring-0"
                          />
                          <span className="truncate text-[11px]">{ds}</span>
                        </label>
                      );
                    })}
                  </div>
                </div>

                {/* Production Hunt Query Logic (Single Unified Query) */}
                <div>
                  <div className="flex items-center justify-between mb-1.5 text-xs">
                    <div className="flex items-center gap-2">
                      <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                      <label className="text-slate-200 font-semibold uppercase tracking-wider font-mono text-[11px]">
                        Production Hunt Query Logic
                      </label>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/60 font-medium">
                        Unified Standard Query
                      </span>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={handleRunQueryTest}
                        disabled={isTestingQuery}
                        className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#0b0f19] hover:bg-[#131d31] text-[11px] font-mono text-emerald-400 hover:text-emerald-300 border border-emerald-900/60 font-semibold cursor-pointer disabled:opacity-50 transition-colors"
                      >
                        {isTestingQuery ? (
                          <>
                            <Loader2 className="w-3 h-3 animate-spin" />
                            <span>Validating Telemetry...</span>
                          </>
                        ) : (
                          <>
                            <Play className="w-3 h-3" />
                            <span>Test Telemetry Dry-Run</span>
                          </>
                        )}
                      </button>
                    </div>
                  </div>
                  <textarea
                    rows={5}
                    value={queryText}
                    onChange={(e) => setQueryText(e.target.value)}
                    className="w-full bg-[#070b13] border border-slate-800 rounded p-3 text-xs text-cyan-300 font-mono focus:outline-none focus:border-cyan-500 leading-relaxed scrollbar-thin"
                    placeholder="Enter production hunting query logic..."
                    required
                  />

                  {/* Dry Run Simulation Result */}
                  {queryTestResult && (
                    <div className="mt-2 p-2.5 bg-emerald-950/40 border border-emerald-800/80 rounded flex items-center justify-between text-xs text-emerald-300 font-mono text-[11px]">
                      <div className="flex items-center gap-2">
                        <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                        <span>
                          Query Validated · {queryTestResult.matches} telemetry hits across {queryTestResult.endpointsChecked} endpoints in last 24h ({queryTestResult.latencyMs}ms).
                        </span>
                      </div>
                      <span className="text-slate-400 text-[10px]">Production Syntax Verified</span>
                    </div>
                  )}
                </div>

                {/* Outcome Selector */}
                <div>
                  <label className="block text-xs text-slate-400 font-medium mb-1.5">
                    Hunt Investigation Outcome
                  </label>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                    {[
                      { val: 'True Positive', icon: CheckCircle2, color: 'text-emerald-400 border-emerald-800/80 bg-emerald-950/40' },
                      { val: 'False Positive', icon: XCircle, color: 'text-amber-400 border-amber-800/80 bg-amber-950/40' },
                      { val: 'No Result', icon: HelpCircle, color: 'text-slate-400 border-slate-700 bg-slate-900' },
                      { val: 'Needs Follow-up', icon: Clock, color: 'text-cyan-400 border-cyan-800/80 bg-cyan-950/40' },
                    ].map((item) => {
                      const Icon = item.icon;
                      const isSelected = outcome === item.val;
                      return (
                        <button
                          key={item.val}
                          type="button"
                          onClick={() => setOutcome(item.val as HuntOutcome)}
                          className={`flex items-center gap-2 p-2.5 rounded border text-left cursor-pointer transition-all ${
                            isSelected
                              ? `${item.color} font-bold ring-1 ring-cyan-400/50`
                              : 'border-slate-800 bg-slate-950/60 text-slate-400 hover:border-slate-700'
                          }`}
                        >
                          <Icon className="w-4 h-4 shrink-0" />
                          <span className="text-[11px]">{item.val}</span>
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Notes & Analysis */}
                <div>
                  <label className="block text-xs text-slate-400 font-medium mb-1">
                    Findings, Remediation Actions, or Triage Notes
                  </label>
                  <textarea
                    rows={3}
                    placeholder="Document specific hostnames, containment actions taken, or vendor whitelisting recommendations..."
                    value={notes}
                    onChange={(e) => setNotes(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
                  />
                </div>

                {/* Indicators of Compromise (IOCs) */}
                <div className="space-y-2 border-t border-slate-800 pt-3">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400 font-medium">Add Discovered Indicators (IOCs)</span>
                    <div className="flex items-center gap-2">
                      <span className="text-[11px] text-slate-500">{iocs.length} attached</span>
                      {iocs.length > 0 && (
                        <button
                          type="button"
                          onClick={handleScanIocs}
                          disabled={isScanningIocs}
                          className="flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300 font-semibold cursor-pointer disabled:opacity-50"
                        >
                          {isScanningIocs ? (
                            <Loader2 className="w-3 h-3 animate-spin" />
                          ) : (
                            <ShieldCheck className="w-3 h-3 text-cyan-400" />
                          )}
                          <span>Scan Threat Intel</span>
                        </button>
                      )}
                    </div>
                  </div>

                  <div className="flex flex-col sm:flex-row gap-2 text-xs">
                    <select
                      aria-label="IOC Type"
                      value={newIocType}
                      onChange={(e) => setNewIocType(e.target.value as any)}
                      className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-slate-200"
                    >
                      <option value="IP">IP Address</option>
                      <option value="Domain">Domain / URL</option>
                      <option value="Hash">SHA256 / MD5 Hash</option>
                      <option value="Process">Process Name / Path</option>
                      <option value="Registry">Registry Key</option>
                      <option value="Account">User Account</option>
                    </select>

                    <input
                      type="text"
                      placeholder="Indicator value (e.g., 185.220.101.45 or evil.exe)..."
                      value={newIocValue}
                      onChange={(e) => setNewIocValue(e.target.value)}
                      className="flex-1 bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-white focus:outline-none focus:border-cyan-500 font-mono text-xs"
                    />

                    <input
                      type="text"
                      placeholder="Notes / Attribution (optional)..."
                      value={newIocNotes}
                      onChange={(e) => setNewIocNotes(e.target.value)}
                      className="flex-1 bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-slate-300 focus:outline-none focus:border-cyan-500 text-xs"
                    />

                    <button
                      type="button"
                      onClick={handleAddIoc}
                      className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs font-semibold cursor-pointer shrink-0 border border-slate-700"
                    >
                      + Add IOC
                    </button>
                  </div>

                  {iocs.length > 0 && (
                    <div className="space-y-1.5 pt-1">
                      {iocs.map((ioc) => {
                        const rep = scannedIocs[ioc.id];
                        return (
                          <div
                            key={ioc.id}
                            className="flex items-center justify-between bg-slate-950 border border-slate-800 px-3 py-1.5 rounded text-xs"
                          >
                            <div className="flex items-center gap-2 font-mono flex-wrap">
                              <span className="text-cyan-400 font-semibold text-[10px] uppercase">{ioc.type}:</span>
                              <span className="text-white select-all">{ioc.value}</span>
                              {ioc.notes && <span className="text-slate-500 text-[11px] font-sans">({ioc.notes})</span>}
                              {rep && (
                                <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-rose-950 text-rose-300 border border-rose-800 flex items-center gap-1">
                                  <span>{rep.verdict}</span>
                                  <span>({rep.score}/100)</span>
                                </span>
                              )}
                            </div>
                            <button
                              type="button"
                              onClick={() => handleRemoveIoc(ioc.id)}
                              className="text-slate-500 hover:text-rose-400"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>

                {/* Form Buttons */}
                <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-800">
                  <button
                    type="button"
                    onClick={() => setActiveTab('archive')}
                    className="px-4 py-2 text-xs font-medium text-slate-400 hover:text-white"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-5 py-2 text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white rounded-md transition-colors shadow-md shadow-cyan-600/20 cursor-pointer"
                  >
                    Log & Save Hunt Report
                  </button>
                </div>
              </form>
            </div>
          )}
        </div>

        {/* Right 1 Col: AI Recommendation Engine (Section 4.1) */}
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-cyan-400" />
                <h3 className="text-xs font-bold text-white uppercase tracking-wider">AI Next-Hunt Recommendations</h3>
              </div>
              <button
                onClick={handleTriggerRecommendations}
                disabled={loadingAi}
                className="text-[11px] text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1 cursor-pointer disabled:opacity-50"
              >
                {loadingAi && <Loader2 className="w-3 h-3 animate-spin" />}
                <span>Refresh AI</span>
              </button>
            </div>

            <p className="text-[11px] text-slate-400 leading-relaxed">
              Mines past reports and cross-references against the full MITRE ATT&CK matrix to suggest high-priority uncovered techniques weighted for <strong className="text-slate-200">{currentClient.industry}</strong>.
            </p>

            {loadingAi ? (
              <div className="py-12 text-center space-y-2">
                <Loader2 className="w-6 h-6 animate-spin text-cyan-400 mx-auto" />
                <p className="text-xs text-slate-400 font-mono">Analyzing matrix coverage gaps & threat intel...</p>
              </div>
            ) : recommendations.length > 0 ? (
              <div className="space-y-3 pt-1">
                {recommendations.map((rec) => (
                  <div
                    key={rec.techniqueId}
                    className="bg-slate-950 border border-slate-800 rounded-md p-3 space-y-2 hover:border-cyan-500/50 transition-colors"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <div className="flex items-center gap-1.5 font-mono text-[10px]">
                          <span className="text-cyan-400 font-bold">{rec.techniqueId}</span>
                          <span className="text-slate-600">/</span>
                          <span className="text-slate-400">{rec.tactic}</span>
                        </div>
                        <h4 className="text-xs font-semibold text-white mt-0.5">{rec.techniqueName}</h4>
                      </div>
                      <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded font-bold uppercase ${
                        rec.priority === 'Critical'
                          ? 'bg-rose-950 text-rose-300 border border-rose-800'
                          : rec.priority === 'High'
                          ? 'bg-amber-950 text-amber-300 border border-amber-800'
                          : 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                      }`}>
                        {rec.priority}
                      </span>
                    </div>

                    <p className="text-[11px] text-slate-300 leading-relaxed">
                      {rec.whyThisTechnique}
                    </p>

                    {rec.threatActorContext && (
                      <div className="text-[10px] text-amber-300/80 font-mono bg-slate-900/60 p-1.5 rounded">
                        Adversary TTPs: {rec.threatActorContext}
                      </div>
                    )}

                    <div className="text-[10px] text-slate-400 font-mono">
                      Telemetry: {rec.requiredDataSources.join(', ')}
                    </div>

                    <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between">
                      <div className="text-[10px] text-slate-500">
                        {rec.subTechniquesUncovered?.length || 0} sub-techniques uncovered
                      </div>
                      <button
                        onClick={() => handleAdoptRecommendation(rec)}
                        className="px-2.5 py-1 text-[11px] font-semibold bg-cyan-600/90 hover:bg-cyan-500 text-white rounded cursor-pointer transition-colors"
                      >
                        Adopt Hypothesis →
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="py-6 text-center text-xs text-slate-500">
                No active recommendations. Click "Refresh AI" to generate tailored next hunts.
              </div>
            )}
          </div>

          {/* Quick Client Telemetry Card */}
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-2">
            <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
              {currentClient.name} Telemetry Feeds
            </h4>
            <ul className="text-[11px] text-slate-400 space-y-1 font-mono">
              {currentClient.primaryTelemetry.map((t) => (
                <li key={t} className="flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                  <span>{t}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};
