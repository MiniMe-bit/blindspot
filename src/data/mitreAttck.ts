import { MitreTactic, MitreTechnique } from '../types';

export interface MitreTacticInfo {
  id: string;
  name: MitreTactic;
  shortCode: string;
  description: string;
}

export const MITRE_TACTICS: MitreTacticInfo[] = [
  {
    id: 'TA0043',
    name: 'Reconnaissance',
    shortCode: 'RECON',
    description: 'The adversary is trying to gather information they can use to plan future operations.',
  },
  {
    id: 'TA0042',
    name: 'Resource Development',
    shortCode: 'RES-DEV',
    description: 'The adversary is trying to establish resources they can use to support operations.',
  },
  {
    id: 'TA0001',
    name: 'Initial Access',
    shortCode: 'INIT-ACC',
    description: 'The adversary is trying to get into your network.',
  },
  {
    id: 'TA0002',
    name: 'Execution',
    shortCode: 'EXEC',
    description: 'The adversary is trying to run malicious code.',
  },
  {
    id: 'TA0003',
    name: 'Persistence',
    shortCode: 'PERSIST',
    description: 'The adversary is trying to maintain their foothold.',
  },
  {
    id: 'TA0004',
    name: 'Privilege Escalation',
    shortCode: 'PRIV-ESC',
    description: 'The adversary is trying to gain higher-level permissions.',
  },
  {
    id: 'TA0005',
    name: 'Defense Evasion',
    shortCode: 'DEF-EVAS',
    description: 'The adversary is trying to avoid being detected.',
  },
  {
    id: 'TA0006',
    name: 'Credential Access',
    shortCode: 'CRED-ACC',
    description: 'The adversary is trying to steal account names and passwords.',
  },
  {
    id: 'TA0007',
    name: 'Discovery',
    shortCode: 'DISCOV',
    description: 'The adversary is trying to observe your system and network.',
  },
  {
    id: 'TA0008',
    name: 'Lateral Movement',
    shortCode: 'LAT-MOV',
    description: 'The adversary is trying to move through your environment.',
  },
  {
    id: 'TA0009',
    name: 'Collection',
    shortCode: 'COLLECT',
    description: 'The adversary is trying to gather data of interest to their goal.',
  },
  {
    id: 'TA0011',
    name: 'Command and Control',
    shortCode: 'C2',
    description: 'The adversary is trying to communicate with compromised systems.',
  },
  {
    id: 'TA0010',
    name: 'Exfiltration',
    shortCode: 'EXFIL',
    description: 'The adversary is trying to steal data.',
  },
  {
    id: 'TA0040',
    name: 'Impact',
    shortCode: 'IMPACT',
    description: 'The adversary is trying to manipulate, interrupt, or destroy your systems and data.',
  },
];

export const MITRE_TECHNIQUES: MitreTechnique[] = [
  // Reconnaissance
  {
    id: 'T1595',
    name: 'Active Scanning',
    tactic: 'Reconnaissance',
    tacticId: 'TA0043',
    description: 'Adversaries may execute active scans to gather information on IP blocks, open ports, and vulnerable services.',
    subTechniques: [
      { id: 'T1595.001', name: 'Scanning IP Blocks', description: 'Scanning public IP subnets for alive hosts.' },
      { id: 'T1595.002', name: 'Vulnerability Scanning', description: 'Scanning externally exposed ports for known CVE banners.' },
    ],
    dataSources: ['Network Traffic', 'Firewall Logs', 'WAF Telemetry'],
    platforms: ['Network', 'Cloud'],
    sampleQuery: {
      language: 'KQL',
      query: `CommonSecurityLog\n| where DeviceAction !in ("Drop", "Deny")\n| summarize DestinationPorts = dcount(DestinationPort), count() by SourceIP, bin(TimeGenerated, 10m)\n| where DestinationPorts > 30`
    }
  },
  {
    id: 'T1592',
    name: 'Gather Victim Host Information',
    tactic: 'Reconnaissance',
    tacticId: 'TA0043',
    description: 'Adversaries may gather information about the victim host systems prior to exploitation.',
    subTechniques: [
      { id: 'T1592.002', name: 'Software', description: 'Identifying software versions running on target endpoints.' }
    ],
    dataSources: ['Web Server Logs', 'DNS Query Logs'],
    platforms: ['PRE'],
  },

  // Resource Development
  {
    id: 'T1583',
    name: 'Acquire Infrastructure',
    tactic: 'Resource Development',
    tacticId: 'TA0042',
    description: 'Adversaries may acquire infrastructure such as domains, VPS instances, or DNS records.',
    subTechniques: [
      { id: 'T1583.001', name: 'Domains', description: 'Registering typosquatted or high-reputation aged domains.' },
      { id: 'T1583.003', name: 'Virtual Private Server', description: 'Provisioning VPS instances across bulletproof hosts.' },
    ],
    dataSources: ['Domain Registration Telemetry', 'Threat Intelligence Feeds'],
    platforms: ['PRE'],
  },
  {
    id: 'T1587',
    name: 'Develop Capabilities',
    tactic: 'Resource Development',
    tacticId: 'TA0042',
    description: 'Adversaries may develop custom malware, exploits, or code-signing certificates.',
    subTechniques: [
      { id: 'T1587.001', name: 'Malware', description: 'Authoring custom loaders, droppers, and post-exploitation implants.' },
      { id: 'T1587.003', name: 'Digital Certificates', description: 'Forging or stealing legitimate code-signing keys.' }
    ],
    dataSources: ['Threat Intelligence Feeds'],
    platforms: ['PRE'],
  },

  // Initial Access
  {
    id: 'T1566',
    name: 'Phishing',
    tactic: 'Initial Access',
    tacticId: 'TA0001',
    description: 'Adversaries may send phishing messages to gain access to victim systems.',
    subTechniques: [
      { id: 'T1566.001', name: 'Spearphishing Attachment', description: 'Malicious attachments disguised as invoices or resumes.' },
      { id: 'T1566.002', name: 'Spearphishing Link', description: 'Hyperlinks pointing to credential harvest portals or payload staging.' },
      { id: 'T1566.003', name: 'Spearphishing via Service', description: 'Phishing delivered through Teams, Slack, LinkedIn, or SMS.' }
    ],
    dataSources: ['Email Gateway Logs', 'Proxy/Web Filter', 'EDR Process Events'],
    platforms: ['Windows', 'macOS', 'Linux', 'SaaS'],
    sampleQuery: {
      language: 'KQL',
      query: `EmailEvents\n| where AttachmentCount > 0 or isnotempty(UrlCount)\n| join kind=inner (DeviceFileEvents | where InitiatingProcessFileName in~ ("outlook.exe", "teams.exe")) on DeviceId\n| where ActionType in ("FileCreated", "FileDownloaded")`
    }
  },
  {
    id: 'T1190',
    name: 'Exploit Public-Facing Application',
    tactic: 'Initial Access',
    tacticId: 'TA0001',
    description: 'Adversaries may attempt to exploit a vulnerability in an Internet-facing computer or program.',
    subTechniques: [],
    dataSources: ['Web Server Logs', 'WAF Telemetry', 'EDR Network Events', 'Kernel Auditing'],
    platforms: ['Windows', 'Linux', 'Containers', 'Network'],
    sampleQuery: {
      language: 'SPL',
      query: `index=web_proxy sourcetype="iis:access" OR sourcetype="nginx:access"\n| where status=200 AND (match(uri_path, "\\.(php|aspx|jsp)\\?") OR uri_query LIKE "%cmd=%")\n| stats count by src_ip, uri_path, status`
    }
  },
  {
    id: 'T1078',
    name: 'Valid Accounts',
    tactic: 'Initial Access',
    tacticId: 'TA0001',
    description: 'Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.',
    subTechniques: [
      { id: 'T1078.001', name: 'Default Accounts', description: 'Utilizing default passwords on appliances and IoT.' },
      { id: 'T1078.003', name: 'Local Accounts', description: 'Using built-in Administrator or guest accounts.' },
      { id: 'T1078.004', name: 'Cloud Accounts', description: 'Abusing stolen Azure AD / Okta / AWS IAM credentials.' },
    ],
    dataSources: ['Identity Broker Logs (Okta, Entra)', 'Windows Event 4624', 'CloudTrail Audit Logs'],
    platforms: ['Windows', 'Linux', 'AWS', 'GCP', 'Azure', 'SaaS'],
    sampleQuery: {
      language: 'KQL',
      query: `SigninLogs\n| where RiskLevelDuringSignIn in ("high", "medium") or ConditionalAccessStatus == "failure"\n| summarize FailedSignins=count() by UserPrincipalName, IPAddress, Location\n| where FailedSignins > 5`
    }
  },

  // Execution
  {
    id: 'T1059',
    name: 'Command and Scripting Interpreter',
    tactic: 'Execution',
    tacticId: 'TA0002',
    description: 'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.',
    subTechniques: [
      { id: 'T1059.001', name: 'PowerShell', description: 'Abuse of powershell.exe and pwsh with encoded commands or reflection.' },
      { id: 'T1059.003', name: 'Windows Command Shell', description: 'Execution via cmd.exe batch files.' },
      { id: 'T1059.004', name: 'Unix Shell', description: 'Execution via bash, sh, zsh on Linux/macOS.' },
      { id: 'T1059.007', name: 'JavaScript', description: 'Execution via wscript.exe or cscript.exe.' },
    ],
    dataSources: ['EDR Process Creation', 'Windows Event 4688', 'Sysmon Event 1', 'Linux auditd'],
    platforms: ['Windows', 'Linux', 'macOS'],
    sampleQuery: {
      language: 'KQL',
      query: `DeviceProcessEvents\n| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe")\n| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "downloadstring", "invoke-expression", "bypass", "hidden")\n| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName`
    }
  },
  {
    id: 'T1047',
    name: 'Windows Management Instrumentation',
    tactic: 'Execution',
    tacticId: 'TA0002',
    description: 'Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands and payloads.',
    subTechniques: [],
    dataSources: ['EDR Process Events', 'WMI-Activity Operational Log', 'Sysmon Event 19, 20, 21'],
    platforms: ['Windows'],
    sampleQuery: {
      language: 'SPL',
      query: `index=endpoint sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1\n(Image="*\\\\wmiprvse.exe" OR ParentImage="*\\\\wmiprvse.exe")\n| stats count by host, Image, CommandLine, ParentCommandLine`
    }
  },
  {
    id: 'T1053',
    name: 'Scheduled Task/Job',
    tactic: 'Execution',
    tacticId: 'TA0002',
    description: 'Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.',
    subTechniques: [
      { id: 'T1053.005', name: 'Scheduled Task', description: 'Creation of Windows scheduled tasks using schtasks or COM interfaces.' },
      { id: 'T1053.003', name: 'Cron', description: 'Persistence via crontab or /etc/cron.* files.' }
    ],
    dataSources: ['Windows Event 4698', 'Sysmon Event 1', 'EDR Process Events', 'Cron logs'],
    platforms: ['Windows', 'Linux'],
    sampleQuery: {
      language: 'KQL',
      query: `SecurityEvent\n| where EventID == 4698\n| parse EventData with * '<Data Name="TaskName">' TaskName '</Data>' *\n| where TaskName !startswith "\\\\Microsoft\\\\Windows\\\\"`
    }
  },

  // Persistence
  {
    id: 'T1547',
    name: 'Boot or Logon Autostart Execution',
    tactic: 'Persistence',
    tacticId: 'TA0003',
    description: 'Adversaries may configure system settings to automatically execute a program during system boot or logon.',
    subTechniques: [
      { id: 'T1547.001', name: 'Registry Run Keys / Startup Folder', description: 'HKLM/HKCU Run and RunOnce keys.' },
      { id: 'T1547.009', name: 'Shortcut Modification', description: 'Altering LNK shortcuts to append malicious arguments.' },
    ],
    dataSources: ['EDR Registry Events', 'Sysmon Event 12, 13', 'Windows Event 4657'],
    platforms: ['Windows'],
    sampleQuery: {
      language: 'KQL',
      query: `DeviceRegistryEvents\n| where RegistryKey has_any ("\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run", "\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce")\n| where ActionType == "RegistryValueSet"\n| project TimeGenerated, DeviceName, RegistryValueName, RegistryValueData, InitiatingProcessCommandLine`
    }
  },
  {
    id: 'T1136',
    name: 'Create Account',
    tactic: 'Persistence',
    tacticId: 'TA0003',
    description: 'Adversaries may create an account to maintain access to victim systems.',
    subTechniques: [
      { id: 'T1136.001', name: 'Local Account', description: 'Net user /add commands on endpoints.' },
      { id: 'T1136.002', name: 'Domain Account', description: 'Creation of new user objects in Active Directory.' },
      { id: 'T1136.003', name: 'Cloud Account', description: 'Creating guest or member users in Azure AD or AWS IAM.' }
    ],
    dataSources: ['Windows Event 4720', 'Entra Audit Logs', 'CloudTrail'],
    platforms: ['Windows', 'Linux', 'Azure', 'AWS'],
  },

  // Privilege Escalation
  {
    id: 'T1548',
    name: 'Abuse Elevation Control Mechanism',
    tactic: 'Privilege Escalation',
    tacticId: 'TA0004',
    description: 'Adversaries may circumvent mechanisms designed to control elevation of privileges to gain higher permissions.',
    subTechniques: [
      { id: 'T1548.002', name: 'Bypass User Account Control', description: 'Bypassing Windows UAC using trusted binaries or mock folders.' },
      { id: 'T1548.003', name: 'Sudo and Sudo Caching', description: 'Abusing sudoers misconfigurations or cached credentials.' }
    ],
    dataSources: ['EDR Process Events', 'Sysmon Event 1', 'auth.log / secure.log'],
    platforms: ['Windows', 'Linux', 'macOS'],
  },
  {
    id: 'T1068',
    name: 'Exploitation for Privilege Escalation',
    tactic: 'Privilege Escalation',
    tacticId: 'TA0004',
    description: 'Adversaries may exploit software vulnerabilities in an elevated service or kernel to elevate privileges.',
    subTechniques: [],
    dataSources: ['EDR Process Events', 'Windows System Event 7045', 'Kernel Audit Events'],
    platforms: ['Windows', 'Linux'],
  },

  // Defense Evasion
  {
    id: 'T1562',
    name: 'Impair Defenses',
    tactic: 'Defense Evasion',
    tacticId: 'TA0005',
    description: 'Adversaries may maliciously modify the environment to hinder or disable defensive tools, logging, or security software.',
    subTechniques: [
      { id: 'T1562.001', name: 'Disable or Modify Tools', description: 'Stopping AV/EDR services, uninstalling agents, or killing processes.' },
      { id: 'T1562.002', name: 'Disable Windows Event Logging', description: 'Clearing security event logs with wevtutil or API tampering.' },
      { id: 'T1562.004', name: 'Disable or Modify System Firewall', description: 'Modifying netsh advfirewall or iptables rules.' }
    ],
    dataSources: ['Windows Event 1102 (Log Cleared)', 'EDR Process Events', 'Service Control Manager Event 7036'],
    platforms: ['Windows', 'Linux'],
    sampleQuery: {
      language: 'KQL',
      query: `DeviceProcessEvents\n| where ProcessCommandLine has_any ("wevtutil cl", "sc stop", "net stop", "Set-MpPreference -DisableRealtimeMonitoring $true")\n| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine`
    }
  },
  {
    id: 'T1027',
    name: 'Obfuscated/Encoded Files or Information',
    tactic: 'Defense Evasion',
    tacticId: 'TA0005',
    description: 'Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents.',
    subTechniques: [
      { id: 'T1027.002', name: 'Software Packing', description: 'Using UPX or custom packers to conceal binary payloads.' },
      { id: 'T1027.005', name: 'Indicator Removal from Tools', description: 'Stripping symbols and metadata from binaries.' }
    ],
    dataSources: ['EDR File Analysis', 'Process Memory Scans'],
    platforms: ['Windows', 'macOS', 'Linux'],
  },
  {
    id: 'T1055',
    name: 'Process Injection',
    tactic: 'Defense Evasion',
    tacticId: 'TA0005',
    description: 'Adversaries may inject code into processes in order to evade process-based defenses and elevate privileges.',
    subTechniques: [
      { id: 'T1055.001', name: 'Dynamic-link Library Injection', description: 'Injecting DLLs into target memory spaces.' },
      { id: 'T1055.002', name: 'Portable Executable Injection', description: 'Injecting unmapped PE files directly.' },
      { id: 'T1055.012', name: 'Process Hollowing', description: 'Replacing process memory with malicious code.' }
    ],
    dataSources: ['Sysmon Event 8 (CreateRemoteThread)', 'Sysmon Event 10', 'EDR Memory Telemetry'],
    platforms: ['Windows', 'Linux'],
    sampleQuery: {
      language: 'Sigma',
      query: `title: Suspicious Process Injection into System Binary\nstatus: stable\nlogsource:\n  product: windows\n  category: create_remote_thread\ndetection:\n  selection:\n    TargetImage|endswith:\n      - '\\\\svchost.exe'\n      - '\\\\explorer.exe'\n      - '\\\\lsass.exe'\n  filter:\n    SourceImage|endswith:\n      - '\\\\csrss.exe'\n  condition: selection and not filter`
    }
  },

  // Credential Access
  {
    id: 'T1003',
    name: 'OS Credential Dumping',
    tactic: 'Credential Access',
    tacticId: 'TA0006',
    description: 'Adversaries may attempt to dump credentials to obtain account login and credential material in the form of cleartext passwords or hashes.',
    subTechniques: [
      { id: 'T1003.001', name: 'LSASS Memory', description: 'Dumping Local Security Authority Subsystem Service memory using procdump or mimikatz.' },
      { id: 'T1003.002', name: 'Security Account Manager', description: 'Extracting hashes from SAM registry hive.' },
      { id: 'T1003.003', name: 'NTDS', description: 'Dumping Active Directory NTDS.dit database with ntdsutil.' }
    ],
    dataSources: ['Sysmon Event 10', 'EDR Process Access Events', 'Windows Event 4656'],
    platforms: ['Windows'],
    sampleQuery: {
      language: 'KQL',
      query: `DeviceProcessEvents\n| where ProcessCommandLine has_any ("mimikatz", "sekurlsa", "procdump.exe -ma lsass", "rundll32.exe comsvcs.dll, #24")\n| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine`
    }
  },
  {
    id: 'T1110',
    name: 'Brute Force',
    tactic: 'Credential Access',
    tacticId: 'TA0006',
    description: 'Adversaries may use brute force techniques to attempt credential access for valid accounts.',
    subTechniques: [
      { id: 'T1110.003', name: 'Password Spraying', description: 'Testing a single password across a large number of accounts.' },
      { id: 'T1110.001', name: 'Password Guessing', description: 'Repeatedly guessing passwords on a single account.' }
    ],
    dataSources: ['Windows Event 4625', 'Okta System Log', 'Azure AD SignIns'],
    platforms: ['Windows', 'Linux', 'Cloud', 'SaaS'],
    sampleQuery: {
      language: 'KQL',
      query: `SigninLogs\n| where ResultType == "50126"\n| summarize TargetAccounts = dcount(UserPrincipalName), TotalAttempts = count() by IPAddress, bin(TimeGenerated, 15m)\n| where TargetAccounts > 10`
    }
  },

  // Discovery
  {
    id: 'T1087',
    name: 'Account Discovery',
    tactic: 'Discovery',
    tacticId: 'TA0007',
    description: 'Adversaries may attempt to get a listing of valid accounts on a system or within an environment.',
    subTechniques: [
      { id: 'T1087.001', name: 'Local Account', description: 'Enumerating local accounts using net user or whoami.' },
      { id: 'T1087.002', name: 'Domain Account', description: 'Enumerating Active Directory users using net user /domain or BloodHound/SharpHound.' }
    ],
    dataSources: ['EDR Process Events', 'Command Line Auditing'],
    platforms: ['Windows', 'Linux', 'Cloud'],
  },
  {
    id: 'T1018',
    name: 'Remote System Discovery',
    tactic: 'Discovery',
    tacticId: 'TA0007',
    description: 'Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network.',
    subTechniques: [],
    dataSources: ['EDR Process Events', 'Network Traffic Logs'],
    platforms: ['Windows', 'Linux', 'macOS'],
  },
  {
    id: 'T1082',
    name: 'System Information Discovery',
    tactic: 'Discovery',
    tacticId: 'TA0007',
    description: 'An adversary may attempt to get detailed information about the operating system and hardware.',
    subTechniques: [],
    dataSources: ['EDR Process Events', 'Sysmon Event 1'],
    platforms: ['Windows', 'Linux', 'macOS'],
  },

  // Lateral Movement
  {
    id: 'T1021',
    name: 'Remote Services',
    tactic: 'Lateral Movement',
    tacticId: 'TA0008',
    description: 'Adversaries may use valid accounts to log into a service that accepts remote connections, such as RDP, SSH, or SMB.',
    subTechniques: [
      { id: 'T1021.001', name: 'Remote Desktop Protocol', description: 'Lateral movement over port 3389.' },
      { id: 'T1021.002', name: 'SMB/Windows Admin Shares', description: 'Moving laterally using PsExec or IPC$ shares.' },
      { id: 'T1021.004', name: 'SSH', description: 'Abusing SSH keys or passwords to pivot into Unix/Linux jump hosts.' }
    ],
    dataSources: ['Windows Event 4624 (LogonType 10 & 3)', 'Network Flow Logs', 'Zeek conn.log'],
    platforms: ['Windows', 'Linux'],
    sampleQuery: {
      language: 'KQL',
      query: `DeviceNetworkEvents\n| where RemotePort in (3389, 445, 22)\n| summarize ConnectionCount=count(), TargetDevices=dcount(RemoteIP) by DeviceName, InitiatingProcessFileName, bin(TimeGenerated, 1h)\n| where TargetDevices > 5`
    }
  },
  {
    id: 'T1570',
    name: 'Lateral Tool Transfer',
    tactic: 'Lateral Movement',
    tacticId: 'TA0008',
    description: 'Adversaries may transfer tools or other files between systems in a compromised environment.',
    subTechniques: [],
    dataSources: ['EDR File Events', 'SMB Network Telemetry'],
    platforms: ['Windows', 'Linux'],
  },

  // Collection
  {
    id: 'T1005',
    name: 'Data from Local System',
    tactic: 'Collection',
    tacticId: 'TA0009',
    description: 'Adversaries may search local system sources, such as file systems and databases, to find files of interest.',
    subTechniques: [],
    dataSources: ['EDR File Access', 'DLP Telemetry'],
    platforms: ['Windows', 'Linux', 'macOS'],
  },
  {
    id: 'T1560',
    name: 'Archive Collected Data',
    tactic: 'Collection',
    tacticId: 'TA0009',
    description: 'An adversary may compress and/or encrypt data that is collected prior to exfiltration.',
    subTechniques: [
      { id: 'T1560.001', name: 'Archive via Utility', description: 'Using 7zip, winrar, or tar to compress target directories into password-protected archives.' }
    ],
    dataSources: ['EDR Process Events', 'File Creation Events'],
    platforms: ['Windows', 'Linux', 'macOS'],
    sampleQuery: {
      language: 'KQL',
      query: `DeviceProcessEvents\n| where FileName in~ ("7z.exe", "rar.exe", "winrar.exe", "tar")\n| where ProcessCommandLine has_any ("-p", "-hp", "a ", "cf ")\n| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine`
    }
  },

  // Command and Control
  {
    id: 'T1071',
    name: 'Application Layer Protocol',
    tactic: 'Command and Control',
    tacticId: 'TA0011',
    description: 'Adversaries may communicate using application layer protocols to avoid detection by blending in with existing traffic.',
    subTechniques: [
      { id: 'T1071.001', name: 'Web Protocols', description: 'Using HTTP/HTTPS beacons disguised as normal web browsing.' },
      { id: 'T1071.004', name: 'DNS', description: 'Using DNS queries (DNS tunneling) for command and control signaling.' }
    ],
    dataSources: ['DNS Query Logs', 'Proxy/Web Gateway Logs', 'Zeek http.log'],
    platforms: ['Windows', 'Linux', 'Network'],
    sampleQuery: {
      language: 'SPL',
      query: `index=dns sourcetype=stream:dns\n| eval query_len=len(query)\n| where query_len > 45\n| stats count, dc(query) as unique_subdomains, avg(query_len) as avg_len by src_ip, domain\n| where unique_subdomains > 50`
    }
  },
  {
    id: 'T1573',
    name: 'Encrypted Channel',
    tactic: 'Command and Control',
    tacticId: 'TA0011',
    description: 'Adversaries may employ a known, encryption algorithm to conceal command and control traffic.',
    subTechniques: [
      { id: 'T1573.001', name: 'Symmetric Cryptography', description: 'Custom AES/RC4 encrypted tunnels over raw TCP sockets.' }
    ],
    dataSources: ['Network Traffic Telemetry', 'JA3/JA4 TLS Fingerprints'],
    platforms: ['Linux', 'Windows'],
  },

  // Exfiltration
  {
    id: 'T1567',
    name: 'Exfiltration Over Web Service',
    tactic: 'Exfiltration',
    tacticId: 'TA0010',
    description: 'Adversaries may use an existing, legitimate external Web service to exfiltrate data rather than their primary command and control channel.',
    subTechniques: [
      { id: 'T1567.002', name: 'Exfiltration to Cloud Storage', description: 'Uploading data dumps to Mega.nz, Dropbox, AWS S3, or Google Drive via rclone.' }
    ],
    dataSources: ['Proxy Logs', 'EDR Network Events', 'CASB / Cloud Access Broker'],
    platforms: ['Windows', 'Linux', 'macOS'],
    sampleQuery: {
      language: 'KQL',
      query: `DeviceProcessEvents\n| where FileName in~ ("rclone.exe", "megasync.exe") or ProcessCommandLine has_any ("mega.nz", "dropbox.com", "s3.amazonaws.com")\n| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine`
    }
  },
  {
    id: 'T1048',
    name: 'Exfiltration Over Alternative Protocol',
    tactic: 'Exfiltration',
    tacticId: 'TA0010',
    description: 'Adversaries may steal data by exfiltrating it over an alternative protocol than the primary command and control channel.',
    subTechniques: [],
    dataSources: ['Firewall Logs', 'NetFlow'],
    platforms: ['Windows', 'Linux'],
  },

  // Impact
  {
    id: 'T1486',
    name: 'Data Encrypted for Impact',
    tactic: 'Impact',
    tacticId: 'TA0040',
    description: 'Adversaries may encrypt data on target systems to interrupt availability to system and network resources (Ransomware).',
    subTechniques: [],
    dataSources: ['EDR File Modification Events', 'Sysmon Event 11', 'Volume Shadow Copy Deletion Logs'],
    platforms: ['Windows', 'Linux', 'macOS', 'ESXi'],
    sampleQuery: {
      language: 'KQL',
      query: `DeviceProcessEvents\n| where ProcessCommandLine has_any ("vssadmin delete shadows", "wbadmin delete catalog", "bdehdcfg.exe", "bcdedit /set {default} bootstatuspolicy ignoreallfailures")\n| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine`
    }
  },
  {
    id: 'T1490',
    name: 'Inhibit System Recovery',
    tactic: 'Impact',
    tacticId: 'TA0040',
    description: 'Adversaries may delete or remove built-in data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery from ransomware.',
    subTechniques: [],
    dataSources: ['EDR Process Events', 'Windows Event 4688'],
    platforms: ['Windows'],
  }
];

export const ALL_DATA_SOURCES = [
  'EDR Process Creation',
  'EDR File Modification Events',
  'EDR Network Events',
  'Windows Event 4624/4625 (Logon)',
  'Windows Event 4688 / Sysmon 1',
  'Windows Event 4698 (Scheduled Tasks)',
  'DNS Query Logs',
  'Proxy / Web Gateway Logs',
  'Firewall / NetFlow Telemetry',
  'Identity Broker Logs (Okta, Entra)',
  'CloudTrail / Cloud Audit Logs',
  'Zeek / Suricata Network NIDS',
  'Linux auditd / syslog',
  'Active Directory Event 4720/4738',
  'WAF Telemetry'
];
