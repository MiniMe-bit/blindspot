/**
 * Hunt guide per catalog technique: who has used it (summarised from MITRE ATT&CK procedure
 * examples on the group pages), how to hunt it, and what a hit looks like.
 * Queries come from the technique catalog (mitreAttck.ts) or `query` below when the catalog has none.
 */

export interface ActorUse {
  name: string;
  /** MITRE group ID, links to https://attack.mitre.org/groups/<id>/ */
  groupId: string;
  procedure: string;
}

export interface TechniqueGuide {
  actors: ActorUse[];
  howToHunt: string;
  lookFor: string;
  query?: { language: 'KQL' | 'SPL' | 'Sigma' | 'EQL'; code: string };
}

const G = {
  APT28: ['APT28', 'G0007'],
  APT29: ['APT29', 'G0016'],
  APT33: ['APT33', 'G0064'],
  APT41: ['APT41', 'G0096'],
  Lazarus: ['Lazarus Group', 'G0032'],
  Kimsuky: ['Kimsuky', 'G0094'],
  FIN7: ['FIN7', 'G0046'],
  Turla: ['Turla', 'G0010'],
  WizardSpider: ['Wizard Spider', 'G0102'],
  Sandworm: ['Sandworm Team', 'G0034'],
  OilRig: ['OilRig', 'G0049'],
  VoltTyphoon: ['Volt Typhoon', 'G1017'],
  ScatteredSpider: ['Scattered Spider', 'G1015'],
  Dragonfly: ['Dragonfly', 'G0035'],
  VolatileCedar: ['Volatile Cedar', 'G0123'],
  Patchwork: ['Patchwork', 'G0040'],
} as const;

const use = (g: keyof typeof G, procedure: string): ActorUse => ({ name: G[g][0], groupId: G[g][1], procedure });

export const TECHNIQUE_GUIDE: Record<string, TechniqueGuide> = {
  T1595: {
    actors: [use('Dragonfly', 'Scanned internet-facing infrastructure for vulnerable services before targeting energy-sector networks.'), use('VolatileCedar', 'Ran vulnerability and directory scanners against target web servers to find exploitable pages.')],
    howToHunt: 'Look at perimeter and WAF logs for single sources hitting many ports, paths or hosts in a short window, especially paths that only scanners request.',
    lookFor: 'One external IP requesting hundreds of distinct URL paths (/.git/config, /admin, /cgi-bin/) with 404s in under 10 minutes.',
  },
  T1592: {
    actors: [use('VoltTyphoon', 'Gathered detailed information about victim hosts and network devices before intrusion to plan access.')],
    howToHunt: 'Hunt for fingerprinting of your public assets: requests that enumerate software versions, banner grabs, and unusual User-Agents probing version endpoints.',
    lookFor: 'Repeated requests to version/status endpoints (e.g. /remote/info, /api/version) from hosting-provider IPs.',
    query: { language: 'KQL', code: 'W3CIISLog\n| where csUriStem has_any ("version", "/remote/info", "/api/v1/info", "server-status")\n| summarize Requests = count(), Paths = dcount(csUriStem) by cIP, csUserAgent\n| where Requests > 20' },
  },
  T1583: {
    actors: [use('APT29', 'Acquired domains for command and control, sometimes registered through resellers to hide ownership.'), use('Lazarus', 'Registered domains that imitate legitimate companies to host phishing and C2.')],
    howToHunt: 'Check outbound traffic and email links against newly registered or look-alike domains of your own brand and suppliers.',
    lookFor: 'Connections to a domain registered in the last 30 days whose name is one edit away from a supplier domain.',
    query: { language: 'KQL', code: 'DeviceNetworkEvents\n| where Timestamp > ago(7d) and isnotempty(RemoteUrl)\n| summarize Devices = dcount(DeviceId), First = min(Timestamp) by RemoteUrl\n| where Devices <= 2  // rare destinations: enrich with domain age from your TI platform' },
  },
  T1587: {
    actors: [use('Lazarus', 'Developed custom malware families and tooling used across its financially motivated operations.'), use('Kimsuky', 'Built its own malware and droppers, updating them between campaigns.')],
    howToHunt: 'Custom malware is rare by definition: hunt for executables seen on only one or two hosts, unsigned, running from user-writable paths.',
    lookFor: 'An unsigned binary in %AppData% with a first-seen date today, present on a single host, making network connections.',
    query: { language: 'KQL', code: 'DeviceProcessEvents\n| where Timestamp > ago(7d) and FolderPath has_any (@"\\AppData\\", @"\\Temp\\")\n| summarize Hosts = dcount(DeviceId), Cmd = any(ProcessCommandLine) by SHA256, FileName\n| where Hosts <= 2' },
  },
  T1566: {
    actors: [use('FIN7', 'Sent spearphishing emails with malicious document attachments to hospitality and retail staff.'), use('Kimsuky', 'Used spearphishing links to credential-harvesting pages imitating webmail and cloud services.')],
    howToHunt: 'Join email delivery with endpoint activity: Office or browser processes spawning script hosts shortly after a user opens mail.',
    lookFor: 'WINWORD.EXE → cmd.exe → powershell.exe within two minutes of the user opening an attachment from an external sender.',
  },
  T1190: {
    actors: [use('APT41', 'Exploited vulnerabilities in internet-facing appliances and applications, such as Citrix ADC, to gain initial access.'), use('VoltTyphoon', 'Exploited vulnerabilities in public-facing network devices (e.g. Fortinet) for initial access.')],
    howToHunt: 'Hunt for web or appliance service accounts spawning shells, and for web requests that succeed on exploit-shaped paths.',
    lookFor: 'w3wp.exe or java spawning cmd.exe / powershell.exe, or nginx/httpd spawning /bin/sh.',
  },
  T1078: {
    actors: [use('APT29', 'Used compromised valid accounts, including cloud and service accounts, to access victim environments.'), use('ScatteredSpider', 'Obtained valid credentials through help-desk social engineering and used them to log in.')],
    howToHunt: 'Look for valid logins that break the account\'s own pattern: new country, new device, impossible travel, or service accounts logging in interactively.',
    lookFor: 'A service account with interactive sign-in from a residential proxy IP at 03:00.',
  },
  T1059: {
    actors: [use('APT29', 'Used PowerShell to run commands and payloads, often encoded, on compromised hosts.'), use('FIN7', 'Used PowerShell and JavaScript scripts to execute payloads delivered by phishing.')],
    howToHunt: 'Hunt for encoded or download-cradle PowerShell, and script hosts launched by unusual parents.',
    lookFor: 'powershell.exe -nop -w hidden -enc JABjAD0A… launched by excel.exe.',
  },
  T1047: {
    actors: [use('VoltTyphoon', 'Used WMIC for remote execution and to gather system information during hands-on-keyboard activity.'), use('APT29', 'Used WMI to execute commands remotely and for persistence.')],
    howToHunt: 'Hunt for wmic process call create and for processes whose parent is WmiPrvSE.exe on servers that do not normally run WMI jobs.',
    lookFor: 'WmiPrvSE.exe spawning cmd.exe /c ntdsutil … on a domain controller.',
  },
  T1053: {
    actors: [use('APT29', 'Created scheduled tasks to execute backdoors and maintain persistence.'), use('FIN7', 'Created scheduled tasks to run malicious scripts at intervals.')],
    howToHunt: 'Review task creations (Event 4698, schtasks /create) whose action points to user-writable paths or script hosts.',
    lookFor: 'schtasks /create /sc minute /mo 15 /tr "C:\\Users\\Public\\update.vbs".',
  },
  T1547: {
    actors: [use('Kimsuky', 'Added Registry Run keys so its malware launches at user logon.'), use('Lazarus', 'Used Run keys and startup folder entries for persistence.')],
    howToHunt: 'Hunt Run/RunOnce key writes and startup-folder file creations that point outside Program Files.',
    lookFor: 'HKCU\\...\\Run value "OneDriveUpdate" → C:\\Users\\x\\AppData\\Roaming\\odu.exe.',
  },
  T1136: {
    actors: [use('Kimsuky', 'Created new local accounts on victims, including ones added to the administrators group.'), use('APT41', 'Created accounts on compromised systems to keep access.')],
    howToHunt: 'Review account creations (4720, cloud user creation events) outside of the identity team\'s change windows and tooling.',
    lookFor: 'net user support$ P@ss /add followed by net localgroup administrators support$ /add.',
    query: { language: 'KQL', code: 'DeviceProcessEvents\n| where Timestamp > ago(14d)\n| where FileName in~ ("net.exe", "net1.exe") and ProcessCommandLine has "/add"\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName' },
  },
  T1548: {
    actors: [use('APT29', 'Bypassed User Account Control to run payloads with elevated privileges.'), use('Patchwork', 'Used known UAC bypass techniques to elevate its malware.')],
    howToHunt: 'Hunt for auto-elevating binaries (fodhelper, computerdefaults, eventvwr) spawning shells, and their registry hijack keys.',
    lookFor: 'Write to HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command then fodhelper.exe spawning cmd.exe.',
    query: { language: 'KQL', code: 'DeviceProcessEvents\n| where InitiatingProcessFileName in~ ("fodhelper.exe", "computerdefaults.exe", "eventvwr.exe", "sdclt.exe")\n| where FileName in~ ("cmd.exe", "powershell.exe", "rundll32.exe", "mshta.exe")' },
  },
  T1068: {
    actors: [use('APT28', 'Exploited Windows privilege-escalation vulnerabilities to gain SYSTEM on compromised hosts.'), use('Turla', 'Exploited a vulnerable signed driver to run code in the kernel.')],
    howToHunt: 'Hunt for low-privileged processes suddenly spawning SYSTEM children, and for known-vulnerable drivers being loaded.',
    lookFor: 'A process running as a normal user whose child runs as NT AUTHORITY\\SYSTEM without a service or task in between.',
    query: { language: 'KQL', code: 'DeviceEvents\n| where ActionType == "DriverLoad"\n| summarize Hosts = dcount(DeviceId) by FileName, SHA256\n| where Hosts < 3  // compare against the LOLDrivers vulnerable-driver list' },
  },
  T1562: {
    actors: [use('WizardSpider', 'Stopped or uninstalled security tools before deploying ransomware.'), use('Lazarus', 'Used malware that disables the Windows firewall to allow its traffic.')],
    howToHunt: 'Hunt for service stops, uninstalls and exclusions that target EDR/AV, and for netsh/iptables rule changes.',
    lookFor: 'Set-MpPreference -DisableRealtimeMonitoring $true or sc stop windefend from a non-admin tool.',
  },
  T1027: {
    actors: [use('APT29', 'Obfuscated PowerShell scripts and payloads to hinder analysis.'), use('FIN7', 'Obfuscated its JavaScript and PowerShell droppers.')],
    howToHunt: 'Hunt for high-entropy or heavily escaped command lines, base64 blobs, and string-concatenation tricks in script hosts.',
    lookFor: "powershell.exe with -enc plus a 3,000-character argument, or ('Down'+'loadString') style splits.",
    query: { language: 'KQL', code: 'DeviceProcessEvents\n| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe")\n| where strlen(ProcessCommandLine) > 1000 or ProcessCommandLine matches regex @"[A-Za-z0-9+/]{200,}={0,2}"' },
  },
  T1055: {
    actors: [use('Turla', 'Injected its payloads into other processes to hide execution.'), use('Kimsuky', 'Injected malicious code into legitimate processes such as explorer.exe.')],
    howToHunt: 'Hunt for remote-thread creation and memory writes into common host processes from unusual sources.',
    lookFor: 'Unsigned binary in %Temp% creating a remote thread in explorer.exe (Sysmon 8).',
  },
  T1003: {
    actors: [use('VoltTyphoon', 'Used ntdsutil to create copies of the Active Directory database (NTDS.dit).'), use('WizardSpider', 'Dumped LSASS memory to harvest credentials before moving laterally.')],
    howToHunt: 'Hunt for LSASS access by non-security tools, comsvcs.dll MiniDump, procdump against lsass, and ntdsutil IFM.',
    lookFor: 'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Temp\\l.dmp full.',
  },
  T1110: {
    actors: [use('APT28', 'Ran password-spraying campaigns against cloud and webmail accounts.'), use('APT33', 'Used password spraying to gain access to target accounts.')],
    howToHunt: 'Look for many accounts failing from few IPs (spraying) or many failures on one account (brute force), then a success.',
    lookFor: '1 IP, 300 different usernames, 1 failure each, then one successful sign-in.',
  },
  T1087: {
    actors: [use('VoltTyphoon', 'Enumerated local and domain accounts with net user and similar commands.'), use('ScatteredSpider', 'Enumerated Active Directory users and groups with tools such as ADRecon.')],
    howToHunt: 'Hunt for bursts of account-enumeration commands and LDAP queries from workstations that do not administer AD.',
    lookFor: 'net user /domain, net group "domain admins" /domain and AdFind.exe within minutes on one laptop.',
    query: { language: 'KQL', code: 'DeviceProcessEvents\n| where ProcessCommandLine has_any ("net user /domain", "net group", "AdFind", "Get-ADUser", "dsquery user")\n| summarize Cmds = make_set(ProcessCommandLine, 10), Count = count() by DeviceName, AccountName, bin(Timestamp, 15m)\n| where Count >= 3' },
  },
  T1018: {
    actors: [use('VoltTyphoon', 'Discovered remote systems on the network during hands-on-keyboard reconnaissance.'), use('WizardSpider', 'Used AdFind and similar tools to list computers in the domain.')],
    howToHunt: 'Hunt for ping sweeps, nltest, net view and AD computer queries from non-admin hosts.',
    lookFor: 'nltest /dclist: followed by a for-loop ping across a /24 from a finance workstation.',
    query: { language: 'KQL', code: 'DeviceProcessEvents\n| where ProcessCommandLine has_any ("nltest", "net view", "Get-ADComputer", "adfind", "arp -a")\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine' },
  },
  T1082: {
    actors: [use('VoltTyphoon', 'Ran systeminfo and similar commands to profile compromised hosts.'), use('Kimsuky', 'Collected OS and hardware details from victims with its malware.')],
    howToHunt: 'Individually benign — hunt for discovery commands clustered together, run by an unusual parent or account.',
    lookFor: 'systeminfo, whoami /all, ipconfig /all, tasklist run within 60 seconds by w3wp.exe.',
    query: { language: 'KQL', code: 'DeviceProcessEvents\n| where FileName in~ ("systeminfo.exe", "whoami.exe", "ipconfig.exe", "tasklist.exe", "hostname.exe")\n| summarize Tools = dcount(FileName), List = make_set(FileName) by DeviceName, InitiatingProcessFileName, bin(Timestamp, 5m)\n| where Tools >= 3' },
  },
  T1021: {
    actors: [use('WizardSpider', 'Used RDP to move laterally between hosts before ransomware deployment.'), use('VoltTyphoon', 'Used RDP with valid accounts to access other systems.')],
    howToHunt: 'Map RDP/SMB/WinRM logons between internal hosts and flag new source-destination pairs and admin-share access.',
    lookFor: 'Workstation-to-workstation RDP (LogonType 10) by a helpdesk account that has never done it before.',
  },
  T1570: {
    actors: [use('WizardSpider', 'Copied tools and ransomware binaries between hosts over SMB admin shares.')],
    howToHunt: 'Hunt for executables written to ADMIN$/C$ on remote hosts and then executed there.',
    lookFor: 'File write \\\\SRV02\\ADMIN$\\svc.exe followed by a service install on SRV02.',
    query: { language: 'KQL', code: 'DeviceFileEvents\n| where ActionType == "FileCreated" and FileName endswith ".exe"\n| where FolderPath has_any (@"\\ADMIN$\\", @"\\C$\\") or isnotempty(RequestSourceIP)\n| project Timestamp, DeviceName, FolderPath, FileName, RequestAccountName, RequestSourceIP' },
  },
  T1005: {
    actors: [use('APT28', 'Collected files and documents from local drives of compromised systems.'), use('Kimsuky', 'Gathered documents and data from infected hosts.')],
    howToHunt: 'Hunt for mass file reads/copies from document folders by processes that are not backup or sync tools.',
    lookFor: 'robocopy of C:\\Users\\*\\Documents\\*.docx to C:\\ProgramData\\x\\ at night.',
    query: { language: 'KQL', code: 'DeviceProcessEvents\n| where FileName in~ ("robocopy.exe", "xcopy.exe") or ProcessCommandLine has_any ("Copy-Item", "*.docx", "*.pdf")\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine' },
  },
  T1560: {
    actors: [use('APT28', 'Archived collected data with tools such as WinRAR before exfiltration.'), use('VoltTyphoon', 'Archived the NTDS.dit database into password-protected 7-Zip archives.')],
    howToHunt: 'Hunt for archivers run with passwords or splitting options, or writing to staging folders.',
    lookFor: '7z.exe a -p -v500m C:\\ProgramData\\bk.7z C:\\Windows\\Temp\\ntds\\*.',
  },
  T1071: {
    actors: [use('APT29', 'Used HTTPS for command and control to blend with normal web traffic.'), use('OilRig', 'Used DNS tunnelling for command and control.')],
    howToHunt: 'Hunt for beaconing: regular-interval connections from one process to one destination, and rare DNS patterns.',
    lookFor: 'rundll32.exe connecting to the same IP every 60 s ±5 % for 12 hours.',
  },
  T1573: {
    actors: [use('Turla', 'Encrypted its command-and-control traffic to avoid inspection.'), use('Lazarus', 'Used custom encryption on C2 channels in its malware.')],
    howToHunt: 'Hunt for TLS to IPs without SNI, self-signed or rare JA3/JA4 fingerprints, and non-browser processes on 443.',
    lookFor: 'A JA3 hash seen on one host only, to a certificate issued to "localhost".',
    query: { language: 'SPL', code: 'index=zeek sourcetype="zeek:ssl"\n| stats dc(id.orig_h) as hosts, values(server_name) as sni by ja3\n| where hosts < 3' },
  },
  T1567: {
    actors: [use('ScatteredSpider', 'Exfiltrated stolen data to cloud storage services before extortion.')],
    howToHunt: 'Hunt for large uploads to file-sharing and cloud storage services from servers, and for rclone/MEGA tooling.',
    lookFor: 'rclone.exe copy \\\\fs01\\finance mega:backup --transfers 16.',
  },
  T1048: {
    actors: [use('APT33', 'Used FTP to exfiltrate data from victim networks.')],
    howToHunt: 'Hunt for outbound FTP/SFTP/DNS volumes that do not match business use, especially from servers.',
    lookFor: 'A file server sending 4 GB over TCP/21 to a hosting-provider IP.',
    query: { language: 'KQL', code: 'DeviceNetworkEvents\n| where RemotePort in (21, 22, 69, 53) and RemoteIPType == "Public"\n| summarize Connections = count() by DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName\n| order by Connections desc' },
  },
  T1486: {
    actors: [use('WizardSpider', 'Deployed Ryuk and Conti ransomware to encrypt victim systems.'), use('Sandworm', 'Used NotPetya to encrypt systems in destructive attacks.')],
    howToHunt: 'Hunt for one process renaming or writing many files with a new extension, and ransom-note creation.',
    lookFor: '5,000 file renames to *.locked by one process in 2 minutes and README.txt dropped in each folder.',
  },
  T1490: {
    actors: [use('WizardSpider', 'Deleted volume shadow copies with vssadmin before encrypting systems.')],
    howToHunt: 'Hunt for shadow-copy deletion, backup-catalog deletion and boot-recovery changes.',
    lookFor: 'vssadmin delete shadows /all /quiet & bcdedit /set {default} recoveryenabled no.',
    query: { language: 'KQL', code: 'DeviceProcessEvents\n| where ProcessCommandLine has_any ("delete shadows", "shadowcopy delete", "delete catalog", "recoveryenabled no")\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine' },
  },
};

export const groupUrl = (groupId: string) => `https://attack.mitre.org/groups/${groupId}/`;
export const techniqueUrl = (id: string) => `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`;
