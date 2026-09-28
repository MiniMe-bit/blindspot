import type { IocHunt } from '../types';

/**
 * Demo rows for the Daily IOC Hunting tab, so the numbers have something to show before a hunter
 * uploads their own sheet. They are marked origin: 'demo' and can be removed from the page.
 */
const INTEL: Array<{ title: string; description: string; category: string; queries: string[] }> = [
  { title: 'Lumma Stealer IOC sweep (C2 domains + payload hashes)', description: 'Vendor advisory IOCs for LummaC2 infrastructure and loader hashes.', category: 'Stealer', queries: ['DeviceNetworkEvents | where RemoteUrl has_any (<Lumma C2 domains>)', 'DeviceFileEvents | where SHA256 in (<Lumma hashes>)', 'DeviceProcessEvents | where ProcessCommandLine has ".a3x"'] },
  { title: 'StealC infostealer hashes and panel IPs', description: 'Hash and IP sweep from community threat feed.', category: 'Stealer', queries: ['DeviceFileEvents | where SHA256 in (<StealC hashes>)', 'DeviceNetworkEvents | where RemoteIP in (<StealC panel IPs>)'] },
  { title: 'ClickFix fake CAPTCHA lure domains', description: 'Domains serving "verify you are human" Run-dialog lures.', category: 'ClickFix', queries: ['DeviceNetworkEvents | where RemoteUrl has_any (<lure domains>)', 'DeviceRegistryEvents | where RegistryKey has "RunMRU"', 'DeviceProcessEvents | where InitiatingProcessFileName =~ "explorer.exe" and FileName in~ ("powershell.exe","mshta.exe")'] },
  { title: 'ClickFix variant using fake Teams error page', description: 'New lure pages imitating a Teams connection error; mshta payload URLs.', category: 'ClickFix', queries: ['DeviceProcessEvents | where FileName =~ "mshta.exe" and ProcessCommandLine has "http"'] },
  { title: 'CVE-2024-3400 PAN-OS GlobalProtect exposure check', description: 'Identify firewalls on vulnerable PAN-OS versions and look for exploitation artefacts.', category: 'CVE', queries: ['Asset inventory: PAN-OS versions with GlobalProtect enabled', 'Firewall logs: requests to /ssl-vpn/hipreport.esp with suspicious SESSID'] },
  { title: 'CVE-2023-4966 Citrix Bleed vulnerable device check', description: 'NetScaler ADC / Gateway versions and session hijack indicators.', category: 'CVE', queries: ['Vulnerability scanner export: NetScaler builds below fixed versions', 'Gateway logs: session reuse from new IPs'] },
  { title: 'CVE-2024-21887 Ivanti Connect Secure check', description: 'Vulnerable appliance identification and web shell artefact search.', category: 'CVE', queries: ['Asset inventory: Ivanti ICS versions', 'Integrity checker tool output review', 'Proxy logs: requests to /api/v1/totp/user-backup-code'] },
  { title: 'CVE-2025-53770 SharePoint "ToolShell" exposure', description: 'On-prem SharePoint servers and spinstall0.aspx artefact search.', category: 'CVE', queries: ['DeviceFileEvents | where FileName =~ "spinstall0.aspx"', 'IIS logs: POST /_layouts/15/ToolPane.aspx'] },
  { title: 'CVE-2024-1709 ScreenConnect auth bypass check', description: 'ConnectWise ScreenConnect versions and setup wizard abuse.', category: 'CVE', queries: ['Asset inventory: ScreenConnect < 23.9.8', 'Web logs: requests to /SetupWizard.aspx/'] },
  { title: 'Akira ransomware IOC sweep', description: 'Hashes, file extensions and tooling from #StopRansomware advisory.', category: 'Ransomware', queries: ['DeviceFileEvents | where FileName endswith ".akira"', 'DeviceFileEvents | where SHA256 in (<Akira hashes>)', 'DeviceProcessEvents | where FileName in~ ("AnyDesk.exe","rclone.exe")'] },
  { title: 'Qilin ransomware affiliate tooling', description: 'Known affiliate tools and staging paths.', category: 'Ransomware', queries: ['DeviceProcessEvents | where ProcessCommandLine has_any (<Qilin tooling>)', 'DeviceFileEvents | where FolderPath has "\\PerfLogs\\"'] },
  { title: 'Play ransomware network IOCs', description: 'C2 and exfil IPs from partner threat report.', category: 'Ransomware', queries: ['DeviceNetworkEvents | where RemoteIP in (<Play IPs>)'] },
  { title: 'Volt Typhoon LOTL command patterns', description: 'ntdsutil, netsh portproxy and wmic patterns from joint advisory.', category: 'APT', queries: ['DeviceProcessEvents | where ProcessCommandLine has_all ("ntdsutil","ifm")', 'DeviceProcessEvents | where ProcessCommandLine has_all ("portproxy","add")'] },
  { title: 'Midnight Blizzard (APT29) OAuth app abuse', description: 'Suspicious OAuth consent and app role assignments.', category: 'APT', queries: ['AuditLogs | where OperationName has "Consent to application"', 'AuditLogs | where OperationName == "Add app role assignment to service principal"'] },
  { title: 'Kimsuky spear-phishing infrastructure', description: 'Sender domains and payload hashes from vendor blog.', category: 'APT', queries: ['EmailEvents | where SenderFromDomain in (<Kimsuky domains>)', 'DeviceFileEvents | where SHA256 in (<hashes>)'] },
  { title: 'AsyncRAT campaign via TryCloudflare tunnels', description: 'trycloudflare.com payload URLs and AsyncRAT hashes.', category: 'Malware', queries: ['DeviceNetworkEvents | where RemoteUrl endswith "trycloudflare.com"', 'DeviceFileEvents | where SHA256 in (<AsyncRAT hashes>)'] },
  { title: 'DarkGate loader delivered via Teams messages', description: 'External Teams chat lures and AutoIt payloads.', category: 'Malware', queries: ['DeviceProcessEvents | where FileName =~ "AutoIt3.exe"', 'CloudAppEvents | where ActionType == "ChatCreated" and IsExternalUser == true'] },
  { title: 'SocGholish fake browser update domains', description: 'Compromised-site injects serving fake update JS.', category: 'Malware', queries: ['DeviceNetworkEvents | where RemoteUrl has_any (<SocGholish domains>)', 'DeviceProcessEvents | where FileName =~ "wscript.exe" and ProcessCommandLine has ".js"'] },
  { title: 'Latrodectus loader hashes', description: 'Loader hashes and rundll32 export names.', category: 'Malware', queries: ['DeviceProcessEvents | where FileName =~ "rundll32.exe" and ProcessCommandLine has_any (<exports>)'] },
  { title: 'QR-code phishing (quishing) sender domains', description: 'Sender domains and credential-harvest URLs.', category: 'Phishing', queries: ['EmailEvents | where SenderFromDomain in (<domains>)', 'UrlClickEvents | where Url has_any (<harvest URLs>)'] },
  { title: 'Adversary-in-the-middle (Tycoon 2FA) phishing kit', description: 'AiTM kit domains and sign-in anomalies.', category: 'Phishing', queries: ['UrlClickEvents | where Url has_any (<Tycoon domains>)', 'AADSignInEventsBeta | where ErrorCode == 0 and RiskLevelDuringSignIn >= 50'] },
  { title: 'Mirai-variant botnet C2 IPs on edge devices', description: 'Outbound connections from IoT / edge segments to botnet C2.', category: 'Botnet', queries: ['Firewall logs: dst_ip in (<C2 IPs>) from IoT VLANs'] },
];

const RESULT_HITS = ['1 host matched — isolated', '2 hosts matched — under review', '1 user clicked lure URL', 'Vulnerable device found (1)', '3 devices on vulnerable version'];

const hash = (s: string) => [...s].reduce((a, c) => (a * 31 + c.charCodeAt(0)) >>> 0, 7);

/** 16–20 deterministic demo rows per client, spread over the last month. */
export function demoIocHunts(clientId: string): IocHunt[] {
  const seed = hash(clientId);
  const count = 16 + (seed % 5);
  const rows: IocHunt[] = [];
  for (let i = 0; i < count; i++) {
    const intel = INTEL[(seed + i * 7) % INTEL.length];
    const h = hash(`${clientId}-${i}`);
    const hit = h % 5 === 0;
    const escalated = hit && h % 2 === 0;
    const day = new Date(Date.UTC(2026, 8, 28 - Math.floor((i * 29) / count)));
    rows.push({
      id: `ioc-demo-${clientId}-${i}`,
      clientId,
      number: String(i + 1),
      title: intel.title,
      description: intel.description,
      category: intel.category,
      queryCount: intel.queries.length + (h % 3),
      results: hit ? RESULT_HITS[h % RESULT_HITS.length] : 'No hits',
      escalation: escalated ? (h % 3 === 0 ? `SCTASK00${(h % 90000) + 10000}` : `INC00${(h % 90000) + 10000}`) : '',
      queries: intel.queries.join('\n'),
      date: day.toISOString().slice(0, 10),
      origin: 'demo',
      importedAt: '2026-09-28T07:00:00Z',
    });
  }
  return rows;
}
