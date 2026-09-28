import type { IocHunt } from '../types';

// ---------------------------------------------------------------------------
// Row semantics
// ---------------------------------------------------------------------------

const EMPTY_MARKERS = /^(|-+|n\/?a|na|none|nil|null|no|0|not escalated|not applicable)$/i;
const NO_RESULT = /^(no\b|none|nil|n\/?a|0\b|clean|not found|nothing|negative|no hits?|no results?|no match(es)?|no findings?)/i;

/** True when the hunt's queries returned something (anything other than a "no hits" style answer). */
export const hasResults = (h: Pick<IocHunt, 'results'>) => {
  const r = h.results.trim();
  return r !== '' && !NO_RESULT.test(r);
};

/** True when the row carries an escalation reference (task / ServiceNow ID). */
export const isEscalated = (h: Pick<IocHunt, 'escalation'>) => !EMPTY_MARKERS.test(h.escalation.trim());

const norm = (v: unknown) => String(v ?? '').replace(/\s+/g, ' ').trim().toLowerCase();

/** Duplicate detection uses every field the hunter records, so a row is only dropped if it is identical. */
export const iocKey = (h: Pick<IocHunt, 'number' | 'title' | 'description' | 'category' | 'queryCount' | 'results' | 'escalation' | 'queries' | 'date'>) =>
  [h.number, h.title, h.description, h.category, h.queryCount, h.results, h.escalation, h.queries, h.date ?? ''].map(norm).join('␟');

// ---------------------------------------------------------------------------
// Categories
// ---------------------------------------------------------------------------

export const KNOWN_CATEGORIES = ['Malware', 'Stealer', 'Ransomware', 'CVE', 'ClickFix', 'APT', 'Phishing', 'Botnet', 'RAT', 'Loader', 'Other'];

const CATEGORY_ALIASES: Array<[RegExp, string]> = [
  [/^(cve|vuln|vulnerab|kev|patch)/i, 'CVE'],
  [/click\s*fix|fake\s*captcha/i, 'ClickFix'],
  [/ransom/i, 'Ransomware'],
  [/steal|infostealer/i, 'Stealer'],
  [/^apt|nation|state[- ]sponsored/i, 'APT'],
  [/phish/i, 'Phishing'],
  [/botnet/i, 'Botnet'],
  [/^rat$|remote access/i, 'RAT'],
  [/loader|dropper/i, 'Loader'],
  [/malware|trojan|worm|backdoor/i, 'Malware'],
];

export function normaliseCategory(raw: string): string {
  const v = raw.trim();
  if (!v) return 'Other';
  for (const [re, name] of CATEGORY_ALIASES) if (re.test(v)) return name;
  return v.charAt(0).toUpperCase() + v.slice(1);
}

// ---------------------------------------------------------------------------
// Sheet import
// ---------------------------------------------------------------------------

type Field = 'number' | 'title' | 'description' | 'category' | 'queryCount' | 'results' | 'escalation' | 'queries' | 'date';

/** Accepted header spellings per field (compared after lower-casing and stripping punctuation). */
const HEADER_ALIASES: Record<Field, string[]> = {
  number: ['number', 'no', 'sno', 'srno', 'slno', 'serialno', 'serial', 'num', 'id', 'ref', 'reference', 'huntid', 'huntno'],
  title: ['title', 'name', 'huntname', 'hunttitle', 'threatintel', 'threatintelname', 'intel', 'intelname', 'threat', 'threatname', 'subject'],
  description: ['description', 'desc', 'details', 'summary', 'intelsummary', 'notes'],
  category: ['threatcategory', 'category', 'type', 'threattype', 'intelcategory', 'categories'],
  queryCount: ['querycount', 'queriescount', 'noofqueries', 'numberofqueries', 'queriesrun', 'count', 'totalqueries'],
  results: ['results', 'result', 'findings', 'outcome', 'hits', 'huntresult', 'huntresults', 'status'],
  escalation: ['escalation', 'escalated', 'taskid', 'servicenowid', 'servicenow', 'snowid', 'ticket', 'ticketid', 'incident', 'incidentid', 'escalationid', 'escalationtaskidservicenowid'],
  queries: ['queries', 'query', 'huntqueries', 'huntquery', 'searchquery', 'kql', 'fql', 'spl'],
  date: ['date', 'huntdate', 'day', 'datehunted', 'performedon'],
};

const headerKey = (h: unknown) => String(h ?? '').toLowerCase().replace(/[^a-z0-9]/g, '');

function mapHeaders(row: unknown[]): Partial<Record<Field, number>> {
  const map: Partial<Record<Field, number>> = {};
  row.forEach((cell, idx) => {
    const k = headerKey(cell);
    if (!k) return;
    for (const field of Object.keys(HEADER_ALIASES) as Field[]) {
      if (map[field] === undefined && HEADER_ALIASES[field].includes(k)) {
        map[field] = idx;
        return;
      }
    }
    // Looser match for long headers like "Escalation (Task ID / ServiceNow ID)".
    for (const field of Object.keys(HEADER_ALIASES) as Field[]) {
      if (map[field] === undefined && HEADER_ALIASES[field].some((a) => a.length > 3 && k.startsWith(a))) {
        map[field] = idx;
        return;
      }
    }
  });
  return map;
}

export interface ParsedSheet {
  rows: Array<Omit<IocHunt, 'id' | 'clientId' | 'origin' | 'importedAt'>>;
  sheetName: string;
  /** Data rows ignored because they had no title. */
  skippedRows: number;
  /** Fields not found in the header row (the columns are optional except Title). */
  missingColumns: Field[];
}

export const FIELD_LABEL: Record<Field, string> = {
  number: 'Number',
  title: 'Title',
  description: 'Description',
  category: 'Threat Category',
  queryCount: 'Query Count',
  results: 'Results',
  escalation: 'Escalation (Task ID / ServiceNow ID)',
  queries: 'Queries',
  date: 'Date',
};

const toDateString = (v: unknown): string | undefined => {
  if (v instanceof Date && !isNaN(v.getTime())) return v.toISOString().slice(0, 10);
  const s = String(v ?? '').trim();
  return s || undefined;
};

/** Read an .xlsx / .xls / .csv file. Picks the first sheet whose header row has a Title column. */
export async function parseIocWorkbook(file: File): Promise<ParsedSheet> {
  const XLSX = await import('xlsx');
  const wb = XLSX.read(await file.arrayBuffer(), { type: 'array', cellDates: true });

  for (const sheetName of wb.SheetNames) {
    const grid = XLSX.utils.sheet_to_json<unknown[]>(wb.Sheets[sheetName], { header: 1, blankrows: false, defval: '' });
    // The header may sit below a banner/title row: look at the first 10 rows.
    const headerIdx = grid.slice(0, 10).findIndex((r) => {
      const m = mapHeaders(r);
      return m.title !== undefined && Object.keys(m).length >= 2;
    });
    if (headerIdx === -1) continue;

    const map = mapHeaders(grid[headerIdx]);
    const cell = (r: unknown[], f: Field) => (map[f] === undefined ? '' : r[map[f]!]);
    const text = (r: unknown[], f: Field) => String(cell(r, f) ?? '').trim();

    let skippedRows = 0;
    const rows: ParsedSheet['rows'] = [];
    for (const r of grid.slice(headerIdx + 1)) {
      const title = text(r, 'title');
      if (!title) {
        if (r.some((c) => String(c ?? '').trim())) skippedRows += 1;
        continue;
      }
      const queries = text(r, 'queries');
      const countRaw = Number(String(cell(r, 'queryCount')).replace(/[^\d.]/g, ''));
      rows.push({
        number: text(r, 'number'),
        title,
        description: text(r, 'description'),
        category: normaliseCategory(text(r, 'category')),
        // No count column: count non-empty query lines instead.
        queryCount: Number.isFinite(countRaw) && String(cell(r, 'queryCount')).trim() !== '' ? Math.round(countRaw) : queries ? queries.split(/\n+/).filter((l) => l.trim()).length : 0,
        results: text(r, 'results'),
        escalation: text(r, 'escalation'),
        queries,
        date: toDateString(cell(r, 'date')),
      });
    }

    const missingColumns = (Object.keys(HEADER_ALIASES) as Field[]).filter((f) => map[f] === undefined);
    return { rows, sheetName, skippedRows, missingColumns };
  }

  throw new Error('No sheet with a "Title" column was found. Check the header row names (see the template).');
}

/** Download an empty sheet with the expected columns. */
export async function downloadIocTemplate() {
  const XLSX = await import('xlsx');
  const headers = ['Number', 'Date', 'Title', 'Description', 'Threat Category', 'Query Count', 'Results', 'Escalation (Task ID / ServiceNow ID)', 'Queries'];
  const example = ['1', new Date().toISOString().slice(0, 10), 'Lumma Stealer C2 domains (vendor advisory)', 'IOC sweep for published C2 domains and hashes', 'Stealer', 3, 'No hits', '', 'DeviceNetworkEvents | where RemoteUrl has_any (...)'];
  const ws = XLSX.utils.aoa_to_sheet([headers, example]);
  ws['!cols'] = headers.map((h) => ({ wch: Math.max(12, h.length + 2) }));
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, ws, 'IOC Hunts');
  XLSX.writeFile(wb, 'blindspot-ioc-hunting-template.xlsx');
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

export interface IocSummary {
  total: number;
  withResults: number;
  escalated: number;
  totalQueries: number;
  categories: Array<{ name: string; count: number; percent: number }>;
}

export function summarise(hunts: IocHunt[]): IocSummary {
  const counts = new Map<string, number>();
  for (const h of hunts) counts.set(h.category, (counts.get(h.category) ?? 0) + 1);
  const total = hunts.length;
  return {
    total,
    withResults: hunts.filter(hasResults).length,
    escalated: hunts.filter(isEscalated).length,
    totalQueries: hunts.reduce((a, h) => a + (h.queryCount || 0), 0),
    categories: [...counts.entries()]
      .map(([name, count]) => ({ name, count, percent: total ? Math.round((count / total) * 1000) / 10 : 0 }))
      .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name)),
  };
}
