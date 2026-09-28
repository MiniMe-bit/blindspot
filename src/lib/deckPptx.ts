import type { ClientOrg, GeneratedDeck } from '../types';
import { CLIENT_LOGOS } from '../data/clientLogos';

/**
 * Export an executive deck as a native, editable PowerPoint file (16:9).
 * pptxgenjs is loaded on demand so it is not part of the main bundle.
 */

const C = {
  navy: '0F1B33',
  ink: '1F2937',
  muted: '6B7280',
  line: 'E5E7EB',
  soft: 'F5F7FB',
  accent: '3B6FD8',
  teal: '0E9488',
  violet: '6D4FD8',
  amber: 'B7791F',
  red: 'C2413A',
  green: '2F855A',
};
const FONT = 'Calibri';
const cells = (values: string[]) => values.map((text) => ({ text }));

/**
 * Client logo as a PNG data URI. Rasterised in the browser because PowerPoint's SVG support is
 * partial (older Office, Google Slides and Keynote show a broken image); falls back to SVG outside a browser.
 */
async function logoDataUri(client: ClientOrg): Promise<string | undefined> {
  const brand = client.logoSlug ? CLIENT_LOGOS[client.logoSlug] : undefined;
  if (!brand) return undefined;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="512" height="512"><path fill="${brand.hex}" d="${brand.path}"/></svg>`;
  const svgUri = `data:image/svg+xml;base64,${btoa(svg)}`;
  if (typeof document === 'undefined') return svgUri;
  try {
    const img = new Image();
    img.src = svgUri;
    await img.decode();
    const canvas = document.createElement('canvas');
    canvas.width = canvas.height = 512;
    canvas.getContext('2d')!.drawImage(img, 0, 0, 512, 512);
    return canvas.toDataURL('image/png');
  } catch {
    return svgUri;
  }
}

export async function exportDeckPptx(deck: GeneratedDeck, client: ClientOrg) {
  const { default: PptxGenJS } = await import('pptxgenjs');
  const pptx = new PptxGenJS();
  pptx.layout = 'LAYOUT_WIDE'; // 13.33 x 7.5 in
  pptx.title = `${deck.clientName} — ${deck.periodLabel}`;
  pptx.company = 'Blindspot';

  const logo = await logoDataUri(client);
  const total = deck.slides.length;

  type Slide = ReturnType<typeof pptx.addSlide>;

  const frame = (title: string, subtitle: string, index: number): Slide => {
    const s = pptx.addSlide();
    s.background = { color: 'FFFFFF' };
    s.addShape(pptx.ShapeType.rect, { x: 0, y: 0, w: 13.33, h: 0.12, fill: { color: C.accent }, line: { color: C.accent } });
    s.addText(`${deck.clientName.toUpperCase()} · ${deck.periodLabel}`, { x: 0.6, y: 0.3, w: 9, h: 0.3, fontFace: FONT, fontSize: 10, color: C.accent, bold: true, charSpacing: 1 });
    s.addText(title, { x: 0.6, y: 0.6, w: 11, h: 0.6, fontFace: FONT, fontSize: 26, color: C.navy, bold: true });
    s.addText(subtitle, { x: 0.6, y: 1.2, w: 11, h: 0.35, fontFace: FONT, fontSize: 13, color: C.muted });
    if (logo) s.addImage({ data: logo, x: 12.1, y: 0.35, w: 0.7, h: 0.7 });
    s.addShape(pptx.ShapeType.line, { x: 0.6, y: 6.95, w: 12.13, h: 0, line: { color: C.line, width: 1 } });
    s.addText('Confidential', { x: 0.6, y: 7.0, w: 4, h: 0.3, fontFace: FONT, fontSize: 9, color: C.muted });
    s.addText(`${index + 1} / ${total}`, { x: 9.73, y: 7.0, w: 3, h: 0.3, fontFace: FONT, fontSize: 9, color: C.muted, align: 'right' });
    return s;
  };

  const kpi = (s: Slide, x: number, y: number, w: number, label: string, value: string | number, color: string, note?: string) => {
    s.addShape(pptx.ShapeType.roundRect, { x, y, w, h: 1.55, fill: { color: C.soft }, line: { color: C.line }, rectRadius: 0.08 });
    s.addText(label.toUpperCase(), { x: x + 0.2, y: y + 0.12, w: w - 0.4, h: 0.3, fontFace: FONT, fontSize: 10, color: C.muted, bold: true });
    s.addText(String(value), { x: x + 0.2, y: y + 0.42, w: w - 0.4, h: 0.7, fontFace: FONT, fontSize: 36, color, bold: true });
    if (note) s.addText(note, { x: x + 0.2, y: y + 1.12, w: w - 0.4, h: 0.3, fontFace: FONT, fontSize: 10, color: C.muted });
  };

  const bullets = (s: Slide, items: string[], x: number, y: number, w: number, h: number, size = 15) =>
    s.addText(
      items.map((t) => ({ text: t, options: { bullet: { code: '25A0' }, paraSpaceAfter: 10 } })),
      { x, y, w, h, fontFace: FONT, fontSize: size, color: C.ink, valign: 'top' },
    );

  deck.slides.forEach((slide, i) => {
    const c = slide.content;
    switch (slide.type) {
      case 'title': {
        const s = pptx.addSlide();
        s.background = { color: C.navy };
        s.addShape(pptx.ShapeType.rect, { x: 0, y: 0, w: 0.25, h: 7.5, fill: { color: C.teal }, line: { color: C.teal } });
        if (logo) {
          s.addShape(pptx.ShapeType.roundRect, { x: 0.9, y: 1.3, w: 1.6, h: 1.6, fill: { color: 'FFFFFF' }, line: { color: 'FFFFFF' }, rectRadius: 0.15 });
          s.addImage({ data: logo, x: 1.1, y: 1.5, w: 1.2, h: 1.2 });
        }
        s.addText(slide.title, { x: 0.9, y: 3.2, w: 11.5, h: 0.5, fontFace: FONT, fontSize: 16, color: '9FB4DA', bold: true, charSpacing: 2 });
        s.addText(deck.clientName, { x: 0.9, y: 3.7, w: 11.5, h: 1.0, fontFace: FONT, fontSize: 48, color: 'FFFFFF', bold: true });
        s.addText(deck.periodLabel, { x: 0.9, y: 4.7, w: 11.5, h: 0.5, fontFace: FONT, fontSize: 20, color: '7DD6CF' });
        s.addText(`${String(c.industry).toLowerCase()} · ${c.date} · Prepared by ${c.preparedBy}`, { x: 0.9, y: 6.4, w: 11.5, h: 0.4, fontFace: FONT, fontSize: 12, color: '9FB4DA' });
        break;
      }
      case 'executive_summary': {
        const s = frame(slide.title, slide.subtitle, i);
        s.addText(c.summary, { x: 0.6, y: 1.8, w: 12.1, h: 1.6, fontFace: FONT, fontSize: 16, color: C.ink, valign: 'top', fill: { color: C.soft } });
        s.addText('Key takeaways', { x: 0.6, y: 3.65, w: 6, h: 0.4, fontFace: FONT, fontSize: 14, color: C.accent, bold: true });
        bullets(s, c.takeaways, 0.6, 4.1, 12.1, 2.6);
        break;
      }
      case 'kpi_performance': {
        const s = frame(slide.title, slide.subtitle, i);
        const w = 2.85;
        kpi(s, 0.6, 1.9, w, 'Hypotheses tested', c.totalHunts, C.navy, 'Structured investigations');
        kpi(s, 0.6 + (w + 0.25), 1.9, w, 'Open follow-ups', c.followUps, C.accent, 'Findings still being worked');
        kpi(s, 0.6 + 2 * (w + 0.25), 1.9, w, 'True positives', c.tpCount, C.red, 'Confirmed malicious activity');
        kpi(s, 0.6 + 3 * (w + 0.25), 1.9, w, 'Hit rate', c.tpRate, C.teal, 'True positives / hunts');
        const b = c.breakdown;
        s.addChart(
          pptx.ChartType.bar,
          [{ name: 'Hunts', labels: ['True positive', 'False positive', 'No result', 'Follow-up'], values: [b.truePositives, b.falsePositives, b.noResults, b.needsFollowUp] }],
          { x: 0.6, y: 3.8, w: 12.1, h: 3.0, barDir: 'bar', chartColors: [C.accent], showValue: true, dataLabelColor: C.ink, catAxisLabelColor: C.ink, valAxisHidden: true, valGridLine: { style: 'none' }, showTitle: true, title: 'Hunt outcomes', titleFontSize: 12, titleColor: C.muted },
        );
        break;
      }
      case 'ioc_hunting': {
        const s = frame(slide.title, slide.subtitle, i);
        const w = 2.85;
        kpi(s, 0.6, 1.8, w, 'IOC hunts performed', c.total, C.navy, c.periodNote);
        kpi(s, 0.6 + (w + 0.25), 1.8, w, 'Hunts with results', c.withResults, C.amber, c.total ? `${Math.round((c.withResults / c.total) * 100)}% of hunts` : '');
        kpi(s, 0.6 + 2 * (w + 0.25), 1.8, w, 'Escalated', c.escalated, C.red, 'Task / ServiceNow tickets');
        kpi(s, 0.6 + 3 * (w + 0.25), 1.8, w, 'Queries run', c.totalQueries, C.teal, 'Across all IOC sweeps');
        const cats = (c.categories as Array<{ name: string; percent: number; count: number }>).slice(0, 8);
        if (cats.length) {
          s.addChart(
            pptx.ChartType.bar,
            [{ name: 'Share of IOC hunts (%)', labels: cats.map((x) => `${x.name} (${x.count})`).reverse(), values: cats.map((x) => x.percent).reverse() }],
            { x: 0.6, y: 3.6, w: 6.2, h: 3.2, barDir: 'bar', chartColors: [C.accent], showValue: true, dataLabelFormatCode: '0"%"', dataLabelColor: C.ink, catAxisLabelColor: C.ink, valAxisHidden: true, valGridLine: { style: 'none' }, showTitle: true, title: 'Threat category weightage', titleFontSize: 12, titleColor: C.muted },
          );
        }
        const esc = c.escalations as Array<{ date?: string; title: string; escalation: string; results: string }>;
        s.addText('Escalations', { x: 7.1, y: 3.6, w: 5.6, h: 0.35, fontFace: FONT, fontSize: 12, color: C.muted, bold: true });
        if (esc.length) {
          s.addTable(
            [
              ['Date', 'Hunt', 'Ticket'].map((h) => ({ text: h, options: { bold: true, color: C.muted, fill: { color: C.soft } } })),
              ...esc.slice(0, 6).map((e) => cells([e.date ?? '—', e.title, e.escalation])),
            ],
            { x: 7.1, y: 3.95, w: 5.6, colW: [1.05, 3.35, 1.2], fontFace: FONT, fontSize: 10, color: C.ink, border: { type: 'solid', color: C.line, pt: 0.75 }, valign: 'middle' },
          );
        } else {
          s.addText('No IOC hunts were escalated this period.', { x: 7.1, y: 4.0, w: 5.6, h: 0.4, fontFace: FONT, fontSize: 12, color: C.ink });
        }
        break;
      }
      case 'mitre_coverage_heatmap': {
        const s = frame(slide.title, slide.subtitle, i);
        kpi(s, 0.6, 1.8, 3.2, 'ATT&CK coverage', `${c.percent}%`, C.violet, `${c.coveredCount} of ${c.totalTechniques} techniques`);
        const tacs = c.tacticsSummary as Array<{ name: string; covered: number; total: number }>;
        s.addChart(
          pptx.ChartType.bar,
          [{ name: 'Techniques hunted (%)', labels: tacs.map((t) => t.name).reverse(), values: tacs.map((t) => (t.total ? Math.round((t.covered / t.total) * 100) : 0)).reverse() }],
          { x: 4.1, y: 1.7, w: 8.6, h: 5.1, barDir: 'bar', chartColors: [C.teal], showValue: true, dataLabelFormatCode: '0"%"', dataLabelColor: C.ink, catAxisLabelColor: C.ink, valAxisHidden: true, valAxisMaxVal: 100, valGridLine: { style: 'none' } },
        );
        break;
      }
      case 'severity_distribution': {
        const s = frame(slide.title, slide.subtitle, i);
        kpi(s, 0.6, 1.8, 3.9, 'Critical severity', c.criticalCount, C.red);
        kpi(s, 4.72, 1.8, 3.9, 'High severity', c.highCount, C.amber);
        kpi(s, 8.84, 1.8, 3.9, 'Medium severity', c.mediumCount, C.accent);
        const findings = c.findings as Array<{ hypothesisTitle: string; techniqueIds: string[]; severityScore?: { compositeScore: number; severityLevel: string } }>;
        s.addText('Featured findings', { x: 0.6, y: 3.6, w: 6, h: 0.35, fontFace: FONT, fontSize: 12, color: C.muted, bold: true });
        if (findings.length) {
          s.addTable(
            [
              ['Finding', 'Techniques', 'Severity'].map((h) => ({ text: h, options: { bold: true, color: C.muted, fill: { color: C.soft } } })),
              ...findings.map((f) => cells([f.hypothesisTitle, f.techniqueIds.join(', '), f.severityScore ? `${f.severityScore.severityLevel} · ${f.severityScore.compositeScore}` : 'Not scored'])),
            ],
            { x: 0.6, y: 3.95, w: 12.1, colW: [7.3, 2.8, 2.0], fontFace: FONT, fontSize: 11, color: C.ink, border: { type: 'solid', color: C.line, pt: 0.75 } },
          );
        }
        break;
      }
      case 'blind_spots': {
        const s = frame(slide.title, slide.subtitle, i);
        bullets(s, c.gaps, 0.6, 1.8, 12.1, 1.6);
        const techs = c.uncoveredTechniqueSamples as Array<{ id: string; name: string; tactic: string }>;
        s.addText('Priority techniques to hunt next', { x: 0.6, y: 3.6, w: 8, h: 0.35, fontFace: FONT, fontSize: 12, color: C.muted, bold: true });
        s.addTable(
          [
            ['Technique', 'Name', 'Tactic'].map((h) => ({ text: h, options: { bold: true, color: C.muted, fill: { color: C.soft } } })),
            ...techs.map((t) => cells([t.id, t.name, t.tactic])),
          ],
          { x: 0.6, y: 3.95, w: 12.1, colW: [1.6, 6.5, 4.0], fontFace: FONT, fontSize: 12, color: C.ink, border: { type: 'solid', color: C.line, pt: 0.75 } },
        );
        break;
      }
      case 'strategic_roadmap': {
        const s = frame(slide.title, slide.subtitle, i);
        (c.roadmap as string[]).forEach((item, idx) => {
          const x = 0.6 + idx * 4.1;
          s.addShape(pptx.ShapeType.roundRect, { x, y: 1.9, w: 3.9, h: 3.6, fill: { color: C.soft }, line: { color: C.line }, rectRadius: 0.08 });
          s.addText(`PHASE ${idx + 1}`, { x: x + 0.25, y: 2.1, w: 3.4, h: 0.4, fontFace: FONT, fontSize: 12, color: C.teal, bold: true });
          s.addText(item, { x: x + 0.25, y: 2.6, w: 3.4, h: 2.7, fontFace: FONT, fontSize: 15, color: C.ink, valign: 'top' });
        });
        break;
      }
      default: {
        frame(slide.title, slide.subtitle, i);
      }
    }
  });

  const safe = (s: string) => s.replace(/[^\w\- ]+/g, '').trim().replace(/\s+/g, '-');
  await pptx.writeFile({ fileName: `${safe(deck.clientName)}-${safe(deck.periodLabel)}.pptx` });
}
