import { ThreatHuntReportDocument, ThreatHuntQueryItem } from '../types';

export function formatQueriesForDisplay(queries: ThreatHuntQueryItem[]): string {
  if (!queries || queries.length === 0) return 'No queries documented.';
  return queries
    .map(
      (q, idx) =>
        `Query #${idx + 1} [${q.platform}${q.title ? ` - ${q.title}` : ''}]:\n${q.code}${
          q.explanation ? `\n\nExplanation: ${q.explanation}` : ''
        }`
    )
    .join('\n\n----------------------------------------\n\n');
}

/**
 * Generate Microsoft Word (.doc) compatible HTML document
 */
export function generateThreatHuntDocHtml(
  thr: ThreatHuntReportDocument,
  clientName: string,
  analystName: string,
  outcome: string = 'Investigation Completed'
): string {
  const queryBlocksHtml = (thr.huntQueries || [])
    .map(
      (q, idx) => `
      <div style="margin-bottom: 20px; border: 1px solid #cbd5e1; border-radius: 6px; overflow: hidden;">
        <div style="background-color: #f1f5f9; padding: 8px 12px; font-weight: bold; font-family: 'Segoe UI', Arial, sans-serif; font-size: 13px; color: #0f172a; border-bottom: 1px solid #cbd5e1;">
          Query #${idx + 1}: ${escapeHtml(q.title || 'Threat Hunt Query')} &nbsp;
          <span style="background-color: #0284c7; color: white; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-family: monospace;">${escapeHtml(q.platform)}</span>
        </div>
        <pre style="background-color: #0f172a; color: #38bdf8; font-family: 'Consolas', 'Courier New', monospace; font-size: 12px; padding: 12px; margin: 0; white-space: pre-wrap; word-break: break-word; line-height: 1.5;">${escapeHtml(q.code)}</pre>
        ${
          q.explanation
            ? `<div style="background-color: #ffffff; padding: 8px 12px; font-size: 12px; color: #475569; border-top: 1px solid #e2e8f0;">
                <strong>Query Intent & Target Indicators:</strong> ${escapeHtml(q.explanation)}
              </div>`
            : ''
        }
      </div>
    `
    )
    .join('');

  const referencesHtml = (thr.references || [])
    .map((ref) => `<li style="margin-bottom: 6px;">${escapeHtml(ref)}</li>`)
    .join('');

  return `<!DOCTYPE html>
<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:w="urn:schemas-microsoft-com:office:word" xmlns="http://www.w3.org/TR/REC-html40">
<head>
  <meta charset="utf-8">
  <title>${escapeHtml(thr.hypothesisName)} - Threat Hunt Report</title>
  <style>
    @page {
      margin: 1.0in;
      size: letter;
    }
    body {
      font-family: 'Calibri', 'Segoe UI', Arial, sans-serif;
      font-size: 11pt;
      line-height: 1.6;
      color: #1e293b;
      background-color: #ffffff;
      margin: 0;
      padding: 0;
    }
    .header-banner {
      border-bottom: 3px solid #0284c7;
      padding-bottom: 14px;
      margin-bottom: 24px;
    }
    .platform-title {
      font-size: 10pt;
      font-weight: bold;
      color: #0284c7;
      text-transform: uppercase;
      letter-spacing: 1.5px;
      margin-bottom: 4px;
    }
    h1 {
      font-size: 20pt;
      color: #0f172a;
      margin: 0 0 10px 0;
      line-height: 1.3;
    }
    .meta-table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 10px;
      background-color: #f8fafc;
      border: 1px solid #e2e8f0;
    }
    .meta-table td {
      padding: 8px 12px;
      font-size: 10pt;
      border-bottom: 1px solid #e2e8f0;
    }
    .meta-label {
      font-weight: bold;
      color: #475569;
      width: 25%;
    }
    .meta-val {
      color: #0f172a;
      font-weight: 500;
    }
    h2 {
      font-size: 13pt;
      color: #0369a1;
      border-bottom: 1.5px solid #e2e8f0;
      padding-bottom: 5px;
      margin-top: 24px;
      margin-bottom: 10px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    p, li {
      font-size: 11pt;
      color: #334155;
      text-align: justify;
    }
    .highlight-box {
      background-color: #f0f9ff;
      border-left: 4px solid #0284c7;
      padding: 12px 16px;
      margin: 14px 0;
      font-size: 11pt;
      color: #0369a1;
    }
    ul {
      margin-top: 6px;
      padding-left: 24px;
    }
    .footer {
      margin-top: 40px;
      border-top: 1px solid #e2e8f0;
      padding-top: 10px;
      font-size: 9pt;
      color: #94a3b8;
      text-align: center;
    }
  </style>
</head>
<body>
  <div class="header-banner">
    <div class="platform-title">BLINDSPOT · Proactive Threat Hunting & Detection Engineering</div>
    <h1>${escapeHtml(thr.hypothesisName)}</h1>
    <table class="meta-table">
      <tr>
        <td class="meta-label">Client Organization:</td>
        <td class="meta-val">${escapeHtml(clientName)}</td>
        <td class="meta-label">Report Date:</td>
        <td class="meta-val">${escapeHtml(thr.reportDate || new Date().toISOString().split('T')[0])}</td>
      </tr>
      <tr>
        <td class="meta-label">Threat Hunter / Analyst:</td>
        <td class="meta-val">${escapeHtml(analystName)}</td>
        <td class="meta-label">Investigation Outcome:</td>
        <td class="meta-val"><strong>${escapeHtml(outcome)}</strong></td>
      </tr>
    </table>
  </div>

  <h2>Executive Summary</h2>
  <p>${formatParagraphs(thr.executiveSummary)}</p>

  <h2>Purpose</h2>
  <p>${formatParagraphs(thr.purpose)}</p>

  <h2>MITRE Information</h2>
  <div class="highlight-box">
    ${formatParagraphs(thr.mitreInformation)}
  </div>

  <h2>High-Level Overview of Hunt Methodology</h2>
  <p>${formatParagraphs(thr.huntMethodology)}</p>

  <h2>Potential Detection Ideas & Hunting Thoughts</h2>
  <p>${formatParagraphs(thr.potentialDetectionIdeas)}</p>

  <h2>Hunt Query</h2>
  <p style="margin-bottom: 12px; font-size: 10pt; color: #64748b;">
    Production queries and platform-specific logic executed during this campaign:
  </p>
  ${queryBlocksHtml || '<p><em>No hunt queries recorded.</em></p>'}

  <h2>Hunt Results</h2>
  <p>${formatParagraphs(thr.huntResults)}</p>

  <h2>Analysis</h2>
  <p>${formatParagraphs(thr.analysis)}</p>

  <h2>Risk</h2>
  <p>${formatParagraphs(thr.risk)}</p>

  <h2>Impact</h2>
  <p>${formatParagraphs(thr.impact)}</p>

  <h2>Recommendation</h2>
  <p>${formatParagraphs(thr.recommendation)}</p>

  <h2>References</h2>
  ${referencesHtml ? `<ul>${referencesHtml}</ul>` : '<p>MITRE ATT&CK Enterprise Matrix, Internal SOC Telemetry Baseline.</p>'}

  <div class="footer">
    Confidential & Proprietary · Threat Hunt Report Generated by Blindspot Platform · ${escapeHtml(clientName)}
  </div>
</body>
</html>`;
}

/**
 * Downloads the THR document as a Microsoft Word compatible (.doc) file
 */
export function downloadThreatHuntDoc(
  thr: ThreatHuntReportDocument,
  clientName: string,
  analystName: string,
  outcome: string = 'Completed'
): void {
  const htmlContent = generateThreatHuntDocHtml(thr, clientName, analystName, outcome);
  const blob = new Blob(['\ufeff', htmlContent], {
    type: 'application/msword;charset=utf-8',
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  const sanitizedTitle = (thr.hypothesisName || 'Threat_Hunt_Report')
    .replace(/[^a-zA-Z0-9_-]/g, '_')
    .slice(0, 45);
  const dateStr = thr.reportDate || new Date().toISOString().split('T')[0];

  link.href = url;
  link.download = `${sanitizedTitle}_THR_${dateStr}.doc`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

/**
 * Opens a dedicated printable window formatted as an executive threat hunt report PDF
 */
export function printThreatHuntPdf(
  thr: ThreatHuntReportDocument,
  clientName: string,
  analystName: string,
  outcome: string = 'Completed'
): void {
  const htmlContent = generateThreatHuntDocHtml(thr, clientName, analystName, outcome);
  const printWindow = window.open('', '_blank', 'width=900,height=1000');
  if (printWindow) {
    printWindow.document.open();
    printWindow.document.write(htmlContent);
    printWindow.document.close();
    // Wait for document to load before printing
    setTimeout(() => {
      printWindow.focus();
      printWindow.print();
    }, 400);
  } else {
    // If popup blocked, fallback to downloading doc
    downloadThreatHuntDoc(thr, clientName, analystName, outcome);
  }
}

function escapeHtml(str: string = ''): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function formatParagraphs(text: string = ''): string {
  if (!text) return 'None documented.';
  return text
    .split(/\n\s*\n/)
    .map((p) => `<p style="margin-bottom: 10px;">${escapeHtml(p.trim())}</p>`)
    .join('');
}
