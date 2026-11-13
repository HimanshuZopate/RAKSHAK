import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { SEVERITY, SEVERITY_ORDER, VERIFICATION, RISK_LEVEL, SCAN_STATUS_LABEL, formatDuration } from './constants';

/**
 * Builds a PDF report from a stored scan (as returned by GET /scanners/web-scans/:id).
 * Evidence is already redacted server-side; no cookies, tokens or bodies are included.
 */

const hexToRgb = (hex) => [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16));
const MARGIN = 14;

export const exportScanPdf = (scan) => {
  const doc = new jsPDF({ unit: 'mm', format: 'a4' });
  const width = doc.internal.pageSize.getWidth();
  const summary = scan.summary || {};
  const risk = RISK_LEVEL[summary.riskLevel] || RISK_LEVEL.minimal;
  let y = 0;

  const ensureSpace = (needed) => {
    if (y + needed > doc.internal.pageSize.getHeight() - 16) {
      doc.addPage();
      y = 18;
    }
  };
  const heading = (text) => {
    ensureSpace(14);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(13);
    doc.setTextColor(15, 23, 42);
    doc.text(text, MARGIN, y);
    y += 7;
  };
  const paragraph = (text, size = 9.5, color = [51, 65, 85]) => {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(size);
    doc.setTextColor(...color);
    const lines = doc.splitTextToSize(String(text || ''), width - MARGIN * 2);
    for (const line of lines) {
      ensureSpace(5);
      doc.text(line, MARGIN, y);
      y += size * 0.45;
    }
    y += 1.5;
  };
  const table = (options) => {
    autoTable(doc, {
      startY: y,
      margin: { left: MARGIN, right: MARGIN },
      styles: { fontSize: 8.5, cellPadding: 2, overflow: 'linebreak' },
      headStyles: { fillColor: [15, 23, 42], textColor: 255 },
      ...options,
    });
    y = doc.lastAutoTable.finalY + 6;
  };

  // ── Cover header ───────────────────────────────────────────────────────
  doc.setFillColor(15, 23, 42);
  doc.rect(0, 0, width, 38, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(20);
  doc.setTextColor(255, 255, 255);
  doc.text('RAKSHAK', MARGIN, 16);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(103, 232, 249);
  doc.text('Web Vulnerability Assessment Report', MARGIN, 24);
  doc.setTextColor(148, 163, 184);
  doc.setFontSize(8.5);
  doc.text(`Generated ${new Date().toLocaleString()}`, MARGIN, 31);
  y = 48;

  table({
    body: [
      ['Target', scan.targetUrl],
      ['Assessment profile', scan.profile],
      ['Scan status', SCAN_STATUS_LABEL[scan.scanStatus] || scan.scanStatus],
      ['Started', new Date(scan.startedAt).toLocaleString()],
      ['Completed', scan.completedAt ? new Date(scan.completedAt).toLocaleString() : '—'],
      ['Duration / requests', `${formatDuration(scan.durationMs)} · ${scan.requestCount ?? '—'} requests`],
      ['Scanner version', `RAKSHAK VulnScanner ${scan.scannerVersion || ''}`],
    ],
    theme: 'plain',
    columnStyles: { 0: { fontStyle: 'bold', cellWidth: 45 } },
  });

  // ── Risk summary ───────────────────────────────────────────────────────
  heading('Risk summary');
  ensureSpace(24);
  doc.setFillColor(...hexToRgb(risk.color));
  doc.roundedRect(MARGIN, y, 52, 20, 2, 2, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(18);
  doc.text(`${summary.securityScore ?? '—'}/100`, MARGIN + 4, y + 9);
  doc.setFontSize(8.5);
  doc.text(`${risk.label} (risk ${summary.riskScore ?? '—'})`, MARGIN + 4, y + 16);
  doc.setTextColor(51, 65, 85);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.text([
    `Findings: ${summary.totalFindings ?? 0}  (confirmed/misconfiguration ${summary.confirmed ?? 0}, potential ${summary.potential ?? 0})`,
    `Checks: ${summary.checksCompleted ?? 0} completed, ${summary.checksInconclusive ?? 0} inconclusive, ${summary.checksSkipped ?? 0} skipped, ${summary.checksFailed ?? 0} failed`,
    'Security score = 100 − risk. Risk combines findings by severity and evidence strength.',
  ], MARGIN + 58, y + 6);
  y += 26;
  paragraph(`Scoring method: ${summary.methodology || ''}`, 8, [100, 116, 139]);

  table({
    head: [['Severity', 'Count']],
    body: SEVERITY_ORDER.map((s) => [SEVERITY[s].label, String(summary.bySeverity?.[s] ?? 0)]),
    columnStyles: { 0: { cellWidth: 40 } },
    tableWidth: 80,
    didParseCell: (data) => {
      if (data.section === 'body' && data.column.index === 0) data.cell.styles.textColor = hexToRgb(SEVERITY[SEVERITY_ORDER[data.row.index]].color);
    },
  });

  // ── Findings overview ──────────────────────────────────────────────────
  const findings = scan.findings || [];
  heading('Findings overview');
  if (!findings.length) paragraph('No findings were reported by the executed checks.');
  else {
    table({
      head: [['#', 'Severity', 'Status', 'Finding', 'Category']],
      body: findings.map((f, i) => [String(i + 1), SEVERITY[f.severity]?.label, VERIFICATION[f.verification]?.label, f.title, f.category]),
      columnStyles: { 0: { cellWidth: 8 }, 1: { cellWidth: 20 }, 2: { cellWidth: 28 } },
      didParseCell: (data) => {
        if (data.section === 'body' && data.column.index === 1) data.cell.styles.textColor = hexToRgb(SEVERITY[findings[data.row.index].severity].color);
      },
    });
  }

  // ── Detailed findings ──────────────────────────────────────────────────
  if (findings.length) {
    doc.addPage();
    y = 18;
    heading('Detailed findings');
    findings.forEach((f, i) => {
      ensureSpace(30);
      doc.setFillColor(...hexToRgb(SEVERITY[f.severity].color));
      doc.rect(MARGIN, y - 4, 2, 6, 'F');
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(10.5);
      doc.setTextColor(15, 23, 42);
      const title = doc.splitTextToSize(`${i + 1}. ${f.title}`, width - MARGIN * 2 - 4);
      doc.text(title, MARGIN + 4, y);
      y += title.length * 5;
      paragraph(`${SEVERITY[f.severity].label} · ${VERIFICATION[f.verification]?.label} · ${f.confidence} confidence · ${f.category}${f.owasp ? ` · ${f.owasp}` : ''}`, 8, [100, 116, 139]);
      paragraph(f.description);
      paragraph(`Affected: ${f.affected}`, 8.5, [30, 64, 175]);
      if (f.evidence?.length) {
        table({ head: [['Evidence', 'Value']], body: f.evidence.map((e) => [e.label, e.value]), columnStyles: { 0: { cellWidth: 50 } }, headStyles: { fillColor: [51, 65, 85] } });
      }
      if (f.cves?.length) {
        table({ head: [['CVE', 'CVSS', 'Description']], body: f.cves.map((c) => [c.id, c.cvss ?? '—', c.description]), columnStyles: { 0: { cellWidth: 32 }, 1: { cellWidth: 14 } }, headStyles: { fillColor: [127, 29, 29] } });
      }
      paragraph(`Impact: ${f.impact}`);
      paragraph(`Remediation: ${f.remediation}`, 9.5, [6, 95, 70]);
      paragraph(`Detection: ${f.detection}`, 8, [100, 116, 139]);
      if (f.references?.length) paragraph(`References: ${f.references.map((r) => `${r.title} (${r.url})`).join('; ')}`, 7.5, [100, 116, 139]);
      y += 3;
    });
  }

  // ── Technology / TLS / checks / limitations ────────────────────────────
  if (scan.technologies?.length) {
    heading('Detected technologies');
    table({ head: [['Technology', 'Version', 'Confidence', 'Evidence']], body: scan.technologies.map((t) => [t.name, t.version || '—', t.confidence, t.evidence]) });
  }
  if (scan.tls?.certificate) {
    const c = scan.tls.certificate;
    heading('TLS configuration');
    table({
      body: [
        ['Negotiated', `${scan.tls.negotiatedProtocol} · ${scan.tls.cipher}`],
        ['Protocol support', Object.entries(scan.tls.supportedProtocols || {}).map(([k, v]) => `${k}: ${v}`).join(', ')],
        ['Subject / issuer', `${c.subject} / ${c.issuer}`],
        ['Validity', `${c.validFrom?.slice(0, 10)} → ${c.validTo?.slice(0, 10)} (${c.daysRemaining} days left)`],
        ['Trust', c.trusted ? 'Trusted chain' : `Not trusted (${c.trustError})`],
        ['Hostname match', c.hostnameMatches ? 'Yes' : 'No'],
      ],
      theme: 'plain',
      columnStyles: { 0: { fontStyle: 'bold', cellWidth: 40 } },
    });
  }
  heading('Checks executed');
  table({ head: [['Check', 'Result', 'Notes']], body: (scan.checks || []).map((c) => [c.label, c.status, c.note || '']) });
  heading('Assessment limitations');
  (scan.limitations || []).forEach((l) => paragraph(`• ${l}`, 8.5));
  paragraph('This report summarises automated, non-destructive checks performed at the time shown. It is not a certification or a guarantee of security; potential findings require manual verification.', 8, [100, 116, 139]);

  // Footer with page numbers
  const pages = doc.getNumberOfPages();
  for (let p = 1; p <= pages; p += 1) {
    doc.setPage(p);
    doc.setFontSize(7.5);
    doc.setTextColor(148, 163, 184);
    doc.text(`RAKSHAK · ${scan.targetHost || ''} · page ${p}/${pages}`, MARGIN, doc.internal.pageSize.getHeight() - 8);
  }

  const date = new Date(scan.startedAt).toISOString().slice(0, 10);
  doc.save(`rakshak-vuln-report-${(scan.targetHost || 'target').replace(/[^a-z0-9.-]/gi, '_')}-${date}.pdf`);
};
