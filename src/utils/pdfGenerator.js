import jsPDF from 'jspdf';
import 'jspdf-autotable';

export const generateScanPDF = (reportData, targetData) => {
  const doc = new jsPDF();
  const dateStr = new Date(reportData.createdAt || Date.now()).toLocaleString();
  const targetHost = targetData?.host || reportData.target?.host || 'Unknown Target';
  const targetName = targetData?.name || reportData.target?.name || 'Asset';

  // Header
  doc.setFontSize(22);
  doc.setTextColor(40, 40, 40);
  doc.text('Security Audit Report', 14, 22);

  doc.setFontSize(11);
  doc.setTextColor(100, 100, 100);
  doc.text(`Generated on: ${dateStr}`, 14, 30);
  doc.text(`Target Asset: ${targetName} (${targetHost})`, 14, 36);
  doc.text(`Service: ${reportData.service || 'Security Scan'}`, 14, 42);
  doc.text(`Overall Status: ${reportData.status || 'Unknown'}`, 14, 48);

  const findings = reportData.findings || [];

  if (findings.length === 0) {
    doc.setFontSize(14);
    doc.setTextColor(34, 139, 34); // Green
    doc.text('No vulnerabilities found. The asset is secure.', 14, 65);
  } else {
    doc.setFontSize(14);
    doc.setTextColor(200, 50, 50); // Red
    doc.text(`Detected Findings: ${findings.length}`, 14, 65);

    const tableColumn = ["Severity", "Type", "Description", "Recommendation"];
    const tableRows = [];

    findings.forEach(finding => {
      let recommendation = "Review configuration and apply patches.";
      if (finding.type.toLowerCase().includes('port')) {
        recommendation = "Close port if not strictly necessary, or restrict via firewall/security groups.";
      } else if (finding.type.toLowerCase().includes('header')) {
        recommendation = "Update web server configuration to include this security header.";
      }

      const rowData = [
        finding.severity,
        finding.type,
        finding.description,
        recommendation
      ];
      tableRows.push(rowData);
    });

    doc.autoTable({
      head: [tableColumn],
      body: tableRows,
      startY: 75,
      theme: 'grid',
      styles: { fontSize: 10, cellPadding: 4 },
      headStyles: { fillColor: [41, 128, 185], textColor: 255 },
      columnStyles: {
        0: { cellWidth: 25, fontStyle: 'bold' },
        1: { cellWidth: 35 },
        2: { cellWidth: 70 },
        3: { cellWidth: 50 }
      },
      didParseCell: function(data) {
        if (data.section === 'body' && data.column.index === 0) {
          const severity = data.cell.raw;
          if (severity === 'CRITICAL' || severity === 'HIGH') {
            data.cell.styles.textColor = [220, 38, 38];
          } else if (severity === 'MEDIUM') {
            data.cell.styles.textColor = [217, 119, 6];
          } else {
            data.cell.styles.textColor = [37, 99, 235];
          }
        }
      }
    });
  }

  // Footer
  const pageCount = doc.internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(10);
    doc.setTextColor(150, 150, 150);
    doc.text(`Page ${i} of ${pageCount}`, doc.internal.pageSize.width / 2, doc.internal.pageSize.height - 10, { align: 'center' });
  }

  // Save the PDF
  const safeName = targetName.toLowerCase().replace(/[^a-z0-9]/g, '-');
  doc.save(`scan-report-${safeName}-${new Date().getTime()}.pdf`);
};
