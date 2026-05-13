import type { ScanReport, AnalyzedEmail, EmailCategory } from "./types.js";

const CATEGORY_ICONS: Record<EmailCategory, string> = {
  personal: "👤",
  professional: "💼",
  financial: "💰",
  shopping: "🛒",
  social: "📱",
  newsletter: "📰",
  promotional: "🎯",
  travel: "✈️",
  health: "🏥",
  security_alert: "🔐",
  spam: "🚫",
  other: "📧",
};

const THREAT_COLORS: Record<string, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#d97706",
  low: "#65a30d",
  none: "#16a34a",
};

const THREAT_BADGES: Record<string, string> = {
  critical: "background:#dc2626;color:#fff",
  high: "background:#ea580c;color:#fff",
  medium: "background:#d97706;color:#fff",
  low: "background:#65a30d;color:#fff",
  none: "background:#16a34a;color:#fff",
};

function threatBadge(level: string): string {
  const style = THREAT_BADGES[level] ?? THREAT_BADGES.none;
  return `<span style="${style};padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600;text-transform:uppercase">${level}</span>`;
}

function categoryBadge(category: EmailCategory): string {
  const icon = CATEGORY_ICONS[category] ?? "📧";
  return `<span style="background:#f1f5f9;color:#475569;padding:2px 8px;border-radius:12px;font-size:11px">${icon} ${category}</span>`;
}

function emailRow(email: AnalyzedEmail, highlight = false): string {
  const bg = highlight ? "#fff7ed" : email.threatLevel === "none" ? "#ffffff" : "#fffbeb";
  const sender = email.raw.from.replace(/<[^>]+>/, "").trim() || email.raw.from;
  const flags = email.securityFlags.map((f) => `⚠️ ${f.description}`).join("<br>");

  return `
    <tr style="background:${bg};border-bottom:1px solid #e2e8f0">
      <td style="padding:10px 12px;font-size:13px;max-width:200px">
        <div style="font-weight:500;color:#1e293b;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(sender)}</div>
        <div style="color:#64748b;font-size:11px">${email.raw.date.split(" ").slice(0, 4).join(" ")}</div>
      </td>
      <td style="padding:10px 12px;font-size:13px;max-width:280px">
        <div style="color:#1e293b;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(email.raw.subject)}</div>
        <div style="color:#64748b;font-size:11px;margin-top:2px">${escapeHtml(email.summary)}</div>
        ${flags ? `<div style="color:#dc2626;font-size:11px;margin-top:4px">${flags}</div>` : ""}
      </td>
      <td style="padding:10px 12px;text-align:center">${categoryBadge(email.category)}</td>
      <td style="padding:10px 12px;text-align:center">${threatBadge(email.threatLevel)}</td>
      <td style="padding:10px 12px;font-size:12px;color:#475569;text-align:center">
        ${email.suggestDelete ? "&#x1F5D1;&#xFE0F; Delete" : ""}
        ${email.suggestUnsubscribe ? "&#x1F4ED; Unsub" : ""}
        ${email.actionRequired ? "&#x26A1; Action" : ""}
      </td>
    </tr>`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function pieChartSvg(report: ScanReport): string {
  const cats = Object.entries(report.categoryBreakdown).filter(([, count]) => count > 0);
  const total = cats.reduce((s, [, c]) => s + c, 0);
  const colors = [
    "#3b82f6","#10b981","#f59e0b","#ef4444","#8b5cf6",
    "#06b6d4","#84cc16","#f97316","#ec4899","#6366f1","#14b8a6","#a3e635",
  ];

  let svgPaths = "";
  let legend = "";
  let startAngle = -Math.PI / 2;

  cats.forEach(([cat, count], i) => {
    const slice = (count / total) * 2 * Math.PI;
    const endAngle = startAngle + slice;
    const x1 = 100 + 80 * Math.cos(startAngle);
    const y1 = 100 + 80 * Math.sin(startAngle);
    const x2 = 100 + 80 * Math.cos(endAngle);
    const y2 = 100 + 80 * Math.sin(endAngle);
    const largeArc = slice > Math.PI ? 1 : 0;
    const color = colors[i % colors.length];
    svgPaths += `<path d="M100,100 L${x1.toFixed(1)},${y1.toFixed(1)} A80,80 0 ${largeArc},1 ${x2.toFixed(1)},${y2.toFixed(1)} Z" fill="${color}" stroke="#fff" stroke-width="2"/>`;
    legend += `<div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">
      <div style="width:12px;height:12px;border-radius:3px;background:${color};flex-shrink:0"></div>
      <span style="font-size:12px;color:#475569">${CATEGORY_ICONS[cat as EmailCategory] ?? "📧"} ${cat} <strong>(${count})</strong></span>
    </div>`;
    startAngle = endAngle;
  });

  return `
    <div style="display:flex;align-items:center;gap:24px;flex-wrap:wrap">
      <svg width="200" height="200" viewBox="0 0 200 200">${svgPaths}</svg>
      <div>${legend}</div>
    </div>`;
}

export function buildHtmlReport(report: ScanReport): string {
  const threatEmails = report.emails
    .filter((e) => e.threatLevel !== "none")
    .sort((a, b) => {
      const order = { critical: 4, high: 3, medium: 2, low: 1, none: 0 };
      return order[b.threatLevel] - order[a.threatLevel];
    });

  const safeEmails = report.emails.filter(
    (e) => e.threatLevel === "none" && !e.isSuspicious && !e.isSpam
  );

  const spamEmails = report.emails.filter((e) => e.isSpam || e.raw.labels?.includes("SPAM"));

  return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Email Security Report — ${report.scannedAt}</title>
</head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f8fafc;margin:0;padding:20px">
<div style="max-width:900px;margin:0 auto">

<!-- Header -->
<div style="background:linear-gradient(135deg,#1e3a5f,#2563eb);color:#fff;border-radius:16px;padding:32px;margin-bottom:24px">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:16px">
    <div>
      <h1 style="margin:0 0 8px;font-size:28px">📧 Email Security Report</h1>
      <p style="margin:0;opacity:.85;font-size:14px">Scanned ${report.totalScanned} emails · Last ${report.hoursBack} hours · ${report.scannedAt}</p>
    </div>
    <div style="background:rgba(255,255,255,.15);border-radius:12px;padding:16px;text-align:center">
      <div style="font-size:36px;font-weight:700">${report.totalScanned}</div>
      <div style="font-size:12px;opacity:.85">emails scanned</div>
    </div>
  </div>
</div>

<!-- Threat Summary Cards -->
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:16px;margin-bottom:24px">
  ${[
    { label: "Critical", count: report.threatSummary.critical, color: "#dc2626", icon: "🚨" },
    { label: "High Risk", count: report.threatSummary.high, color: "#ea580c", icon: "⚠️" },
    { label: "Medium", count: report.threatSummary.medium, color: "#d97706", icon: "🔶" },
    { label: "Spam", count: report.statistics.spamCount, color: "#7c3aed", icon: "🚫" },
    { label: "Safe", count: report.statistics.safeCount, color: "#16a34a", icon: "✅" },
    { label: "Action Needed", count: report.actionRequired.length, color: "#0891b2", icon: "⚡" },
  ]
    .map(
      (c) => `
    <div style="background:#fff;border-radius:12px;padding:20px;text-align:center;border-top:4px solid ${c.color};box-shadow:0 1px 3px rgba(0,0,0,.08)">
      <div style="font-size:28px;margin-bottom:4px">${c.icon}</div>
      <div style="font-size:28px;font-weight:700;color:${c.color}">${c.count}</div>
      <div style="font-size:12px;color:#64748b;margin-top:4px">${c.label}</div>
    </div>`
    )
    .join("")}
</div>

<!-- Category Breakdown -->
<div style="background:#fff;border-radius:12px;padding:24px;margin-bottom:24px;box-shadow:0 1px 3px rgba(0,0,0,.08)">
  <h2 style="margin:0 0 20px;font-size:18px;color:#1e293b">📊 Category Breakdown</h2>
  ${pieChartSvg(report)}
</div>

<!-- Security Threats -->
${
  threatEmails.length > 0
    ? `
<div style="background:#fff;border-radius:12px;padding:24px;margin-bottom:24px;box-shadow:0 1px 3px rgba(0,0,0,.08);border-left:4px solid #dc2626">
  <h2 style="margin:0 0 16px;font-size:18px;color:#dc2626">🚨 Security Threats & Suspicious Emails (${threatEmails.length})</h2>
  <table style="width:100%;border-collapse:collapse">
    <thead>
      <tr style="background:#fef2f2;border-bottom:2px solid #fecaca">
        <th style="padding:10px 12px;text-align:left;font-size:12px;color:#7f1d1d;font-weight:600">SENDER</th>
        <th style="padding:10px 12px;text-align:left;font-size:12px;color:#7f1d1d;font-weight:600">SUBJECT / SUMMARY</th>
        <th style="padding:10px 12px;text-align:center;font-size:12px;color:#7f1d1d;font-weight:600">CATEGORY</th>
        <th style="padding:10px 12px;text-align:center;font-size:12px;color:#7f1d1d;font-weight:600">THREAT</th>
        <th style="padding:10px 12px;text-align:center;font-size:12px;color:#7f1d1d;font-weight:600">ACTIONS</th>
      </tr>
    </thead>
    <tbody>${threatEmails.map((e) => emailRow(e, true)).join("")}</tbody>
  </table>
</div>`
    : ""
}

<!-- Action Required -->
${
  report.actionRequired.length > 0
    ? `
<div style="background:#fff;border-radius:12px;padding:24px;margin-bottom:24px;box-shadow:0 1px 3px rgba(0,0,0,.08);border-left:4px solid #0891b2">
  <h2 style="margin:0 0 16px;font-size:18px;color:#0891b2">⚡ Action Required (${report.actionRequired.length})</h2>
  <table style="width:100%;border-collapse:collapse">
    <thead>
      <tr style="background:#ecfeff;border-bottom:2px solid #a5f3fc">
        <th style="padding:10px 12px;text-align:left;font-size:12px;color:#164e63;font-weight:600">SENDER</th>
        <th style="padding:10px 12px;text-align:left;font-size:12px;color:#164e63;font-weight:600">SUBJECT / ACTION</th>
        <th style="padding:10px 12px;text-align:center;font-size:12px;color:#164e63;font-weight:600">CATEGORY</th>
        <th style="padding:10px 12px;text-align:center;font-size:12px;color:#164e63;font-weight:600">THREAT</th>
        <th style="padding:10px 12px;text-align:center;font-size:12px;color:#164e63;font-weight:600">ACTIONS</th>
      </tr>
    </thead>
    <tbody>${report.actionRequired.map((e) => emailRow(e)).join("")}</tbody>
  </table>
</div>`
    : ""
}

<!-- Unsubscribe Suggestions -->
${
  report.unsubscribeCandidates.length > 0
    ? `
<div style="background:#fff;border-radius:12px;padding:24px;margin-bottom:24px;box-shadow:0 1px 3px rgba(0,0,0,.08);border-left:4px solid #8b5cf6">
  <h2 style="margin:0 0 16px;font-size:18px;color:#8b5cf6">📭 Unsubscribe Suggestions (${report.unsubscribeCandidates.length})</h2>
  <table style="width:100%;border-collapse:collapse">
    ${report.unsubscribeCandidates
      .slice(0, 20)
      .map(
        (e) => `
    <tr style="border-bottom:1px solid #e2e8f0">
      <td style="padding:8px 12px;font-size:13px;color:#1e293b">${escapeHtml(e.raw.from)}</td>
      <td style="padding:8px 12px;font-size:13px;color:#475569">${escapeHtml(e.raw.subject)}</td>
      <td style="padding:8px 12px;font-size:12px;color:#8b5cf6">${e.unsubscribeReason ?? "Recurring promotional"}</td>
    </tr>`
      )
      .join("")}
  </table>
</div>`
    : ""
}

<!-- Deletion Suggestions -->
${
  report.deletionCandidates.length > 0
    ? `
<div style="background:#fff;border-radius:12px;padding:24px;margin-bottom:24px;box-shadow:0 1px 3px rgba(0,0,0,.08);border-left:4px solid #64748b">
  <h2 style="margin:0 0 16px;font-size:18px;color:#475569">🗑️ Suggested for Deletion (${report.deletionCandidates.length})</h2>
  <table style="width:100%;border-collapse:collapse">
    ${report.deletionCandidates
      .slice(0, 20)
      .map(
        (e) => `
    <tr style="border-bottom:1px solid #e2e8f0">
      <td style="padding:8px 12px;font-size:13px;color:#1e293b">${escapeHtml(e.raw.from)}</td>
      <td style="padding:8px 12px;font-size:13px;color:#475569">${escapeHtml(e.raw.subject)}</td>
      <td style="padding:8px 12px;font-size:12px;color:#64748b">${e.deleteReason ?? "Low priority"}</td>
    </tr>`
      )
      .join("")}
  </table>
</div>`
    : ""
}

<!-- All Emails Table -->
<div style="background:#fff;border-radius:12px;padding:24px;margin-bottom:24px;box-shadow:0 1px 3px rgba(0,0,0,.08)">
  <h2 style="margin:0 0 16px;font-size:18px;color:#1e293b">📬 All Scanned Emails (${report.totalAnalyzed})</h2>
  <table style="width:100%;border-collapse:collapse">
    <thead>
      <tr style="background:#f8fafc;border-bottom:2px solid #e2e8f0">
        <th style="padding:10px 12px;text-align:left;font-size:12px;color:#475569;font-weight:600">SENDER</th>
        <th style="padding:10px 12px;text-align:left;font-size:12px;color:#475569;font-weight:600">SUBJECT / SUMMARY</th>
        <th style="padding:10px 12px;text-align:center;font-size:12px;color:#475569;font-weight:600">CATEGORY</th>
        <th style="padding:10px 12px;text-align:center;font-size:12px;color:#475569;font-weight:600">THREAT</th>
        <th style="padding:10px 12px;text-align:center;font-size:12px;color:#475569;font-weight:600">ACTIONS</th>
      </tr>
    </thead>
    <tbody>${report.emails.map((e) => emailRow(e)).join("")}</tbody>
  </table>
</div>

<!-- Footer -->
<div style="text-align:center;color:#94a3b8;font-size:12px;padding:16px">
  Generated by Email Scanner MCP · ${report.scannedAt} · Scan ID: ${report.scanId}
</div>

</div>
</body>
</html>`;
}

export function buildMarkdownReport(report: ScanReport): string {
  const lines: string[] = [
    `# Email Security Report — ${report.scannedAt}`,
    ``,
    `**Scanned:** ${report.totalScanned} emails | **Period:** Last ${report.hoursBack} hours`,
    ``,
    `## Threat Summary`,
    `| Level | Count |`,
    `|-------|-------|`,
    `| 🚨 Critical | ${report.threatSummary.critical} |`,
    `| ⚠️ High | ${report.threatSummary.high} |`,
    `| 🔶 Medium | ${report.threatSummary.medium} |`,
    `| 🔵 Low | ${report.threatSummary.low} |`,
    `| ✅ Safe | ${report.statistics.safeCount} |`,
    `| 🚫 Spam | ${report.statistics.spamCount} |`,
    ``,
    `## Category Breakdown`,
    ...Object.entries(report.categoryBreakdown)
      .filter(([, c]) => c > 0)
      .map(([cat, count]) => `- ${CATEGORY_ICONS[cat as EmailCategory] ?? "📧"} **${cat}**: ${count}`),
    ``,
    `## Security Threats`,
    ...report.topThreats.map(
      (e) =>
        `- [${e.threatLevel.toUpperCase()}] **${e.raw.subject}** from ${e.raw.from}\n  ${e.summary}\n  Flags: ${e.securityFlags.map((f) => f.type).join(", ") || "none"}`
    ),
    ``,
    `## Unsubscribe Suggestions (${report.unsubscribeCandidates.length})`,
    ...report.unsubscribeCandidates
      .slice(0, 10)
      .map((e) => `- ${e.raw.from} — ${e.unsubscribeReason ?? "Recurring promotional"}`),
    ``,
    `## Deletion Suggestions (${report.deletionCandidates.length})`,
    ...report.deletionCandidates
      .slice(0, 10)
      .map((e) => `- ${e.raw.subject} (${e.raw.from}) — ${e.deleteReason ?? "Low priority"}`),
  ];

  return lines.join("\n");
}
