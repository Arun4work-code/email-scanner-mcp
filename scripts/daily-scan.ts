/**
 * Standalone daily scan script — run by GitHub Actions every morning.
 * Fetches emails, analyzes them, and emails the HTML report back to the user.
 */

import { runScan } from "../src/scanner.js";
import { buildHtmlReport, buildMarkdownReport } from "../src/reporter.js";
import { sendReportEmail } from "../src/gmail-client.js";
import * as fs from "fs/promises";
import * as path from "path";

const RECIPIENT = process.env.REPORT_EMAIL ?? process.env.GMAIL_USER_EMAIL ?? "";
const HOURS_BACK = parseInt(process.env.SCAN_HOURS_BACK ?? "24", 10);
const MAX_EMAILS = parseInt(process.env.SCAN_MAX_EMAILS ?? "200", 10);
const OUTPUT_DIR = process.env.OUTPUT_DIR ?? "./reports";

async function main() {
  console.log(`[daily-scan] Starting email scan — last ${HOURS_BACK}h, max ${MAX_EMAILS} emails`);

  if (!process.env.GMAIL_CLIENT_ID || !process.env.GMAIL_CLIENT_SECRET || !process.env.GMAIL_REFRESH_TOKEN) {
    console.error("[daily-scan] ERROR: Missing Gmail OAuth2 credentials in environment");
    process.exit(1);
  }

  if (!process.env.GEMINI_API_KEY) {
    console.error("[daily-scan] ERROR: Missing GEMINI_API_KEY in environment");
    process.exit(1);
  }

  const report = await runScan({
    hoursBack: HOURS_BACK,
    maxEmails: MAX_EMAILS,
    includeSpam: true,
  });

  // Save reports to disk (GitHub Actions will upload as artifacts)
  await fs.mkdir(OUTPUT_DIR, { recursive: true });

  const dateStr = new Date().toISOString().split("T")[0];
  const htmlPath = path.join(OUTPUT_DIR, `email-report-${dateStr}.html`);
  const mdPath = path.join(OUTPUT_DIR, `email-report-${dateStr}.md`);
  const jsonPath = path.join(OUTPUT_DIR, `email-report-${dateStr}.json`);

  const htmlReport = buildHtmlReport(report);
  const mdReport = buildMarkdownReport(report);

  await Promise.all([
    fs.writeFile(htmlPath, htmlReport, "utf-8"),
    fs.writeFile(mdPath, mdReport, "utf-8"),
    fs.writeFile(jsonPath, JSON.stringify(report, null, 2), "utf-8"),
  ]);

  console.log(`[daily-scan] Reports saved:`);
  console.log(`  HTML:     ${htmlPath}`);
  console.log(`  Markdown: ${mdPath}`);
  console.log(`  JSON:     ${jsonPath}`);

  // Print summary to stdout (visible in GitHub Actions logs)
  console.log("\n" + "=".repeat(60));
  console.log("DAILY EMAIL SCAN SUMMARY");
  console.log("=".repeat(60));
  console.log(`Scanned at:    ${report.scannedAt}`);
  console.log(`Total emails:  ${report.totalScanned}`);
  console.log(`Analyzed:      ${report.totalAnalyzed}`);
  console.log(`Critical:      ${report.threatSummary.critical}`);
  console.log(`High risk:     ${report.threatSummary.high}`);
  console.log(`Medium risk:   ${report.threatSummary.medium}`);
  console.log(`Spam:          ${report.statistics.spamCount}`);
  console.log(`Safe:          ${report.statistics.safeCount}`);
  console.log(`Unsubscribe:   ${report.unsubscribeCandidates.length} candidates`);
  console.log(`Delete:        ${report.deletionCandidates.length} candidates`);
  console.log("=".repeat(60));

  // Send report email if recipient is configured
  if (RECIPIENT) {
    const totalThreats =
      report.threatSummary.critical + report.threatSummary.high + report.threatSummary.medium;
    const urgencyEmoji =
      report.threatSummary.critical > 0
        ? "🚨"
        : report.threatSummary.high > 0
          ? "⚠️"
          : totalThreats > 0
            ? "🔶"
            : "✅";

    const subject = `${urgencyEmoji} Email Report ${dateStr} — ${report.totalScanned} emails, ${totalThreats} threats`;

    console.log(`[daily-scan] Sending report email to ${RECIPIENT}…`);
    await sendReportEmail(RECIPIENT, subject, htmlReport);
    console.log(`[daily-scan] Report email sent successfully.`);
  } else {
    console.log(`[daily-scan] REPORT_EMAIL not set — skipping email delivery.`);
  }

  // Exit with non-zero if critical threats found (so GitHub Actions can alert)
  if (report.threatSummary.critical > 0) {
    console.error(
      `[daily-scan] ⚠️  ${report.threatSummary.critical} CRITICAL threats detected!`
    );
    process.exit(2); // exit code 2 = critical threats found
  }

  process.exit(0);
}

main().catch((err) => {
  console.error("[daily-scan] FATAL:", err);
  process.exit(1);
});
