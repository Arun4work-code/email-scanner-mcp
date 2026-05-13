import { randomUUID } from "crypto";
import { fetchEmails } from "./gmail-client.js";
import { analyzeEmailBatch } from "./analyzer.js";
import type { ScanOptions, ScanReport, EmailCategory, AnalyzedEmail } from "./types.js";

export async function runScan(options: ScanOptions = {}): Promise<ScanReport> {
  const { hoursBack = 24, maxEmails = 200 } = options;
  const scannedAt = new Date().toISOString();

  console.error(`[scanner] Fetching emails from last ${hoursBack}h (max ${maxEmails})…`);
  const rawEmails = await fetchEmails(options);
  console.error(`[scanner] Fetched ${rawEmails.length} emails. Starting analysis…`);

  const emails = await analyzeEmailBatch(rawEmails);
  console.error(`[scanner] Analysis complete for ${emails.length} emails.`);

  const categoryBreakdown: Record<EmailCategory, number> = {
    personal: 0,
    professional: 0,
    financial: 0,
    shopping: 0,
    social: 0,
    newsletter: 0,
    promotional: 0,
    travel: 0,
    health: 0,
    security_alert: 0,
    spam: 0,
    other: 0,
  };

  const threatSummary = { critical: 0, high: 0, medium: 0, low: 0, none: 0 };

  for (const email of emails) {
    categoryBreakdown[email.category] = (categoryBreakdown[email.category] ?? 0) + 1;
    threatSummary[email.threatLevel] = (threatSummary[email.threatLevel] ?? 0) + 1;
  }

  const topThreats = emails
    .filter((e) => e.threatLevel !== "none")
    .sort((a, b) => {
      const order = { critical: 4, high: 3, medium: 2, low: 1, none: 0 };
      return order[b.threatLevel] - order[a.threatLevel];
    });

  const unsubscribeCandidates = emails.filter((e) => e.suggestUnsubscribe);
  const deletionCandidates = emails.filter((e) => e.suggestDelete);
  const actionRequired = emails.filter((e) => e.actionRequired);

  const suspiciousSenders = [
    ...new Set(
      emails
        .filter((e) => e.senderReputation === "suspicious" || e.senderReputation === "malicious")
        .map((e) => e.raw.from)
    ),
  ];

  const spamCount = emails.filter(
    (e) => e.isSpam || e.raw.labels.includes("SPAM")
  ).length;

  const suspiciousCount = emails.filter((e) => e.isSuspicious).length;
  const safeCount = emails.filter(
    (e) => e.threatLevel === "none" && !e.isSuspicious && !e.isSpam
  ).length;

  return {
    scanId: randomUUID(),
    scannedAt,
    hoursBack,
    totalScanned: rawEmails.length,
    totalAnalyzed: emails.length,
    emails,
    categoryBreakdown,
    threatSummary,
    topThreats,
    unsubscribeCandidates,
    deletionCandidates,
    actionRequired,
    suspiciousSenders,
    statistics: {
      spamCount,
      suspiciousCount,
      safeCount,
      avgImportance: computeAvgImportance(emails),
    },
  };
}

function computeAvgImportance(emails: AnalyzedEmail[]): string {
  if (emails.length === 0) return "low";
  const weights = { high: 2, medium: 1, low: 0 };
  const avg = emails.reduce((s, e) => s + weights[e.importance], 0) / emails.length;
  if (avg >= 1.5) return "high";
  if (avg >= 0.75) return "medium";
  return "low";
}
