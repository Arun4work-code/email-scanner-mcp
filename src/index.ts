import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { runScan } from "./scanner.js";
import { analyzeSingleEmail } from "./analyzer.js";
import { fetchEmailById } from "./gmail-client.js";
import { buildHtmlReport, buildMarkdownReport } from "./reporter.js";
import type { ScanReport } from "./types.js";

const server = new Server(
  { name: "email-scanner-mcp", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

// In-memory cache of the last scan (cleared on new scan)
let lastReport: ScanReport | null = null;

// ── Tool schemas ──────────────────────────────────────────────────────────────

const ScanEmailsSchema = z.object({
  hoursBack: z.number().optional().describe("Hours to look back (default: 24)"),
  maxEmails: z.number().optional().describe("Max emails to fetch (default: 200)"),
  includeSpam: z.boolean().optional().describe("Include spam folder (default: true)"),
});

const AnalyzeEmailSchema = z.object({
  emailId: z.string().describe("Gmail message ID to analyze"),
});

const GenerateReportSchema = z.object({
  format: z.enum(["html", "markdown", "json"]).optional().describe("Report format (default: markdown)"),
});

const GetThreatsSchema = z.object({
  minLevel: z
    .enum(["low", "medium", "high", "critical"])
    .optional()
    .describe("Minimum threat level to include (default: low)"),
});

// ── Tool list ─────────────────────────────────────────────────────────────────

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "scan_emails",
      description:
        "Scan your Gmail inbox for the last N hours. Fetches emails, runs AI security analysis, categorizes them, and caches the report. Run this first before using other tools.",
      inputSchema: {
        type: "object",
        properties: {
          hoursBack: { type: "number", description: "Hours to look back (default: 24)" },
          maxEmails: { type: "number", description: "Max emails to fetch (default: 200)" },
          includeSpam: { type: "boolean", description: "Include spam folder (default: true)" },
        },
      },
    },
    {
      name: "analyze_email",
      description:
        "Deep-analyze a single email by its Gmail message ID. Returns detailed security analysis, category, threats, and suggestions.",
      inputSchema: {
        type: "object",
        properties: {
          emailId: { type: "string", description: "Gmail message ID" },
        },
        required: ["emailId"],
      },
    },
    {
      name: "get_security_threats",
      description:
        "Get all emails from the last scan that have security threats or are suspicious. Returns threat details and security flags.",
      inputSchema: {
        type: "object",
        properties: {
          minLevel: {
            type: "string",
            enum: ["low", "medium", "high", "critical"],
            description: "Minimum threat level (default: low)",
          },
        },
      },
    },
    {
      name: "get_unsubscribe_candidates",
      description:
        "Get a list of senders/emails from the last scan that are suggested for unsubscribing, along with the reason.",
      inputSchema: { type: "object", properties: {} },
    },
    {
      name: "get_deletion_candidates",
      description:
        "Get emails from the last scan suggested for deletion, along with the reason.",
      inputSchema: { type: "object", properties: {} },
    },
    {
      name: "generate_report",
      description:
        "Generate a full formatted report from the last scan in HTML, Markdown, or JSON format.",
      inputSchema: {
        type: "object",
        properties: {
          format: {
            type: "string",
            enum: ["html", "markdown", "json"],
            description: "Report format (default: markdown)",
          },
        },
      },
    },
    {
      name: "get_category_summary",
      description:
        "Get a breakdown of emails by category from the last scan (personal, professional, financial, etc.).",
      inputSchema: { type: "object", properties: {} },
    },
  ],
}));

// ── Tool handler ──────────────────────────────────────────────────────────────

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  if (name === "scan_emails") {
    const opts = ScanEmailsSchema.parse(args ?? {});
    const report = await runScan(opts);
    lastReport = report;

    const lines = [
      `✅ Scan complete — ${report.scannedAt}`,
      `📧 Emails scanned: ${report.totalScanned}`,
      `🔍 Emails analyzed: ${report.totalAnalyzed}`,
      ``,
      `THREAT SUMMARY`,
      `  🚨 Critical: ${report.threatSummary.critical}`,
      `  ⚠️  High:     ${report.threatSummary.high}`,
      `  🔶 Medium:   ${report.threatSummary.medium}`,
      `  🔵 Low:      ${report.threatSummary.low}`,
      `  ✅ Safe:     ${report.statistics.safeCount}`,
      `  🚫 Spam:     ${report.statistics.spamCount}`,
      ``,
      `CATEGORIES`,
      ...Object.entries(report.categoryBreakdown)
        .filter(([, c]) => c > 0)
        .map(([cat, count]) => `  ${cat}: ${count}`),
      ``,
      `📭 Unsubscribe candidates: ${report.unsubscribeCandidates.length}`,
      `🗑️  Deletion candidates: ${report.deletionCandidates.length}`,
      `⚡ Action required: ${report.actionRequired.length}`,
      ``,
      `Use generate_report to get the full formatted report.`,
    ];

    return { content: [{ type: "text", text: lines.join("\n") }] };
  }

  if (name === "analyze_email") {
    const { emailId } = AnalyzeEmailSchema.parse(args);
    const target = await fetchEmailById(emailId);

    if (!target) {
      return {
        content: [{ type: "text", text: `Email ${emailId} not found.` }],
      };
    }

    const result = await analyzeSingleEmail(target);
    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  }

  if (name === "get_security_threats") {
    if (!lastReport) {
      return {
        content: [{ type: "text", text: "No scan found. Run scan_emails first." }],
      };
    }

    const { minLevel = "low" } = GetThreatsSchema.parse(args ?? {});
    const order = { critical: 4, high: 3, medium: 2, low: 1, none: 0 };
    const minOrder = order[minLevel];

    const threats = lastReport.emails
      .filter((e) => order[e.threatLevel] >= minOrder)
      .sort((a, b) => order[b.threatLevel] - order[a.threatLevel]);

    if (threats.length === 0) {
      return {
        content: [{ type: "text", text: `No threats found at level ≥ ${minLevel}.` }],
      };
    }

    const text = threats
      .map(
        (e) =>
          `[${e.threatLevel.toUpperCase()}] ${e.raw.subject}\n` +
          `  From: ${e.raw.from}\n` +
          `  Summary: ${e.summary}\n` +
          `  Flags: ${e.securityFlags.map((f) => `${f.type}(${(f.confidence * 100).toFixed(0)}%)`).join(", ") || "none"}\n` +
          `  SPF: ${e.raw.spfResult ?? "?"} | DKIM: ${e.raw.dkimResult ?? "?"} | DMARC: ${e.raw.dmarcResult ?? "?"}`
      )
      .join("\n\n");

    return { content: [{ type: "text", text }] };
  }

  if (name === "get_unsubscribe_candidates") {
    if (!lastReport) {
      return {
        content: [{ type: "text", text: "No scan found. Run scan_emails first." }],
      };
    }

    if (lastReport.unsubscribeCandidates.length === 0) {
      return { content: [{ type: "text", text: "No unsubscribe candidates found." }] };
    }

    const text = lastReport.unsubscribeCandidates
      .map(
        (e, i) =>
          `${i + 1}. ${e.raw.from}\n   Subject: ${e.raw.subject}\n   Reason: ${e.unsubscribeReason ?? "Recurring promotional"}`
      )
      .join("\n\n");

    return { content: [{ type: "text", text }] };
  }

  if (name === "get_deletion_candidates") {
    if (!lastReport) {
      return {
        content: [{ type: "text", text: "No scan found. Run scan_emails first." }],
      };
    }

    if (lastReport.deletionCandidates.length === 0) {
      return { content: [{ type: "text", text: "No deletion candidates found." }] };
    }

    const text = lastReport.deletionCandidates
      .map(
        (e, i) =>
          `${i + 1}. ${e.raw.subject}\n   From: ${e.raw.from}\n   Reason: ${e.deleteReason ?? "Low priority"}`
      )
      .join("\n\n");

    return { content: [{ type: "text", text }] };
  }

  if (name === "generate_report") {
    if (!lastReport) {
      return {
        content: [{ type: "text", text: "No scan found. Run scan_emails first." }],
      };
    }

    const { format = "markdown" } = GenerateReportSchema.parse(args ?? {});

    if (format === "html") {
      return { content: [{ type: "text", text: buildHtmlReport(lastReport) }] };
    }
    if (format === "json") {
      return { content: [{ type: "text", text: JSON.stringify(lastReport, null, 2) }] };
    }
    return { content: [{ type: "text", text: buildMarkdownReport(lastReport) }] };
  }

  if (name === "get_category_summary") {
    if (!lastReport) {
      return {
        content: [{ type: "text", text: "No scan found. Run scan_emails first." }],
      };
    }

    const lines = Object.entries(lastReport.categoryBreakdown)
      .filter(([, c]) => c > 0)
      .sort(([, a], [, b]) => b - a)
      .map(([cat, count]) => `${cat.padEnd(15)} ${count} email${count !== 1 ? "s" : ""}`);

    return {
      content: [
        {
          type: "text",
          text: `Category Breakdown (${lastReport.totalAnalyzed} emails)\n${"─".repeat(35)}\n${lines.join("\n")}`,
        },
      ],
    };
  }

  throw new Error(`Unknown tool: ${name}`);
});

// ── Start ─────────────────────────────────────────────────────────────────────

const transport = new StdioServerTransport();
await server.connect(transport);
console.error("Email Scanner MCP server running on stdio");
