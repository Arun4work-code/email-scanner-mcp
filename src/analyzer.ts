import Anthropic from "@anthropic-ai/sdk";
import type { RawEmail, AnalyzedEmail, EmailCategory, ThreatLevel, SecurityFlag } from "./types.js";

const client = new Anthropic();

const SYSTEM_PROMPT = `You are an expert email security analyst and inbox organizer. Your job is to analyze emails and return structured JSON analysis.

For each email, determine:
1. **Category** (one of): personal, professional, financial, shopping, social, newsletter, promotional, travel, health, security_alert, spam, other
2. **Threat level** (one of): none, low, medium, high, critical
3. **Security flags** — check for: phishing, malware_attachment, suspicious_link, impersonation, urgency_scam, data_collection, spoofed_sender, credential_harvest
4. **Sender reputation**: trusted, neutral, suspicious, malicious
5. **Action required**: whether the user needs to act on this email
6. **Suggestions**: whether to delete or unsubscribe

CATEGORY RULES:
- personal: emails from known individuals (family, friends), no organizational sender
- professional: work-related, job alerts, LinkedIn, recruiters, business communications
- financial: banks, invoices, payments, tax, insurance, investments, receipts
- shopping: orders, shipping, product recommendations, e-commerce
- social: Facebook, Twitter/X, Instagram, WhatsApp, YouTube notifications
- newsletter: regular editorial content, blogs, publications (non-promotional)
- promotional: sales, discounts, marketing from brands
- travel: booking confirmations, flight/hotel updates, travel deals
- health: medical, pharmacy, fitness, wellness
- security_alert: password reset, login alerts, breach notifications, OTP
- spam: unsolicited mass email with no legitimate value
- other: doesn't fit above categories

THREAT DETECTION RULES:
- critical: confirmed phishing/malware, credential harvesting, obvious scam
- high: strong phishing indicators, suspicious attachments (.exe, .zip from unknown), spoofed sender
- medium: suspicious links, mismatched reply-to/return-path, urgency language from unknown senders
- low: minor concerns like tracking pixels, soft marketing pressure
- none: clean email

SPF/DKIM/DMARC: SPF fail + unknown sender = suspicious. All three failing = high threat.

DELETION SUGGESTIONS: newsletters older than a week, promotional emails already read, repeated notifications, social notifications from inactive accounts.
UNSUBSCRIBE SUGGESTIONS: any recurring promotional/newsletter sender the user likely doesn't need.

Always respond with valid JSON only — no markdown, no explanation text.`;

interface EmailBatchAnalysis {
  emailId: string;
  category: EmailCategory;
  categoryConfidence: number;
  threatLevel: ThreatLevel;
  securityFlags: SecurityFlag[];
  isSpam: boolean;
  isSuspicious: boolean;
  suggestDelete: boolean;
  suggestUnsubscribe: boolean;
  unsubscribeReason?: string;
  deleteReason?: string;
  summary: string;
  importance: "low" | "medium" | "high";
  senderReputation: "trusted" | "neutral" | "suspicious" | "malicious";
  actionRequired: boolean;
  actionDescription?: string;
}

function buildEmailPrompt(emails: RawEmail[]): string {
  const items = emails.map((e) =>
    JSON.stringify({
      id: e.id,
      from: e.from,
      replyTo: e.replyTo,
      returnPath: e.returnPath,
      subject: e.subject,
      snippet: e.snippet,
      body: e.body.slice(0, 800),
      date: e.date,
      labels: e.labels,
      hasAttachments: e.hasAttachments,
      attachmentNames: e.attachmentNames,
      spf: e.spfResult,
      dkim: e.dkimResult,
      dmarc: e.dmarcResult,
    })
  );

  return `Analyze the following ${emails.length} emails and return a JSON array of analysis objects.

Each object must have these exact fields:
- emailId (string): the email "id" field
- category (string): one of the valid categories
- categoryConfidence (number): 0-1
- threatLevel (string): none/low/medium/high/critical
- securityFlags (array): [{type, description, confidence}] or []
- isSpam (boolean)
- isSuspicious (boolean)
- suggestDelete (boolean)
- suggestUnsubscribe (boolean)
- unsubscribeReason (string, optional)
- deleteReason (string, optional)
- summary (string): 1-sentence summary
- importance (string): low/medium/high
- senderReputation (string): trusted/neutral/suspicious/malicious
- actionRequired (boolean)
- actionDescription (string, optional)

EMAILS TO ANALYZE:
${items.join("\n---\n")}

Return ONLY a JSON array, no other text.`;
}

export async function analyzeEmailBatch(emails: RawEmail[]): Promise<AnalyzedEmail[]> {
  if (emails.length === 0) return [];

  // Process in batches of 15 to stay within token limits
  const batchSize = 15;
  const results: AnalyzedEmail[] = [];

  for (let i = 0; i < emails.length; i += batchSize) {
    const batch = emails.slice(i, i + batchSize);

    // Use prompt caching (anthropic-beta header) to cache the large system prompt
    // across repeated batch calls — significantly reduces cost and latency.
    const response = await (client as any).messages.create(
      {
        model: "claude-sonnet-4-6",
        max_tokens: 8000,
        system: [
          {
            type: "text",
            text: SYSTEM_PROMPT,
            cache_control: { type: "ephemeral" },
          },
        ],
        messages: [
          {
            role: "user",
            content: buildEmailPrompt(batch),
          },
        ],
      },
      {
        headers: { "anthropic-beta": "prompt-caching-2024-07-31" },
      }
    );

    const text = response.content[0].type === "text" ? response.content[0].text : "";

    let analyses: EmailBatchAnalysis[] = [];
    try {
      analyses = JSON.parse(text);
    } catch {
      // Try to extract JSON from response if there's extra text
      const match = text.match(/\[[\s\S]*\]/);
      if (match) {
        try {
          analyses = JSON.parse(match[0]);
        } catch {
          console.error("Failed to parse batch analysis response");
          analyses = [];
        }
      }
    }

    for (const analysis of analyses) {
      const raw = batch.find((e) => e.id === analysis.emailId);
      if (!raw) continue;
      results.push({ raw, ...analysis });
    }
  }

  return results;
}

export async function analyzeSingleEmail(email: RawEmail): Promise<AnalyzedEmail> {
  const results = await analyzeEmailBatch([email]);
  if (results.length === 0) {
    return {
      raw: email,
      category: "other",
      categoryConfidence: 0,
      threatLevel: "none",
      securityFlags: [],
      isSpam: false,
      isSuspicious: false,
      suggestDelete: false,
      suggestUnsubscribe: false,
      summary: "Analysis unavailable",
      importance: "low",
      senderReputation: "neutral",
      actionRequired: false,
    };
  }
  return results[0];
}
