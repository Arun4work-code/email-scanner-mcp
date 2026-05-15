import { google } from "googleapis";
import type { RawEmail, ScanOptions } from "./types.js";

export function createGmailClient() {
  const oauth2Client = new google.auth.OAuth2(
    process.env.GMAIL_CLIENT_ID,
    process.env.GMAIL_CLIENT_SECRET,
    "urn:ietf:wg:oauth:2.0:oob"
  );

  oauth2Client.setCredentials({
    refresh_token: process.env.GMAIL_REFRESH_TOKEN,
  });

  return google.gmail({ version: "v1", auth: oauth2Client });
}

function decodeBase64(data: string): string {
  return Buffer.from(data.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf-8");
}

type HeaderEntry = { name?: string | null; value?: string | null };

function extractHeader(headers: HeaderEntry[], name: string): string {
  return headers.find((h) => h.name?.toLowerCase() === name.toLowerCase())?.value ?? "";
}

function extractBody(payload: any): string {
  if (!payload) return "";

  if (payload.body?.data) {
    return decodeBase64(payload.body.data);
  }

  if (payload.parts) {
    for (const part of payload.parts) {
      if (part.mimeType === "text/plain" && part.body?.data) {
        return decodeBase64(part.body.data);
      }
    }
    for (const part of payload.parts) {
      if (part.mimeType === "text/html" && part.body?.data) {
        const html = decodeBase64(part.body.data);
        return html.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
      }
    }
    for (const part of payload.parts) {
      const nested = extractBody(part);
      if (nested) return nested;
    }
  }

  return "";
}

function extractAttachments(payload: any): string[] {
  const names: string[] = [];
  if (!payload?.parts) return names;
  for (const part of payload.parts) {
    if (part.filename && part.filename.length > 0) {
      names.push(part.filename);
    }
    names.push(...extractAttachments(part));
  }
  return names;
}

function parseAuthResults(received: string[]): {
  spf?: string;
  dkim?: string;
  dmarc?: string;
} {
  const combined = received.join(" ").toLowerCase();
  const spfMatch = combined.match(/spf=(pass|fail|softfail|neutral|none)/);
  const dkimMatch = combined.match(/dkim=(pass|fail|none)/);
  const dmarcMatch = combined.match(/dmarc=(pass|fail|none)/);
  return {
    spf: spfMatch?.[1],
    dkim: dkimMatch?.[1],
    dmarc: dmarcMatch?.[1],
  };
}

export async function fetchEmails(options: ScanOptions = {}): Promise<RawEmail[]> {
  const { hoursBack = 24, maxEmails = 200, includeSpam = true, includeTrash = false } = options;

  const gmail = createGmailClient();
  const afterTimestamp = Math.floor((Date.now() - hoursBack * 3600 * 1000) / 1000);

  const labelIds = ["INBOX"];
  if (includeSpam) labelIds.push("SPAM");
  if (includeTrash) labelIds.push("TRASH");

  const listResponse = await gmail.users.messages.list({
    userId: "me",
    q: `after:${afterTimestamp}`,
    maxResults: maxEmails,
    includeSpamTrash: includeSpam || includeTrash,
  });

  const messages = listResponse.data.messages ?? [];
  if (messages.length === 0) return [];

  const emails: RawEmail[] = [];

  // Fetch full message details in parallel batches of 10
  const batchSize = 10;
  for (let i = 0; i < messages.length; i += batchSize) {
    const batch = messages.slice(i, i + batchSize);
    const details = await Promise.all(
      batch.map((msg) =>
        gmail.users.messages.get({
          userId: "me",
          id: msg.id!,
          format: "full",
        })
      )
    );

    for (const detail of details) {
      const msg = detail.data;
      if (!msg.payload) continue;

      const headers: HeaderEntry[] = msg.payload.headers ?? [];
      const receivedHeaders = headers
        .filter((h) => h.name?.toLowerCase() === "received")
        .map((h) => h.value ?? "");
      const authResults = parseAuthResults(receivedHeaders);

      const attachmentNames = extractAttachments(msg.payload);
      const body = extractBody(msg.payload);

      emails.push({
        id: msg.id!,
        threadId: msg.threadId!,
        from: extractHeader(headers, "from"),
        to: extractHeader(headers, "to"),
        subject: extractHeader(headers, "subject") || "(no subject)",
        snippet: msg.snippet ?? "",
        body: body.slice(0, 2000), // cap at 2000 chars for analysis
        date: extractHeader(headers, "date"),
        labels: msg.labelIds ?? [],
        hasAttachments: attachmentNames.length > 0,
        attachmentNames,
        messageId: extractHeader(headers, "message-id"),
        replyTo: extractHeader(headers, "reply-to"),
        returnPath: extractHeader(headers, "return-path"),
        spfResult: authResults.spf,
        dkimResult: authResults.dkim,
        dmarcResult: authResults.dmarc,
      });
    }
  }

  return emails;
}

export async function fetchEmailById(emailId: string): Promise<RawEmail | null> {
  const gmail = createGmailClient();

  const detail = await gmail.users.messages.get({
    userId: "me",
    id: emailId,
    format: "full",
  });

  const msg = detail.data;
  if (!msg.payload) return null;

  const headers: HeaderEntry[] = msg.payload.headers ?? [];
  const receivedHeaders = headers
    .filter((h) => h.name?.toLowerCase() === "received")
    .map((h) => h.value ?? "");
  const authResults = parseAuthResults(receivedHeaders);
  const attachmentNames = extractAttachments(msg.payload);
  const body = extractBody(msg.payload);

  return {
    id: msg.id!,
    threadId: msg.threadId!,
    from: extractHeader(headers, "from"),
    to: extractHeader(headers, "to"),
    subject: extractHeader(headers, "subject") || "(no subject)",
    snippet: msg.snippet ?? "",
    body: body.slice(0, 2000),
    date: extractHeader(headers, "date"),
    labels: msg.labelIds ?? [],
    hasAttachments: attachmentNames.length > 0,
    attachmentNames,
    messageId: extractHeader(headers, "message-id"),
    replyTo: extractHeader(headers, "reply-to"),
    returnPath: extractHeader(headers, "return-path"),
    spfResult: authResults.spf,
    dkimResult: authResults.dkim,
    dmarcResult: authResults.dmarc,
  };
}

export async function sendReportEmail(
  to: string,
  subject: string,
  htmlBody: string
): Promise<void> {
  const gmail = createGmailClient();

  const raw = [
    `From: Email Scanner <${process.env.GMAIL_USER_EMAIL ?? to}>`,
    `To: ${to}`,
    `Subject: ${subject}`,
    `MIME-Version: 1.0`,
    `Content-Type: text/html; charset=utf-8`,
    ``,
    htmlBody,
  ].join("\n");

  const encoded = Buffer.from(raw)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  await gmail.users.messages.send({
    userId: "me",
    requestBody: { raw: encoded },
  });
}
