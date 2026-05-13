export type EmailCategory =
  | "personal"
  | "professional"
  | "financial"
  | "shopping"
  | "social"
  | "newsletter"
  | "promotional"
  | "travel"
  | "health"
  | "security_alert"
  | "spam"
  | "other";

export type ThreatLevel = "none" | "low" | "medium" | "high" | "critical";

export interface SecurityFlag {
  type:
    | "phishing"
    | "malware_attachment"
    | "suspicious_link"
    | "impersonation"
    | "urgency_scam"
    | "data_collection"
    | "spoofed_sender"
    | "credential_harvest";
  description: string;
  confidence: number; // 0-1
}

export interface RawEmail {
  id: string;
  threadId: string;
  from: string;
  to: string;
  subject: string;
  snippet: string;
  body: string;
  date: string;
  labels: string[];
  hasAttachments: boolean;
  attachmentNames: string[];
  messageId: string;
  replyTo?: string;
  returnPath?: string;
  spfResult?: string;
  dkimResult?: string;
  dmarcResult?: string;
}

export interface AnalyzedEmail {
  raw: RawEmail;
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

export interface ScanReport {
  scanId: string;
  scannedAt: string;
  hoursBack: number;
  totalScanned: number;
  totalAnalyzed: number;
  emails: AnalyzedEmail[];
  categoryBreakdown: Record<EmailCategory, number>;
  threatSummary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    none: number;
  };
  topThreats: AnalyzedEmail[];
  unsubscribeCandidates: AnalyzedEmail[];
  deletionCandidates: AnalyzedEmail[];
  actionRequired: AnalyzedEmail[];
  suspiciousSenders: string[];
  statistics: {
    spamCount: number;
    suspiciousCount: number;
    safeCount: number;
    avgImportance: string;
  };
}

export interface ScanOptions {
  hoursBack?: number;
  maxEmails?: number;
  includeSpam?: boolean;
  includeTrash?: boolean;
}
