# Email Scanner MCP

AI-powered Gmail scanner that runs daily via GitHub Actions, analyzes your emails for security threats, categorizes them, and emails you an HTML digest report.

## What It Does

- **Scans** Gmail inbox for the last 24 hours (configurable)
- **Categorizes** every email: Personal, Professional, Financial, Shopping, Social, Newsletter, Promotional, Travel, Health, Security Alert, Spam
- **Detects threats**: Phishing, malware attachments, spoofed senders, credential harvesting, urgency scams
- **Flags** SPF/DKIM/DMARC authentication failures
- **Suggests** emails to delete and senders to unsubscribe from
- **Emails you** a beautiful HTML report every morning
- **Alerts GitHub Actions** with exit code 2 when critical threats are found

## Architecture

```
email-scanner-mcp/
├── src/
│   ├── index.ts          # MCP server (7 tools exposed to Claude)
│   ├── gmail-client.ts   # Gmail API via OAuth2
│   ├── analyzer.ts       # Claude claude-sonnet-4-6 with prompt caching
│   ├── reporter.ts       # HTML + Markdown report generation
│   ├── scanner.ts        # Scan orchestration
│   └── types.ts          # TypeScript types
├── scripts/
│   ├── daily-scan.ts     # CI/CD entrypoint script
│   └── get-refresh-token.ts  # One-time OAuth setup
└── .github/workflows/
    ├── daily-scan.yml    # Cron job: 6:30 AM UTC daily
    └── ci.yml            # Build + type-check on push/PR
```

## Setup

### 1. Create Google Cloud OAuth2 Credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Create a project → Enable **Gmail API**
3. Create **OAuth 2.0 Client ID** → Application type: **Desktop app**
4. Download the client ID and secret

### 2. Get Your Refresh Token

```bash
npm install
GMAIL_CLIENT_ID=xxx GMAIL_CLIENT_SECRET=xxx npm run get-token
```

Follow the URL, sign in, paste the code. Copy the printed `GMAIL_REFRESH_TOKEN`.

### 3. Configure Environment

```bash
cp .env.example .env
# Edit .env with your values
```

### 4. Test Locally

```bash
npm run daily-scan
```

This scans the last 24 hours, saves reports to `./reports/`, and emails you the HTML report.

### 5. Push to GitHub + Add Secrets

```bash
git init
git remote add origin https://github.com/YOUR_USERNAME/email-scanner-mcp.git
git push -u origin main
```

Go to **GitHub → Settings → Secrets and variables → Actions** and add:

| Secret | Value |
|--------|-------|
| `GMAIL_CLIENT_ID` | From Google Cloud |
| `GMAIL_CLIENT_SECRET` | From Google Cloud |
| `GMAIL_REFRESH_TOKEN` | From `npm run get-token` |
| `ANTHROPIC_API_KEY` | From [Anthropic Console](https://console.anthropic.com) |
| `REPORT_EMAIL` | Your Gmail address |

The workflow runs automatically at **6:30 AM UTC (12:00 PM IST)** every day.

## MCP Server

Add to Claude Code (`~/.claude/claude_code_config.json`):

```json
{
  "mcpServers": {
    "email-scanner": {
      "command": "node",
      "args": ["/path/to/email-scanner-mcp/dist/src/index.js"],
      "env": {
        "GMAIL_CLIENT_ID": "...",
        "GMAIL_CLIENT_SECRET": "...",
        "GMAIL_REFRESH_TOKEN": "...",
        "ANTHROPIC_API_KEY": "..."
      }
    }
  }
}
```

### Available MCP Tools

| Tool | Description |
|------|-------------|
| `scan_emails` | Scan Gmail inbox (last N hours) |
| `analyze_email` | Deep-analyze a specific email by ID |
| `get_security_threats` | List all threats found |
| `get_unsubscribe_candidates` | Senders to unsubscribe from |
| `get_deletion_candidates` | Emails to delete |
| `generate_report` | Full report (HTML/Markdown/JSON) |
| `get_category_summary` | Category breakdown |

## CI/CD Workflow

```
Daily at 6:30 UTC
       │
       ▼
[GitHub Actions]
       │
       ├── npm ci
       ├── tsx scripts/daily-scan.ts
       │       ├── fetchEmails() → Gmail API
       │       ├── analyzeEmailBatch() → Claude API (with prompt caching)
       │       ├── buildHtmlReport()
       │       ├── Save to ./reports/ (uploaded as artifact)
       │       └── sendReportEmail() → Gmail API
       │
       ├── Upload artifact (retained 30 days)
       ├── Post summary to GitHub Actions Summary
       └── Exit 1 if critical threats found → GitHub notifies you
```

## Email Categories

| Category | What it covers |
|----------|---------------|
| personal | Emails from individuals (family, friends) |
| professional | Work emails, job alerts, LinkedIn, recruiters |
| financial | Banks, invoices, payments, tax, investments |
| shopping | Orders, shipping, e-commerce |
| social | Facebook, Twitter, Instagram notifications |
| newsletter | Editorial content, blogs, publications |
| promotional | Sales, discounts, brand marketing |
| travel | Bookings, flight/hotel updates |
| health | Medical, pharmacy, fitness |
| security_alert | Password resets, login alerts, OTPs |
| spam | Unsolicited junk |
| other | Doesn't fit above |

## Security Threat Types

- `phishing` — Fake login/credential pages
- `malware_attachment` — Dangerous attachments (.exe, .zip from unknown senders)
- `suspicious_link` — Links to untrusted domains
- `impersonation` — Pretending to be a known brand/person
- `urgency_scam` — "Act now or lose your account" pressure tactics
- `data_collection` — Harvesting personal info
- `spoofed_sender` — From address doesn't match actual sender
- `credential_harvest` — Trying to steal passwords

## Threat Levels

| Level | Meaning | Action |
|-------|---------|--------|
| critical | Confirmed attack (phishing, malware) | Delete immediately |
| high | Strong phishing/impersonation indicators | Don't click anything |
| medium | Suspicious patterns, unverified sender | Review carefully |
| low | Minor concerns (tracking pixels, soft pressure) | Be aware |
| none | Clean email | Safe |
