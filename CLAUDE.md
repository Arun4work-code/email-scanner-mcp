# Email Scanner MCP — Claude Code Context

## What This Project Does
AI-powered Gmail inbox scanner. Fetches emails via Gmail API, analyzes them with Claude (security threats, categories, spam), generates an HTML report, and emails it to the owner daily via GitHub Actions.

## Owner
- **GitHub:** Arun4work-code
- **Report recipient:** work4aarun@gmail.com
- **Gmail API account:** Techifynow@gmail.com

## Repo
https://github.com/Arun4work-code/email-scanner-mcp

## Project Structure
```
src/
  types.ts          # All TypeScript interfaces (EmailCategory, ThreatLevel, etc.)
  gmail-client.ts   # Gmail API OAuth2 — fetchEmails(), sendReportEmail()
  analyzer.ts       # Claude claude-sonnet-4-6 analysis with prompt caching (batches of 15)
  scanner.ts        # Orchestration — runScan() returns ScanReport
  reporter.ts       # buildHtmlReport() + buildMarkdownReport()
  index.ts          # MCP server entry point (7 tools)
scripts/
  daily-scan.ts     # CI/CD entrypoint — scans, saves reports, emails digest
  get-refresh-token.ts  # One-time OAuth2 setup helper
.github/workflows/
  daily-scan.yml    # Cron: 06:30 UTC (12PM IST) daily
  ci.yml            # Build + type-check on push/PR
```

## Key Commands
```bash
npm run type-check      # TypeScript check (no emit)
npm run build           # Compile to dist/
npm run dev             # Run MCP server locally (needs .env)
npm run daily-scan      # Run the full scan pipeline locally
npm run get-token       # One-time: get Gmail OAuth2 refresh token
```

## Environment Variables (copy .env.example → .env)
| Variable | Purpose |
|----------|---------|
| `GMAIL_CLIENT_ID` | Google Cloud OAuth2 client ID |
| `GMAIL_CLIENT_SECRET` | Google Cloud OAuth2 client secret |
| `GMAIL_REFRESH_TOKEN` | OAuth2 refresh token (run `npm run get-token`) |
| `ANTHROPIC_API_KEY` | Claude API key |
| `REPORT_EMAIL` | work4aarun@gmail.com |
| `GMAIL_USER_EMAIL` | Techifynow@gmail.com |

## GitHub Secrets Required (same names as above)
Go to: https://github.com/Arun4work-code/email-scanner-mcp/settings/secrets/actions

## Current Status
- [x] Code complete and type-checks clean
- [x] Pushed to GitHub — workflows are live
- [ ] Gmail OAuth2 credentials not yet created
- [ ] GitHub Secrets not yet added
- [ ] End-to-end test not yet run

## Setup Checklist (do this to make it work)
1. **Google Cloud Console** → https://console.cloud.google.com/apis/credentials
   - Create project → Enable Gmail API
   - Create OAuth 2.0 Client ID (type: Desktop app)
   - Download Client ID + Client Secret

2. **Get refresh token locally:**
   ```bash
   GMAIL_CLIENT_ID=xxx GMAIL_CLIENT_SECRET=xxx npm run get-token
   ```

3. **Add GitHub Secrets** (5 total — see table above)

4. **Test manually:** GitHub → Actions → Daily Email Scan → Run workflow

## MCP Tools (exposed to Claude Code)
| Tool | What it does |
|------|-------------|
| `scan_emails` | Fetch + analyze last N hours of Gmail |
| `analyze_email` | Deep-analyze a single email by ID |
| `get_security_threats` | List all threats from last scan |
| `get_unsubscribe_candidates` | Senders to unsubscribe from |
| `get_deletion_candidates` | Emails to delete |
| `generate_report` | Full report in HTML/Markdown/JSON |
| `get_category_summary` | Category breakdown |

## Email Categories
personal, professional, financial, shopping, social, newsletter, promotional, travel, health, security_alert, spam, other

## Threat Levels
critical → high → medium → low → none
Exit code 2 from daily-scan.ts when critical threats found (triggers GitHub failure alert).

## Architecture Notes
- Emails fetched in parallel batches of 10 via Gmail API
- Claude analysis in batches of 15 with prompt caching on system prompt (reduces cost ~80% across batches)
- SPF/DKIM/DMARC parsed from Received headers for sender authentication checks
- Report artifacts retained 30 days in GitHub Actions

## Coding Conventions
- TypeScript ESM (`"type": "module"`)
- No comments unless WHY is non-obvious
- Arun is sole author on all commits — no Co-Authored-By lines
