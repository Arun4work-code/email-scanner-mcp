/**
 * One-time script to get Gmail OAuth2 refresh token.
 * Run: tsx scripts/get-refresh-token.ts
 * Follow the URL printed, paste the code, and save the refresh token.
 */

import { google } from "googleapis";
import * as readline from "readline";

const CLIENT_ID = process.env.GMAIL_CLIENT_ID;
const CLIENT_SECRET = process.env.GMAIL_CLIENT_SECRET;

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.error("Set GMAIL_CLIENT_ID and GMAIL_CLIENT_SECRET env vars first.");
  console.error("Get them from: https://console.cloud.google.com/apis/credentials");
  process.exit(1);
}

const oauth2Client = new google.auth.OAuth2(
  CLIENT_ID,
  CLIENT_SECRET,
  "urn:ietf:wg:oauth:2.0:oob"
);

const SCOPES = [
  "https://www.googleapis.com/auth/gmail.readonly",
  "https://www.googleapis.com/auth/gmail.send",
];

const authUrl = oauth2Client.generateAuthUrl({
  access_type: "offline",
  scope: SCOPES,
  prompt: "consent",
});

console.log("\n1. Open this URL in your browser:\n");
console.log(authUrl);
console.log("\n2. Sign in with your Google account and allow access.");
console.log("3. Copy the code shown and paste it below.\n");

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
rl.question("Enter the authorization code: ", async (code) => {
  rl.close();
  const { tokens } = await oauth2Client.getToken(code.trim());
  console.log("\n✅ Success! Add these to your .env and GitHub Secrets:\n");
  console.log(`GMAIL_CLIENT_ID=${CLIENT_ID}`);
  console.log(`GMAIL_CLIENT_SECRET=${CLIENT_SECRET}`);
  console.log(`GMAIL_REFRESH_TOKEN=${tokens.refresh_token}`);
  console.log(`\nAlso set:`);
  console.log(`ANTHROPIC_API_KEY=your-anthropic-api-key`);
  console.log(`REPORT_EMAIL=your-gmail@gmail.com`);
});
