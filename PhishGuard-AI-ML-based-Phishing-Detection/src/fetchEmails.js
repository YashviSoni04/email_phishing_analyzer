const fs = require("fs");
const path = require("path");
const { google } = require("googleapis");

// File paths
const TOKEN_PATH = path.join(__dirname, "token.json");
const CREDENTIALS_PATH = path.join(__dirname, "client_secret.json");

// Helper to authorize Gmail API
async function authorize() {
  if (!fs.existsSync(CREDENTIALS_PATH)) throw new Error("Missing credentials.json");
  if (!fs.existsSync(TOKEN_PATH)) throw new Error("Missing token.json");

  const credentials = JSON.parse(fs.readFileSync(CREDENTIALS_PATH, "utf8"));
  const token = JSON.parse(fs.readFileSync(TOKEN_PATH, "utf8"));
  const { client_secret, client_id, redirect_uris } = credentials.installed;

  const oAuth2Client = new google.auth.OAuth2(client_id, client_secret, redirect_uris[0]);
  oAuth2Client.setCredentials(token);
  return oAuth2Client;
}

// Extract plain text body
function extractEmailBody(payload) {
  if (payload?.body?.data) {
    return Buffer.from(payload.body.data, "base64").toString("utf8");
  }

  if (payload?.parts) {
    for (const part of payload.parts) {
      if (part.mimeType === "text/plain" && part.body?.data) {
        return Buffer.from(part.body.data, "base64").toString("utf8");
      }
    }

    for (const part of payload.parts) {
      if (part.mimeType === "text/html" && part.body?.data) {
        return Buffer.from(part.body.data, "base64").toString("utf8").replace(/<[^>]+>/g, " ");
      }
    }

    for (const part of payload.parts) {
      if (part.parts) {
        const nested = extractEmailBody(part);
        if (nested) return nested;
      }
    }
  }

  return "";
}

// Main fetch function
async function fetchEmails() {
  try {
    const auth = await authorize();
    const gmail = google.gmail({ version: "v1", auth });

    const res = await gmail.users.messages.list({
      userId: "me",
      maxResults: 5,
    });

    const messages = res.data.messages || [];
    if (messages.length === 0) return [];

    const results = [];
    for (const msg of messages) {
      const full = await gmail.users.messages.get({ userId: "me", id: msg.id });
      const headers = full.data.payload.headers;
      const from = headers.find(h => h.name === "From")?.value || "Unknown";
      const subject = headers.find(h => h.name === "Subject")?.value || "No Subject";
      const snippet = full.data.snippet || "";
      const body = extractEmailBody(full.data.payload);

      // Placeholder phishing detection
      const isPhishing = body.toLowerCase().includes("password") || subject.toLowerCase().includes("verify");

      results.push({
        from,
        subject,
        snippet,
        isPhishingEmail: isPhishing,
        reasons: isPhishing ? ["Basic keyword flag (e.g., 'password')"] : [],
        suspiciousScore: isPhishing ? 2 : 0
      });
    }

    return results;
  } catch (err) {
    console.error("fetchEmails error:", err.message);
    return [];
  }
}

module.exports = fetchEmails;
