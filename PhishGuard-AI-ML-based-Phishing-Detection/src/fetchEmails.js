const fs = require("fs");
const path = require("path");
const { google } = require("googleapis");
const axios = require("axios");
const whois = require("whois-json");

// Load credentials
const TOKEN_PATH = path.join(__dirname, "token.json");
const CREDENTIALS_PATH = path.join(__dirname, "client_secret.json");

// Authenticate Google API
async function authorize() {
    try {
        if (!fs.existsSync(CREDENTIALS_PATH)) {
            throw new Error(`Credentials file not found at: ${CREDENTIALS_PATH}`);
        }
        if (!fs.existsSync(TOKEN_PATH)) {
            throw new Error(`Token file not found at: ${TOKEN_PATH}`);
        }

        const credentials = JSON.parse(fs.readFileSync(CREDENTIALS_PATH, "utf8"));
        const { client_secret, client_id, redirect_uris } = credentials.installed;
        const token = JSON.parse(fs.readFileSync(TOKEN_PATH, "utf8"));

        const oAuth2Client = new google.auth.OAuth2(client_id, client_secret, redirect_uris[0]);
        oAuth2Client.setCredentials(token);
        return oAuth2Client;
    } catch (error) {
        console.error("Authentication error:", error.message);
        throw error;
    }
}

// Function to extract URLs from a string
function extractUrls(text) {
    const urlRegex = /(https?:\/\/[^\s]+)/g;
    return text.match(urlRegex) || [];
}

// Function to check URL against VirusTotal
async function checkPhishingUrl(url) {
    try {
        const apiKey = process.env.VIRUS_TOTAL_API_KEY || "2102dbc3e064715a75e41e6c821be0397fe35ad53c26c232b6e3a1ed27da2dbc";
        const response = await axios.get(`https://www.virustotal.com/vtapi/v2/url/report`, {
            params: { apikey: apiKey, resource: url },
            timeout: 5000
        });

        if (response.data.positives > 0) {
            return true;
        }
    } catch (error) {
        console.error(`Error checking URL: ${url}`, error.message);
    }
    return false;
}

// Check domain reputation using WHOIS
async function checkDomainReputation(url) {
    try {
        const domain = new URL(url).hostname;
        const whoisData = await whois(domain);
        if (whoisData.creationDate) {
            const domainAge = (new Date() - new Date(whoisData.creationDate)) / (1000 * 60 * 60 * 24);
            if (domainAge < 90) {
                return "Newly registered domain (potentially suspicious)";
            }
        }
        return "Domain age check passed";
    } catch (error) {
        console.error(`Error checking domain reputation for ${url}:`, error.message);
        return "Domain reputation check failed";
    }
}

// Detect phishing patterns
function detectPhishingPatterns(text) {
    const phishingKeywords = [
        "verify your account",
        "urgent action required",
        "password expired",
        "click here to reset",
        "suspicious activity detected",
        "update your payment information",
    ];

    const lowerText = text.toLowerCase();
    const detectedKeywords = phishingKeywords.filter(keyword => lowerText.includes(keyword));

    return {
        detected: detectedKeywords.length > 0,
        keywords: detectedKeywords
    };
}

// Extract email body safely
function extractEmailBody(payload) {
    let emailBody = "";

    if (payload?.body?.data) {
        return Buffer.from(payload.body.data, "base64").toString("utf-8");
    }

    if (payload?.parts) {
        for (const part of payload.parts) {
            if (part.mimeType === "text/plain" && part.body?.data) {
                return Buffer.from(part.body.data, "base64").toString("utf-8");
            }
        }

        for (const part of payload.parts) {
            if (part.mimeType === "text/html" && part.body?.data) {
                const htmlBody = Buffer.from(part.body.data, "base64").toString("utf-8");
                return htmlBody.replace(/<[^>]*>?/gm, ' ');
            }
        }

        for (const part of payload.parts) {
            if (part.parts) {
                const nestedBody = extractEmailBody(part);
                if (nestedBody) return nestedBody;
            }
        }
    }

    return emailBody;
}

// Fetch and analyze up to 100 emails
async function fetchEmails() {
    try {
        console.log("Starting to fetch emails...");

        const auth = await authorize();
        console.log("Authorization successful");

        const gmail = google.gmail({ version: "v1", auth });
        console.log("Gmail API initialized");

// Take limit 
        const res = await gmail.users.messages.list({
            userId: "me",
            maxResults: 10,
        });
        console.log("Fetched message list from Gmail");

        const messages = res.data.messages || [];
        if (messages.length === 0) {
            return { message: "No emails found." };
        }

        const emailData = [];
        console.log(`Processing ${messages.length} emails...`);

        for (const msg of messages) {
            console.log(`Fetching details for message ID: ${msg.id}`);
            const email = await gmail.users.messages.get({ userId: "me", id: msg.id });

            const headers = email.data.payload.headers;
            const from = headers.find(h => h.name === "From")?.value || "Unknown";
            const subject = headers.find(h => h.name === "Subject")?.value || "No Subject";
            const snippet = email.data.snippet || "";

            console.log(`Processing email from: ${from}, subject: ${subject}`);
            const emailBody = extractEmailBody(email.data.payload);

            const urls = extractUrls(emailBody);
            console.log(`Found ${urls.length} URLs in email`);

            const phishingUrls = [];

            for (const url of urls) {
                console.log(`Checking URL: ${url}`);
                const isPhishing = await checkPhishingUrl(url);
                if (isPhishing) {
                    console.log(`⚠️ Phishing URL detected: ${url}`);
                    phishingUrls.push(url);
                }
            }

            console.log("Checking domain reputations...");
            const domainReputations = await Promise.all(
                urls.map(async (url) => {
                    const reputation = await checkDomainReputation(url);
                    return { url, reputation };
                })
            );

            console.log("Checking for phishing patterns in email content...");
            const phishingPatternResult = detectPhishingPatterns(emailBody);
            const isPhishingEmail = phishingPatternResult.detected || phishingUrls.length > 0;

            emailData.push({
                from,
                subject,
                snippet,
                urls,
                phishingUrls,
                domainReputations,
                phishingPatterns: phishingPatternResult,
                isPhishingEmail
            });

            console.log(`Email analysis complete. Phishing detected: ${isPhishingEmail ? "YES" : "NO"}`);
        }

        console.log("All emails processed successfully");
        return emailData;
    } catch (error) {
        console.error("Detailed error in fetchEmails:", error);
        if (error.stack) console.error(error.stack);

        if (error.message && error.message.includes("Credentials file not found")) {
            return { error: "Missing Google API credentials file" };
        } else if (error.message && error.message.includes("Token file not found")) {
            return { error: "Missing Google API token file" };
        } else if (error.code === 'ENOTFOUND') {
            return { error: "Network connection issue" };
        } else {
            return { error: `Failed to fetch emails: ${error.message || "Unknown error"}` };
        }
    }
}

// Export the function
module.exports = fetchEmails;
