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
        // Check if credential files exist
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

// Function to check URL against a phishing database (Google Safe Browsing API or PhishTank)
async function checkPhishingUrl(url) {
    try {
        // Replace with your actual VirusTotal API key
        const apiKey = process.env.VIRUS_TOTAL_API_KEY || "YOUR_API_KEY_HERE";
        
        if (apiKey === "YOUR_API_KEY_HERE") {
            console.warn("Warning: Using placeholder API key for VirusTotal. API requests will fail.");
        }
        
        const response = await axios.get(`https://www.virustotal.com/vtapi/v2/url/report`, {
            params: {
                apikey: apiKey,
                resource: url,
            },
            timeout: 5000 // Add timeout to prevent hanging
        });

        if (response.data.positives > 0) {
            return true; // URL is flagged as phishing
        }
    } catch (error) {
        console.error(`Error checking URL: ${url}`, error.message);
    }
    return false; // URL is not flagged
}

// Function to check domain reputation using WHOIS lookup
async function checkDomainReputation(url) {
    try {
        const domain = new URL(url).hostname;
        const whoisData = await whois(domain);

        if (whoisData.creationDate) {
            const domainAge = (new Date() - new Date(whoisData.creationDate)) / (1000 * 60 * 60 * 24); // Age in days
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

// Function to analyze email for phishing patterns
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

// Helper function to safely extract email body
function extractEmailBody(payload) {
    let emailBody = "";
    
    // Case 1: Body data directly available
    if (payload?.body?.data) {
        return Buffer.from(payload.body.data, "base64").toString("utf-8");
    }
    
    // Case 2: Multipart message
    if (payload?.parts) {
        // Look for text/plain part first
        for (const part of payload.parts) {
            if (part.mimeType === "text/plain" && part.body?.data) {
                return Buffer.from(part.body.data, "base64").toString("utf-8");
            }
        }
        
        // If no text/plain, try text/html
        for (const part of payload.parts) {
            if (part.mimeType === "text/html" && part.body?.data) {
                const htmlBody = Buffer.from(part.body.data, "base64").toString("utf-8");
                // Strip HTML tags for basic text analysis
                return htmlBody.replace(/<[^>]*>?/gm, ' ');
            }
        }
        
        // If still no body found, try to go deeper into nested parts
        for (const part of payload.parts) {
            if (part.parts) {
                const nestedBody = extractEmailBody(part);
                if (nestedBody) return nestedBody;
            }
        }
    }
    
    return emailBody;
}

// Fetch emails from Gmail and analyze for phishing
async function fetchEmails() {
    try {
        // Add detailed logging
        console.log("Starting to fetch emails...");
        
        const auth = await authorize();
        console.log("Authorization successful");
        
        const gmail = google.gmail({ version: "v1", auth });
        console.log("Gmail API initialized");

        const res = await gmail.users.messages.list({
            userId: "me",
            maxResults: 5, // Fetch latest 5 emails
        });
        console.log("Fetched message list from Gmail");

        const messages = res.data.messages || [];
        if (messages.length === 0) {
            return { message: "No emails found." };
        }

        // Fetch full email details
        const emailData = [];
        console.log(`Processing ${messages.length} emails...`);
        
        for (const msg of messages) {
            console.log(`Fetching details for message ID: ${msg.id}`);
            const email = await gmail.users.messages.get({ userId: "me", id: msg.id });
            
            // Extract important fields
            const headers = email.data.payload.headers;
            const from = headers.find(h => h.name === "From")?.value || "Unknown";
            const subject = headers.find(h => h.name === "Subject")?.value || "No Subject";
            const snippet = email.data.snippet || ""; // Short preview of the email content
            
            console.log(`Processing email from: ${from}, subject: ${subject}`);
            
            // Extract email body with improved extraction function
            const emailBody = extractEmailBody(email.data.payload);

            // Extract URLs from the email body
            const urls = extractUrls(emailBody);
            console.log(`Found ${urls.length} URLs in email`);
            
            const phishingUrls = [];

            // Check each URL for phishing
            for (const url of urls) {
                console.log(`Checking URL: ${url}`);
                const isPhishing = await checkPhishingUrl(url);
                if (isPhishing) {
                    console.log(`⚠️ Phishing URL detected: ${url}`);
                    phishingUrls.push(url);
                }
            }

            // Check domain reputation for all URLs
            console.log("Checking domain reputations...");
            const domainReputations = await Promise.all(
                urls.map(async (url) => {
                    const reputation = await checkDomainReputation(url);
                    return { url, reputation };
                })
            );

            // Detect phishing patterns in the email content
            console.log("Checking for phishing patterns in email content...");
            const phishingPatternResult = detectPhishingPatterns(emailBody);

            // Mark email as suspicious if any phishing signs are detected
            const isPhishingEmail = phishingPatternResult.detected || phishingUrls.length > 0;

            // Add to results
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
        
        // Return more specific error messages for different failure cases
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

// Export the main function
module.exports = fetchEmails;