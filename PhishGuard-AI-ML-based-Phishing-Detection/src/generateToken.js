const fs = require("fs");
const path = require("path");
const readline = require("readline");
const { google } = require("googleapis");

const SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"];
const TOKEN_PATH = path.join(__dirname, "token.json");
const CREDENTIALS_PATH = path.join(__dirname, "client_secret.json");

function authorize(credentials, callback) {
  const { client_secret, client_id, redirect_uris } = credentials.installed;

  // 👇 Using the OOB (manual copy-paste) flow
  const oAuth2Client = new google.auth.OAuth2(client_id, client_secret, "urn:ietf:wg:oauth:2.0:oob");

  const authUrl = oAuth2Client.generateAuthUrl({
    access_type: "offline",
    scope: SCOPES,
  });

  console.log("🔗 Authorize this app by visiting this URL:\n", authUrl);

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  rl.question("\n📥 Paste the code from that page here: ", (code) => {
    rl.close();
    oAuth2Client.getToken(code, (err, token) => {
      if (err) return console.error("❌ Error retrieving token:", err);
      oAuth2Client.setCredentials(token);
      fs.writeFileSync(TOKEN_PATH, JSON.stringify(token));
      console.log("✅ Token stored at", TOKEN_PATH);
    });
  });
}

function main() {
  const content = fs.readFileSync(CREDENTIALS_PATH);
  const credentials = JSON.parse(content);
  authorize(credentials);
}

main();
