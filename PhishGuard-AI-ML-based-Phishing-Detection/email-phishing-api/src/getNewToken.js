const fs = require('fs');
const readline = require('readline');
const { google } = require('googleapis');
const path = require('path');

const CREDENTIALS_PATH = path.join(__dirname, 'client_secret.json');
const TOKEN_PATH = path.join(__dirname, 'token.json');

async function getNewToken() {
  const content = fs.readFileSync(CREDENTIALS_PATH, 'utf8');
  const credentials = JSON.parse(content).installed;

  const oAuth2Client = new google.auth.OAuth2(
    credentials.client_id,
    credentials.client_secret,
    credentials.redirect_uris[0]
  );

  const authUrl = oAuth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: ['https://www.googleapis.com/auth/gmail.readonly'], // or modify based on your need
  });

  console.log('Authorize this app by visiting this URL:\n', authUrl);

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  rl.question('\nEnter the code from that page here: ', async (code) => {
    rl.close();
    try {
      const { tokens } = await oAuth2Client.getToken(code);
      oAuth2Client.setCredentials(tokens);
      fs.writeFileSync(TOKEN_PATH, JSON.stringify(tokens));
      console.log('\n✅ Token stored to', TOKEN_PATH);
    } catch (err) {
      console.error('Error retrieving access token', err);
    }
  });
}

getNewToken();
