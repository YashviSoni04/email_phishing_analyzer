const fs = require('fs');
const path = require('path');
const { google } = require('googleapis');
const express = require('express');

const SCOPES = ['https://www.googleapis.com/auth/gmail.readonly'];
const CREDENTIALS_PATH = path.join(__dirname, 'client_secret.json');
const TOKEN_PATH = path.join(__dirname, 'token.json');

const credentials = JSON.parse(fs.readFileSync(CREDENTIALS_PATH));
const { client_secret, client_id, redirect_uris } = credentials.installed;
const oAuth2Client = new google.auth.OAuth2(client_id, client_secret, redirect_uris[0]);

const app = express();

// 🔗 Step 1: Generate and open the URL
const authUrl = oAuth2Client.generateAuthUrl({
  access_type: 'offline',
  scope: SCOPES,
  prompt: 'consent',
});
console.log('\n🔗 Authorize this app by visiting this URL:\n', authUrl);

// 🚪 Step 2: Create a temporary server to receive the code
app.get('/oauth2callback', async (req, res) => {
  const code = req.query.code;
  if (!code) {
    res.send('❌ No code found in URL');
    return;
  }

  try {
    const { tokens } = await oAuth2Client.getToken(code);
    oAuth2Client.setCredentials(tokens);
    fs.writeFileSync(TOKEN_PATH, JSON.stringify(tokens, null, 2));
    res.send('✅ Authorization successful! You can close this window.');
    console.log('\n✅ Token stored to', TOKEN_PATH);
    server.close(); // Close server after success
  } catch (err) {
    console.error('❌ Error retrieving access token:', err.message);
    res.send('❌ Failed to get access token');
  }
});

// 🔊 Step 3: Start server
const server = app.listen(3000, () => {
  console.log('\n🚀 Waiting for OAuth2 callback at http://localhost:3000/oauth2callback ...');
});
