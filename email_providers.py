from typing import Optional, List, Dict
import base64
from datetime import datetime
import json
import os
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from msal import ConfidentialClientApplication
import requests
from email import message_from_bytes
from email.utils import parsedate_to_datetime
import logging

logger = logging.getLogger(__name__)

# Gmail API configuration
GMAIL_SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
GMAIL_CREDENTIALS_FILE = 'credentials/gmail_credentials.json'
GMAIL_TOKEN_FILE = 'credentials/gmail_token.json'

# Microsoft Graph API configuration
GRAPH_SCOPES = ['Mail.Read']
GRAPH_CREDENTIALS = {
    'client_id': os.getenv('MICROSOFT_CLIENT_ID'),
    'client_secret': os.getenv('MICROSOFT_CLIENT_SECRET'),
    'authority': 'https://login.microsoftonline.com/common'
}

class EmailMessage:
    def __init__(self, 
                 message_id: str,
                 sender: str,
                 subject: str,
                 content: str,
                 received_date: datetime,
                 urls: List[str],
                 attachments: List[Dict],
                 headers: Dict):
        self.message_id = message_id
        self.sender = sender
        self.subject = subject
        self.content = content
        self.received_date = received_date
        self.urls = urls
        self.attachments = attachments
        self.headers = headers

class GmailProvider:
    def __init__(self):
        self.service = None
        self._authenticate()

    def _authenticate(self):
        creds = None
        if os.path.exists(GMAIL_TOKEN_FILE):
            with open(GMAIL_TOKEN_FILE, 'r') as token:
                creds = Credentials.from_authorized_user_file(GMAIL_TOKEN_FILE, GMAIL_SCOPES)

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(GMAIL_CREDENTIALS_FILE, GMAIL_SCOPES)
                creds = flow.run_local_server(port=0)
            
            with open(GMAIL_TOKEN_FILE, 'w') as token:
                token.write(creds.to_json())

        self.service = build('gmail', 'v1', credentials=creds)

    def _extract_urls(self, content: str) -> List[str]:
        from bs4 import BeautifulSoup
        import re

        urls = []
        # Extract URLs from HTML content
        soup = BeautifulSoup(content, 'html.parser')
        for link in soup.find_all('a'):
            url = link.get('href')
            if url and url.startswith(('http://', 'https://')):
                urls.append(url)

        # Extract URLs from plain text
        text_content = soup.get_text()
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls.extend(re.findall(url_pattern, text_content))

        return list(set(urls))

    def get_email(self, message_id: str) -> EmailMessage:
        try:
            message = self.service.users().messages().get(
                userId='me',
                id=message_id,
                format='full'
            ).execute()

            headers = {header['name']: header['value'] 
                     for header in message['payload']['headers']}

            sender = headers.get('From', '')
            subject = headers.get('Subject', '')
            received_date = parsedate_to_datetime(headers.get('Date', ''))

            # Get email content
            if 'parts' in message['payload']:
                parts = message['payload']['parts']
                content = ''
                attachments = []

                for part in parts:
                    if part['mimeType'] == 'text/html':
                        data = base64.urlsafe_b64decode(part['body']['data']).decode()
                        content = data
                    elif part['mimeType'].startswith('application/') or part['mimeType'].startswith('image/'):
                        attachment_data = self.service.users().messages().attachments().get(
                            userId='me',
                            messageId=message_id,
                            id=part['body']['attachmentId']
                        ).execute()
                        
                        attachments.append({
                            'filename': part['filename'],
                            'mimeType': part['mimeType'],
                            'content': attachment_data['data']
                        })
            else:
                content = base64.urlsafe_b64decode(
                    message['payload']['body']['data']
                ).decode()
                attachments = []

            # Extract URLs from content
            urls = self._extract_urls(content)

            return EmailMessage(
                message_id=message_id,
                sender=sender,
                subject=subject,
                content=content,
                received_date=received_date,
                urls=urls,
                attachments=attachments,
                headers=headers
            )

        except Exception as e:
            logger.error(f"Error fetching Gmail message: {str(e)}")
            raise

class OutlookProvider:
    def __init__(self):
        self.app = ConfidentialClientApplication(
            GRAPH_CREDENTIALS['client_id'],
            authority=GRAPH_CREDENTIALS['authority'],
            client_credential=GRAPH_CREDENTIALS['client_secret']
        )
        self.token = None
        self._authenticate()

    def _authenticate(self):
        try:
            self.token = self.app.acquire_token_silent(GRAPH_SCOPES, account=None)
            if not self.token:
                self.token = self.app.acquire_token_for_client(scopes=GRAPH_SCOPES)
        except Exception as e:
            logger.error(f"Error authenticating with Microsoft Graph: {str(e)}")
            raise

    def _extract_urls(self, content: str) -> List[str]:
        from bs4 import BeautifulSoup
        import re

        urls = []
        # Extract URLs from HTML content
        soup = BeautifulSoup(content, 'html.parser')
        for link in soup.find_all('a'):
            url = link.get('href')
            if url and url.startswith(('http://', 'https://')):
                urls.append(url)

        # Extract URLs from plain text
        text_content = soup.get_text()
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls.extend(re.findall(url_pattern, text_content))

        return list(set(urls))

    def get_email(self, message_id: str) -> EmailMessage:
        try:
            if not self.token:
                self._authenticate()

            # Get message
            headers = {
                'Authorization': f"Bearer {self.token['access_token']}",
                'Content-Type': 'application/json'
            }
            
            response = requests.get(
                f"https://graph.microsoft.com/v1.0/me/messages/{message_id}",
                headers=headers
            )
            response.raise_for_status()
            message = response.json()

            # Get attachments
            attachments_response = requests.get(
                f"https://graph.microsoft.com/v1.0/me/messages/{message_id}/attachments",
                headers=headers
            )
            attachments_response.raise_for_status()
            attachments_data = attachments_response.json()

            attachments = []
            for attachment in attachments_data.get('value', []):
                attachments.append({
                    'filename': attachment['name'],
                    'mimeType': attachment.get('contentType', 'application/octet-stream'),
                    'content': attachment['contentBytes']
                })

            # Extract URLs from content
            urls = self._extract_urls(message['body']['content'])

            return EmailMessage(
                message_id=message['id'],
                sender=message['from']['emailAddress']['address'],
                subject=message['subject'],
                content=message['body']['content'],
                received_date=datetime.fromisoformat(message['receivedDateTime'].replace('Z', '+00:00')),
                urls=urls,
                attachments=attachments,
                headers={
                    'messageId': message.get('internetMessageId', ''),
                    'from': message['from']['emailAddress']['address'],
                    'to': [r['emailAddress']['address'] for r in message['toRecipients']],
                    'cc': [r['emailAddress']['address'] for r in message.get('ccRecipients', [])],
                    'receivedDateTime': message['receivedDateTime']
                }
            )

        except Exception as e:
            logger.error(f"Error fetching Outlook message: {str(e)}")
            raise
