from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import os
import json

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def save_credentials(creds, token_path='credentials/token.json'):
    """Save credentials to file"""
    token_data = {
        'token': creds.token,
        'refresh_token': creds.refresh_token,
        'token_uri': creds.token_uri,
        'client_id': creds.client_id,
        'client_secret': creds.client_secret,
        'scopes': creds.scopes
    }
    with open(token_path, 'w') as token_file:
        json.dump(token_data, token_file)

def load_credentials(token_path='credentials/token.json'):
    """Load credentials from file"""
    if not os.path.exists(token_path):
        return None
    
    with open(token_path) as token_file:
        token_data = json.load(token_file)
        return Credentials(
            token=token_data['token'],
            refresh_token=token_data['refresh_token'],
            token_uri=token_data['token_uri'],
            client_id=token_data['client_id'],
            client_secret=token_data['client_secret'],
            scopes=token_data['scopes']
        )

def authenticate():
    """Authenticate with Gmail API"""
    creds = load_credentials()
    
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not os.path.exists('credentials/client_secret.json'):
                raise FileNotFoundError(
                    "Client secrets file not found. Please download it from "
                    "Google Cloud Console and save as 'credentials/client_secret.json'"
                )
            
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials/client_secret.json', SCOPES)
            creds = flow.run_local_server(port=0)
        
        save_credentials(creds)
    
    return build('gmail', 'v1', credentials=creds)

def list_messages(service, user_id='me', query=''):
    """List messages in the user's mailbox"""
    try:
        response = service.users().messages().list(
            userId=user_id, q=query, maxResults=10
        ).execute()
        
        messages = response.get('messages', [])
        return messages
    except Exception as error:
        print(f'An error occurred: {error}')
        return []

if __name__ == '__main__':
    try:
        # Test authentication
        service = authenticate()
        print("Authentication successful!")
        
        # Test listing messages
        messages = list_messages(service)
        print(f"Found {len(messages)} messages")
        
        if messages:
            # Get first message details
            msg = service.users().messages().get(
                userId='me', id=messages[0]['id']
            ).execute()
            print(f"First message subject: {msg['snippet'][:50]}...")
            
    except Exception as e:
        print(f"Error: {str(e)}")
