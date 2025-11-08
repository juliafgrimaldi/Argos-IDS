import os
import base64
from email.message import EmailMessage
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from typing import List

SCOPES = ['https://www.googleapis.com/auth/gmail.send']

def _paths():
    base = os.path.dirname(os.path.abspath(__file__))
    cred = os.getenv("GMAIL_CREDENTIALS_FILE", os.path.join(base, "credentials.json"))
    token = os.getenv("GMAIL_TOKEN_FILE", os.path.join(base, "token.json"))
    return cred, token

def get_gmail_service():
    credentials_file, token_file = _paths()

    if not os.path.exists(credentials_file):
        raise FileNotFoundError(f"Credenciais do Gmail não encontradas em {credentials_file}")
    
    creds = None
    if os.path.exists(token_file):
        creds = Credentials.from_authorized_user_file(token_file, SCOPES)
    
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request()) 
        else:
            flow = InstalledAppFlow.from_client_secrets_file(credentials_file, SCOPES)
            creds = flow.run_local_server(port=0)
        
        with open(token_file, 'w') as token:
            token.write(creds.to_json())
    
    return build('gmail', 'v1', credentials=creds)

def send_gmail(subject: str, body: str, to_list: List[str], sender_alias: str | None = None):
    if not to_list:
        raise ValueError("A lista de destinatários não pode estar vazia.")
    
    msg = EmailMessage()
    msg['To'] = ", ".join(to_list)
    if sender_alias:
        msg['From'] = sender_alias
    msg['Subject'] = subject
    msg.set_content(body)
    
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode('utf-8')
    
    try:
        service = get_gmail_service()
        result = service.users().messages().send(userId='me', body={'raw': raw}).execute()
        return result
    except Exception as error:
        raise RuntimeError(f"Erro ao enviar e-mail: {error}")

