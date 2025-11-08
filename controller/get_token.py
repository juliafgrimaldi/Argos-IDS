from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

SCOPES = ['https://www.googleapis.com/auth/gmail.send']

credentials_file = 'credentials.json'

flow = InstalledAppFlow.from_client_secrets_file(credentials_file, SCOPES)

creds = flow.run_local_server(port=8080)

with open('token.json', 'w') as token:
    token.write(creds.to_json())

service = build('gmail', 'v1', credentials=creds)
