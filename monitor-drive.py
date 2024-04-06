import argparse
import json
import os.path
import string
import random
import time

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


SCOPES = ["https://www.googleapis.com/auth/drive"]


def art():
    return """
             ___________________
            /                   \\
           /     ___     ___     \\
          /     /   \\   /   \\     \\
         /     /     \\ /     \\     \\
        /     /_______V_______\\     \\
       /     /  \\           /  \\     \\
      /     /    \\         /    \\     \\
     /     /      \\       /      \\     \\
    /     /        \\     /        \\     \\
   /     /__________\\   /__________\\     \\
  /                                       \\
 /           Google Drive Monitor          \\
/               By Tamir Yehuda             \\
\\___________________________________________/

"""


def connect_to_drive_api(credentials_file, token_file=None):
    creds = None
    if token_file and os.path.exists(token_file):
        creds = Credentials.from_authorized_user_file(token_file, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                credentials_file, SCOPES)
            creds = flow.run_local_server(port=0)
        with open("token.json", 'w') as token:
            token.write(creds.to_json())
    return build('drive', 'v3', credentials=creds)


def generate_random_string():
    """Generate a random string of fixed length."""
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(10))


def enumerate_sharing_settings(session, test_email, test_domain, test_group_id):
    """
        Create a test file and try different sharing settings to determine the current set sharing settings.
    """
    file_name = f"testfile-{generate_random_string()}"
    file_metadata = {
        'name': f'{file_name}',
        'mimeType': 'text/plain'
    }
    try:
        print(
            "[!] Creating a test file to enumerate available sharing configurations...")
        file = session.files().create(body=file_metadata, fields='id').execute()
        file_id = file.get('id')
        print(f"[+] Created file {file_name} with ID {file_id}")
        print(
            f"[!] Testing sharing settings against Email: {test_email}, Domain: {test_domain}, Group ID: {test_group_id}")

        types_and_roles = [
            ('user', 'reader'),
            ('user', 'commenter'),
            ('user', 'writer'),
            ('domain', 'reader'),
            ('domain', 'commenter'),
            ('domain', 'writer'),
            ('anyone', 'reader'),
            ('anyone', 'commenter'),
            ('anyone', 'writer'),
            ('group', 'reader'),
            ('group', 'commenter'),
            ('group', 'writer')
        ]

        sharing_results = []
        for type_, role in types_and_roles:
            body = {
                'type': type_,
                'role': role,
                'emailAddress': test_email if type_ in ['user'] else None,
                'domain': test_domain if type_ == 'domain' else None
            }
            if type_ == 'group':
                body['emailAddress'] = test_group_id

            try:
                session.permissions().create(
                    fileId=file_id,
                    body={k: v for k, v in body.items() if v is not None},
                    fields='id').execute()
                sharing_results.append(
                    f"[+] Success: {type_} with role {role}")
            except HttpError as error:
                error_content = error.content.decode("utf-8")
                error_json = json.loads(error_content)
                error_message = error_json.get("error").get("errors")[
                    0].get("message")
                sharing_results.append(
                    f"[-] Failed: {type_} with role {role} - {error_message}")

        print("[+] Enumerated sharing policy:")
        print("-------------------------------------")
        for result in sharing_results:
            print(result)
        print("-------------------------------------")

    except HttpError as error:
        print(f'[-] An error occurred: {error}')

    try:
        session.files().delete(fileId=file_id).execute()
        print(f"[+] Deleted test file {file_id}")
    except HttpError as error:
        print(f"[-] Failed to delete test file {file_id}: {error}")


def enumerate_publicly_accessible_folders(session):
    """
        List all folders and check for each folder if it is publicly accessible.
        Returns a list of publicly accessible folders.
    """
    try:
        print("[+] Enumerating publicly accessible folders....")
        query = "mimeType = 'application/vnd.google-apps.folder' and trashed = false"
        results = session.files().list(q=query,
                                       spaces='drive',
                                       fields='nextPageToken, files(id, name, permissions)').execute()
        folders = results.get('files', [])
        public_folders = []

        for folder in folders:
            for permission in folder.get('permissions', []):
                if permission.get('type') == 'anyone':
                    print(
                        f"[!] Folder {folder['name']} ({folder['id']}) is publicly accessible, adding it to watch list")
                    public_folders.append(folder)
                    break

        return public_folders
    except HttpError as error:
        print(f'An error occurred: {error}')
        return []


def monitor_public_folders_change_new_file_permissions(session, folders, sleep_period):
    """
        Monitor specified folders and adjust permissions of new files to private.
    """
    known_files = {}
    for folder in folders:
        known_files[folder['id']] = []
        query = f"'{folder['id']}' in parents and trashed = false"
        results = session.files().list(q=query,
                                       spaces='drive',
                                       fields='nextPageToken, files(id, name, permissions)').execute()
        files = results.get('files', [])
        for file in files:
            known_files[folder['id']].append(file['id'])
    start_scan_time = time.time()
    rescan = False
    while not rescan:
        try:
            for folder in folders:
                query = f"'{folder['id']}' in parents and trashed = false"
                results = session.files().list(q=query,
                                               spaces='drive',
                                               fields='nextPageToken, files(id, name, permissions)').execute()
                files = results.get('files', [])

                for file in files:
                    if file['id'] not in known_files[folder['id']]:

                        print(
                            f"[!] New file detected: {file['name']} in folder: {folder['name']}")
                        for permission in file.get('permissions', []):
                            if permission.get('type') == 'anyone':
                                try:
                                    session.permissions().delete(
                                        fileId=file['id'], permissionId=permission['id']).execute()
                                    print(
                                        f"[+] Made file private: {file['name']} ({file['id']})")
                                except HttpError as error:
                                    print(
                                        f"[-] Failed to change permission for {file['name']}: {error}")
                        known_files[folder['id']].append(file['id'])

            time.sleep(sleep_period)
            current_time = time.time()
            if current_time - start_scan_time > 1800:
                print("[!] Rescannig the Drive for publicly accessible folders")
                rescan = True
        except HttpError as error:
            print(f'[-] An error occurred: {error}')

    new_public_folders = enumerate_publicly_accessible_folders(session)
    monitor_public_folders_change_new_file_permissions(
        session, new_public_folders, sleep_period)


def main():
    try:
        print(art())
        parser = argparse.ArgumentParser(
            description='Enumerate Google Drive enforced sharing permissions and public accessible folders. monitor public accessible folders and adjust access permissions for new files inisde them to private.')
        parser.add_argument('-c', '--credentials_file', type=str,
                            required=True, help='Path to the credentials file')
        parser.add_argument('-t', '--token_file', type=str,
                            help='Path to the token file (optional)')
        parser.add_argument('-e', '--test_email', type=str,
                            help='Email address to test sharing options against (optional)', default='email@example.com')
        parser.add_argument('-d', '--test_domain', type=str,
                            help='domain to test sharing options against (optional)', default='google.com')
        parser.add_argument('-g', '--test_group_id', type=str,
                            help='group id to test sharing options against (optional)', default='testvaronis123@googlegroups.com')
        parser.add_argument('-s', '--sleep_period', type=int,
                            help='sleep period for new file creation monitoring, default is 10 seconds. Adjust to reduce API calls according to rate limit (optional)', default=10)

        args = parser.parse_args()
        if os.path.exists(args.credentials_file):
            session = connect_to_drive_api(
                args.credentials_file, args.token_file)
            enumerate_sharing_settings(
                session, args.test_email, args.test_domain, args.test_group_id)
            public_folders = enumerate_publicly_accessible_folders(session)
            print(
                f"[+] Found {len(public_folders)} publicly accessible folders to monitor.")
            if public_folders:
                monitor_public_folders_change_new_file_permissions(
                    session, public_folders, args.sleep_period)
            else:
                print("[!] No publicly accessible folder found")
                print("[-] Bye :)")
        else:
            print("[-] The credentials file path you supplied does not exist!")

    except KeyboardInterrupt:
        print("\n[!] Script interrupted by user. Exiting gracefully...")
        print("[-] Bye :)")


if __name__ == "__main__":
    main()
