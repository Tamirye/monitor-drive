# Google Drive Monitor

This Python script is designed enumerate the enforced Google Drive file sharing settings in a given Google account, find all publicly accessible folders and monitor them for new files. If a new file is added to a publicly accessible folder, the file permissions are adjusted to keep it private.

## Prerequisites

- **Python Environment**: Ensure Python 3.7 or higher is installed on your system.

Before running this script, you must have an enabled Google Drive API and a credentials file to connect to it. If you don't have those,
Complete the following steps to enable the Google Drive API and create the necessary credentials:

1. **Google Account**: Ensure you have a Google account, if not, create one:

   - Navigate to [Create Google Account Page](https://accounts.google.com/signup) and create an account.

2. **Google Cloud Project**: Ensure you have a Google Cloud Project. If not, create one:

   - Navigate to the [Google API Console](https://console.developers.google.com/) and choose your organization (if you are a part of one).
   - Create a new project, if you are restricted from doing so, contact your administrators.

3. **Enable the Google Drive API**:

   - Navigate to the [Google API Console](https://console.developers.google.com/).
   - Select your project.
   - Click on “Library”.
   - Search for “Google Drive API”, select it, and click “Enable”.

4. **Create OAuth Consent**:

   - Navigate to the [Google API Console](https://console.developers.google.com/).
   - Select your project.
   - Click on “OAuth consent screen".
   - For User type select Internal for account that is a member of an organization (or Google Workspace), and External otherwise. Then click Create.
   - Complete the app registration form, then click Save and Continue.
   - Add the authorization scopes that the application requires (/auth/drive).

5. **Create Credentials**:
   - Navigate to the [Google API Console](https://console.developers.google.com/).
   - Select your project.
   - Click on “Credentials”.
   - Click “Create Credentials” and select “OAuth client ID”.
   - Choose the application type “Desktop app” and give it a name.
   - Once created, you can download the credentials file by clicking the download button (JSON format).

After completing these steps, you should have a `credentials.json` file, which is required to authenticate and authorize the script to access your Google Drive.

### Installation

1. **Clone the project**:
   - `git clone https://github.com/Tamirye/drive-monitor`
2. **Install Dependencies**:
   - Install the required Python packages by running:
     ```
     pip install -r requirements.txt
     ```

### Usage

1. **Script Configuration**:
   - Place the `credentials.json` file in the same directory as the script, or specify its path when running the script.
2. **Running the Script**:

   - To run the script, use the following command in the terminal, replacing `<credentials_file>` with the path to your credentials file:
     ```
     python google_drive_monitor.py -c <credentials_file>
     ```
   - Optionally, you can specify a token file (which stores your user's session tokens) using the `-t` or `--token_file` argument. This is useful for avoiding repeated authorizations.

   ```
   python google_drive_monitor.py -c path/to/your/credentials.json -t path/to/your/token.json
   ```

   - Optionally, for testing the enforced sharing settings you can use the following options:
     - `-e`, `--test_email`: Email address used to test sharing options. Default is `email@example.com`.
     - `-d`, `--test_domain`: Domain to test sharing options against. Default is `google.com`.
     - `-g`, `--test_group_id`: Group ID to test sharing options against. Default is `testvaronis123@googlegroups.com`.

   ```
   python google_drive_monitor.py -c path/to/credentials.json -e user@example.com -d example.com -g yourgroup@example.com
   ```

   - **Notes on Sharing Settings Enumeration**:

     - Admin users in the Google Suite can view the directly using the admin SDK, as I didn't have Google Suite license and I couldn't test this functionality, I decided to test locally by trying to share a file in different scenarios using the given user permissions. This may produce different results depending on the user's permissions and could not be relied for organization wide policies.
     - Changing ownership on a file via API is restricted so it is not tested
     - The default email was chosen as an email that is definitely not part of the google account domain
     - The reason I chose google.com as a default domain is that I know that they are using Google Suite so I can be sure that the domain is eligible for sharing.
     - Groups cannot be tested without a group id so I decided to use a group id I own on a different google account then the one I tested the script on.

   - Optionally, the user can adjust the sleep time between file monitoring scanning operations so not to exceed the Google Drive API rate limit. This can be done using `-s`, `--sleep_period` (in seconds). Default is 10 seconds.

   ```
   python google_drive_monitor.py -c path/to/credentials.json -s 60
   ```

### Important Notes

- **Rate Limits**: The Google Drive API has usage limits; excessive requests may lead to temporary blocking.
- **Rescanning All the Folders**: In a large drive with a lot of folders and subfolders rescanning the drive for publicly accessible folders might be time consuming so the rescan is done once every 30 minutes.
- **Permission Adjustments**: The script adjusts permissions for new files only; existing file permissions are not modified.

## Attack Surface

- **Google Suite\Google Workspace Usage**: Using the API and trying to share a file with a specific domain can expose if this domain is used in a GCP organization, Google workspace or Google Suite. When trying to share a file with a domain that is not registered with any of those services you get an error `The specified domain is invalid or not applicable for the given permission type.`. Note that this error might also occur if the Google account used is blocked for sharing files with this domain but this can be assessed by using an attacker-controlled Google account with no restriction in place.
- **File Sharing Settings Enumeration**: By trying to share a file with different types of configurations (internal\external users, domains and groups) even a low privileged user can enumerate the enforced sharing settings.
