"""
SSO Handler

AWS SSO authentication and credential management.
"""

import subprocess
import time
import os
import glob
import json


def auto_sso_login(profile_name):
    """Automatically run SSO login if no valid session exists."""
    print(f"\n🔄 [SSO] Checking/logging in profile: {profile_name}...")
    try:
        subprocess.run(["aws", "sso", "login", "--profile", profile_name], check=True)
        time.sleep(2)
        return True
    except subprocess.CalledProcessError:
        print(f"❌ Error logging in to SSO profile {profile_name}")
        return False


def get_sso_token():
    """Find and read access token from AWS SSO cache."""
    sso_cache_dir = os.path.expanduser('~/.aws/sso/cache')
    cache_files = glob.glob(os.path.join(sso_cache_dir, '*.json'))
    if not cache_files:
        raise Exception("No SSO cache files found.")
    latest_file = max(cache_files, key=os.path.getmtime)
    with open(latest_file, 'r') as f:
        data = json.load(f)
        return data.get('accessToken')


def load_accounts_from_file(filename):
    """
    Load list of Account IDs from text file.
    
    Format: AccountID, AccountName
    Example:
        123456789012, Production Account
        234567890123, Development Account
    """
    if not os.path.exists(filename):
        print(f"⚠️  Warning: Account file '{filename}' not found.")
        return []
    
    accounts = []
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                parts = line.split(',', 1)
                acc_id = parts[0].strip()
                acc_name = parts[1].strip() if len(parts) > 1 else acc_id
                accounts.append({'Id': acc_id, 'Name': acc_name})
    return accounts
