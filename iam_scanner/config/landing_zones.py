"""
Landing Zone Configuration

Configure multiple AWS landing zones for multi-account scanning.
"""

# List of landing zones to scan
LIST_LANDING_ZONES = [
    {
        "profile": "sso-demo",
        "permission_set": "AWSReadOnlyAccess",
        "account_file": "accounts_demo.txt",
        "regions": ["ap-southeast-1"]
    }
    # Add more landing zones as needed
]
