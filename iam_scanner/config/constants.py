"""
Application Constants

Configuration values for the IAM privilege escalation scanner.
"""

from datetime import datetime

# AWS managed policies that indicate admin access
ADMIN_POLICIES = [
    "AdministratorAccess",
    "PowerUserAccess",  # Often has enough permissions for privesc
]

# Role name patterns to ignore
IGNORE_ROLE_PATTERNS = [
    "AWSReservedSSO_AWSAdministratorAccess",
    "AWSReservedSSO_AdministratorAccess",
    "OrganizationAccountAccessRole",
    "AWSServiceRoleForCloudFormationStackSetsOrgMember",
    "AWSServiceRoleForSSO",
    "AWSReservedSSO"
]

# User name patterns to ignore (e.g., service accounts, break-glass accounts)
IGNORE_USER_PATTERNS = [
    "aws-service-account-",
    "break-glass-",
    "emergency-access-"
]

# Number of accounts to scan in parallel per landing zone
MAX_ACCOUNT_WORKERS = 10

# Output file for multi-LZ scans
def get_output_filename():
    """Generate output filename with timestamp."""
    return f"IAM_PrivEsc_Scan_{datetime.now().strftime('%Y%m%d_%H%M')}.json"

