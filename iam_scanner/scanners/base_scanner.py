"""
Base IAM Scanner

Contains common functionality shared by role and user scanners.
"""

import boto3
from typing import Dict, List, Set, Tuple
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

from ..config.patterns import PRIVESC_PATTERNS


class IAMPrivEscScanner:
    """Base scanner for IAM privilege escalation vulnerabilities."""
    
    def __init__(self, profile=None, region=None, verbose=False, max_threads=10, sso_credentials=None):
        """Initialize the scanner with AWS credentials.
        
        Args:
            profile: AWS profile name (for profile-based auth)
            region: AWS region
            verbose: Enable verbose logging
            max_threads: Number of threads for parallel scanning
            sso_credentials: Dict with SSO credentials (access_key_id, secret_access_key, session_token)
                            If provided, uses these instead of profile-based auth
        """
        self.verbose = verbose
        self.max_threads = max_threads
        self.profile = profile
        self.region = region
        self.sso_credentials = sso_credentials
        self.results_lock = Lock()
        
        # Create initial IAM client
        if sso_credentials:
            self.iam_client = boto3.client(
                'iam',
                region_name='us-east-1',
                aws_access_key_id=sso_credentials['access_key_id'],
                aws_secret_access_key=sso_credentials['secret_access_key'],
                aws_session_token=sso_credentials['session_token']
            )
            sts_client = boto3.client(
                'sts',
                region_name='us-east-1',
                aws_access_key_id=sso_credentials['access_key_id'],
                aws_secret_access_key=sso_credentials['secret_access_key'],
                aws_session_token=sso_credentials['session_token']
            )
            self.account_id = sts_client.get_caller_identity()['Account']
        else:
            session = boto3.Session(profile_name=profile, region_name=region)
            self.iam_client = session.client('iam')
            self.account_id = session.client('sts').get_caller_identity()['Account']
    
    def log(self, message, level="INFO"):
        """Log messages if verbose mode is enabled."""
        if self.verbose or level == "ERROR":
            print(f"[{level}] {message}")
    
    def extract_permissions_from_policy(self, policy_document: Dict) -> Set[str]:
        """Extract all Allow permissions from a policy document."""
        permissions = set()
        statements = policy_document.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        for statement in statements:
            if statement.get('Effect') != 'Allow':
                continue
            
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            
            for action in actions:
                if '*' in action:
                    permissions.add(action)
                else:
                    permissions.add(action.lower())
        
        return permissions
    
    def check_privesc_patterns(self, permissions: Set[str]) -> List[Dict]:
        """Check if permissions contain any privilege escalation patterns."""
        findings = []
        normalized_perms = {p.lower() for p in permissions}
        
        for pattern_name, pattern_info in PRIVESC_PATTERNS.items():
            required = [p.lower() for p in pattern_info['required']]
            
            has_all = all(
                any(self.permission_matches(perm, req) for perm in normalized_perms)
                for req in required
            )
            
            if has_all:
                findings.append({
                    'pattern': pattern_name,
                    'category': pattern_info['category'],
                    'severity': pattern_info['severity'],
                    'description': pattern_info['description'],
                    'services': pattern_info['services'],
                    'matched_permissions': required
                })
        
        return findings
    
    def permission_matches(self, permission: str, required: str) -> bool:
        """Check if a permission matches a required permission (handles wildcards)."""
        if permission == required:
            return True
        if permission == '*':
            return True
        if permission.endswith(':*'):
            service = permission.split(':')[0]
            req_service = required.split(':')[0]
            if service == req_service:
                return True
        if '*' in permission:
            import re
            pattern = permission.replace('*', '.*')
            if re.match(f"^{pattern}$", required):
                return True
        return False
    
    def is_service_role_only(self, trust_policy: Dict) -> Tuple[bool, List[str]]:
        """Check if a role can only be assumed by AWS services."""
        statements = trust_policy.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        service_principals = []
        has_non_service_principal = False
        
        for statement in statements:
            if statement.get('Effect') != 'Allow':
                continue
            
            principal = statement.get('Principal', {})
            
            if principal == '*' or principal.get('AWS') == '*':
                has_non_service_principal = True
                break
            
            if 'AWS' in principal:
                aws_principals = principal['AWS']
                if isinstance(aws_principals, str):
                    aws_principals = [aws_principals]
                if aws_principals:
                    has_non_service_principal = True
                    break
            
            if 'Federated' in principal:
                has_non_service_principal = True
                break
            
            if 'Service' in principal:
                services = principal['Service']
                if isinstance(services, str):
                    services = [services]
                service_principals.extend(services)
        
        is_service_only = len(service_principals) > 0 and not has_non_service_principal
        return is_service_only, service_principals
    
    def create_thread_local_iam_client(self):
        """Create a thread-local IAM client for parallel execution."""
        if self.sso_credentials:
            return boto3.client(
                'iam',
                region_name='us-east-1',
                aws_access_key_id=self.sso_credentials['access_key_id'],
                aws_secret_access_key=self.sso_credentials['secret_access_key'],
                aws_session_token=self.sso_credentials['session_token']
            )
        else:
            session = boto3.Session(profile_name=self.profile, region_name=self.region)
            return session.client('iam')
