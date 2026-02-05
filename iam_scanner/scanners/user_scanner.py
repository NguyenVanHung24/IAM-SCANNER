"""
User Scanner

IAM user scanning functionality.
"""

from typing import Dict, List, Set, Tuple
from .base_scanner import IAMPrivEscScanner
from ..config.constants import IGNORE_USER_PATTERNS, ADMIN_POLICIES


class UserScanner(IAMPrivEscScanner):
    """Scanner for IAM users."""
    
    def should_ignore_user(self, user_name: str, attached_policies: List[str]) -> Tuple[bool, str]:
        """Determine if a user should be ignored from scanning."""
        # Check user name patterns
        for pattern in IGNORE_USER_PATTERNS:
            if pattern.lower() in user_name.lower():
                return True, f"User name matches ignore pattern: {pattern}"
        
        # Check for admin managed policies
        for policy_arn in attached_policies:
            policy_name = policy_arn.split('/')[-1]
            if policy_name in ADMIN_POLICIES:
                return True, f"Has admin policy: {policy_name}"
        
        return False, ""
    
    def get_all_users(self) -> List[Dict]:
        """Retrieve all IAM users in the account."""
        self.log("Fetching all IAM users...")
        users = []
        paginator = self.iam_client.get_paginator('list_users')
        
        for page in paginator.paginate():
            users.extend(page['Users'])
        
        self.log(f"Found {len(users)} total users")
        return users
    
    def _get_user_permissions_with_client(self, iam_client, user_name: str) -> Set[str]:
        """Get all permissions for a user (direct policies + group policies)."""
        permissions = set()
        
        # Get attached managed policies
        try:
            attached_response = iam_client.list_attached_user_policies(UserName=user_name)
            for policy in attached_response.get('AttachedPolicies', []):
                policy_arn = policy['PolicyArn']
                policy_response = iam_client.get_policy(PolicyArn=policy_arn)
                version_id = policy_response['Policy']['DefaultVersionId']
                version_response = iam_client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=version_id
                )
                policy_doc = version_response['PolicyVersion']['Document']
                permissions.update(self.extract_permissions_from_policy(policy_doc))
        except Exception as e:
            self.log(f"Error getting attached policies for user {user_name}: {e}", "ERROR")
        
        # Get inline policies
        try:
            inline_response = iam_client.list_user_policies(UserName=user_name)
            for policy_name in inline_response.get('PolicyNames', []):
                policy_response = iam_client.get_user_policy(
                    UserName=user_name,
                    PolicyName=policy_name
                )
                policy_doc = policy_response['PolicyDocument']
                permissions.update(self.extract_permissions_from_policy(policy_doc))
        except Exception as e:
            self.log(f"Error getting inline policies for user {user_name}: {e}", "ERROR")
        
        # Get permissions from groups
        try:
            groups_response = iam_client.list_groups_for_user(UserName=user_name)
            for group in groups_response.get('Groups', []):
                group_name = group['GroupName']
                
                # Group attached policies
                try:
                    attached_group_response = iam_client.list_attached_group_policies(GroupName=group_name)
                    for policy in attached_group_response.get('AttachedPolicies', []):
                        policy_arn = policy['PolicyArn']
                        policy_response = iam_client.get_policy(PolicyArn=policy_arn)
                        version_id = policy_response['Policy']['DefaultVersionId']
                        version_response = iam_client.get_policy_version(
                            PolicyArn=policy_arn,
                            VersionId=version_id
                        )
                        policy_doc = version_response['PolicyVersion']['Document']
                        permissions.update(self.extract_permissions_from_policy(policy_doc))
                except Exception as e:
                    self.log(f"Error getting attached policies for group {group_name}: {e}", "ERROR")
                
                # Group inline policies
                try:
                    inline_group_response = iam_client.list_group_policies(GroupName=group_name)
                    for policy_name in inline_group_response.get('PolicyNames', []):
                        policy_response = iam_client.get_group_policy(
                            GroupName=group_name,
                            PolicyName=policy_name
                        )
                        policy_doc = policy_response['PolicyDocument']
                        permissions.update(self.extract_permissions_from_policy(policy_doc))
                except Exception as e:
                    self.log(f"Error getting inline policies for group {group_name}: {e}", "ERROR")
        except Exception as e:
            self.log(f"Error getting groups for user {user_name}: {e}", "ERROR")
        
        return permissions
    
    def scan_single_user(self, user: Dict) -> Tuple[str, Dict]:
        """Scan a single IAM user for privilege escalation vulnerabilities."""
        iam_client = self.create_thread_local_iam_client()
        
        user_name = user['UserName']
        result = {
            'user_name': user_name,
            'user_arn': user['Arn'],
            'ignored': False,
            'ignore_reason': None,
            'findings': [],
            'total_permissions': 0
        }
        
        try:
            # Get attached policies for filtering
            try:
                attached_policies_response = iam_client.list_attached_user_policies(UserName=user_name)
                attached_policy_arns = [
                    p['PolicyArn'] for p in attached_policies_response.get('AttachedPolicies', [])
                ]
            except Exception as e:
                self.log(f"Error listing attached policies for {user_name}: {e}", "ERROR")
                attached_policy_arns = []
            
            # Check if user should be ignored
            should_ignore, ignore_reason = self.should_ignore_user(user_name, attached_policy_arns)
            
            if should_ignore:
                self.log(f"Ignoring user {user_name}: {ignore_reason}")
                result['ignored'] = True
                result['ignore_reason'] = ignore_reason
                return user_name, result
            
            # Get permissions
            permissions = self._get_user_permissions_with_client(iam_client, user_name)
            result['total_permissions'] = len(permissions)
            
            # Check for privilege escalation patterns
            findings = self.check_privesc_patterns(permissions)
            result['findings'] = findings
            
            if findings:
                self.log(f"✗ VULNERABLE USER: {user_name} - {len(findings)} privilege escalation path(s) found")
            else:
                self.log(f"✓ OK: {user_name}")
        
        except Exception as e:
            self.log(f"Error scanning user {user_name}: {e}", "ERROR")
        
        return user_name, result
