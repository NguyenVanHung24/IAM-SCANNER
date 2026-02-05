"""
Role Scanner

IAM role scanning functionality.
"""

from typing import Dict, List, Set, Tuple
from .base_scanner import IAMPrivEscScanner
from ..config.constants import IGNORE_ROLE_PATTERNS, ADMIN_POLICIES


class RoleScanner(IAMPrivEscScanner):
    """Scanner for IAM roles."""

    def _get_trusted_services_only(self, trust_policy: Dict) -> Tuple[bool, List[str]]:
        """
        Helper: Kiểm tra xem Trust Policy có phải chỉ dành riêng cho AWS Service không.
        Loại bỏ các trường hợp Trust User, Account ID hoặc Web Identity (Federated).
        
        Returns:
            Tuple[bool, List[str]]: (IsServiceOnly, ListOfServices)
        """
        if not trust_policy:
            return False, []

        statements = trust_policy.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]

        services = set()

        for stmt in statements:
            if stmt.get('Effect') != 'Allow':
                continue

            principals = stmt.get('Principal', {})
            
            # Nếu Principal chứa 'AWS' (IAM User/Role/Account) hoặc 'Federated' 
            # -> Role này có thể được assume bởi con người hoặc identity bên ngoài -> KHÔNG IGNORE.
            if 'AWS' in principals or 'Federated' in principals:
                return False, []

            # Thu thập Service Principals
            if 'Service' in principals:
                svc = principals['Service']
                if isinstance(svc, list):
                    services.update(svc)
                else:
                    services.add(svc)
            else:
                # Trường hợp Principal là Wildcard (*) hoặc CanonicalUser -> Không an toàn
                return False, []

        return True, list(services)

    def should_ignore_role(self, role_name: str, attached_policies: List[str], trust_policy: Dict = None) -> Tuple[bool, str]:
        """Determine if a role should be ignored from scanning."""
        
        # 1. Check role name patterns (Logic cũ)
        for pattern in IGNORE_ROLE_PATTERNS:
            if pattern in role_name:
                return True, f"Role name matches ignore pattern: {pattern}"
        
        # 2. Check for admin managed policies (Logic cũ)
        for policy_arn in attached_policies:
            policy_name = policy_arn.split('/')[-1]
            if policy_name in ADMIN_POLICIES:
                return True, f"Has admin policy: {policy_name}"
        
        # 3. LOGIC MỚI: Check Standard Service Role
        # Yêu cầu: Trust Service + Policy là AWS Managed + Tên Policy khớp Service
        if trust_policy:
            is_service_only, services = self._get_trusted_services_only(trust_policy)
            
            if is_service_only and services:
                # Nếu Role không có policy nào, coi là an toàn
                if not attached_policies:
                    return True, "Empty service role (No permissions attached)"

                # Kiểm tra tính hợp lệ của TẤT CẢ policy được gắn
                all_policies_standard = True
                
                for policy_arn in attached_policies:
                    # Check 3a: Phải là AWS Managed Policy (bắt đầu bằng arn:aws:iam::aws:policy)
                    if not policy_arn.startswith("arn:aws:iam::aws:policy"):
                        all_policies_standard = False
                        # Nếu có Customer Managed Policy thì không ignore, vì user có thể sửa quyền
                        break
                    
                    # Check 3b: Tên Policy phải liên quan đến Service trong Trust Policy
                    policy_name = policy_arn.split('/')[-1]
                    is_related = False
                    
                    for service in services:
                        # Lấy short name: "lambda.amazonaws.com" -> "lambda"
                        service_short = service.split('.')[0].lower()
                        
                        # So sánh chuỗi (case-insensitive): check "lambda" in "AWSLambdaBasicExecutionRole"
                        if service_short in policy_name.lower():
                            is_related = True
                            break
                    
                    if not is_related:
                        all_policies_standard = False
                        break
                
                if all_policies_standard:
                    services_str = ', '.join(services[:3])
                    if len(services) > 3:
                        services_str += f" (+{len(services) - 3} more)"
                    return True, f"Standard Service Role (Trusted: {services_str})"

        return False, ""
    
    def get_all_roles(self) -> List[Dict]:
        """Retrieve all IAM roles in the account."""
        self.log("Fetching all IAM roles...")
        roles = []
        paginator = self.iam_client.get_paginator('list_roles')
        
        for page in paginator.paginate():
            roles.extend(page['Roles'])
        
        self.log(f"Found {len(roles)} total roles")
        return roles
    
    def _get_role_permissions_with_client(self, iam_client, role_name: str) -> Set[str]:
        """Get all permissions for a role using a specific IAM client."""
        permissions = set()
        
        # Get attached managed policies
        try:
            attached_response = iam_client.list_attached_role_policies(RoleName=role_name)
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
            self.log(f"Error getting attached policies for {role_name}: {e}", "ERROR")
        
        # Get inline policies
        try:
            inline_response = iam_client.list_role_policies(RoleName=role_name)
            for policy_name in inline_response.get('PolicyNames', []):
                policy_response = iam_client.get_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name
                )
                policy_doc = policy_response['PolicyDocument']
                permissions.update(self.extract_permissions_from_policy(policy_doc))
        except Exception as e:
            self.log(f"Error getting inline policies for {role_name}: {e}", "ERROR")
        
        return permissions
    
    def scan_single_role(self, role: Dict) -> Tuple[str, Dict]:
        """Scan a single IAM role for privilege escalation vulnerabilities."""
        iam_client = self.create_thread_local_iam_client()
        
        role_name = role['RoleName']
        result = {
            'role_name': role_name,
            'role_arn': role['Arn'],
            'ignored': False,
            'ignore_reason': None,
            'findings': [],
            'total_permissions': 0
        }
        
        try:
            # Get attached policies for filtering
            try:
                attached_policies_response = iam_client.list_attached_role_policies(RoleName=role_name)
                attached_policy_arns = [
                    p['PolicyArn'] for p in attached_policies_response.get('AttachedPolicies', [])
                ]
            except Exception as e:
                self.log(f"Error listing attached policies for {role_name}: {e}", "ERROR")
                attached_policy_arns = []
            
            # Check if role should be ignored
            trust_policy = role.get('AssumeRolePolicyDocument', {})
            should_ignore, ignore_reason = self.should_ignore_role(
                role_name, attached_policy_arns, trust_policy
            )
            
            if should_ignore:
                self.log(f"Ignoring role {role_name}: {ignore_reason}")
                result['ignored'] = True
                result['ignore_reason'] = ignore_reason
                return role_name, result
            
            # Get permissions
            permissions = self._get_role_permissions_with_client(iam_client, role_name)
            result['total_permissions'] = len(permissions)
            
            # Check for privilege escalation patterns
            findings = self.check_privesc_patterns(permissions)
            result['findings'] = findings
            
            if findings:
                self.log(f"✗ VULNERABLE: {role_name} - {len(findings)} privilege escalation path(s) found")
            else:
                self.log(f"✓ OK: {role_name}")
        
        except Exception as e:
            self.log(f"Error scanning role {role_name}: {e}", "ERROR")
        
        return role_name, result