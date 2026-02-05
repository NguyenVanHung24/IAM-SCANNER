"""
Report Generator

Generate human-readable reports from scan results.
"""

import csv
from typing import Dict


def generate_report(results: Dict, verbose: bool = False) -> str:
    """Generate a human-readable report from scan results."""
    report = []
    report.append("=" * 80)
    report.append("AWS IAM PRIVILEGE ESCALATION SCAN REPORT")
    report.append("=" * 80)
    report.append(f"Account ID: {results['account_id']}")
    report.append("")
    report.append("ROLES:")
    report.append(f"  Total Roles: {results.get('total_roles', 0)}")
    report.append(f"  Scanned Roles: {results.get('scanned_roles', 0)}")
    report.append(f"  Ignored Roles: {results.get('ignored_roles', 0)}")
    report.append(f"  Vulnerable Roles: {len(results.get('vulnerable_roles', []))}")
    report.append("")
    report.append("USERS:")
    report.append(f"  Total Users: {results.get('total_users', 0)}")
    report.append(f"  Scanned Users: {results.get('scanned_users', 0)}")
    report.append(f"  Ignored Users: {results.get('ignored_users', 0)}")
    report.append(f"  Vulnerable Users: {len(results.get('vulnerable_users', []))}")
    report.append("=" * 80)
    report.append("")
    
    # Vulnerable Roles Section
    if results.get('vulnerable_roles'):
        report.append("VULNERABLE ROLES:")
        report.append("")
        
        for vuln_role in results['vulnerable_roles']:
            report.append(f"Role: {vuln_role['role_name']}")
            report.append(f"ARN: {vuln_role['role_arn']}")
            report.append(f"Findings: {len(vuln_role['findings'])}")
            report.append("")
            
            for idx, finding in enumerate(vuln_role['findings'], 1):
                report.append(f"  [{idx}] {finding['pattern']}")
                report.append(f"      Severity: {finding['severity']}")
                report.append(f"      Category: {finding['category']}")
                desc = finding['description'][:100] + "..." if len(finding['description']) > 100 else finding['description']
                report.append(f"      Description: {desc}")
                report.append(f"      Matched Permissions: {', '.join(finding['matched_permissions'])}")
                report.append("")
            
            report.append("-" * 80)
            report.append("")
    
    # Vulnerable Users Section
    if results.get('vulnerable_users'):
        report.append("VULNERABLE USERS:")
        report.append("")
        
        for vuln_user in results['vulnerable_users']:
            report.append(f"User: {vuln_user['user_name']}")
            report.append(f"ARN: {vuln_user['user_arn']}")
            report.append(f"Findings: {len(vuln_user['findings'])}")
            report.append("")
            
            for idx, finding in enumerate(vuln_user['findings'], 1):
                report.append(f"  [{idx}] {finding['pattern']}")
                report.append(f"      Severity: {finding['severity']}")
                report.append(f"      Category: {finding['category']}")
                desc = finding['description'][:100] + "..." if len(finding['description']) > 100 else finding['description']
                report.append(f"      Description: {desc}")
                report.append(f"      Matched Permissions: {', '.join(finding['matched_permissions'])}")
                report.append("")
            
            report.append("-" * 80)
            report.append("")
    
    if not results.get('vulnerable_roles') and not results.get('vulnerable_users'):
        report.append("✓ No vulnerable roles or users found!")
        report.append("")
    
    # Verbose information
    if verbose:
        if results.get('ignored_role_details'):
            report.append("IGNORED ROLES:")
            report.append("")
            for ignored in results['ignored_role_details']:
                report.append(f"  - {ignored['role_name']}: {ignored['reason']}")
            report.append("")
        
        if results.get('ignored_user_details'):
            report.append("IGNORED USERS:")
            report.append("")
            for ignored in results['ignored_user_details']:
                report.append(f"  - {ignored['user_name']}: {ignored['reason']}")
            report.append("")
    
    return "\n".join(report)


def generate_csv_report(results: Dict, output_file: str):
    """
    Generate a CSV report from scan results.
    
    Args:
        results: Dictionary containing scan results
        output_file: Path to the output CSV file
    
    CSV Columns:
        - account: AWS Account ID
        - role: Role or User name
        - detect_policy: Pattern/policy that was detected
        - severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
        - category: Category of the finding
        - service: AWS services involved (comma-separated)
    """
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ['account', 'role', 'detect_policy', 'severity', 'category', 'service']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        
        account_id = results.get('account_id', 'Unknown')
        
        # Process vulnerable roles
        for vuln_role in results.get('vulnerable_roles', []):
            role_name = vuln_role['role_name']
            
            for finding in vuln_role['findings']:
                # Extract services from the finding
                services = finding.get('services', [])
                service_str = ', '.join(services) if services else 'N/A'
                
                writer.writerow({
                    'account': account_id,
                    'role': role_name,
                    'detect_policy': finding['pattern'],
                    'severity': finding['severity'],
                    'category': finding['category'],
                    'service': service_str
                })
        
        # Process vulnerable users
        for vuln_user in results.get('vulnerable_users', []):
            user_name = vuln_user['user_name']
            
            for finding in vuln_user['findings']:
                # Extract services from the finding
                services = finding.get('services', [])
                service_str = ', '.join(services) if services else 'N/A'
                
                writer.writerow({
                    'account': account_id,
                    'role': user_name,
                    'detect_policy': finding['pattern'],
                    'severity': finding['severity'],
                    'category': finding['category'],
                    'service': service_str
                })

