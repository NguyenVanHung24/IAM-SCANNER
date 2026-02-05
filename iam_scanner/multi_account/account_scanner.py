"""
Account Scanner

Multi-account and multi-landing-zone scanning functionality.
"""

import boto3
import traceback
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.exceptions import ClientError

from ..scanners.role_scanner import RoleScanner
from ..scanners.user_scanner import UserScanner
from ..processors.result_processor import scan_all_principals
from ..processors.report_generator import generate_csv_report
from .sso_handler import auto_sso_login, get_sso_token, load_accounts_from_file


# Combined scanner class
class CombinedScanner(RoleScanner, UserScanner):
    """Scanner that can scan both roles and users."""
    pass


def scan_account_via_sso(account, permission_set, profile, sso_region, max_threads=10):
    """
    Scan a single account using SSO credentials.
    Thread-safe: Creates its own boto3 session and clients.
    """
    acc_id = account['Id']
    acc_name = account['Name']
    
    try:
        print(f"   [{acc_id}] ⏳ Assuming role and scanning IAM...")
        
        # Create thread-local session and clients
        session = boto3.Session(profile_name=profile)
        sso_client = session.client('sso', region_name=sso_region)
        access_token = get_sso_token()
        
        # Get credentials from SSO
        response = sso_client.get_role_credentials(
            roleName=permission_set,
            accountId=acc_id,
            accessToken=access_token
        )
        creds = response['roleCredentials']
        
        # Create scanner with SSO credentials
        sso_credentials = {
            'access_key_id': creds['accessKeyId'],
            'secret_access_key': creds['secretAccessKey'],
            'session_token': creds['sessionToken']
        }
        
        scanner = CombinedScanner(
            profile=None,
            region=None,
            verbose=False,
            max_threads=max_threads,
            sso_credentials=sso_credentials
        )
        
        # Run the scan (both roles and users)
        results = scan_all_principals(scanner)
        results['account_name'] = acc_name
        
        vuln_count = len(results['vulnerable_roles']) + len(results['vulnerable_users'])
        scanned_count = results['scanned_roles'] + results['scanned_users']
        print(f"   [{acc_id}] ✅ Scan complete: {scanned_count} scanned, {vuln_count} vulnerable")
        
        return {
            'success': True,
            'account_id': acc_id,
            'account_name': acc_name,
            'results': results
        }
        
    except ClientError as e:
        error_msg = f"AWS Error: {e}"
        print(f"   [{acc_id}] ❌ {error_msg}")
        return {
            'success': False,
            'account_id': acc_id,
            'account_name': acc_name,
            'error': error_msg
        }
    except Exception as e:
        error_msg = str(e)
        print(f"   [{acc_id}] ❌ Error: {error_msg}")
        return {
            'success': False,
            'account_id': acc_id,
            'account_name': acc_name,
            'error': error_msg
        }


def run_scan_for_landing_zone(config, max_account_workers=10, max_role_threads=10):
    """Scan all accounts in a landing zone."""
    profile = config['profile']
    perm_set = config['permission_set']
    acc_file = config['account_file']
    
    print(f"\n{'='*60}")
    print(f"🚀 SCANNING LANDING ZONE: {profile}")
    print(f"{'='*60}")
    
    lz_results = {
        'profile': profile,
        'permission_set': perm_set,
        'accounts': {},
        'summary': {
            'total_accounts': 0,
            'successful_scans': 0,
            'failed_scans': 0,
            'total_vulnerable_roles': 0,
            'total_vulnerable_users': 0,
            'total_scanned_roles': 0,
            'total_scanned_users': 0
        }
    }
    
    # SSO Login
    if not auto_sso_login(profile):
        lz_results['error'] = 'SSO login failed'
        return lz_results
    
    try:
        # Get SSO region
        session = boto3.Session(profile_name=profile)
        sso_region = session.region_name if session.region_name else 'ap-southeast-1'
        
        # Load accounts
        accounts = load_accounts_from_file(acc_file)
        if not accounts:
            lz_results['error'] = f'No accounts found in {acc_file}'
            return lz_results
        
        lz_results['summary']['total_accounts'] = len(accounts)
        print(f"📋 Found {len(accounts)} accounts to scan")
        
        # Scan accounts in parallel
        with ThreadPoolExecutor(max_workers=max_account_workers) as executor:
            futures = {
                executor.submit(
                    scan_account_via_sso,
                    acc,
                    perm_set,
                    profile,
                    sso_region,
                    max_role_threads
                ): acc for acc in accounts
            }
            
            for future in as_completed(futures):
                result = future.result()
                acc_id = result['account_id']
                
                if result['success']:
                    lz_results['accounts'][acc_id] = result['results']
                    lz_results['summary']['successful_scans'] += 1
                    lz_results['summary']['total_vulnerable_roles'] += len(result['results']['vulnerable_roles'])
                    lz_results['summary']['total_vulnerable_users'] += len(result['results'].get('vulnerable_users', []))
                    lz_results['summary']['total_scanned_roles'] += result['results']['scanned_roles']
                    lz_results['summary']['total_scanned_users'] += result['results'].get('scanned_users', 0)
                else:
                    lz_results['accounts'][acc_id] = {'error': result.get('error', 'Unknown error')}
                    lz_results['summary']['failed_scans'] += 1
        
        total_vulns = lz_results['summary']['total_vulnerable_roles'] + lz_results['summary']['total_vulnerable_users']
        print(f"\n✅ Landing zone {profile} complete:")
        print(f"   - Successful: {lz_results['summary']['successful_scans']}/{lz_results['summary']['total_accounts']}")
        print(f"   - Vulnerable principals found: {total_vulns}")
        
    except Exception as e:
        error_msg = f"Critical error in landing zone {profile}: {e}"
        print(f"❌ {error_msg}")
        traceback.print_exc()
        lz_results['error'] = error_msg
    
    return lz_results


def run_multi_lz_scan(landing_zones, output_file, csv_file=None, max_account_workers=10, max_role_threads=10):
    """Run scan across all configured landing zones.
    
    Args:
        landing_zones: List of landing zone configurations
        output_file: Path to JSON output file
        csv_file: Optional path to CSV output file
        max_account_workers: Max parallel account scans
        max_role_threads: Max parallel role scans per account
    """
    print("="*60)
    print("🌐 MULTI-LANDING-ZONE IAM PRIVILEGE ESCALATION SCAN")
    print("="*60)
    
    all_results = {
        'scan_metadata': {
            'start_time': datetime.now().isoformat(),
            'landing_zones_configured': len(landing_zones),
            'max_account_workers': max_account_workers,
            'max_role_threads': max_role_threads
        },
        'landing_zones': {}
    }
    
    # Scan each landing zone sequentially
    for config in landing_zones:
        lz_results = run_scan_for_landing_zone(config, max_account_workers, max_role_threads)
        all_results['landing_zones'][config['profile']] = lz_results
    
    # Calculate overall summary
    all_results['scan_metadata']['end_time'] = datetime.now().isoformat()
    all_results['scan_metadata']['total_accounts_scanned'] = sum(
        lz['summary']['total_accounts']
        for lz in all_results['landing_zones'].values()
        if 'summary' in lz
    )
    all_results['scan_metadata']['total_vulnerable_principals'] = sum(
        lz['summary'].get('total_vulnerable_roles', 0) + lz['summary'].get('total_vulnerable_users', 0)
        for lz in all_results['landing_zones'].values()
        if 'summary' in lz
    )
    
    # Save JSON results
    import json
    import os
    with open(output_file, 'w') as f:
        json.dump(all_results, f, indent=2)
    
    # Save CSV results if requested
    if csv_file:
        # Flatten all results into a single CSV
        combined_results = {
            'account_id': 'Multiple',
            'vulnerable_roles': [],
            'vulnerable_users': []
        }
        
        # Collect all vulnerable principals from all landing zones and accounts
        for lz_name, lz_data in all_results['landing_zones'].items():
            if 'accounts' in lz_data:
                for acc_id, acc_data in lz_data['accounts'].items():
                    if 'vulnerable_roles' in acc_data:
                        for vuln_role in acc_data['vulnerable_roles']:
                            # Add account info to each role
                            role_copy = vuln_role.copy()
                            role_copy['_source_account'] = acc_id
                            role_copy['_source_lz'] = lz_name
                            combined_results['vulnerable_roles'].append(role_copy)
                    
                    if 'vulnerable_users' in acc_data:
                        for vuln_user in acc_data['vulnerable_users']:
                            # Add account info to each user
                            user_copy = vuln_user.copy()
                            user_copy['_source_account'] = acc_id
                            user_copy['_source_lz'] = lz_name
                            combined_results['vulnerable_users'].append(user_copy)
        
        # Generate CSV with modified account IDs
        _generate_multi_account_csv(combined_results, csv_file)
        print(f"📊 CSV report saved to: {os.path.abspath(csv_file)}")
    
    print(f"\n{'='*60}")
    print(f"🏁 MULTI-LZ SCAN COMPLETE!")
    print(f"📊 JSON results saved to: {os.path.abspath(output_file)}")
    print(f"{'='*60}")
    print(f"Total accounts: {all_results['scan_metadata']['total_accounts_scanned']}")
    print(f"Total vulnerable principals: {all_results['scan_metadata']['total_vulnerable_principals']}")
    print(f"{'='*60}")
    
    return all_results


def _generate_multi_account_csv(combined_results, csv_file):
    """Generate CSV for multi-account scans with account ID in each row."""
    import csv
    
    with open(csv_file, 'w', newline='') as csvfile:
        fieldnames = ['account', 'role', 'detect_policy', 'severity', 'category', 'service']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        
        # Process vulnerable roles
        for vuln_role in combined_results.get('vulnerable_roles', []):
            account_id = vuln_role.get('_source_account', 'Unknown')
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
        for vuln_user in combined_results.get('vulnerable_users', []):
            account_id = vuln_user.get('_source_account', 'Unknown')
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
