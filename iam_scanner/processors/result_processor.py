"""
Result Processor

Process and aggregate scan results for roles and users.
"""

from typing import Dict
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False


def process_role_result(result: Dict, results: Dict, lock: Lock):
    """Process a role scan result and update the results dictionary (thread-safe)."""
    with lock:
        if result['ignored']:
            results['ignored_roles'] += 1
            results['ignored_role_details'].append({
                'role_name': result['role_name'],
                'reason': result['ignore_reason']
            })
        else:
            results['scanned_roles'] += 1
            if result['findings']:
                results['vulnerable_roles'].append({
                    'role_name': result['role_name'],
                    'role_arn': result['role_arn'],
                    'findings': result['findings'],
                    'total_permissions': result['total_permissions']
                })


def process_user_result(result: Dict, results: Dict, lock: Lock):
    """Process a user scan result and update the results dictionary (thread-safe)."""
    with lock:
        if result['ignored']:
            results['ignored_users'] += 1
            results['ignored_user_details'].append({
                'user_name': result['user_name'],
                'reason': result['ignore_reason']
            })
        else:
            results['scanned_users'] += 1
            if result['findings']:
                results['vulnerable_users'].append({
                    'user_name': result['user_name'],
                    'user_arn': result['user_arn'],
                    'findings': result['findings'],
                    'total_permissions': result['total_permissions']
                })


def scan_all_principals(scanner):
    """
    Scan all IAM roles and users for privilege escalation vulnerabilities.
    
    Args:
        scanner: Combined role and user scanner instance
        
    Returns:
        Dictionary with scan results for both roles and users
    """
    results = {
        'account_id': scanner.account_id,
        'total_roles': 0,
        'scanned_roles': 0,
        'ignored_roles': 0,
        'vulnerable_roles': [],
        'ignored_role_details': [],
        'total_users': 0,
        'scanned_users': 0,
        'ignored_users': 0,
        'vulnerable_users': [],
        'ignored_user_details': []
    }
    
    lock = scanner.results_lock
    
    # Scan roles
    if hasattr(scanner, 'get_all_roles'):
        roles = scanner.get_all_roles()
        results['total_roles'] = len(roles)
        
        if roles:
            if scanner.max_threads == 1:
                print(f"Scanning {len(roles)} roles...")
            else:
                print(f"Scanning {len(roles)} roles using {scanner.max_threads} threads...")
            
            pbar = tqdm(total=len(roles), desc="Scanning roles", unit="role") if HAS_TQDM and not scanner.verbose else None
            
            if scanner.max_threads == 1:
                for role in roles:
                    _, result = scanner.scan_single_role(role)
                    process_role_result(result, results, lock)
                    if pbar:
                        pbar.update(1)
            else:
                with ThreadPoolExecutor(max_workers=scanner.max_threads) as executor:
                    future_to_role = {executor.submit(scanner.scan_single_role, role): role for role in roles}
                    for future in as_completed(future_to_role):
                        role_name, result = future.result()
                        process_role_result(result, results, lock)
                        if pbar:
                            pbar.update(1)
            
            if pbar:
                pbar.close()
    
    # Scan users
    if hasattr(scanner, 'get_all_users'):
        users = scanner.get_all_users()
        results['total_users'] = len(users)
        
        if users:
            if scanner.max_threads == 1:
                print(f"Scanning {len(users)} users...")
            else:
                print(f"Scanning {len(users)} users using {scanner.max_threads} threads...")
            
            pbar = tqdm(total=len(users), desc="Scanning users", unit="user") if HAS_TQDM and not scanner.verbose else None
            
            if scanner.max_threads == 1:
                for user in users:
                    _, result = scanner.scan_single_user(user)
                    process_user_result(result, results, lock)
                    if pbar:
                        pbar.update(1)
            else:
                with ThreadPoolExecutor(max_workers=scanner.max_threads) as executor:
                    future_to_user = {executor.submit(scanner.scan_single_user, user): user for user in users}
                    for future in as_completed(future_to_user):
                        user_name, result = future.result()
                        process_user_result(result, results, lock)
                        if pbar:
                            pbar.update(1)
            
            if pbar:
                pbar.close()
    
    return results
