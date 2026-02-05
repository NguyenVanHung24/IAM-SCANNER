"""
IAM Privilege Escalation Scanner - Main Entry Point

Command-line interface for the IAM scanner package.
"""

import argparse
import sys
import json

from .scanners.role_scanner import RoleScanner
from .scanners.user_scanner import UserScanner
from .processors.result_processor import scan_all_principals
from .processors.report_generator import generate_report, generate_csv_report
from .multi_account.account_scanner import run_multi_lz_scan, CombinedScanner
from .config.landing_zones import LIST_LANDING_ZONES
from .config.constants import get_output_filename


def main():
    """Main entry point for the scanner."""
    parser = argparse.ArgumentParser(
        description='Scan AWS IAM roles and users for privilege escalation vulnerabilities'
    )
    
    # Mode selection
    parser.add_argument(
        '--multi-lz',
        action='store_true',
        help='Run multi-landing-zone scan (uses LIST_LANDING_ZONES configuration)'
    )
    
    # Single account mode arguments
    parser.add_argument(
        '--profile',
        help='AWS CLI profile to use (single account mode)',
        default=None
    )
    parser.add_argument(
        '--region',
        help='AWS region (single account mode)',
        default=None
    )
    parser.add_argument(
        '--output', '-o',
        help='Output file for JSON results (single account mode)',
        default=None
    )
    parser.add_argument(
        '--csv',
        help='Output file for CSV results',
        default=None
    )
    
    # Common arguments
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    parser.add_argument(
        '--threads', '-t',
        type=int,
        help='Number of threads for parallel scanning (default: 10)',
        default=10
    )
    parser.add_argument(
        '--account-workers',
        type=int,
        help='Number of parallel account scans in multi-LZ mode (default: 10)',
        default=10
    )
    
    args = parser.parse_args()
    
    try:
        if args.multi_lz:
            # Multi-landing-zone mode
            print("Running in MULTI-LANDING-ZONE mode\n")
            
            # Create /result directory if it doesn't exist
            import os
            result_dir = os.path.join(os.getcwd(), 'result')
            os.makedirs(result_dir, exist_ok=True)
            
            # Set output paths in /result folder
            output_file = os.path.join(result_dir, get_output_filename())
            csv_file = os.path.join(result_dir, get_output_filename().replace('.json', '.csv')) if args.csv else None
            
            results = run_multi_lz_scan(
                LIST_LANDING_ZONES,
                output_file,
                csv_file=csv_file,
                max_account_workers=args.account_workers,
                max_role_threads=args.threads
            )
            
            # Print summary
            print(f"\n{'='*60}")
            print("SCAN SUMMARY:")
            print(f"{'='*60}")
            for lz_name, lz_data in results['landing_zones'].items():
                if 'summary' in lz_data:
                    print(f"\n{lz_name}:")
                    print(f"  - Accounts scanned: {lz_data['summary']['successful_scans']}/{lz_data['summary']['total_accounts']}")
                    vuln_count = lz_data['summary'].get('total_vulnerable_roles', 0) + lz_data['summary'].get('total_vulnerable_users', 0)
                    print(f"  - Vulnerable principals: {vuln_count}")
            
            # Exit code based on findings
            if results['scan_metadata']['total_vulnerable_principals'] > 0:
                sys.exit(1)
            else:
                sys.exit(0)
        
        else:
            # Single account mode
            # If no profile specified, use environment credentials (AWS_ACCESS_KEY_ID, etc.)
            if not args.profile:
                print("Running in SINGLE ACCOUNT mode")
                print("Using AWS credentials from environment\n")
            else:
                print(f"Running in SINGLE ACCOUNT mode")
                print(f"Using profile: {args.profile}\n")
            
            # Create combined scanner
            scanner = CombinedScanner(
                profile=args.profile,  # Will be None if using env credentials
                region=args.region,
                verbose=args.verbose,
                max_threads=args.threads
            )
            
            # Run scan
            print("Starting IAM privilege escalation scan...")
            print("")
            results = scan_all_principals(scanner)
            
            # Generate report
            report = generate_report(results, verbose=args.verbose)
            print(report)
            
            # Auto-save to JSON if no output specified
            import os
            if not args.output and not args.csv:
                # Create /result directory
                result_dir = os.path.join(os.getcwd(), 'result')
                os.makedirs(result_dir, exist_ok=True)
                
                # Generate filename with account ID and timestamp
                from datetime import datetime
                timestamp = datetime.now().strftime('%Y%m%d_%H%M')
                account_id = results.get('account_id', 'unknown')
                default_output = os.path.join(result_dir, f'IAM_Scan_{account_id}_{timestamp}.json')
                
                with open(default_output, 'w') as f:
                    json.dump(results, f, indent=2)
                print(f"\n📄 Results saved to: {default_output}")
            
            # Save JSON output if requested
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2)
                print(f"\nDetailed results saved to: {args.output}")
            
            # Save CSV output if requested
            if args.csv:
                # Ensure /result directory exists
                import os
                if not os.path.isabs(args.csv):
                    result_dir = os.path.join(os.getcwd(), 'result')
                    os.makedirs(result_dir, exist_ok=True)
                    csv_path = os.path.join(result_dir, args.csv)
                else:
                    csv_path = args.csv
                
                generate_csv_report(results, csv_path)
                print(f"CSV report saved to: {csv_path}")

            
            # Exit with appropriate code
            vuln_count = len(results.get('vulnerable_roles', [])) + len(results.get('vulnerable_users', []))
            if vuln_count > 0:
                sys.exit(1)  # Vulnerabilities found
            else:
                sys.exit(0)  # No vulnerabilities
    
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        if args.verbose if 'args' in locals() else False:
            import traceback
            traceback.print_exc()
        sys.exit(2)


if __name__ == '__main__':
    main()
