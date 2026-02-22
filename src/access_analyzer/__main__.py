#!/usr/bin/env python3
"""CLI entry point for Access Analyzer."""

import sys
import argparse
from .client import AccessAnalyzerClient
from .cicd import PolicyValidator
from .dashboard import SecurityDashboard


def main():
    parser = argparse.ArgumentParser(description='AWS IAM Access Analyzer CLI')
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # scan command
    scan_parser = subparsers.add_parser('scan', help='Run security scan')
    scan_parser.add_argument('--region', help='AWS region')
    scan_parser.add_argument('--all-regions', action='store_true', help='Scan all commercial regions')
    scan_parser.add_argument('--org', action='store_true', help='Use organization-level analyzers')

    # validate command
    validate_parser = subparsers.add_parser('validate', help='Validate policies')
    validate_parser.add_argument('path', help='Policy file or directory')
    validate_parser.add_argument('--type', default='IDENTITY_POLICY', help='Policy type')

    # dashboard command
    dash_parser = subparsers.add_parser('dashboard', help='Show security dashboard')
    dash_parser.add_argument('--export', help='Export to JSON file')
    dash_parser.add_argument('--region', help='AWS region')

    args = parser.parse_args()

    if args.command == 'scan':
        if args.all_regions:
            results = AccessAnalyzerClient.scan_all_commercial_regions(use_org=args.org)
            print(f"Regions scanned: {results['summary']['regions_scanned']}")
            print(f"Total external findings: {results['summary']['total_external']}")
            print(f"Total unused findings: {results['summary']['total_unused']}")
        else:
            client = AccessAnalyzerClient(region=args.region)
            results = client.full_scan(use_org=args.org)
            print(f"Region: {results['summary']['region']}")
            print(f"External findings: {results['summary']['external_count']}")
            print(f"Unused findings: {results['summary']['unused_count']}")

    elif args.command == 'validate':
        validator = PolicyValidator()
        results = validator.validate_directory(args.path)
        print(f"Passed: {results['passed']}/{results['total']}")
        return 1 if results['errors'] else 0

    elif args.command == 'dashboard':
        dashboard = SecurityDashboard(region=args.region)
        if args.export:
            path = dashboard.export_json(args.export)
            print(f"Exported to {path}")
        else:
            dashboard.print_report()

    else:
        parser.print_help()

    return 0


if __name__ == "__main__":
    sys.exit(main())
