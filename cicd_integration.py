#!/usr/bin/env python3
"""
CI/CD Integration for IAM Access Analyzer.
Block deployments with security issues.

Usage:
    python3 cicd_integration.py <policies_dir>
    python3 cicd_integration.py --check-policy <policy.json> <resource_type>
"""

import sys
import json
import logging
import boto3
from pathlib import Path
from typing import Dict, List, Any
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

aa = boto3.client('accessanalyzer')


def validate_all_policies(policies_dir: str) -> Dict[str, Any]:
    """
    Validate all JSON policies in directory.

    Args:
        policies_dir: Path to directory containing policy JSON files

    Returns:
        Dict with errors, warnings, passed count, and total count
    """
    results = {'errors': [], 'warnings': [], 'passed': 0, 'total': 0}

    policy_files = list(Path(policies_dir).rglob('*.json'))
    if not policy_files:
        logger.warning("No JSON files found in %s", policies_dir)
        return results

    for policy_file in policy_files:
        results['total'] += 1

        try:
            with open(policy_file) as f:
                policy = json.load(f)
        except json.JSONDecodeError as e:
            results['errors'].append({
                'file': str(policy_file),
                'issue': 'INVALID_JSON',
                'detail': str(e)
            })
            continue

        # Detect policy type from path
        path_str = str(policy_file).lower()
        if 'scp' in path_str:
            policy_type = 'SERVICE_CONTROL_POLICY'
        elif 'resource' in path_str or 'trust' in path_str:
            policy_type = 'RESOURCE_POLICY'
        else:
            policy_type = 'IDENTITY_POLICY'

        try:
            resp = aa.validate_policy(
                policyDocument=json.dumps(policy),
                policyType=policy_type
            )
            findings = resp.get('findings', [])

            for finding in findings:
                item = {
                    'file': str(policy_file),
                    'issue': finding['issueCode'],
                    'detail': finding['findingDetails']
                }
                if finding['findingType'] in ['ERROR', 'SECURITY_WARNING']:
                    results['errors'].append(item)
                else:
                    results['warnings'].append(item)

            if not findings:
                results['passed'] += 1

        except ClientError as e:
            results['errors'].append({
                'file': str(policy_file),
                'issue': 'API_ERROR',
                'detail': str(e)
            })

    return results


def check_no_public_access(policy: dict, resource_type: str) -> Dict[str, Any]:
    """
    Check if policy grants public access.

    Args:
        policy: Resource policy document
        resource_type: AWS resource type (AWS::S3::Bucket, etc.)

    Returns:
        Dict with result and reasons
    """
    try:
        resp = aa.check_no_public_access(
            policyDocument=json.dumps(policy),
            resourceType=resource_type
        )
        return {'result': resp['result'], 'reasons': resp.get('reasons', [])}
    except ClientError as e:
        return {'result': 'ERROR', 'reasons': [str(e)]}


def check_no_privilege_escalation(policy: dict) -> Dict[str, Any]:
    """
    Check for privilege escalation paths.

    Args:
        policy: IAM policy document

    Returns:
        Dict with result and list of dangerous actions found
    """
    dangerous_action_sets = [
        ['iam:*'],
        ['iam:PassRole'],
        ['iam:CreatePolicyVersion'],
        ['iam:AttachUserPolicy', 'iam:AttachRolePolicy'],
        ['sts:AssumeRole'],
    ]

    failed_actions = []
    for actions in dangerous_action_sets:
        try:
            resp = aa.check_access_not_granted(
                policyDocument=json.dumps(policy),
                access=[{'actions': actions}],
                policyType='IDENTITY_POLICY'
            )
            if resp['result'] == 'FAIL':
                failed_actions.extend(actions)
        except ClientError:
            pass

    return {
        'result': 'PASS' if not failed_actions else 'FAIL',
        'dangerous_actions': failed_actions
    }


def check_single_policy(policy_path: str, resource_type: str) -> int:
    """
    Check a single policy file.

    Args:
        policy_path: Path to policy JSON file
        resource_type: AWS resource type

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    try:
        with open(policy_path) as f:
            policy = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        logger.error("Failed to read policy: %s", e)
        return 1

    print(f"Checking {policy_path}...")

    public_result = check_no_public_access(policy, resource_type)
    print(f"  Public access check: {public_result['result']}")

    priv_result = check_no_privilege_escalation(policy)
    print(f"  Privilege escalation check: {priv_result['result']}")

    if priv_result['dangerous_actions']:
        print(f"  Dangerous actions found: {priv_result['dangerous_actions']}")

    if public_result['result'] != 'PASS' or priv_result['result'] != 'PASS':
        return 1
    return 0


def validate_directory(policies_dir: str) -> int:
    """
    Validate all policies in a directory.

    Args:
        policies_dir: Path to directory

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    print(f"Scanning {policies_dir}...")

    results = validate_all_policies(policies_dir)

    print(f"\nResults ({results['total']} policies):")
    print(f"  Passed: {results['passed']}")
    print(f"  Warnings: {len(results['warnings'])}")
    print(f"  Errors: {len(results['errors'])}")

    if results['warnings']:
        print("\nWarnings:")
        for warning in results['warnings'][:5]:
            print(f"  {Path(warning['file']).name}: {warning['issue']}")
        if len(results['warnings']) > 5:
            print(f"  ... and {len(results['warnings']) - 5} more")

    if results['errors']:
        print("\nErrors (blocking):")
        for error in results['errors']:
            detail = error['detail'][:50] if len(error['detail']) > 50 else error['detail']
            print(f"  {Path(error['file']).name}: {error['issue']} - {detail}")
        return 1

    print("\nAll policies passed validation!")
    return 0


def print_usage():
    """Print usage information."""
    print("Usage:")
    print("  cicd_integration.py <policies_dir>")
    print("  cicd_integration.py --check-policy <policy.json> <resource_type>")
    print("")
    print("Examples:")
    print("  cicd_integration.py ./policies")
    print("  cicd_integration.py --check-policy bucket-policy.json AWS::S3::Bucket")


def main() -> int:
    """Main entry point."""
    if len(sys.argv) < 2:
        print_usage()
        return 1

    if sys.argv[1] == '--check-policy':
        if len(sys.argv) < 4:
            print("Error: --check-policy requires <policy.json> and <resource_type>")
            return 1
        return check_single_policy(sys.argv[2], sys.argv[3])

    if sys.argv[1] in ['--help', '-h']:
        print_usage()
        return 0

    return validate_directory(sys.argv[1])


if __name__ == "__main__":
    sys.exit(main())
