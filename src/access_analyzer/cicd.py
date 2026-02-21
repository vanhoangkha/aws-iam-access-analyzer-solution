#!/usr/bin/env python3
"""
CI/CD Policy Validator for IAM Access Analyzer.
Validates IAM policies in CI/CD pipelines.

Usage:
    python -m access_analyzer.cicd <policies_dir>
    python -m access_analyzer.cicd --check-policy <policy.json> <resource_type>
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


class PolicyValidator:
    """Validates IAM policies using Access Analyzer APIs."""

    def __init__(self, region: str = None):
        self.region = region or boto3.session.Session().region_name
        self.client = boto3.client('accessanalyzer', region_name=self.region)

    def validate_policy(self, policy: dict, policy_type: str = 'IDENTITY_POLICY') -> List[Dict]:
        """Validate a single policy."""
        try:
            resp = self.client.validate_policy(
                policyDocument=json.dumps(policy),
                policyType=policy_type
            )
            return resp.get('findings', [])
        except ClientError as e:
            return [{'findingType': 'ERROR', 'issueCode': 'API_ERROR', 'findingDetails': str(e)}]

    def check_no_public_access(self, policy: dict, resource_type: str) -> Dict[str, Any]:
        """Check if policy grants public access."""
        try:
            resp = self.client.check_no_public_access(
                policyDocument=json.dumps(policy),
                resourceType=resource_type
            )
            return {'result': resp['result'], 'reasons': resp.get('reasons', [])}
        except ClientError as e:
            return {'result': 'ERROR', 'reasons': [str(e)]}

    def check_no_privilege_escalation(self, policy: dict) -> Dict[str, Any]:
        """Check for privilege escalation paths."""
        dangerous_actions = [
            ['iam:*'],
            ['iam:PassRole'],
            ['iam:CreatePolicyVersion'],
            ['iam:AttachUserPolicy', 'iam:AttachRolePolicy'],
            ['sts:AssumeRole'],
        ]

        failed = []
        for actions in dangerous_actions:
            try:
                resp = self.client.check_access_not_granted(
                    policyDocument=json.dumps(policy),
                    access=[{'actions': actions}],
                    policyType='IDENTITY_POLICY'
                )
                if resp['result'] == 'FAIL':
                    failed.extend(actions)
            except ClientError:
                pass

        return {'result': 'PASS' if not failed else 'FAIL', 'dangerous_actions': failed}

    def validate_directory(self, policies_dir: str) -> Dict[str, Any]:
        """Validate all JSON policies in directory."""
        results = {'errors': [], 'warnings': [], 'passed': 0, 'total': 0}

        base_path = Path(policies_dir).resolve()
        if not base_path.exists():
            raise ValueError(f"Directory not found: {policies_dir}")

        for policy_file in base_path.rglob('*.json'):
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

            path_str = str(policy_file).lower()
            if 'scp' in path_str:
                policy_type = 'SERVICE_CONTROL_POLICY'
            elif 'resource' in path_str or 'trust' in path_str:
                policy_type = 'RESOURCE_POLICY'
            else:
                policy_type = 'IDENTITY_POLICY'

            findings = self.validate_policy(policy, policy_type)

            for finding in findings:
                item = {
                    'file': str(policy_file),
                    'issue': finding.get('issueCode', 'UNKNOWN'),
                    'detail': finding.get('findingDetails', '')
                }
                if finding.get('findingType') in ['ERROR', 'SECURITY_WARNING']:
                    results['errors'].append(item)
                else:
                    results['warnings'].append(item)

            if not findings:
                results['passed'] += 1

        return results


def main() -> int:
    """CLI entry point."""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python -m access_analyzer.cicd <policies_dir>")
        print("  python -m access_analyzer.cicd --check-policy <policy.json> <resource_type>")
        return 1

    validator = PolicyValidator()

    if sys.argv[1] == '--check-policy':
        if len(sys.argv) < 4:
            print("Error: --check-policy requires <policy.json> and <resource_type>")
            return 1

        with open(sys.argv[2]) as f:
            policy = json.load(f)

        print(f"Checking {sys.argv[2]}...")
        public = validator.check_no_public_access(policy, sys.argv[3])
        print(f"  Public access: {public['result']}")

        priv = validator.check_no_privilege_escalation(policy)
        print(f"  Privilege escalation: {priv['result']}")

        return 0 if public['result'] == 'PASS' and priv['result'] == 'PASS' else 1

    results = validator.validate_directory(sys.argv[1])

    print(f"\nResults ({results['total']} policies):")
    print(f"  Passed: {results['passed']}")
    print(f"  Warnings: {len(results['warnings'])}")
    print(f"  Errors: {len(results['errors'])}")

    if results['errors']:
        print("\nErrors (blocking):")
        for e in results['errors'][:5]:
            print(f"  {Path(e['file']).name}: {e['issue']}")
        return 1

    print("\nAll policies passed!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
