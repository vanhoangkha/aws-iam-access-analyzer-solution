#!/usr/bin/env python3
"""
CI/CD Integration - Block deployments with security issues.
Usage: python3 cicd_integration.py <policies_dir>
"""

import sys
import json
import boto3
from pathlib import Path
from botocore.exceptions import ClientError

aa = boto3.client('accessanalyzer')


def validate_all_policies(policies_dir: str) -> dict:
    """Validate all JSON policies in directory."""
    results = {'errors': [], 'warnings': [], 'passed': 0, 'total': 0}

    for policy_file in Path(policies_dir).rglob('*.json'):
        results['total'] += 1
        try:
            with open(policy_file) as f:
                policy = json.load(f)
        except json.JSONDecodeError as e:
            results['errors'].append({'file': str(policy_file), 'issue': 'INVALID_JSON', 'detail': str(e)})
            continue

        # Detect policy type
        path_str = str(policy_file).lower()
        if 'scp' in path_str:
            policy_type = 'SERVICE_CONTROL_POLICY'
        elif 'resource' in path_str or 'trust' in path_str:
            policy_type = 'RESOURCE_POLICY'
        else:
            policy_type = 'IDENTITY_POLICY'

        try:
            resp = aa.validate_policy(policyDocument=json.dumps(policy), policyType=policy_type)
            findings = resp.get('findings', [])

            for f in findings:
                item = {'file': str(policy_file), 'issue': f['issueCode'], 'detail': f['findingDetails']}
                if f['findingType'] in ['ERROR', 'SECURITY_WARNING']:
                    results['errors'].append(item)
                else:
                    results['warnings'].append(item)

            if not findings:
                results['passed'] += 1
        except ClientError as e:
            results['errors'].append({'file': str(policy_file), 'issue': 'API_ERROR', 'detail': str(e)})

    return results


def check_no_public_access(policy: dict, resource_type: str) -> dict:
    """Check if policy grants public access."""
    try:
        resp = aa.check_no_public_access(policyDocument=json.dumps(policy), resourceType=resource_type)
        return {'result': resp['result'], 'reasons': resp.get('reasons', [])}
    except ClientError as e:
        return {'result': 'ERROR', 'reasons': [str(e)]}


def check_no_privilege_escalation(policy: dict) -> dict:
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
            resp = aa.check_access_not_granted(
                policyDocument=json.dumps(policy),
                access=[{'actions': actions}],
                policyType='IDENTITY_POLICY'
            )
            if resp['result'] == 'FAIL':
                failed.extend(actions)
        except ClientError:
            pass

    return {'result': 'PASS' if not failed else 'FAIL', 'dangerous_actions': failed}


def main():
    if len(sys.argv) < 2:
        print("Usage: cicd_integration.py <policies_dir>")
        print("       cicd_integration.py --check-policy <policy.json> <resource_type>")
        sys.exit(1)

    if sys.argv[1] == '--check-policy' and len(sys.argv) >= 4:
        with open(sys.argv[2]) as f:
            policy = json.load(f)
        resource_type = sys.argv[3]

        print(f"🔍 Checking {sys.argv[2]}...")
        public = check_no_public_access(policy, resource_type)
        print(f"   Public access: {public['result']}")

        priv = check_no_privilege_escalation(policy)
        print(f"   Privilege escalation: {priv['result']}")
        if priv['dangerous_actions']:
            print(f"   ⚠️ Dangerous actions: {priv['dangerous_actions']}")

        sys.exit(0 if public['result'] == 'PASS' and priv['result'] == 'PASS' else 1)

    policies_dir = sys.argv[1]
    print(f"🔍 Scanning {policies_dir}...")

    results = validate_all_policies(policies_dir)

    print(f"\n📊 Results ({results['total']} policies):")
    print(f"   ✅ Passed: {results['passed']}")
    print(f"   ⚠️  Warnings: {len(results['warnings'])}")
    print(f"   ❌ Errors: {len(results['errors'])}")

    if results['warnings']:
        print("\n⚠️ WARNINGS:")
        for w in results['warnings'][:5]:
            print(f"   {Path(w['file']).name}: {w['issue']}")

    if results['errors']:
        print("\n❌ ERRORS (blocking):")
        for e in results['errors']:
            print(f"   {Path(e['file']).name}: {e['issue']} - {e['detail'][:50]}")
        sys.exit(1)

    print("\n✅ All policies passed validation!")
    sys.exit(0)


if __name__ == "__main__":
    main()
