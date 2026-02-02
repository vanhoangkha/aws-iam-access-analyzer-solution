#!/usr/bin/env python3
"""
CI/CD Integration - Chạy trong pipeline để block deployments có security issues
"""

import sys
import json
import boto3
from pathlib import Path

aa = boto3.client('accessanalyzer')

def validate_all_policies(policies_dir: str) -> dict:
    """Validate tất cả policies trong directory"""
    results = {'errors': [], 'warnings': [], 'passed': 0}
    
    for policy_file in Path(policies_dir).rglob('*.json'):
        with open(policy_file) as f:
            policy = json.load(f)
        
        # Detect policy type from path
        path_str = str(policy_file).lower()
        if 'scp' in path_str:
            policy_type = 'SERVICE_CONTROL_POLICY'
        elif 'trust' in path_str:
            policy_type = 'RESOURCE_POLICY'  # Trust policies are resource policies
        elif 'resource' in path_str:
            policy_type = 'RESOURCE_POLICY'
        else:
            policy_type = 'IDENTITY_POLICY'
        
        findings = aa.validate_policy(
            policyDocument=json.dumps(policy),
            policyType=policy_type
        )['findings']
        
        for f in findings:
            item = {'file': str(policy_file), 'issue': f['issueCode'], 'detail': f['findingDetails']}
            if f['findingType'] in ['ERROR', 'SECURITY_WARNING']:
                results['errors'].append(item)
            else:
                results['warnings'].append(item)
        
        if not findings:
            results['passed'] += 1
    
    return results

def check_no_public_access(policy: dict, resource_type: str) -> bool:
    """Block nếu policy cho phép public access"""
    resp = aa.check_no_public_access(
        policyDocument=json.dumps(policy),
        resourceType=resource_type
    )
    return resp['result'] == 'PASS'

def check_no_privilege_escalation(policy: dict) -> bool:
    """Block nếu policy có thể dẫn đến privilege escalation"""
    dangerous_actions = [
        {'actions': ['iam:*']},
        {'actions': ['iam:PassRole']},
        {'actions': ['iam:CreatePolicyVersion']},
        {'actions': ['iam:AttachUserPolicy', 'iam:AttachRolePolicy']},
        {'actions': ['lambda:CreateFunction', 'lambda:InvokeFunction']},
    ]
    
    for access in dangerous_actions:
        resp = aa.check_access_not_granted(
            policyDocument=json.dumps(policy),
            access=[access],
            policyType='IDENTITY_POLICY'
        )
        if resp['result'] == 'FAIL':
            return False
    return True

def main():
    if len(sys.argv) < 2:
        print("Usage: cicd_integration.py <policies_dir>")
        sys.exit(1)
    
    policies_dir = sys.argv[1]
    print(f"🔍 Scanning {policies_dir}...")
    
    results = validate_all_policies(policies_dir)
    
    print(f"\n📊 Results:")
    print(f"   ✅ Passed: {results['passed']}")
    print(f"   ⚠️  Warnings: {len(results['warnings'])}")
    print(f"   ❌ Errors: {len(results['errors'])}")
    
    if results['errors']:
        print("\n❌ ERRORS (blocking):")
        for e in results['errors']:
            print(f"   {e['file']}: {e['issue']}")
        sys.exit(1)
    
    print("\n✅ All policies passed validation!")
    sys.exit(0)

if __name__ == "__main__":
    main()
