#!/usr/bin/env python3
"""
AWS IAM Access Analyzer - Comprehensive Solution
Covers ALL Access Analyzer features with proper error handling.

Features:
1. External Access Analyzer - Detect cross-account/public access (FREE)
2. Unused Access Analyzer - Detect unused permissions ($0.20/identity/month)
3. Policy Validation - Validate against AWS best practices (FREE)
4. Custom Policy Checks - check_no_public_access, check_access_not_granted (FREE)
5. Access Preview - Preview findings before deployment (FREE)
6. Policy Generation - Generate least-privilege from CloudTrail (FREE)

References:
- https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html
"""

import boto3
import json
import time
from datetime import datetime, timezone, timedelta
from typing import Optional, Union
from botocore.exceptions import ClientError


class AccessAnalyzerSolution:
    def __init__(self, region: str = None):
        self.region = region or boto3.session.Session().region_name
        self.aa = boto3.client('accessanalyzer', region_name=self.region)
        self.sts = boto3.client('sts')
        self.account_id = self.sts.get_caller_identity()['Account']

    # ========== 1. ANALYZER MANAGEMENT ==========

    def ensure_analyzers(self) -> dict:
        """Create ACCOUNT and ACCOUNT_UNUSED_ACCESS analyzers."""
        analyzers = {}
        for analyzer_type in ['ACCOUNT', 'ACCOUNT_UNUSED_ACCESS']:
            name = f"analyzer-{analyzer_type.lower().replace('_', '-')}"
            try:
                resp = self.aa.list_analyzers(type=analyzer_type)
                active = [a for a in resp['analyzers'] if a['status'] == 'ACTIVE']
                if active:
                    analyzers[analyzer_type] = active[0]['arn']
                else:
                    params = {'analyzerName': name, 'type': analyzer_type}
                    if analyzer_type == 'ACCOUNT_UNUSED_ACCESS':
                        params['configuration'] = {'unusedAccess': {'unusedAccessAge': 90}}
                    resp = self.aa.create_analyzer(**params)
                    analyzers[analyzer_type] = resp['arn']
                    print(f"✅ Created {analyzer_type} analyzer")
            except ClientError as e:
                print(f"⚠️ {analyzer_type}: {e.response['Error']['Message']}")
        return analyzers

    # ========== 2. POLICY VALIDATION (FREE) ==========

    def validate_policy(self, policy: Union[dict, str], policy_type: str = 'IDENTITY_POLICY',
                        resource_type: str = None) -> list:
        """
        Validate policy against AWS best practices.
        policy_type: IDENTITY_POLICY, RESOURCE_POLICY, SERVICE_CONTROL_POLICY
        """
        policy_doc = json.dumps(policy) if isinstance(policy, dict) else policy
        params = {'policyDocument': policy_doc, 'policyType': policy_type}
        if resource_type:
            params['validatePolicyResourceType'] = resource_type

        findings = []
        try:
            paginator = self.aa.get_paginator('validate_policy')
            for page in paginator.paginate(**params):
                findings.extend(page['findings'])
        except ClientError as e:
            return [{'findingType': 'ERROR', 'findingDetails': str(e)}]
        return findings

    # ========== 3. CUSTOM POLICY CHECKS ($0.002/call) ==========

    def check_no_public_access(self, policy: Union[dict, str], resource_type: str) -> dict:
        """
        Check if policy grants public access.
        resource_type: AWS::S3::Bucket, AWS::SQS::Queue, AWS::SNS::Topic, etc.
        """
        policy_doc = json.dumps(policy) if isinstance(policy, dict) else policy
        try:
            resp = self.aa.check_no_public_access(
                policyDocument=policy_doc,
                resourceType=resource_type
            )
            return {
                'result': resp['result'],
                'message': resp.get('message', ''),
                'reasons': resp.get('reasons', [])
            }
        except ClientError as e:
            return {'result': 'ERROR', 'message': str(e), 'reasons': []}

    def check_access_not_granted(self, policy: Union[dict, str], actions: list,
                                  policy_type: str = 'IDENTITY_POLICY') -> dict:
        """Check if policy does NOT grant specified actions."""
        policy_doc = json.dumps(policy) if isinstance(policy, dict) else policy
        try:
            resp = self.aa.check_access_not_granted(
                policyDocument=policy_doc,
                access=[{'actions': actions}],
                policyType=policy_type
            )
            return {
                'result': resp['result'],
                'message': resp.get('message', ''),
                'reasons': resp.get('reasons', [])
            }
        except ClientError as e:
            return {'result': 'ERROR', 'message': str(e), 'reasons': []}

    def check_no_new_access(self, new_policy: Union[dict, str], existing_policy: Union[dict, str],
                            policy_type: str = 'IDENTITY_POLICY') -> dict:
        """Check if new policy grants additional access compared to existing."""
        new_doc = json.dumps(new_policy) if isinstance(new_policy, dict) else new_policy
        existing_doc = json.dumps(existing_policy) if isinstance(existing_policy, dict) else existing_policy
        try:
            resp = self.aa.check_no_new_access(
                newPolicyDocument=new_doc,
                existingPolicyDocument=existing_doc,
                policyType=policy_type
            )
            return {
                'result': resp['result'],
                'message': resp.get('message', ''),
                'reasons': resp.get('reasons', [])
            }
        except ClientError as e:
            return {'result': 'ERROR', 'message': str(e), 'reasons': []}

    # ========== 4. ACCESS PREVIEW (FREE) ==========

    def preview_access(self, analyzer_arn: str, resource_arn: str,
                       resource_type: str, policy: Union[dict, str]) -> list:
        """Preview findings before deploying policy changes."""
        policy_doc = json.dumps(policy) if isinstance(policy, dict) else policy

        config_map = {
            'AWS::S3::Bucket': ('s3Bucket', 'bucketPolicy'),
            'AWS::SQS::Queue': ('sqsQueue', 'queuePolicy'),
            'AWS::KMS::Key': ('kmsKey', 'keyPolicies'),
            'AWS::IAM::Role': ('iamRole', 'trustPolicy'),
            'AWS::SecretsManager::Secret': ('secretsManagerSecret', 'secretPolicy'),
            'AWS::SNS::Topic': ('snsTopic', 'topicPolicy'),
        }

        if resource_type not in config_map:
            raise ValueError(f"Unsupported resource type: {resource_type}")

        config_key, policy_key = config_map[resource_type]

        if config_key == 'kmsKey':
            config = {resource_arn: {config_key: {policy_key: {'default': policy_doc}}}}
        else:
            config = {resource_arn: {config_key: {policy_key: policy_doc}}}

        try:
            resp = self.aa.create_access_preview(analyzerArn=analyzer_arn, configurations=config)
            preview_id = resp['id']

            for _ in range(60):
                resp = self.aa.get_access_preview(accessPreviewId=preview_id, analyzerArn=analyzer_arn)
                if resp['accessPreview']['status'] in ['COMPLETED', 'FAILED']:
                    break
                time.sleep(2)

            if resp['accessPreview']['status'] == 'FAILED':
                raise Exception(f"Preview failed: {resp['accessPreview'].get('statusReason', {})}")

            findings = []
            paginator = self.aa.get_paginator('list_access_preview_findings')
            for page in paginator.paginate(accessPreviewId=preview_id, analyzerArn=analyzer_arn):
                findings.extend(page['findings'])
            return findings
        except ClientError as e:
            raise Exception(f"Preview error: {e}")

    # ========== 5. FINDINGS MANAGEMENT ==========

    def get_findings(self, analyzer_arn: str, status: str = 'ACTIVE',
                     resource_type: str = None, finding_type: str = None) -> list:
        """Get findings from analyzer."""
        filter_criteria = {'status': {'eq': [status]}}
        if resource_type:
            filter_criteria['resourceType'] = {'eq': [resource_type]}
        if finding_type:
            filter_criteria['findingType'] = {'eq': [finding_type]}

        findings = []
        try:
            paginator = self.aa.get_paginator('list_findings_v2')
            for page in paginator.paginate(analyzerArn=analyzer_arn, filter=filter_criteria):
                findings.extend(page['findings'])
        except ClientError as e:
            print(f"⚠️ Error getting findings: {e}")
        return findings

    def archive_findings(self, analyzer_arn: str, finding_ids: list) -> bool:
        """Archive findings (mark as reviewed)."""
        try:
            self.aa.update_findings(analyzerArn=analyzer_arn, ids=finding_ids, status='ARCHIVED')
            return True
        except ClientError:
            return False

    # ========== 6. POLICY GENERATION (FREE) ==========

    def generate_policy(self, principal_arn: str, trail_arn: str,
                        access_role_arn: str, days: int = 90) -> str:
        """Generate least-privilege policy from CloudTrail. Returns job_id."""
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days)

        resp = self.aa.start_policy_generation(
            policyGenerationDetails={'principalArn': principal_arn},
            cloudTrailDetails={
                'trails': [{'cloudTrailArn': trail_arn, 'allRegions': True}],
                'accessRole': access_role_arn,
                'startTime': start_time,
                'endTime': end_time
            }
        )
        return resp['jobId']

    def get_generated_policy(self, job_id: str) -> dict:
        """Get policy generation job result."""
        return self.aa.get_generated_policy(jobId=job_id)

    # ========== 7. ARCHIVE RULES ==========

    def create_archive_rule(self, analyzer_name: str, rule_name: str,
                            filter_criteria: dict) -> bool:
        """Create rule to auto-archive expected findings."""
        try:
            self.aa.create_archive_rule(
                analyzerName=analyzer_name,
                ruleName=rule_name,
                filter=filter_criteria
            )
            return True
        except ClientError:
            return False

    # ========== 8. FINDING RECOMMENDATIONS ==========

    def get_finding_recommendation(self, analyzer_arn: str, finding_id: str) -> dict:
        """Get recommendations for unused permissions finding."""
        try:
            self.aa.generate_finding_recommendation(analyzerArn=analyzer_arn, id=finding_id)
            time.sleep(2)
            return self.aa.get_finding_recommendation(analyzerArn=analyzer_arn, id=finding_id)
        except ClientError as e:
            return {'error': str(e)}

    # ========== 9. FULL SCAN ==========

    def full_scan(self) -> dict:
        """Run comprehensive scan with all analyzer types."""
        results = {'external_access': [], 'unused_access': [], 'summary': {}}
        analyzers = self.ensure_analyzers()

        if 'ACCOUNT' in analyzers:
            results['external_access'] = self.get_findings(analyzers['ACCOUNT'])
        if 'ACCOUNT_UNUSED_ACCESS' in analyzers:
            results['unused_access'] = self.get_findings(analyzers['ACCOUNT_UNUSED_ACCESS'])

        results['summary'] = {
            'external_access_count': len(results['external_access']),
            'unused_access_count': len(results['unused_access']),
            'analyzers': analyzers
        }
        return results


def main():
    solution = AccessAnalyzerSolution()

    print("🔍 Setting up analyzers...")
    analyzers = solution.ensure_analyzers()

    print("\n📋 Validating sample policy...")
    sample_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::my-bucket/*"]}]
    }
    findings = solution.validate_policy(sample_policy)
    print(f"   Validation findings: {len(findings)}")

    print("\n🔎 Running full scan...")
    results = solution.full_scan()
    print(f"   External access findings: {results['summary']['external_access_count']}")
    print(f"   Unused access findings: {results['summary']['unused_access_count']}")

    print("\n🛡️ Custom policy checks...")
    s3_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{solution.account_id}:root"},
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::my-bucket/*"
        }]
    }
    public_check = solution.check_no_public_access(s3_policy, 'AWS::S3::Bucket')
    print(f"   No public access: {'✅ PASS' if public_check['result'] == 'PASS' else '❌ ' + public_check['result']}")

    dangerous_check = solution.check_access_not_granted(sample_policy, ['iam:*', 'iam:PassRole'])
    print(f"   No dangerous IAM actions: {'✅ PASS' if dangerous_check['result'] == 'PASS' else '❌ ' + dangerous_check['result']}")

    print("\n✅ Done!")
    return results


if __name__ == "__main__":
    main()
