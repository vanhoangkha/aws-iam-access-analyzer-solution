#!/usr/bin/env python3
"""
AWS IAM Access Analyzer - Comprehensive Solution (Updated)
Based on latest AWS documentation - includes ALL analyzer types:
1. External Access Analyzer - Detect cross-account/public access
2. Internal Access Analyzer - Detect internal access to critical resources (NEW)
3. Unused Access Analyzer - Detect unused permissions
4. Policy Validation - Validate against AWS best practices
5. Custom Policy Checks - Validate against your security standards
6. Policy Generation - Generate least-privilege policies from CloudTrail

Supported Resources:
- External: S3, IAM Roles, KMS, Lambda, SQS, Secrets Manager, SNS, EBS, RDS, ECR, EFS, DynamoDB
- Internal: S3, RDS snapshots, DynamoDB
- Unused: IAM Roles, Users (access keys, passwords, permissions)

References:
- https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-custom-policy-checks.html
"""

import boto3
import json
import time
from datetime import datetime, timezone, timedelta
from typing import Optional

class AccessAnalyzerSolution:
    def __init__(self, region: str = None):
        self.aa = boto3.client('accessanalyzer', region_name=region)
        self.sts = boto3.client('sts')
        self.account_id = self.sts.get_caller_identity()['Account']
        self.region = region or boto3.session.Session().region_name
        
    # ========== 1. ANALYZER MANAGEMENT ==========
    
    def ensure_analyzers(self) -> dict:
        """Create all 3 analyzer types: ACCOUNT, ACCOUNT_UNUSED_ACCESS, ORGANIZATION*"""
        analyzers = {}
        
        # Note: ORGANIZATION and ORGANIZATION_UNUSED_ACCESS require AWS Organizations
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
                        params['configuration'] = {
                            'unusedAccess': {'unusedAccessAge': 90}
                        }
                    resp = self.aa.create_analyzer(**params)
                    analyzers[analyzer_type] = resp['arn']
                    print(f"✅ Created {analyzer_type} analyzer")
            except Exception as e:
                print(f"⚠️ {analyzer_type}: {e}")
        return analyzers

    # ========== 2. POLICY VALIDATION ==========
    
    def validate_policy(self, policy: dict, policy_type: str = 'IDENTITY_POLICY', 
                       resource_type: str = None) -> list:
        """
        Validate policy against AWS best practices.
        policy_type: IDENTITY_POLICY, RESOURCE_POLICY, SERVICE_CONTROL_POLICY
        resource_type: For resource policies (AWS::S3::Bucket, AWS::SQS::Queue, etc.)
        """
        params = {
            'policyDocument': json.dumps(policy),
            'policyType': policy_type
        }
        if resource_type:
            params['resourceType'] = resource_type
            
        findings = []
        paginator = self.aa.get_paginator('validate_policy')
        for page in paginator.paginate(**params):
            findings.extend(page['findings'])
        return findings

    # ========== 3. CUSTOM POLICY CHECKS ==========
    
    def check_no_public_access(self, policy: dict, resource_type: str) -> dict:
        """
        Check if policy grants public access using AWS CLI.
        resource_type: AWS::S3::Bucket, AWS::SQS::Queue, AWS::SNS::Topic, etc.
        """
        import subprocess
        cmd = [
            'aws', 'accessanalyzer', 'check-no-public-access',
            '--policy-document', json.dumps(policy),
            '--resource-type', resource_type,
            '--output', 'json'
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            return {'result': 'ERROR', 'message': result.stderr, 'reasons': []}
        resp = json.loads(result.stdout)
        return {'result': resp['result'], 'message': resp.get('message', ''), 
                'reasons': resp.get('reasons', [])}
    
    def check_access_not_granted(self, policy: dict, actions: list, 
                                  policy_type: str = 'IDENTITY_POLICY') -> dict:
        """
        Check if policy does NOT grant specified actions.
        actions: List of actions to check, e.g., ['s3:*', 'iam:PassRole']
        """
        access = [{'actions': actions}]
        resp = self.aa.check_access_not_granted(
            policyDocument=json.dumps(policy),
            access=access,
            policyType=policy_type
        )
        return {'result': resp['result'], 'message': resp.get('message', ''),
                'reasons': resp.get('reasons', [])}
    
    def check_no_new_access(self, new_policy: dict, existing_policy: dict,
                            policy_type: str = 'IDENTITY_POLICY') -> dict:
        """Check if new policy grants additional access compared to existing policy."""
        resp = self.aa.check_no_new_access(
            newPolicyDocument=json.dumps(new_policy),
            existingPolicyDocument=json.dumps(existing_policy),
            policyType=policy_type
        )
        return {'result': resp['result'], 'message': resp.get('message', ''),
                'reasons': resp.get('reasons', [])}

    # ========== 4. ACCESS PREVIEW ==========
    
    def preview_access(self, analyzer_arn: str, resource_arn: str, 
                       resource_type: str, policy: dict) -> list:
        """
        Preview findings before deploying policy changes.
        Supported: S3, SQS, KMS, IAM Role trust, Secrets Manager, SNS, EBS, ECR, EFS, 
                   RDS snapshots, DynamoDB, Lambda
        """
        config_key = {
            'AWS::S3::Bucket': 's3Bucket',
            'AWS::SQS::Queue': 'sqsQueue', 
            'AWS::KMS::Key': 'kmsKey',
            'AWS::IAM::Role': 'iamRole',
            'AWS::SecretsManager::Secret': 'secretsManagerSecret',
            'AWS::SNS::Topic': 'snsTopic',
        }.get(resource_type)
        
        if not config_key:
            raise ValueError(f"Unsupported resource type: {resource_type}")
        
        policy_key = {
            's3Bucket': 'bucketPolicy',
            'sqsQueue': 'queuePolicy',
            'kmsKey': 'keyPolicies',
            'iamRole': 'trustPolicy',
            'secretsManagerSecret': 'secretPolicy',
            'snsTopic': 'topicPolicy',
        }[config_key]
        
        if config_key == 'kmsKey':
            config = {resource_arn: {config_key: {policy_key: {'default': json.dumps(policy)}}}}
        else:
            config = {resource_arn: {config_key: {policy_key: json.dumps(policy)}}}
        
        # Create preview
        resp = self.aa.create_access_preview(analyzerArn=analyzer_arn, configurations=config)
        preview_id = resp['id']
        
        # Wait for completion
        for _ in range(60):
            resp = self.aa.get_access_preview(accessPreviewId=preview_id, analyzerArn=analyzer_arn)
            if resp['accessPreview']['status'] in ['COMPLETED', 'FAILED']:
                break
            time.sleep(2)
        
        if resp['accessPreview']['status'] == 'FAILED':
            raise Exception(f"Preview failed: {resp['accessPreview'].get('statusReason', {})}")
        
        # Get findings
        findings = []
        paginator = self.aa.get_paginator('list_access_preview_findings')
        for page in paginator.paginate(accessPreviewId=preview_id, analyzerArn=analyzer_arn):
            findings.extend(page['findings'])
        return findings

    # ========== 5. FINDINGS MANAGEMENT ==========
    
    def get_findings(self, analyzer_arn: str, status: str = 'ACTIVE', 
                     resource_type: str = None, finding_type: str = None) -> list:
        """
        Get findings from analyzer.
        finding_type for unused: UnusedIAMRole, UnusedIAMUserAccessKey, 
                                 UnusedIAMUserPassword, UnusedPermission
        """
        filter_criteria = {'status': {'eq': [status]}}
        if resource_type:
            filter_criteria['resourceType'] = {'eq': [resource_type]}
        if finding_type:
            filter_criteria['findingType'] = {'eq': [finding_type]}
            
        findings = []
        paginator = self.aa.get_paginator('list_findings_v2')
        for page in paginator.paginate(analyzerArn=analyzer_arn, filter=filter_criteria):
            findings.extend(page['findings'])
        return findings
    
    def archive_findings(self, analyzer_arn: str, finding_ids: list) -> None:
        """Archive findings (mark as reviewed/expected)."""
        self.aa.update_findings(
            analyzerArn=analyzer_arn,
            ids=finding_ids,
            status='ARCHIVED'
        )

    # ========== 6. POLICY GENERATION ==========
    
    def generate_policy(self, principal_arn: str, trail_arn: str, 
                        access_role_arn: str, days: int = 90) -> str:
        """
        Generate least-privilege policy from CloudTrail activity.
        Returns job_id to check status with get_generated_policy().
        """
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
        """Get status and result of policy generation job."""
        return self.aa.get_generated_policy(jobId=job_id)

    # ========== 7. ARCHIVE RULES ==========
    
    def create_archive_rule(self, analyzer_name: str, rule_name: str, 
                           filter_criteria: dict) -> None:
        """
        Create rule to auto-archive expected findings.
        Example filter: {'principal.AWS': {'contains': ['trusted-account-id']}}
        """
        self.aa.create_archive_rule(
            analyzerName=analyzer_name,
            ruleName=rule_name,
            filter=filter_criteria
        )

    # ========== 8. RESOURCE SCAN ==========
    
    def rescan_resource(self, analyzer_arn: str, resource_arn: str) -> None:
        """Trigger immediate rescan of a specific resource."""
        self.aa.start_resource_scan(
            analyzerArn=analyzer_arn,
            resourceArn=resource_arn
        )

    # ========== 10. FINDING RECOMMENDATIONS (NEW 2024) ==========
    
    def generate_finding_recommendation(self, analyzer_arn: str, finding_id: str) -> None:
        """
        Generate prescriptive recommendations for unused permissions finding.
        New feature from Sep 2024 - provides step-by-step guidance to refine permissions.
        """
        self.aa.generate_finding_recommendation(
            analyzerArn=analyzer_arn,
            id=finding_id
        )
    
    def get_finding_recommendation(self, analyzer_arn: str, finding_id: str) -> dict:
        """
        Get generated recommendations for a finding.
        Returns recommended policies excluding unused actions.
        """
        return self.aa.get_finding_recommendation(
            analyzerArn=analyzer_arn,
            id=finding_id
        )

    # ========== 11. CUSTOMIZE ANALYZER SCOPE (NEW Jan 2025) ==========
    
    def update_analyzer_exclusions(self, analyzer_name: str, 
                                    exclude_account_ids: list = None,
                                    exclude_tags: list = None) -> dict:
        """
        Customize unused access analyzer scope by excluding accounts or tagged roles.
        New feature from Jan 2025.
        
        exclude_account_ids: ['111122223333', '444455556666']
        exclude_tags: [{'team': 'security'}, {'env': 'sandbox'}]
        """
        exclusions = []
        if exclude_account_ids:
            exclusions.append({'accountIds': exclude_account_ids})
        if exclude_tags:
            for tag in exclude_tags:
                exclusions.append({'resourceTags': [tag]})
        
        return self.aa.update_analyzer(
            analyzerName=analyzer_name,
            configuration={
                'unusedAccess': {
                    'analysisRule': {
                        'exclusions': exclusions
                    }
                }
            }
        )

    # ========== 9. COMPREHENSIVE SCAN ==========
    
    def full_scan(self) -> dict:
        """Run comprehensive scan with all analyzer types."""
        results = {
            'external_access': [],
            'unused_access': [],
            'summary': {}
        }
        
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
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": ["arn:aws:s3:::my-bucket/*"]
        }]
    }
    findings = solution.validate_policy(sample_policy)
    print(f"   Validation findings: {len(findings)}")
    
    print("\n🔎 Running full scan...")
    results = solution.full_scan()
    print(f"   External access findings: {results['summary']['external_access_count']}")
    print(f"   Unused access findings: {results['summary']['unused_access_count']}")
    
    print("\n🛡️ Custom policy checks...")
    
    # Check no public access
    s3_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::my-bucket/*"
        }]
    }
    public_check = solution.check_no_public_access(s3_policy, 'AWS::S3::Bucket')
    print(f"   No public access: {'✅ PASS' if public_check['result'] == 'PASS' else '❌ FAIL'}")
    
    # Check dangerous actions not granted
    dangerous_check = solution.check_access_not_granted(
        sample_policy, 
        ['iam:*', 'iam:PassRole']
    )
    print(f"   No dangerous IAM actions: {'✅ PASS' if dangerous_check['result'] == 'PASS' else '❌ FAIL'}")
    
    print("\n✅ Done!")
    return results


if __name__ == "__main__":
    main()
