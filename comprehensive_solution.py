#!/usr/bin/env python3
"""
AWS IAM Access Analyzer - Comprehensive Solution

Features:
- External Access Analyzer: Detect cross-account/public access (FREE)
- Unused Access Analyzer: Detect unused permissions ($0.20/identity/month)
- Policy Validation: Validate against AWS best practices (FREE)
- Custom Policy Checks: check_no_public_access, check_access_not_granted ($0.002/call)
- Access Preview: Preview findings before deployment (FREE)
- Policy Generation: Generate least-privilege from CloudTrail (FREE)

References:
- https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html
"""

import boto3
import json
import time
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Union, List, Dict, Any
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


class AccessAnalyzerSolution:
    """AWS IAM Access Analyzer wrapper with all features."""

    ANALYZER_TYPES = ['ACCOUNT', 'ACCOUNT_UNUSED_ACCESS']
    SUPPORTED_RESOURCE_TYPES = {
        'AWS::S3::Bucket': ('s3Bucket', 'bucketPolicy'),
        'AWS::SQS::Queue': ('sqsQueue', 'queuePolicy'),
        'AWS::KMS::Key': ('kmsKey', 'keyPolicies'),
        'AWS::IAM::Role': ('iamRole', 'trustPolicy'),
        'AWS::SecretsManager::Secret': ('secretsManagerSecret', 'secretPolicy'),
        'AWS::SNS::Topic': ('snsTopic', 'topicPolicy'),
    }

    def __init__(self, region: str = None):
        """Initialize Access Analyzer client."""
        self.region = region or boto3.session.Session().region_name
        self.aa = boto3.client('accessanalyzer', region_name=self.region)
        self.sts = boto3.client('sts')
        self.account_id = self.sts.get_caller_identity()['Account']

    def _to_json(self, policy: Union[dict, str]) -> str:
        """Convert policy to JSON string."""
        return json.dumps(policy) if isinstance(policy, dict) else policy

    # ========== ANALYZER MANAGEMENT ==========

    def ensure_analyzers(self) -> Dict[str, str]:
        """Create ACCOUNT and ACCOUNT_UNUSED_ACCESS analyzers if not exist."""
        analyzers = {}
        for analyzer_type in self.ANALYZER_TYPES:
            name = f"analyzer-{analyzer_type.lower().replace('_', '-')}"
            try:
                resp = self.aa.list_analyzers(type=analyzer_type)
                active = [a for a in resp['analyzers'] if a['status'] == 'ACTIVE']
                if active:
                    analyzers[analyzer_type] = active[0]['arn']
                    logger.info("Found existing %s analyzer", analyzer_type)
                else:
                    params = {'analyzerName': name, 'type': analyzer_type}
                    if analyzer_type == 'ACCOUNT_UNUSED_ACCESS':
                        params['configuration'] = {'unusedAccess': {'unusedAccessAge': 90}}
                    resp = self.aa.create_analyzer(**params)
                    analyzers[analyzer_type] = resp['arn']
                    logger.info("Created %s analyzer", analyzer_type)
            except ClientError as e:
                logger.warning("%s: %s", analyzer_type, e.response['Error']['Message'])
        return analyzers

    def get_analyzer_arn(self, analyzer_type: str = 'ACCOUNT') -> Optional[str]:
        """Get ARN of existing analyzer by type."""
        try:
            resp = self.aa.list_analyzers(type=analyzer_type)
            active = [a for a in resp['analyzers'] if a['status'] == 'ACTIVE']
            return active[0]['arn'] if active else None
        except ClientError:
            return None

    # ========== POLICY VALIDATION (FREE) ==========

    def validate_policy(
        self,
        policy: Union[dict, str],
        policy_type: str = 'IDENTITY_POLICY',
        resource_type: str = None
    ) -> List[Dict[str, Any]]:
        """
        Validate policy against AWS best practices.

        Args:
            policy: IAM policy document (dict or JSON string)
            policy_type: IDENTITY_POLICY, RESOURCE_POLICY, SERVICE_CONTROL_POLICY
            resource_type: For resource policies (AWS::S3::Bucket, etc.)

        Returns:
            List of validation findings
        """
        params = {
            'policyDocument': self._to_json(policy),
            'policyType': policy_type
        }
        if resource_type:
            params['validatePolicyResourceType'] = resource_type

        findings = []
        try:
            paginator = self.aa.get_paginator('validate_policy')
            for page in paginator.paginate(**params):
                findings.extend(page['findings'])
        except ClientError as e:
            logger.error("Policy validation failed: %s", e)
            return [{'findingType': 'ERROR', 'findingDetails': str(e)}]
        return findings

    # ========== CUSTOM POLICY CHECKS ($0.002/call) ==========

    def check_no_public_access(
        self,
        policy: Union[dict, str],
        resource_type: str
    ) -> Dict[str, Any]:
        """
        Check if policy grants public access.

        Args:
            policy: Resource policy document
            resource_type: AWS::S3::Bucket, AWS::SQS::Queue, AWS::SNS::Topic, etc.

        Returns:
            Dict with 'result' (PASS/FAIL/ERROR), 'message', 'reasons'
        """
        try:
            resp = self.aa.check_no_public_access(
                policyDocument=self._to_json(policy),
                resourceType=resource_type
            )
            return {
                'result': resp['result'],
                'message': resp.get('message', ''),
                'reasons': resp.get('reasons', [])
            }
        except ClientError as e:
            logger.error("check_no_public_access failed: %s", e)
            return {'result': 'ERROR', 'message': str(e), 'reasons': []}

    def check_access_not_granted(
        self,
        policy: Union[dict, str],
        actions: List[str],
        policy_type: str = 'IDENTITY_POLICY'
    ) -> Dict[str, Any]:
        """
        Check if policy does NOT grant specified actions.

        Args:
            policy: IAM policy document
            actions: List of actions to check (e.g., ['iam:*', 's3:DeleteBucket'])
            policy_type: IDENTITY_POLICY or RESOURCE_POLICY

        Returns:
            Dict with 'result' (PASS/FAIL/ERROR), 'message', 'reasons'
        """
        try:
            resp = self.aa.check_access_not_granted(
                policyDocument=self._to_json(policy),
                access=[{'actions': actions}],
                policyType=policy_type
            )
            return {
                'result': resp['result'],
                'message': resp.get('message', ''),
                'reasons': resp.get('reasons', [])
            }
        except ClientError as e:
            logger.error("check_access_not_granted failed: %s", e)
            return {'result': 'ERROR', 'message': str(e), 'reasons': []}

    def check_no_new_access(
        self,
        new_policy: Union[dict, str],
        existing_policy: Union[dict, str],
        policy_type: str = 'IDENTITY_POLICY'
    ) -> Dict[str, Any]:
        """
        Check if new policy grants additional access compared to existing.

        Args:
            new_policy: New policy document
            existing_policy: Existing policy document
            policy_type: IDENTITY_POLICY or RESOURCE_POLICY

        Returns:
            Dict with 'result' (PASS/FAIL/ERROR), 'message', 'reasons'
        """
        try:
            resp = self.aa.check_no_new_access(
                newPolicyDocument=self._to_json(new_policy),
                existingPolicyDocument=self._to_json(existing_policy),
                policyType=policy_type
            )
            return {
                'result': resp['result'],
                'message': resp.get('message', ''),
                'reasons': resp.get('reasons', [])
            }
        except ClientError as e:
            logger.error("check_no_new_access failed: %s", e)
            return {'result': 'ERROR', 'message': str(e), 'reasons': []}

    # ========== ACCESS PREVIEW (FREE) ==========

    def preview_access(
        self,
        analyzer_arn: str,
        resource_arn: str,
        resource_type: str,
        policy: Union[dict, str],
        timeout: int = 120
    ) -> List[Dict[str, Any]]:
        """
        Preview findings before deploying policy changes.

        Args:
            analyzer_arn: ARN of the analyzer
            resource_arn: ARN of the resource
            resource_type: Type of resource (AWS::S3::Bucket, etc.)
            policy: New policy document
            timeout: Max seconds to wait for preview completion

        Returns:
            List of preview findings

        Raises:
            ValueError: If resource type is not supported
            Exception: If preview fails
        """
        if resource_type not in self.SUPPORTED_RESOURCE_TYPES:
            raise ValueError(f"Unsupported resource type: {resource_type}")

        config_key, policy_key = self.SUPPORTED_RESOURCE_TYPES[resource_type]
        policy_doc = self._to_json(policy)

        if config_key == 'kmsKey':
            config = {resource_arn: {config_key: {policy_key: {'default': policy_doc}}}}
        else:
            config = {resource_arn: {config_key: {policy_key: policy_doc}}}

        resp = self.aa.create_access_preview(analyzerArn=analyzer_arn, configurations=config)
        preview_id = resp['id']

        # Wait for completion
        start_time = time.time()
        while time.time() - start_time < timeout:
            resp = self.aa.get_access_preview(
                accessPreviewId=preview_id,
                analyzerArn=analyzer_arn
            )
            status = resp['accessPreview']['status']
            if status == 'COMPLETED':
                break
            if status == 'FAILED':
                raise Exception(f"Preview failed: {resp['accessPreview'].get('statusReason', {})}")
            time.sleep(2)
        else:
            raise Exception("Preview timed out")

        # Get findings
        findings = []
        paginator = self.aa.get_paginator('list_access_preview_findings')
        for page in paginator.paginate(accessPreviewId=preview_id, analyzerArn=analyzer_arn):
            findings.extend(page['findings'])
        return findings

    # ========== FINDINGS MANAGEMENT ==========

    def get_findings(
        self,
        analyzer_arn: str,
        status: str = 'ACTIVE',
        resource_type: str = None,
        finding_type: str = None
    ) -> List[Dict[str, Any]]:
        """
        Get findings from analyzer.

        Args:
            analyzer_arn: ARN of the analyzer
            status: ACTIVE, ARCHIVED, RESOLVED
            resource_type: Filter by resource type
            finding_type: Filter by finding type (UnusedIAMRole, UnusedPermission, etc.)

        Returns:
            List of findings
        """
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
            logger.error("Failed to get findings: %s", e)
        return findings

    def archive_findings(self, analyzer_arn: str, finding_ids: List[str]) -> bool:
        """Archive findings (mark as reviewed)."""
        try:
            self.aa.update_findings(
                analyzerArn=analyzer_arn,
                ids=finding_ids,
                status='ARCHIVED'
            )
            return True
        except ClientError as e:
            logger.error("Failed to archive findings: %s", e)
            return False

    # ========== POLICY GENERATION (FREE) ==========

    def generate_policy(
        self,
        principal_arn: str,
        trail_arn: str,
        access_role_arn: str,
        days: int = 90
    ) -> str:
        """
        Generate least-privilege policy from CloudTrail activity.

        Args:
            principal_arn: ARN of the principal to generate policy for
            trail_arn: ARN of the CloudTrail trail
            access_role_arn: ARN of role with CloudTrail read access
            days: Number of days of activity to analyze

        Returns:
            Job ID to check status with get_generated_policy()
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

    def get_generated_policy(self, job_id: str) -> Dict[str, Any]:
        """Get policy generation job result."""
        return self.aa.get_generated_policy(jobId=job_id)

    # ========== ARCHIVE RULES ==========

    def create_archive_rule(
        self,
        analyzer_name: str,
        rule_name: str,
        filter_criteria: Dict[str, Any]
    ) -> bool:
        """
        Create rule to auto-archive expected findings.

        Args:
            analyzer_name: Name of the analyzer
            rule_name: Name for the archive rule
            filter_criteria: Filter for findings to archive

        Returns:
            True if successful
        """
        try:
            self.aa.create_archive_rule(
                analyzerName=analyzer_name,
                ruleName=rule_name,
                filter=filter_criteria
            )
            return True
        except ClientError as e:
            logger.error("Failed to create archive rule: %s", e)
            return False

    # ========== FULL SCAN ==========

    def full_scan(self) -> Dict[str, Any]:
        """
        Run comprehensive scan with all analyzer types.

        Returns:
            Dict with external_access, unused_access findings and summary
        """
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
    """Run Access Analyzer scan and checks."""
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    solution = AccessAnalyzerSolution()

    print("Setting up analyzers...")
    analyzers = solution.ensure_analyzers()

    print("\nValidating sample policy...")
    sample_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": ["arn:aws:s3:::my-bucket/*"]
        }]
    }
    findings = solution.validate_policy(sample_policy)
    print(f"  Validation findings: {len(findings)}")

    print("\nRunning full scan...")
    results = solution.full_scan()
    print(f"  External access findings: {results['summary']['external_access_count']}")
    print(f"  Unused access findings: {results['summary']['unused_access_count']}")

    print("\nCustom policy checks...")
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
    status = "PASS" if public_check['result'] == 'PASS' else public_check['result']
    print(f"  No public access: {status}")

    dangerous_check = solution.check_access_not_granted(sample_policy, ['iam:*', 'iam:PassRole'])
    status = "PASS" if dangerous_check['result'] == 'PASS' else dangerous_check['result']
    print(f"  No dangerous IAM actions: {status}")

    print("\nDone!")
    return results


if __name__ == "__main__":
    main()
