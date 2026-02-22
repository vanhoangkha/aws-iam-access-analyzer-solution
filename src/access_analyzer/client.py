#!/usr/bin/env python3
"""
AWS IAM Access Analyzer - Complete API Implementation

Implements ALL 37 Access Analyzer APIs:
- Analyzer Management: CreateAnalyzer, DeleteAnalyzer, GetAnalyzer, ListAnalyzers, UpdateAnalyzer
- Findings: ListFindings, ListFindingsV2, GetFinding, GetFindingV2, UpdateFindings, GetFindingsStatistics
- Archive Rules: CreateArchiveRule, DeleteArchiveRule, GetArchiveRule, ListArchiveRules, 
                 UpdateArchiveRule, ApplyArchiveRule
- Policy Checks: ValidatePolicy, CheckNoPublicAccess, CheckAccessNotGranted, CheckNoNewAccess
- Access Preview: CreateAccessPreview, GetAccessPreview, ListAccessPreviews, ListAccessPreviewFindings
- Policy Generation: StartPolicyGeneration, GetGeneratedPolicy, CancelPolicyGeneration, ListPolicyGenerations
- Resources: GetAnalyzedResource, ListAnalyzedResources, StartResourceScan
- Recommendations: GenerateFindingRecommendation, GetFindingRecommendation
- Tags: TagResource, UntagResource, ListTagsForResource

Reference: https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_Operations.html
"""

import boto3
import json
import time
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Union, List, Dict, Any
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


class AccessAnalyzerClient:
    """Complete AWS IAM Access Analyzer API wrapper."""

    ANALYZER_TYPES = ['ACCOUNT', 'ACCOUNT_UNUSED_ACCESS', 'ORGANIZATION', 'ORGANIZATION_UNUSED_ACCESS']
    
    SUPPORTED_PREVIEW_RESOURCES = {
        'AWS::S3::Bucket': ('s3Bucket', 'bucketPolicy'),
        'AWS::S3::AccessPoint': ('s3AccessPoint', 'accessPointPolicy'),
        'AWS::SQS::Queue': ('sqsQueue', 'queuePolicy'),
        'AWS::KMS::Key': ('kmsKey', 'keyPolicies'),
        'AWS::IAM::Role': ('iamRole', 'trustPolicy'),
        'AWS::SecretsManager::Secret': ('secretsManagerSecret', 'secretPolicy'),
        'AWS::SNS::Topic': ('snsTopic', 'topicPolicy'),
        'AWS::EFS::FileSystem': ('efsFileSystem', 'fileSystemPolicy'),
        'AWS::EC2::Snapshot': ('ebsSnapshot', None),
        'AWS::ECR::Repository': ('ecrRepository', 'repositoryPolicy'),
        'AWS::RDS::DBSnapshot': ('rdsDbSnapshot', None),
        'AWS::RDS::DBClusterSnapshot': ('rdsDbClusterSnapshot', None),
        'AWS::DynamoDB::Table': ('dynamodbTable', 'policy'),
        'AWS::DynamoDB::Stream': ('dynamodbStream', 'streamPolicy'),
    }

    def __init__(self, region: str = None):
        self.region = region or boto3.session.Session().region_name or 'us-east-1'
        self.aa = boto3.client('accessanalyzer', region_name=self.region)
        self.sts = boto3.client('sts', region_name=self.region)
        self.account_id = self.sts.get_caller_identity()['Account']

    def _to_json(self, policy: Union[dict, str]) -> str:
        return json.dumps(policy) if isinstance(policy, dict) else policy

    # ==================== ANALYZER MANAGEMENT ====================

    def create_analyzer(
        self,
        analyzer_name: str,
        analyzer_type: str = 'ACCOUNT',
        tags: Dict[str, str] = None,
        configuration: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Create an analyzer (CreateAnalyzer API)."""
        params = {'analyzerName': analyzer_name, 'type': analyzer_type}
        if tags:
            params['tags'] = tags
        if configuration:
            params['configuration'] = configuration
        elif analyzer_type in ['ACCOUNT_UNUSED_ACCESS', 'ORGANIZATION_UNUSED_ACCESS']:
            params['configuration'] = {'unusedAccess': {'unusedAccessAge': 90}}
        try:
            return self.aa.create_analyzer(**params)
        except ClientError as e:
            logger.error("create_analyzer failed: %s", e)
            return {'error': str(e)}

    def delete_analyzer(self, analyzer_name: str) -> bool:
        """Delete an analyzer (DeleteAnalyzer API)."""
        try:
            self.aa.delete_analyzer(analyzerName=analyzer_name)
            return True
        except ClientError as e:
            logger.error("delete_analyzer failed: %s", e)
            return False

    def get_analyzer(self, analyzer_name: str) -> Dict[str, Any]:
        """Get analyzer details (GetAnalyzer API)."""
        try:
            return self.aa.get_analyzer(analyzerName=analyzer_name)
        except ClientError as e:
            logger.error("get_analyzer failed: %s", e)
            return {'error': str(e)}

    def list_analyzers(self, analyzer_type: str = None) -> List[Dict[str, Any]]:
        """List all analyzers (ListAnalyzers API)."""
        try:
            params = {}
            if analyzer_type:
                params['type'] = analyzer_type
            resp = self.aa.list_analyzers(**params)
            return resp.get('analyzers', [])
        except ClientError as e:
            logger.error("list_analyzers failed: %s", e)
            return []

    def update_analyzer(
        self,
        analyzer_name: str,
        configuration: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update analyzer configuration (UpdateAnalyzer API). Only for unused access analyzers."""
        try:
            return self.aa.update_analyzer(analyzerName=analyzer_name, configuration=configuration)
        except ClientError as e:
            logger.error("update_analyzer failed: %s", e)
            return {'error': str(e)}

    def ensure_analyzers(self) -> Dict[str, str]:
        """Ensure ACCOUNT and ACCOUNT_UNUSED_ACCESS analyzers exist."""
        analyzers = {}
        for atype in ['ACCOUNT', 'ACCOUNT_UNUSED_ACCESS']:
            name = f"analyzer-{atype.lower().replace('_', '-')}"
            existing = [a for a in self.list_analyzers(atype) if a['status'] == 'ACTIVE']
            if existing:
                analyzers[atype] = existing[0]['arn']
            else:
                result = self.create_analyzer(name, atype)
                if 'arn' in result:
                    analyzers[atype] = result['arn']
        return analyzers

    # ==================== FINDINGS ====================

    def list_findings(self, analyzer_arn: str, filter_criteria: Dict = None) -> List[Dict]:
        """List findings v1 (ListFindings API)."""
        findings = []
        try:
            params = {'analyzerArn': analyzer_arn}
            if filter_criteria:
                params['filter'] = filter_criteria
            paginator = self.aa.get_paginator('list_findings')
            for page in paginator.paginate(**params):
                findings.extend(page.get('findings', []))
        except ClientError as e:
            logger.error("list_findings failed: %s", e)
        return findings

    def list_findings_v2(
        self,
        analyzer_arn: str,
        status: str = 'ACTIVE',
        resource_type: str = None,
        finding_type: str = None
    ) -> List[Dict]:
        """List findings v2 with enhanced details (ListFindingsV2 API)."""
        filter_criteria = {'status': {'eq': [status]}}
        if resource_type:
            filter_criteria['resourceType'] = {'eq': [resource_type]}
        if finding_type:
            filter_criteria['findingType'] = {'eq': [finding_type]}
        
        findings = []
        try:
            paginator = self.aa.get_paginator('list_findings_v2')
            for page in paginator.paginate(analyzerArn=analyzer_arn, filter=filter_criteria):
                findings.extend(page.get('findings', []))
        except ClientError as e:
            logger.error("list_findings_v2 failed: %s", e)
        return findings

    def get_finding(self, analyzer_arn: str, finding_id: str) -> Dict[str, Any]:
        """Get finding details v1 (GetFinding API)."""
        try:
            return self.aa.get_finding(analyzerArn=analyzer_arn, id=finding_id)
        except ClientError as e:
            logger.error("get_finding failed: %s", e)
            return {'error': str(e)}

    def get_finding_v2(self, analyzer_arn: str, finding_id: str) -> Dict[str, Any]:
        """Get finding details v2 (GetFindingV2 API)."""
        try:
            return self.aa.get_finding_v2(analyzerArn=analyzer_arn, id=finding_id)
        except ClientError as e:
            logger.error("get_finding_v2 failed: %s", e)
            return {'error': str(e)}

    def update_findings(
        self,
        analyzer_arn: str,
        finding_ids: List[str],
        status: str = 'ARCHIVED'
    ) -> bool:
        """Update findings status (UpdateFindings API)."""
        try:
            self.aa.update_findings(analyzerArn=analyzer_arn, ids=finding_ids, status=status)
            return True
        except ClientError as e:
            logger.error("update_findings failed: %s", e)
            return False

    def get_findings_statistics(self, analyzer_arn: str) -> Dict[str, Any]:
        """Get aggregated finding statistics (GetFindingsStatistics API)."""
        try:
            return self.aa.get_findings_statistics(analyzerArn=analyzer_arn)
        except ClientError as e:
            logger.error("get_findings_statistics failed: %s", e)
            return {'error': str(e)}

    # ==================== ARCHIVE RULES ====================

    def create_archive_rule(
        self,
        analyzer_name: str,
        rule_name: str,
        filter_criteria: Dict[str, Any]
    ) -> bool:
        """Create archive rule (CreateArchiveRule API)."""
        try:
            self.aa.create_archive_rule(
                analyzerName=analyzer_name,
                ruleName=rule_name,
                filter=filter_criteria
            )
            return True
        except ClientError as e:
            logger.error("create_archive_rule failed: %s", e)
            return False

    def delete_archive_rule(self, analyzer_name: str, rule_name: str) -> bool:
        """Delete archive rule (DeleteArchiveRule API)."""
        try:
            self.aa.delete_archive_rule(analyzerName=analyzer_name, ruleName=rule_name)
            return True
        except ClientError as e:
            logger.error("delete_archive_rule failed: %s", e)
            return False

    def get_archive_rule(self, analyzer_name: str, rule_name: str) -> Dict[str, Any]:
        """Get archive rule (GetArchiveRule API)."""
        try:
            return self.aa.get_archive_rule(analyzerName=analyzer_name, ruleName=rule_name)
        except ClientError as e:
            logger.error("get_archive_rule failed: %s", e)
            return {'error': str(e)}

    def list_archive_rules(self, analyzer_name: str) -> List[Dict]:
        """List archive rules (ListArchiveRules API)."""
        rules = []
        try:
            paginator = self.aa.get_paginator('list_archive_rules')
            for page in paginator.paginate(analyzerName=analyzer_name):
                rules.extend(page.get('archiveRules', []))
        except ClientError as e:
            logger.error("list_archive_rules failed: %s", e)
        return rules

    def update_archive_rule(
        self,
        analyzer_name: str,
        rule_name: str,
        filter_criteria: Dict[str, Any]
    ) -> bool:
        """Update archive rule (UpdateArchiveRule API)."""
        try:
            self.aa.update_archive_rule(
                analyzerName=analyzer_name,
                ruleName=rule_name,
                filter=filter_criteria
            )
            return True
        except ClientError as e:
            logger.error("update_archive_rule failed: %s", e)
            return False

    def apply_archive_rule(self, analyzer_arn: str, rule_name: str) -> bool:
        """Apply archive rule to existing findings (ApplyArchiveRule API)."""
        try:
            self.aa.apply_archive_rule(analyzerArn=analyzer_arn, ruleName=rule_name)
            return True
        except ClientError as e:
            logger.error("apply_archive_rule failed: %s", e)
            return False

    # ==================== POLICY VALIDATION ====================

    def validate_policy(
        self,
        policy: Union[dict, str],
        policy_type: str = 'IDENTITY_POLICY',
        resource_type: str = None,
        locale: str = None
    ) -> List[Dict]:
        """Validate policy (ValidatePolicy API)."""
        params = {'policyDocument': self._to_json(policy), 'policyType': policy_type}
        if resource_type:
            params['validatePolicyResourceType'] = resource_type
        if locale:
            params['locale'] = locale
        
        findings = []
        try:
            paginator = self.aa.get_paginator('validate_policy')
            for page in paginator.paginate(**params):
                findings.extend(page.get('findings', []))
        except ClientError as e:
            logger.error("validate_policy failed: %s", e)
            return [{'findingType': 'ERROR', 'findingDetails': str(e)}]
        return findings

    def check_no_public_access(
        self,
        policy: Union[dict, str],
        resource_type: str
    ) -> Dict[str, Any]:
        """Check no public access (CheckNoPublicAccess API)."""
        try:
            resp = self.aa.check_no_public_access(
                policyDocument=self._to_json(policy),
                resourceType=resource_type
            )
            return {'result': resp['result'], 'message': resp.get('message', ''), 'reasons': resp.get('reasons', [])}
        except ClientError as e:
            logger.error("check_no_public_access failed: %s", e)
            return {'result': 'ERROR', 'message': str(e), 'reasons': []}

    def check_access_not_granted(
        self,
        policy: Union[dict, str],
        actions: List[str],
        policy_type: str = 'IDENTITY_POLICY',
        resources: List[str] = None
    ) -> Dict[str, Any]:
        """Check access not granted (CheckAccessNotGranted API)."""
        access = [{'actions': actions}]
        if resources:
            access[0]['resources'] = resources
        try:
            resp = self.aa.check_access_not_granted(
                policyDocument=self._to_json(policy),
                access=access,
                policyType=policy_type
            )
            return {'result': resp['result'], 'message': resp.get('message', ''), 'reasons': resp.get('reasons', [])}
        except ClientError as e:
            logger.error("check_access_not_granted failed: %s", e)
            return {'result': 'ERROR', 'message': str(e), 'reasons': []}

    def check_no_new_access(
        self,
        new_policy: Union[dict, str],
        existing_policy: Union[dict, str],
        policy_type: str = 'IDENTITY_POLICY'
    ) -> Dict[str, Any]:
        """Check no new access (CheckNoNewAccess API)."""
        try:
            resp = self.aa.check_no_new_access(
                newPolicyDocument=self._to_json(new_policy),
                existingPolicyDocument=self._to_json(existing_policy),
                policyType=policy_type
            )
            return {'result': resp['result'], 'message': resp.get('message', ''), 'reasons': resp.get('reasons', [])}
        except ClientError as e:
            logger.error("check_no_new_access failed: %s", e)
            return {'result': 'ERROR', 'message': str(e), 'reasons': []}

    # ==================== ACCESS PREVIEW ====================

    def create_access_preview(
        self,
        analyzer_arn: str,
        configurations: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create access preview (CreateAccessPreview API)."""
        try:
            return self.aa.create_access_preview(analyzerArn=analyzer_arn, configurations=configurations)
        except ClientError as e:
            logger.error("create_access_preview failed: %s", e)
            return {'error': str(e)}

    def get_access_preview(self, analyzer_arn: str, preview_id: str) -> Dict[str, Any]:
        """Get access preview (GetAccessPreview API)."""
        try:
            return self.aa.get_access_preview(analyzerArn=analyzer_arn, accessPreviewId=preview_id)
        except ClientError as e:
            logger.error("get_access_preview failed: %s", e)
            return {'error': str(e)}

    def list_access_previews(self, analyzer_arn: str) -> List[Dict]:
        """List access previews (ListAccessPreviews API)."""
        previews = []
        try:
            paginator = self.aa.get_paginator('list_access_previews')
            for page in paginator.paginate(analyzerArn=analyzer_arn):
                previews.extend(page.get('accessPreviews', []))
        except ClientError as e:
            logger.error("list_access_previews failed: %s", e)
        return previews

    def list_access_preview_findings(
        self,
        analyzer_arn: str,
        preview_id: str,
        filter_criteria: Dict = None
    ) -> List[Dict]:
        """List access preview findings (ListAccessPreviewFindings API)."""
        findings = []
        try:
            params = {'analyzerArn': analyzer_arn, 'accessPreviewId': preview_id}
            if filter_criteria:
                params['filter'] = filter_criteria
            paginator = self.aa.get_paginator('list_access_preview_findings')
            for page in paginator.paginate(**params):
                findings.extend(page.get('findings', []))
        except ClientError as e:
            logger.error("list_access_preview_findings failed: %s", e)
        return findings

    def preview_resource_access(
        self,
        analyzer_arn: str,
        resource_arn: str,
        resource_type: str,
        policy: Union[dict, str],
        timeout: int = 120
    ) -> List[Dict]:
        """High-level: Create preview and wait for findings."""
        if resource_type not in self.SUPPORTED_PREVIEW_RESOURCES:
            raise ValueError(f"Unsupported: {resource_type}")
        
        config_key, policy_key = self.SUPPORTED_PREVIEW_RESOURCES[resource_type]
        policy_doc = self._to_json(policy)
        
        if config_key == 'kmsKey':
            config = {resource_arn: {config_key: {policy_key: {'default': policy_doc}}}}
        elif policy_key:
            config = {resource_arn: {config_key: {policy_key: policy_doc}}}
        else:
            config = {resource_arn: {config_key: {}}}
        
        result = self.create_access_preview(analyzer_arn, config)
        if 'error' in result:
            raise Exception(result['error'])
        
        preview_id = result['id']
        start = time.time()
        while time.time() - start < timeout:
            preview = self.get_access_preview(analyzer_arn, preview_id)
            status = preview.get('accessPreview', {}).get('status')
            if status == 'COMPLETED':
                return self.list_access_preview_findings(analyzer_arn, preview_id)
            if status == 'FAILED':
                raise Exception(f"Preview failed: {preview}")
            time.sleep(2)
        raise Exception("Preview timed out")

    # ==================== POLICY GENERATION ====================

    def start_policy_generation(
        self,
        principal_arn: str,
        trail_arn: str,
        access_role_arn: str,
        days: int = 90
    ) -> str:
        """Start policy generation (StartPolicyGeneration API)."""
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days)
        try:
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
        except ClientError as e:
            logger.error("start_policy_generation failed: %s", e)
            return ''

    def get_generated_policy(self, job_id: str) -> Dict[str, Any]:
        """Get generated policy (GetGeneratedPolicy API)."""
        try:
            return self.aa.get_generated_policy(jobId=job_id)
        except ClientError as e:
            logger.error("get_generated_policy failed: %s", e)
            return {'error': str(e)}

    def cancel_policy_generation(self, job_id: str) -> bool:
        """Cancel policy generation (CancelPolicyGeneration API)."""
        try:
            self.aa.cancel_policy_generation(jobId=job_id)
            return True
        except ClientError as e:
            logger.error("cancel_policy_generation failed: %s", e)
            return False

    def list_policy_generations(self, principal_arn: str = None) -> List[Dict]:
        """List policy generations (ListPolicyGenerations API)."""
        jobs = []
        try:
            params = {}
            if principal_arn:
                params['principalArn'] = principal_arn
            paginator = self.aa.get_paginator('list_policy_generations')
            for page in paginator.paginate(**params):
                jobs.extend(page.get('policyGenerations', []))
        except ClientError as e:
            logger.error("list_policy_generations failed: %s", e)
        return jobs

    # ==================== RESOURCES ====================

    def get_analyzed_resource(self, analyzer_arn: str, resource_arn: str) -> Dict[str, Any]:
        """Get analyzed resource (GetAnalyzedResource API). External analyzers only."""
        try:
            return self.aa.get_analyzed_resource(analyzerArn=analyzer_arn, resourceArn=resource_arn)
        except ClientError as e:
            logger.error("get_analyzed_resource failed: %s", e)
            return {'error': str(e)}

    def list_analyzed_resources(
        self,
        analyzer_arn: str,
        resource_type: str = None
    ) -> List[Dict]:
        """List analyzed resources (ListAnalyzedResources API). External analyzers only."""
        resources = []
        try:
            params = {'analyzerArn': analyzer_arn}
            if resource_type:
                params['resourceType'] = resource_type
            paginator = self.aa.get_paginator('list_analyzed_resources')
            for page in paginator.paginate(**params):
                resources.extend(page.get('analyzedResources', []))
        except ClientError as e:
            logger.error("list_analyzed_resources failed: %s", e)
        return resources

    def start_resource_scan(self, analyzer_arn: str, resource_arn: str) -> bool:
        """Start resource scan (StartResourceScan API)."""
        try:
            self.aa.start_resource_scan(analyzerArn=analyzer_arn, resourceArn=resource_arn)
            return True
        except ClientError as e:
            logger.error("start_resource_scan failed: %s", e)
            return False

    # ==================== RECOMMENDATIONS ====================

    def generate_finding_recommendation(self, analyzer_arn: str, finding_id: str) -> bool:
        """Generate finding recommendation (GenerateFindingRecommendation API)."""
        try:
            self.aa.generate_finding_recommendation(analyzerArn=analyzer_arn, id=finding_id)
            return True
        except ClientError as e:
            logger.error("generate_finding_recommendation failed: %s", e)
            return False

    def get_finding_recommendation(self, analyzer_arn: str, finding_id: str) -> Dict[str, Any]:
        """Get finding recommendation (GetFindingRecommendation API)."""
        try:
            return self.aa.get_finding_recommendation(analyzerArn=analyzer_arn, id=finding_id)
        except ClientError as e:
            logger.error("get_finding_recommendation failed: %s", e)
            return {'error': str(e)}

    # ==================== TAGS ====================

    def tag_resource(self, resource_arn: str, tags: Dict[str, str]) -> bool:
        """Tag resource (TagResource API)."""
        try:
            self.aa.tag_resource(resourceArn=resource_arn, tags=tags)
            return True
        except ClientError as e:
            logger.error("tag_resource failed: %s", e)
            return False

    def untag_resource(self, resource_arn: str, tag_keys: List[str]) -> bool:
        """Untag resource (UntagResource API)."""
        try:
            self.aa.untag_resource(resourceArn=resource_arn, tagKeys=tag_keys)
            return True
        except ClientError as e:
            logger.error("untag_resource failed: %s", e)
            return False

    def list_tags_for_resource(self, resource_arn: str) -> Dict[str, str]:
        """List tags for resource (ListTagsForResource API)."""
        try:
            resp = self.aa.list_tags_for_resource(resourceArn=resource_arn)
            return resp.get('tags', {})
        except ClientError as e:
            logger.error("list_tags_for_resource failed: %s", e)
            return {}

    # ==================== HIGH-LEVEL OPERATIONS ====================

    def full_scan(self) -> Dict[str, Any]:
        """Run comprehensive scan."""
        results = {'external_access': [], 'unused_access': [], 'statistics': {}, 'summary': {}}
        analyzers = self.ensure_analyzers()
        
        if 'ACCOUNT' in analyzers:
            results['external_access'] = self.list_findings_v2(analyzers['ACCOUNT'])
            stats = self.get_findings_statistics(analyzers['ACCOUNT'])
            if 'findingsStatistics' in stats:
                results['statistics']['external'] = stats
        
        if 'ACCOUNT_UNUSED_ACCESS' in analyzers:
            results['unused_access'] = self.list_findings_v2(analyzers['ACCOUNT_UNUSED_ACCESS'])
            stats = self.get_findings_statistics(analyzers['ACCOUNT_UNUSED_ACCESS'])
            if 'findingsStatistics' in stats:
                results['statistics']['unused'] = stats
        
        results['summary'] = {
            'external_count': len(results['external_access']),
            'unused_count': len(results['unused_access']),
            'analyzers': analyzers
        }
        return results


def main():
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    
    solution = AccessAnalyzerClient()
    
    print("Setting up analyzers...")
    analyzers = solution.ensure_analyzers()
    print(f"  Active analyzers: {len(analyzers)}")
    
    print("\nValidating sample policy...")
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
    findings = solution.validate_policy(policy)
    print(f"  Findings: {len(findings)}")
    
    print("\nRunning full scan...")
    results = solution.full_scan()
    print(f"  External findings: {results['summary']['external_count']}")
    print(f"  Unused findings: {results['summary']['unused_count']}")
    
    print("\nCustom policy checks...")
    s3_policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{solution.account_id}:root"}, "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"}]}
    r1 = solution.check_no_public_access(s3_policy, 'AWS::S3::Bucket')
    print(f"  No public access: {r1['result']}")
    
    r2 = solution.check_access_not_granted(policy, ['iam:*'])
    print(f"  No IAM actions: {r2['result']}")
    
    print("\nDone!")


if __name__ == "__main__":
    main()
