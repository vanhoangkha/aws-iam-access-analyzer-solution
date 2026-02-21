#!/usr/bin/env python3
"""Unit tests for Access Analyzer Solution."""

import json
import pytest
from unittest.mock import Mock, patch
from access_analyzer.client import AccessAnalyzerClient


@pytest.fixture
def mock_clients():
    with patch('boto3.client') as mock_client:
        mock_aa = Mock()
        mock_sts = Mock()
        mock_sts.get_caller_identity.return_value = {'Account': '123456789012'}
        
        def client_factory(service, **kwargs):
            if service == 'accessanalyzer':
                return mock_aa
            elif service == 'sts':
                return mock_sts
            return Mock()
        
        mock_client.side_effect = client_factory
        yield {'aa': mock_aa, 'sts': mock_sts}


class TestValidatePolicy:
    def test_valid_policy(self, mock_clients):
        mock_clients['aa'].get_paginator.return_value.paginate.return_value = [{'findings': []}]
        
        solution = AccessAnalyzerClient(region='us-east-1')
        policy = {"Version": "2012-10-17", "Statement": []}
        result = solution.validate_policy(policy)
        
        assert result == []

    def test_policy_with_findings(self, mock_clients):
        findings = [{'findingType': 'WARNING', 'findingDetails': 'Test warning'}]
        mock_clients['aa'].get_paginator.return_value.paginate.return_value = [{'findings': findings}]
        
        solution = AccessAnalyzerClient(region='us-east-1')
        result = solution.validate_policy({"Version": "2012-10-17", "Statement": []})
        
        assert len(result) == 1
        assert result[0]['findingType'] == 'WARNING'


class TestCheckNoPublicAccess:
    def test_private_policy_passes(self, mock_clients):
        mock_clients['aa'].check_no_public_access.return_value = {'result': 'PASS', 'reasons': []}
        
        solution = AccessAnalyzerClient(region='us-east-1')
        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                "Action": "s3:GetObject",
                "Resource": "*"
            }]
        }
        result = solution.check_no_public_access(policy, 'AWS::S3::Bucket')
        
        assert result['result'] == 'PASS'

    def test_public_policy_fails(self, mock_clients):
        mock_clients['aa'].check_no_public_access.return_value = {
            'result': 'FAIL',
            'reasons': [{'description': 'Public access granted'}]
        }
        
        solution = AccessAnalyzerClient(region='us-east-1')
        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "*"
            }]
        }
        result = solution.check_no_public_access(policy, 'AWS::S3::Bucket')
        
        assert result['result'] == 'FAIL'


class TestCheckAccessNotGranted:
    def test_no_dangerous_actions(self, mock_clients):
        mock_clients['aa'].check_access_not_granted.return_value = {'result': 'PASS'}
        
        solution = AccessAnalyzerClient(region='us-east-1')
        policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
        result = solution.check_access_not_granted(policy, ['iam:*'])
        
        assert result['result'] == 'PASS'

    def test_dangerous_actions_detected(self, mock_clients):
        mock_clients['aa'].check_access_not_granted.return_value = {
            'result': 'FAIL',
            'reasons': [{'description': 'iam:* is granted'}]
        }
        
        solution = AccessAnalyzerClient(region='us-east-1')
        policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        result = solution.check_access_not_granted(policy, ['iam:*'])
        
        assert result['result'] == 'FAIL'


class TestGetFindings:
    def test_get_findings_empty(self, mock_clients):
        mock_clients['aa'].get_paginator.return_value.paginate.return_value = [{'findings': []}]
        
        solution = AccessAnalyzerClient(region='us-east-1')
        result = solution.get_findings('arn:aws:access-analyzer:us-east-1:123456789012:analyzer/test')
        
        assert result == []

    def test_get_findings_with_results(self, mock_clients):
        findings = [
            {'id': '1', 'resourceType': 'AWS::S3::Bucket', 'status': 'ACTIVE'},
            {'id': '2', 'resourceType': 'AWS::IAM::Role', 'status': 'ACTIVE'}
        ]
        mock_clients['aa'].get_paginator.return_value.paginate.return_value = [{'findings': findings}]
        
        solution = AccessAnalyzerClient(region='us-east-1')
        result = solution.get_findings('arn:aws:access-analyzer:us-east-1:123456789012:analyzer/test')
        
        assert len(result) == 2


class TestEnsureAnalyzers:
    def test_creates_analyzers_when_none_exist(self, mock_clients):
        mock_clients['aa'].list_analyzers.return_value = {'analyzers': []}
        mock_clients['aa'].create_analyzer.return_value = {'arn': 'arn:aws:access-analyzer:us-east-1:123456789012:analyzer/test'}
        
        solution = AccessAnalyzerClient(region='us-east-1')
        result = solution.ensure_analyzers()
        
        assert 'ACCOUNT' in result or 'ACCOUNT_UNUSED_ACCESS' in result

    def test_uses_existing_analyzers(self, mock_clients):
        mock_clients['aa'].list_analyzers.return_value = {
            'analyzers': [{'arn': 'arn:aws:access-analyzer:us-east-1:123456789012:analyzer/existing', 'status': 'ACTIVE'}]
        }
        
        solution = AccessAnalyzerClient(region='us-east-1')
        result = solution.ensure_analyzers()
        
        assert len(result) >= 1


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
