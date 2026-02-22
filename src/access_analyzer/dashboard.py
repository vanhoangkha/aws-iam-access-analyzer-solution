#!/usr/bin/env python3
"""
Security Dashboard for IAM Access Analyzer.
Generates reports and metrics from findings.
"""

import boto3
import json
from datetime import datetime, timezone
from typing import Dict, List, Any
from collections import defaultdict
from botocore.exceptions import ClientError


class SecurityDashboard:
    """Dashboard for Access Analyzer findings and metrics."""

    def __init__(self, region: str = None):
        self.region = region or boto3.session.Session().region_name or 'us-east-1'
        self.client = boto3.client('accessanalyzer', region_name=self.region)

    def get_analyzers(self) -> List[Dict[str, Any]]:
        """Get all active analyzers."""
        try:
            resp = self.client.list_analyzers()
            return [a for a in resp['analyzers'] if a['status'] == 'ACTIVE']
        except ClientError:
            return []

    def get_findings_summary(self, analyzer_arn: str) -> Dict[str, Any]:
        """Get summary of findings for an analyzer."""
        summary = {
            'total': 0,
            'by_resource_type': defaultdict(int),
            'by_finding_type': defaultdict(int),
            'by_status': defaultdict(int),
            'critical': []
        }

        critical_types = ['AWS::S3::Bucket', 'AWS::IAM::Role', 'AWS::KMS::Key']

        try:
            paginator = self.client.get_paginator('list_findings_v2')
            for page in paginator.paginate(analyzerArn=analyzer_arn):
                for finding in page.get('findings', []):
                    summary['total'] += 1
                    summary['by_resource_type'][finding.get('resourceType', 'Unknown')] += 1
                    summary['by_finding_type'][finding.get('findingType', 'Unknown')] += 1
                    summary['by_status'][finding.get('status', 'Unknown')] += 1

                    if finding.get('resourceType') in critical_types:
                        summary['critical'].append({
                            'resource': finding.get('resource'),
                            'type': finding.get('resourceType'),
                            'finding_type': finding.get('findingType')
                        })
        except ClientError:
            pass

        summary['by_resource_type'] = dict(summary['by_resource_type'])
        summary['by_finding_type'] = dict(summary['by_finding_type'])
        summary['by_status'] = dict(summary['by_status'])

        return summary

    def generate_report(self) -> Dict[str, Any]:
        """Generate full security report."""
        report = {
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'region': self.region,
            'analyzers': [],
            'totals': {'external': 0, 'unused': 0, 'critical': 0}
        }

        for analyzer in self.get_analyzers():
            summary = self.get_findings_summary(analyzer['arn'])
            report['analyzers'].append({
                'name': analyzer['name'],
                'type': analyzer['type'],
                'arn': analyzer['arn'],
                'summary': summary
            })

            if analyzer['type'] == 'ACCOUNT':
                report['totals']['external'] += summary['total']
            elif analyzer['type'] == 'ACCOUNT_UNUSED_ACCESS':
                report['totals']['unused'] += summary['total']

            report['totals']['critical'] += len(summary['critical'])

        return report

    def print_report(self, report: Dict[str, Any] = None):
        """Print formatted report."""
        if report is None:
            report = self.generate_report()

        print("=" * 60)
        print("IAM Access Analyzer Security Report")
        print("=" * 60)
        print(f"Generated: {report['generated_at']}")
        print(f"Region: {report['region']}")
        print("")
        print("Summary:")
        print(f"  External findings: {report['totals']['external']}")
        print(f"  Unused findings: {report['totals']['unused']}")
        print(f"  Critical findings: {report['totals']['critical']}")
        print("")

        for analyzer in report['analyzers']:
            print(f"Analyzer: {analyzer['name']} ({analyzer['type']})")
            print(f"  Total: {analyzer['summary']['total']}")

            if analyzer['summary']['by_finding_type']:
                print("  By type:")
                for ftype, count in sorted(
                    analyzer['summary']['by_finding_type'].items(),
                    key=lambda x: x[1], reverse=True
                )[:5]:
                    print(f"    {ftype}: {count}")
            print("")

        print("=" * 60)

    def export_json(self, filepath: str = None) -> str:
        """Export report to JSON."""
        report = self.generate_report()
        if filepath is None:
            filepath = f"security_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"

        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        return filepath


def main():
    """CLI entry point."""
    dashboard = SecurityDashboard()
    dashboard.print_report()


if __name__ == "__main__":
    main()
