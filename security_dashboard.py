#!/usr/bin/env python3
"""
Security Dashboard for IAM Access Analyzer findings.
Generates summary reports and metrics.
"""

import boto3
import json
from datetime import datetime, timezone
from typing import Dict, List, Any
from collections import defaultdict
from botocore.exceptions import ClientError


class SecurityDashboard:
    """Dashboard for Access Analyzer findings."""

    def __init__(self, region: str = None):
        """Initialize dashboard."""
        self.region = region or boto3.session.Session().region_name
        self.aa = boto3.client('accessanalyzer', region_name=self.region)

    def get_all_analyzers(self) -> List[Dict[str, Any]]:
        """Get all active analyzers."""
        analyzers = []
        try:
            resp = self.aa.list_analyzers()
            analyzers = [a for a in resp['analyzers'] if a['status'] == 'ACTIVE']
        except ClientError:
            pass
        return analyzers

    def get_findings_summary(self, analyzer_arn: str) -> Dict[str, Any]:
        """
        Get summary of findings for an analyzer.

        Returns:
            Dict with counts by resource type, finding type, and status
        """
        summary = {
            'total': 0,
            'by_resource_type': defaultdict(int),
            'by_finding_type': defaultdict(int),
            'by_status': defaultdict(int),
            'critical_resources': []
        }

        critical_types = ['AWS::S3::Bucket', 'AWS::IAM::Role', 'AWS::KMS::Key']

        try:
            paginator = self.aa.get_paginator('list_findings_v2')
            for page in paginator.paginate(analyzerArn=analyzer_arn):
                for finding in page['findings']:
                    summary['total'] += 1
                    summary['by_resource_type'][finding.get('resourceType', 'Unknown')] += 1
                    summary['by_finding_type'][finding.get('findingType', 'Unknown')] += 1
                    summary['by_status'][finding.get('status', 'Unknown')] += 1

                    if finding.get('resourceType') in critical_types:
                        summary['critical_resources'].append({
                            'resource': finding.get('resource'),
                            'type': finding.get('resourceType'),
                            'finding_type': finding.get('findingType')
                        })
        except ClientError:
            pass

        # Convert defaultdicts to regular dicts
        summary['by_resource_type'] = dict(summary['by_resource_type'])
        summary['by_finding_type'] = dict(summary['by_finding_type'])
        summary['by_status'] = dict(summary['by_status'])

        return summary

    def generate_report(self) -> Dict[str, Any]:
        """
        Generate full security report.

        Returns:
            Dict with report data for all analyzers
        """
        report = {
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'region': self.region,
            'analyzers': [],
            'totals': {
                'external_findings': 0,
                'unused_findings': 0,
                'critical_findings': 0
            }
        }

        analyzers = self.get_all_analyzers()

        for analyzer in analyzers:
            summary = self.get_findings_summary(analyzer['arn'])
            analyzer_report = {
                'name': analyzer['name'],
                'type': analyzer['type'],
                'arn': analyzer['arn'],
                'summary': summary
            }
            report['analyzers'].append(analyzer_report)

            if analyzer['type'] == 'ACCOUNT':
                report['totals']['external_findings'] += summary['total']
            elif analyzer['type'] == 'ACCOUNT_UNUSED_ACCESS':
                report['totals']['unused_findings'] += summary['total']

            report['totals']['critical_findings'] += len(summary['critical_resources'])

        return report

    def print_report(self, report: Dict[str, Any] = None):
        """Print formatted report to console."""
        if report is None:
            report = self.generate_report()

        print("=" * 60)
        print("IAM Access Analyzer Security Report")
        print("=" * 60)
        print(f"Generated: {report['generated_at']}")
        print(f"Region: {report['region']}")
        print("")

        print("Summary:")
        print(f"  External access findings: {report['totals']['external_findings']}")
        print(f"  Unused access findings: {report['totals']['unused_findings']}")
        print(f"  Critical resource findings: {report['totals']['critical_findings']}")
        print("")

        for analyzer in report['analyzers']:
            print(f"Analyzer: {analyzer['name']} ({analyzer['type']})")
            print(f"  Total findings: {analyzer['summary']['total']}")

            if analyzer['summary']['by_resource_type']:
                print("  By resource type:")
                for rtype, count in sorted(
                    analyzer['summary']['by_resource_type'].items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:5]:
                    print(f"    {rtype}: {count}")

            if analyzer['summary']['by_finding_type']:
                print("  By finding type:")
                for ftype, count in sorted(
                    analyzer['summary']['by_finding_type'].items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:5]:
                    print(f"    {ftype}: {count}")

            print("")

        print("=" * 60)

    def export_json(self, filepath: str = None) -> str:
        """
        Export report to JSON file.

        Args:
            filepath: Output file path (default: security_report_<timestamp>.json)

        Returns:
            Path to exported file
        """
        report = self.generate_report()

        if filepath is None:
            timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
            filepath = f"security_report_{timestamp}.json"

        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        return filepath


def main():
    """Generate and print security dashboard."""
    dashboard = SecurityDashboard()
    dashboard.print_report()


if __name__ == "__main__":
    main()
