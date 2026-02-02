#!/usr/bin/env python3
"""
Security Dashboard - Tổng hợp tất cả findings từ Access Analyzer
"""

import boto3
import json
from datetime import datetime
from collections import defaultdict

def generate_report():
    aa = boto3.client('accessanalyzer')
    
    report = {
        'generated_at': datetime.utcnow().isoformat(),
        'analyzers': [],
        'findings_summary': defaultdict(int),
        'findings_by_resource': defaultdict(list),
        'recommendations': []
    }
    
    # Get all analyzers
    for analyzer in aa.list_analyzers()['analyzers']:
        if analyzer['status'] != 'ACTIVE':
            continue
            
        analyzer_info = {
            'name': analyzer['name'],
            'type': analyzer['type'],
            'arn': analyzer['arn'],
            'findings': []
        }
        
        # Get findings
        paginator = aa.get_paginator('list_findings_v2')
        for page in paginator.paginate(
            analyzerArn=analyzer['arn'],
            filter={'status': {'eq': ['ACTIVE']}}
        ):
            for finding in page['findings']:
                analyzer_info['findings'].append({
                    'id': finding['id'],
                    'resource': finding['resource'],
                    'resourceType': finding['resourceType'],
                    'findingType': finding.get('findingType', 'ExternalAccess'),
                    'createdAt': finding['createdAt'].isoformat()
                })
                
                report['findings_summary'][finding['resourceType']] += 1
                report['findings_by_resource'][finding['resource']].append(finding['id'])
        
        report['analyzers'].append(analyzer_info)
    
    # Generate recommendations
    total_findings = sum(report['findings_summary'].values())
    if total_findings > 0:
        report['recommendations'].append(f"⚠️ {total_findings} active findings cần review")
        
        if report['findings_summary'].get('AWS::S3::Bucket', 0) > 0:
            report['recommendations'].append("🪣 Review S3 bucket policies - có thể có public access")
        if report['findings_summary'].get('AWS::IAM::Role', 0) > 0:
            report['recommendations'].append("👤 Review IAM role trust policies - có thể có cross-account access")
    else:
        report['recommendations'].append("✅ Không có findings - tất cả resources đều secure")
    
    return report

def print_report(report):
    print("=" * 60)
    print("🔐 IAM ACCESS ANALYZER SECURITY REPORT")
    print("=" * 60)
    print(f"Generated: {report['generated_at']}")
    print()
    
    print("📊 FINDINGS SUMMARY")
    print("-" * 40)
    for resource_type, count in report['findings_summary'].items():
        print(f"  {resource_type}: {count}")
    print()
    
    print("🔍 ANALYZERS")
    print("-" * 40)
    for analyzer in report['analyzers']:
        print(f"  {analyzer['name']} ({analyzer['type']}): {len(analyzer['findings'])} findings")
    print()
    
    print("💡 RECOMMENDATIONS")
    print("-" * 40)
    for rec in report['recommendations']:
        print(f"  {rec}")
    print()

if __name__ == "__main__":
    report = generate_report()
    print_report(report)
    
    # Save to file
    with open('security_report.json', 'w') as f:
        json.dump(report, f, indent=2, default=str)
    print(f"📄 Report saved to security_report.json")
