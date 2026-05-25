"""Cloud Policy Guard Scanner"""

import json
from typing import List, Dict


class CloudPolicyScanner:
    """Scans cloud infrastructure for misconfigurations"""

    def __init__(self, cloud_provider: str):
        self.cloud_provider = cloud_provider
        self.findings = []

    def scan_s3_buckets(self) -> List[Dict]:
        """Scan S3 buckets for public access"""
        findings = []
        sample_buckets = [
            {'name': 'prod-data-bucket', 'public': True},
            {'name': 'app-logs', 'public': False},
        ]
        for bucket in sample_buckets:
            if bucket['public']:
                findings.append({
                    'resource': bucket['name'],
                    'issue': 'Public Access',
                    'severity': 'CRITICAL',
                    'cis_control': '1.20'
                })
        return findings

    def scan_security_groups(self) -> List[Dict]:
        """Scan security groups for overly permissive rules"""
        findings = []
        sample_groups = [
            {'name': 'sg-web', 'inbound': [{'port': 22, 'source': '0.0.0.0/0'}]},
        ]
        for group in sample_groups:
            for rule in group.get('inbound', []):
                if rule['source'] == '0.0.0.0/0' and rule['port'] in [22, 3389]:
                    findings.append({
                        'resource': group['name'],
                        'issue': f"Port {rule['port']} open to internet",
                        'severity': 'HIGH',
                        'cis_control': '5.2'
                    })
        return findings

    def scan_encryption(self) -> List[Dict]:
        """Scan for unencrypted resources"""
        findings = []
        sample_volumes = [{'name': 'vol-001', 'encrypted': False}]
        for vol in sample_volumes:
            if not vol['encrypted']:
                findings.append({
                    'resource': vol['name'],
                    'issue': 'EBS volume not encrypted',
                    'severity': 'MEDIUM',
                    'cis_control': '2.2.1'
                })
        return findings

    def scan_all(self) -> List[Dict]:
        """Run all scans"""
        all_findings = []
        all_findings.extend(self.scan_s3_buckets())
        all_findings.extend(self.scan_security_groups())
        all_findings.extend(self.scan_encryption())
        return all_findings


if __name__ == "__main__":
    scanner = CloudPolicyScanner("aws")
    findings = scanner.scan_all()
    print(json.dumps(findings, indent=2))
