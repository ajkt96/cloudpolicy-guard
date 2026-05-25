# CLOUDPOLICY-GUARD: Cloud Misconfiguration Scanner

Enterprise-grade cloud infrastructure security scanner that detects misconfigurations and provides auto-remediation.

## Features

- S3 bucket public access detection
- - Security group overly permissive rule scanning
  - - EBS encryption compliance checking
    - - CIS Benchmark mapping
      - - Auto-remediation guidance
        - - Multi-cloud support (AWS, Azure, GCP)
         
          - ## Quick Start
         
          - ```python
            from src.scanner import CloudPolicyScanner

            scanner = CloudPolicyScanner("aws")
            findings = scanner.scan_all()
            print(f"Found {len(findings)} misconfigurations")
            ```

            ## Example Output

            ```json
            [
              {
                "resource": "prod-data-bucket",
                "issue": "Public Access",
                "severity": "CRITICAL",
                "cis_control": "1.20"
              }
            ]
            ```

            ## Running Tests

            ```bash
            pytest tests/ -v --cov=src
            ```

            ## License

            MIT License
            
