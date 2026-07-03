# File Forensics Analyzer

Static malware analysis tool for extracting indicators of compromise (IOCs), calculating entropy, and generating risk scores.

## Features

- Hash calculation (MD5, SHA1, SHA256)
- Entropy analysis for packed/encrypted detection
- String extraction (URLs, IPs, emails, registry, PowerShell, etc.)
- File type detection
- Risk scoring (0-100)
- Optional VirusTotal integration

## Quick Start

pip3 install -r requirements.txt
python3 file_forensics.py tests/test_samples/suspicious_test.bin

## Risk Levels

| Score | Level |
|-------|-------|
| 0-19  | Minimal |
| 20-39 | Low |
| 40-59 | Medium |
| 60-79 | High |
| 80-100| Critical |

## Connect

- LinkedIn: https://www.linkedin.com/in/zeak-meadows-043616264/
- Email: zeakmeadows@icloud.com
