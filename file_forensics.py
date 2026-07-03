#!/usr/bin/env python3
"""
File Forensics Analyzer
Static malware analysis tool for extracting IOCs and calculating risk scores.
"""

import hashlib
import math
import re
import json
import yaml
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

import requests


class FileForensicsAnalyzer:
    """Main forensic analyzer class."""
    
    def __init__(self, config_path: str = "config.yaml"):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.vt_api_key = self.config.get('virustotal', {}).get('api_key', '')
        self.vt_enabled = self.config.get('virustotal', {}).get('enabled', False)
        self.patterns = self.config.get('suspicious_patterns', {})
        self.risk_scores = self.config.get('risk_scoring', {})
        self.min_string_length = self.config.get('analysis', {}).get('min_string_length', 4)
        self.max_strings = self.config.get('analysis', {}).get('max_strings_per_category', 20)
        self.entropy_threshold = self.config.get('analysis', {}).get('entropy_threshold', 7.5)
    
    def analyze(self, file_path: str) -> Dict[str, Any]:
        """Analyze a file and return comprehensive report."""
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        report = {
            'metadata': {
                'file_name': path.name,
                'file_path': str(path.absolute()),
                'file_size': path.stat().st_size,
                'file_extension': path.suffix.lower(),
                'analyzed_at': datetime.now().isoformat(),
            },
            'hashes': self._calculate_hashes(path),
            'entropy': self._calculate_entropy(path),
            'strings': self._extract_strings(path),
            'file_type': self._detect_file_type(path),
            'risk_score': 0,
            'risk_level': 'low',
            'indicators': [],
            'recommendations': []
        }
        
        report['risk_score'] = self._calculate_risk(report)
        report['risk_level'] = self._get_risk_level(report['risk_score'])
        
        if self.vt_enabled and self.vt_api_key:
            report['virustotal'] = self._check_virustotal(report['hashes']['sha256'])
        
        return report
    
    def _calculate_hashes(self, file_path: Path) -> Dict[str, str]:
        """Calculate MD5, SHA1, and SHA256 hashes."""
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        
        return {
            'md5': md5.hexdigest(),
            'sha1': sha1.hexdigest(),
            'sha256': sha256.hexdigest()
        }
    
    def _calculate_entropy(self, file_path: Path) -> Dict[str, Any]:
        """Calculate Shannon entropy of file."""
        with open(file_path, 'rb') as f:
            data = f.read()
        
        if not data:
            return {'value': 0, 'assessment': 'empty'}
        
        entropy = 0.0
        for x in range(256):
            p_x = data.count(bytes([x])) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log(p_x, 2)
        
        entropy = round(entropy, 2)
        
        assessment = 'normal'
        if entropy > 7.5:
            assessment = 'high - possible packed/encrypted'
        elif entropy > 6.5:
            assessment = 'elevated - possible compressed'
        
        return {
            'value': entropy,
            'max_possible': 8.0,
            'assessment': assessment,
            'threshold': self.entropy_threshold
        }
    
    def _extract_strings(self, file_path: Path) -> Dict[str, List[str]]:
        """Extract suspicious strings from file."""
        strings = {key: [] for key in self.patterns.keys()}
        
        with open(file_path, 'rb') as f:
            data = f.read()
        
        printable = re.findall(
            rb'[\x20-\x7e]{' + str(self.min_string_length).encode() + rb',}', 
            data
        )
        text = b' '.join(printable).decode('ascii', errors='ignore')
        
        try:
            utf16_text = data.decode('utf-16le', errors='ignore')
            text += ' ' + utf16_text
        except:
            pass
        
        for key, pattern in self.patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            unique_matches = list(set(matches))[:self.max_strings]
            strings[key] = unique_matches
        
        return strings
    
    def _detect_file_type(self, file_path: Path) -> Dict[str, Any]:
        """Detect file type using extension."""
        extension = file_path.suffix.lower()
        
        type_map = {
            '.exe': 'Windows Executable (PE)',
            '.dll': 'Windows Dynamic Link Library',
            '.pdf': 'PDF Document',
            '.doc': 'Microsoft Word Document',
            '.docx': 'Microsoft Word Document (OpenXML)',
            '.xls': 'Microsoft Excel Spreadsheet',
            '.xlsx': 'Microsoft Excel Spreadsheet (OpenXML)',
            '.zip': 'ZIP Archive',
            '.rar': 'RAR Archive',
            '.7z': '7-Zip Archive',
            '.jar': 'Java Archive',
            '.py': 'Python Script',
            '.ps1': 'PowerShell Script',
            '.bat': 'Windows Batch Script',
            '.cmd': 'Windows Command Script',
            '.sh': 'Shell Script',
        }
        
        detected = type_map.get(extension, 'Unknown')
        
        return {
            'extension': extension,
            'detected_type': detected,
            'is_executable': extension in ['.exe', '.dll', '.jar', '.py', '.ps1', '.bat', '.cmd', '.sh'],
            'is_document': extension in ['.pdf', '.doc', '.docx', '.xls', '.xlsx'],
            'is_archive': extension in ['.zip', '.rar', '.7z', '.tar', '.gz']
        }
    
    def _calculate_risk(self, report: Dict[str, Any]) -> int:
        """Calculate overall risk score."""
        score = 0
        indicators = []
        recommendations = []
        
        entropy = report['entropy']['value']
        if entropy > self.entropy_threshold:
            score += self.risk_scores.get('entropy_high', 25)
            indicators.append(f"High entropy ({entropy}) - possible packed/encrypted malware")
            recommendations.append("Consider dynamic analysis in sandbox")
        
        strings = report['strings']
        
        if strings.get('powershell'):
            count = len(strings['powershell'])
            score += self.risk_scores.get('powershell_detected', 20)
            indicators.append(f"PowerShell commands detected: {count}")
            recommendations.append("Analyze PowerShell for obfuscation or malicious intent")
        
        if strings.get('urls'):
            count = len(strings['urls'])
            score += self.risk_scores.get('urls_found', 10)
            indicators.append(f"URLs embedded in file: {count}")
            recommendations.append("Check URLs against threat intelligence feeds")
        
        if strings.get('ips'):
            count = len(strings['ips'])
            score += self.risk_scores.get('ips_found', 10)
            indicators.append(f"IP addresses embedded: {count}")
            recommendations.append("Investigate IP reputation and geolocation")
        
        if strings.get('emails'):
            count = len(strings['emails'])
            score += self.risk_scores.get('emails_found', 5)
            indicators.append(f"Email addresses found: {count}")
        
        if strings.get('registry'):
            count = len(strings['registry'])
            score += self.risk_scores.get('registry_found', 10)
            indicators.append(f"Registry references: {count}")
            recommendations.append("Check for persistence mechanisms")
        
        if strings.get('cmd_execution'):
            count = len(strings['cmd_execution'])
            score += self.risk_scores.get('cmd_execution', 15)
            indicators.append(f"Command execution patterns: {count}")
            recommendations.append("Look for command injection or shell execution")
        
        if strings.get('network'):
            count = len(strings['network'])
            score += self.risk_scores.get('network_tools', 10)
            indicators.append(f"Network tool references: {count}")
            recommendations.append("Check for C2 communication or data exfiltration")
        
        if strings.get('dll_injection'):
            count = len(strings['dll_injection'])
            score += self.risk_scores.get('dll_injection', 30)
            indicators.append(f"DLL injection APIs detected: {count}")
            recommendations.append("HIGH RISK: Possible process injection malware")
        
        file_type = report['file_type']
        if file_type['is_executable'] and entropy > 6.5:
            score += 10
            indicators.append("Executable file with elevated entropy")
        
        report['indicators'] = indicators
        report['recommendations'] = recommendations
        
        return min(score, 100)
    
    def _get_risk_level(self, score: int) -> str:
        """Convert score to risk level."""
        if score >= 80:
            return 'critical'
        elif score >= 60:
            return 'high'
        elif score >= 40:
            return 'medium'
        elif score >= 20:
            return 'low'
        return 'minimal'
    
    def _check_virustotal(self, sha256: str) -> Optional[Dict[str, Any]]:
        """Check file hash against VirusTotal."""
        if not self.vt_api_key:
            return None
        
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        headers = {"x-apikey": self.vt_api_key}
        
        try:
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                return {
                    'found': True,
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'total_engines': sum(stats.values()),
                    'permalink': f"https://www.virustotal.com/gui/file/{sha256}"
                }
            elif response.status_code == 404:
                return {'found': False, 'message': 'File not previously analyzed'}
        except Exception as e:
            return {'found': False, 'error': str(e)}
        
        return None


def main():
    parser = argparse.ArgumentParser(
        description='File Forensics Analyzer - Static malware analysis tool'
    )
    parser.add_argument('file', help='File to analyze')
    parser.add_argument('-c', '--config', default='config.yaml', help='Config file path')
    parser.add_argument('-o', '--output', help='Output JSON report file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    args = parser.parse_args()
    
    try:
        analyzer = FileForensicsAnalyzer(config_path=args.config)
        report = analyzer.analyze(args.file)
        
        print(json.dumps(report, indent=2, default=str))
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            print(f"\nReport saved to: {args.output}")
        
        print(f"\n{'='*50}")
        print(f"RISK SCORE: {report['risk_score']}/100 ({report['risk_level'].upper()})")
        print(f"{'='*50}")
        
        if report['indicators']:
            print(f"\nIndicators Found ({len(report['indicators'])}):")
            for i, indicator in enumerate(report['indicators'], 1):
                print(f"  {i}. {indicator}")
        
        if report['recommendations']:
            print(f"\nRecommendations:")
            for i, rec in enumerate(report['recommendations'], 1):
                print(f"  {i}. {rec}")
        
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
