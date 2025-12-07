# React2Shell Scanner (CVE-2025-55182)

<div align="center">

![Version](https://img.shields.io/badge/version-2.1-blue.svg)
![Python](https://img.shields.io/badge/python-3.7+-brightgreen.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![CVE](https://img.shields.io/badge/CVE-2025--55182-red.svg)
![CVSS](https://img.shields.io/badge/CVSS-10.0-critical.svg)

**Advanced Mass Vulnerability Scanner for React Server Components RCE**

*by [loogezh-alt](https://github.com/loogezh-alt)*

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Examples](#-examples) • [Detection Methods](#-detection-methods) • [Legal](#-legal-disclaimer)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage](#-usage)
- [Detection Methods](#-detection-methods)
- [Understanding the Vulnerability](#-understanding-the-vulnerability)
- [Scan Results](#-scan-results)
- [Advanced Usage](#-advanced-usage)
- [Contributing](#-contributing)
- [Credits](#-credits)
- [Legal Disclaimer](#-legal-disclaimer)

---

## 🔍 Overview

**React2Shell Scanner** is an advanced vulnerability detection tool for **CVE-2025-55182**, a critical remote code execution (RCE) vulnerability in React Server Components with a maximum CVSS score of **10.0**.

This scanner implements multiple detection techniques based on:
- **maple3142's real PoC exploit**
- **TryHackMe's detailed vulnerability analysis**
- **Lachlan Davidson's original research** (vulnerability discoverer)
- **Real-world exploitation patterns** observed in the wild

### What is CVE-2025-55182?

React2Shell is an **unauthenticated remote code execution** vulnerability affecting React 19's Server Components. It exploits unsafe deserialization in the Flight protocol, allowing attackers to execute arbitrary JavaScript code on vulnerable servers through a single crafted HTTP request.

**Affected Versions:**
- React Server Components: `19.0.0`, `19.1.0`, `19.1.1`, `19.2.0`
- Next.js: `≥14.3.0-canary.77`, all `15.x` and `16.x` (pre-patch)
- Other frameworks: React Router (RSC), Waku, Redwood SDK, and various RSC plugins

**Patched Versions:**
- React: `19.0.1`, `19.1.2`, `19.2.1`
- Next.js: `15.0.5`, `15.1.9`, `15.2.6`, `15.3.6`, `15.4.8`, `15.5.7`, `16.0.7`

---

## ✨ Features

### 🎯 **Core Capabilities**
- ✅ **Multi-threaded scanning** - Concurrent vulnerability checks with configurable threads
- ✅ **Real PoC-based verification** - Uses actual exploit payloads (safe mode)
- ✅ **Advanced fingerprinting** - Flight protocol detection and RSC endpoint discovery
- ✅ **Smart risk scoring** - 0-100 risk assessment per target
- ✅ **WAF detection** - Identifies Cloudflare, AWS WAF, Vercel, Akamai, Fastly
- ✅ **Mass scanning** - Process hundreds/thousands of domains from a file
- ✅ **JSON reporting** - Structured output for automation and integration
- ✅ **Colored terminal output** - Easy-to-read results with ANSI colors

### 🔬 **Detection Methods**
1. **Next.js Presence Detection** (9 indicators)
   - Static file patterns (`_next/static`)
   - Build ID extraction
   - App Router detection
   - RSC manifest checking
   - Server component markers

2. **React Version Fingerprinting**
   - Multiple regex patterns for version extraction
   - Package.json exposure checks
   - Vulnerable version identification

3. **RSC Endpoint Discovery**
   - Tests 8+ common RSC paths
   - POST/GET method verification
   - Response pattern analysis

4. **Flight Protocol Fingerprinting**
   - Serialization format detection (`$@`, `$B`, `$Q`)
   - Content-Type validation (`text/x-component`)
   - Chunk and model resolution checks

5. **Safe PoC Execution**
   - Real exploit structure (based on maple3142)
   - Non-destructive payload (`echo` command)
   - Response analysis for RCE confirmation

6. **WAF & Protection Detection**
   - Header-based identification
   - Response code analysis
   - Generic WAF pattern matching

---

## 🚀 Installation

### Prerequisites
- Python 3.7 or higher
- `pip` package manager

### Install Dependencies

```bash
# Clone the repository
git clone https://github.com/loogezh-alt/react2shell-scanner.git
cd react2shell-scanner

# Install required packages
pip install -r requirements.txt
```

**requirements.txt:**
```
requests>=2.31.0
urllib3>=2.0.0
```

### Quick Install (One-liner)
```bash
git clone https://github.com/loogezh-alt/react2shell-scanner.git && cd react2shell-scanner && pip install -r requirements.txt
```

---

## ⚡ Quick Start

### Scan a Single Target
```bash
python react2shell_scanner.py -u https://example.com
```

### Scan Multiple Targets
```bash
# Create targets.txt with one URL per line
echo "https://target1.com" > targets.txt
echo "https://target2.com" >> targets.txt
echo "target3.com" >> targets.txt

# Run mass scan
python react2shell_scanner.py -f targets.txt -t 20 -o results.json
```

---

## 📖 Usage

### Command-Line Options

```
usage: react2shell_scanner.py [-h] [-u URL] [-f FILE] [-t THREADS] [-o OUTPUT]
                              [--timeout TIMEOUT] [-v] [-a]

React2Shell (CVE-2025-55182) Advanced Mass Scanner by loogezh-alt

options:
  -h, --help            Show this help message and exit
  -u URL, --url URL     Single URL to scan
  -f FILE, --file FILE  File containing URLs (one per line)
  -t THREADS, --threads THREADS
                        Number of threads (default: 10)
  -o OUTPUT, --output OUTPUT
                        Output file for JSON report
  --timeout TIMEOUT     Request timeout in seconds (default: 10)
  -v, --verbose         Verbose output with debug information
  -a, --aggressive      Aggressive scanning mode (more thorough)
```

### Input File Format

Create a text file with one URL per line:

```
https://example1.com
https://example2.com
example3.com
http://example4.com:3000

# Comments start with #
# Blank lines are ignored
```

---

## 📝 Examples

### Example 1: Single URL Scan
```bash
python react2shell_scanner.py -u https://vulnerable-app.com
```

**Output:**
```
[*] Starting comprehensive scan for https://vulnerable-app.com
[+] Next.js detected: 7 indicators
[+] RSC endpoints found: ['/_next/data', '/__flight__']
[+] Flight protocol indicators: 3/4 detected
[!!!] CONFIRMED VULNERABLE! PoC executed successfully
```

### Example 2: Mass Scan with JSON Output
```bash
python react2shell_scanner.py -f domains.txt -t 30 -o scan_results.json -v
```

**Output:**
```
Progress: [250/250] 100.0%

================================================================================
SCAN REPORT SUMMARY
================================================================================
Total Scanned: 250
Vulnerable (HIGH): 12
Potentially Vulnerable (MEDIUM): 35
Uncertain: 18
Not Vulnerable: 185

================================================================================
CRITICAL: VULNERABLE TARGETS FOUND
================================================================================
  [!!!] https://victim1.com
       Risk Score: 85/100
       Details: CONFIRMED VULNERABLE - PoC executed successfully
       Endpoints: /_next/data, /__flight__

  [!!!] https://victim2.com
       Risk Score: 78/100
       Details: VULNERABLE - Exploit indicators detected
       Endpoints: /_next/data

[+] Full JSON report saved to: scan_results.json
```

### Example 3: Aggressive Verbose Scan
```bash
python react2shell_scanner.py -f high-priority.txt -t 50 -v -a -o detailed_results.json
```

This mode performs:
- More thorough endpoint discovery
- Extended fingerprinting
- Detailed debug logging
- Comprehensive risk assessment

---

## 🔬 Detection Methods

### 1. Next.js Fingerprinting

The scanner checks for multiple Next.js indicators:

| Indicator | Description | Weight |
|-----------|-------------|--------|
| `_next/static` | Next.js static file path | High |
| `__NEXT_DATA__` | Next.js data script tag | High |
| `x-powered-by: Next.js` | HTTP header | Medium |
| App Router chunks | `/_next/static/chunks/app/` | Critical |
| `__RSC_MANIFEST__` | RSC manifest in HTML | Critical |
| Build ID extraction | Next.js build identifier | Medium |
| Flight protocol markers | `$@`, `$B`, `$Q` in responses | Critical |

### 2. Vulnerability Verification

The scanner uses a **safe PoC** based on maple3142's real exploit:

```python
# Simplified payload structure
{
  "then": "$1:__proto__:then",
  "status": "resolved_model",
  "value": '{"then":"$B1337"}',
  "_response": {
    "_prefix": "echo VULN_TEST_CONFIRMED",
    "_formData": {
      "get": "$1:constructor:constructor"
    }
  }
}
```

**What it does:**
1. Crafts multipart form data mimicking RSC chunk structure
2. Exploits prototype chain traversal to access `Function.constructor`
3. Executes safe command (`echo`) instead of malicious code
4. Detects successful execution via response analysis

**Detection Criteria:**
- ✅ `VULN_TEST_CONFIRMED` in response = **CONFIRMED VULNERABLE**
- ✅ `NEXT_REDIRECT` + `digest` in response = **VULNERABLE**
- ✅ 500 error + constructor references = **LIKELY VULNERABLE**
- ⚠️ 403 Forbidden = **Possibly protected but vulnerable**

### 3. Risk Scoring System

Each target receives a risk score (0-100) based on:

| Factor | Points | Description |
|--------|--------|-------------|
| Next.js detected | +20 | Base score for Next.js presence |
| Vulnerable React version | +30 | React 19.0-19.2.0 detected |
| RSC endpoints found | +20 | Flight protocol endpoints accessible |
| Flight indicators | +5 each | Up to +20 for protocol markers |
| PoC success | +30 | Exploit payload executed |
| WAF detected | -10 | Protection layer present |

**Risk Levels:**
- **90-100**: Critical - Immediate action required
- **70-89**: High - Confirm and patch urgently
- **50-69**: Medium - Manual verification needed
- **30-49**: Low - Monitor and verify
- **0-29**: Minimal - Likely not vulnerable

---

## 🛡️ Understanding the Vulnerability

### Technical Deep Dive

**CVE-2025-55182** is an unsafe deserialization vulnerability in React's Flight protocol. Here's how it works:

#### 1. Flight Protocol Basics
React Server Components use the Flight protocol to serialize/deserialize data between client and server:

```javascript
// Normal usage
"$@0"  // Reference to chunk 0
"$B123" // Blob reference with ID 123
```

#### 2. The Vulnerability
The `requireModule` function doesn't validate property access:

```javascript
function requireModule(metadata) {
  var moduleExports = __webpack_require__(metadata[0]);
  return moduleExports[metadata[2]];  // VULNERABLE!
}
```

#### 3. Exploitation Chain

```
1. Attacker sends: "$1:constructor:constructor"
   ↓
2. React traverses: chunk[1].constructor.constructor
   ↓
3. Returns: Function constructor (global)
   ↓
4. Attacker invokes: Function("malicious code")()
   ↓
5. Result: Remote Code Execution
```

#### 4. Real-World Impact

```bash
# What attackers can do:
- Execute system commands
- Read environment variables (API keys, secrets)
- Establish reverse shells
- Exfiltrate sensitive data
- Modify server files
- Pivot to internal networks
```

### Why This is Critical

1. **No authentication required** - Anyone can exploit
2. **Default configurations vulnerable** - Fresh `create-next-app` affected
3. **Single HTTP request** - One-shot exploitation
4. **High reliability** - Near 100% success rate
5. **Wide deployment** - 39% of cloud environments affected

---

## 📊 Scan Results

### Console Output

The scanner provides real-time colored output:

```
[*] Starting comprehensive scan for https://target.com
[+] Next.js detected: 7 indicators
[+] React version: 19.1.0
[!] WAF detected: ['cloudflare']
[+] RSC endpoints found: ['/_next/data', '/__flight__']
[+] Flight protocol indicators: 3/4 detected
[!!!] CONFIRMED VULNERABLE! PoC executed successfully

================================================================================
SCAN REPORT SUMMARY
================================================================================
Total Scanned: 50
Vulnerable (HIGH): 8
Potentially Vulnerable (MEDIUM): 12
Uncertain: 5
Not Vulnerable: 25
```

### JSON Report Structure

```json
{
  "metadata": {
    "scan_date": "2025-12-07T10:30:00",
    "scanner_version": "2.1",
    "author": "loogezh-alt",
    "github": "https://github.com/loogezh-alt"
  },
  "statistics": {
    "scanned": 50,
    "vulnerable": 8,
    "potentially_vulnerable": 12,
    "protected": 5,
    "not_vulnerable": 25,
    "errors": 0
  },
  "vulnerable": [
    {
      "url": "https://victim.com",
      "timestamp": "2025-12-07T10:32:15",
      "vulnerable": true,
      "confidence": "high",
      "risk_score": 85,
      "details": {
        "nextjs": {
          "nextjs_static": true,
          "app_router": true,
          "rsc_manifest": true,
          "build_id": "abc123xyz"
        },
        "react_version": "19.1.0",
        "version_vulnerable": true,
        "rsc_endpoints": ["/_next/data", "/__flight__"],
        "flight_protocol": {
          "flight_protocol": true,
          "rsc_processing": true,
          "server_components": true
        },
        "poc_test": {
          "result": true,
          "message": "CONFIRMED VULNERABLE - PoC executed successfully"
        },
        "waf": {
          "cloudflare": false,
          "aws_waf": false,
          "vercel": false
        }
      }
    }
  ]
}
```

---

## 🔧 Advanced Usage

### Custom Timeout & Threading

```bash
# Fast scan with more threads, shorter timeout
python react2shell_scanner.py -f targets.txt -t 50 --timeout 5

# Careful scan with fewer threads, longer timeout
python react2shell_scanner.py -f targets.txt -t 5 --timeout 20
```

### Filtering & Processing Results

```bash
# Scan and extract only vulnerable URLs
python react2shell_scanner.py -f targets.txt -o results.json
cat results.json | jq -r '.vulnerable[].url' > vulnerable_targets.txt

# Count by risk level
cat results.json | jq '.summary'
```

### Integration with Other Tools

```bash
# Feed results to Nuclei for further testing
cat vulnerable_targets.txt | nuclei -t react-rce.yaml

# Send alerts for critical findings
python react2shell_scanner.py -f targets.txt -o results.json
cat results.json | jq -r '.vulnerable[] | select(.risk_score >= 80) | .url' | \
  xargs -I {} curl -X POST https://alerts.example.com/notify -d "url={}"
```

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### Reporting Issues
- 🐛 **Bug reports** - Open an issue with detailed reproduction steps
- 💡 **Feature requests** - Suggest new detection methods or improvements
- 📖 **Documentation** - Help improve this README or add examples

### Pull Requests
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-detection`)
3. Commit your changes (`git commit -m 'Add amazing detection method'`)
4. Push to the branch (`git push origin feature/amazing-detection`)
5. Open a Pull Request

### Development Setup
```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/react2shell-scanner.git
cd react2shell-scanner

# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests (if available)
python -m pytest tests/
```

---

## 🙏 Credits

This scanner is built upon the groundbreaking work of:

### Primary Research & PoC
- **Lachlan Davidson** ([@lachlan2k](https://github.com/lachlan2k)) - Original vulnerability discoverer
  - Reported to Meta Bug Bounty on November 29, 2025
  - Detailed analysis at [react2shell.com](https://react2shell.com/)

- **maple3142** ([@maple3142](https://github.com/maple3142)) - Working PoC exploit
  - Real exploitation code that this scanner is based on
  - [GitHub Gist](https://gist.github.com/maple3142/48bc9393f45e068cf8c90ab865c0f5f3)

### Analysis & Education
- **TryHackMe** - Comprehensive vulnerability lab and analysis
  - [React2Shell: CVE-2025-55182 Room](https://tryhackme.com/room/react2shellcve202555182)
  - Detailed exploitation walkthrough and detection techniques

- **Wiz Research** - Cloud security analysis and statistics
- **Datadog Security Labs** - Technical deep dive
- **AWS Threat Intelligence** - In-the-wild exploitation tracking

### Framework Maintainers
- **React Team** - Rapid response and patching
- **Vercel/Next.js Team** - Coordinated disclosure and fixes

---

## ⚖️ Legal Disclaimer

### ⚠️ IMPORTANT: READ BEFORE USE

This tool is provided for **educational and authorized security testing purposes only**.

### Authorized Use Only
✅ **You MAY use this tool:**
- On systems you own or have explicit written permission to test
- As part of authorized bug bounty programs (check program rules)
- In legal penetration testing engagements with signed contracts
- For academic research in controlled environments
- On your own development/staging servers

❌ **You MUST NOT use this tool:**
- Against any system without explicit authorization
- To cause harm, damage, or disruption
- For illegal purposes or unauthorized access
- In violation of local, state, or federal laws
- Against production systems without permission

### Legal Consequences
Unauthorized access to computer systems is illegal in most jurisdictions:
- 🇺🇸 USA: Computer Fraud and Abuse Act (CFAA) - up to 10 years in prison
- 🇬🇧 UK: Computer Misuse Act 1990 - up to 2 years in prison
- 🇪🇺 EU: Network and Information Systems Directive - fines up to €20M
- 🌍 Most countries: Criminal penalties including imprisonment and fines

### Liability
- The author (loogezh-alt) is **NOT responsible** for any misuse of this tool
- Users assume **FULL LEGAL RESPONSIBILITY** for their actions
- This tool is provided "AS IS" without any warranty
- Always obtain proper authorization before testing any system

### Bug Bounty Programs
If using for bug bounty hunting:
1. ✅ Read and follow the program's rules carefully
2. ✅ Only test in-scope targets
3. ✅ Report findings responsibly
4. ✅ Respect rate limits and testing guidelines
5. ❌ Never cause service disruption
6. ❌ Don't access or exfiltrate sensitive data

### Ethical Guidelines
- **Be responsible** - Test only what you're authorized to test
- **Do no harm** - Use non-destructive payloads only
- **Report responsibly** - Disclose vulnerabilities to affected parties
- **Respect privacy** - Never access, view, or share unauthorized data
- **Follow the law** - When in doubt, don't test

---

## 📜 License

MIT License

Copyright (c) 2025 loogezh-alt

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

## 📞 Contact & Support

- **Author**: loogezh-alt
- **GitHub**: [@loogezh-alt](https://github.com/loogezh-alt)
- **Issues**: [Report bugs or request features](https://github.com/loogezh-alt/react2shell-scanner/issues)

### Stay Updated
- ⭐ Star this repository to show support
- 👁️ Watch for updates and new features
- 🍴 Fork to contribute your improvements

---

## 🔗 Related Resources

### Official Advisories
- [React Blog: Critical Security Vulnerability](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)
- [CVE-2025-55182 Record](https://www.cve.org/CVERecord?id=CVE-2025-55182)
- [Next.js Security Advisory (CVE-2025-66478)](https://nextjs.org/blog/CVE-2025-66478)

### Security Research
- [Lachlan Davidson - react2shell.com](https://react2shell.com/)
- [Wiz Research Analysis](https://www.wiz.io/blog/critical-vulnerability-in-react-cve-2025-55182)
- [Datadog Security Labs Deep Dive](https://securitylabs.datadoghq.com/articles/cve-2025-55182-react2shell-remote-code-execution-react-server-components/)
- [AWS Threat Intelligence Report](https://aws.amazon.com/blogs/security/china-nexus-cyber-threat-groups-rapidly-exploit-react2shell-vulnerability-cve-2025-55182/)

### Learning Resources
- [TryHackMe: React2Shell Lab](https://tryhackme.com/room/react2shellcve202555182)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)

---

<div align="center">

**Made with ❤️ by [loogezh-alt](https://github.com/loogezh-alt)**

If this tool helped you, consider giving it a ⭐!

[Report Bug](https://github.com/loogezh-alt/react2shell-scanner/issues) · [Request Feature](https://github.com/loogezh-alt/react2shell-scanner/issues) · [Contribute](https://github.com/loogezh-alt/react2shell-scanner/pulls)

</div>
