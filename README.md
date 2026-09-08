# Malicious Browser Extension Detection and Management System

A cybersecurity-focused platform for **detecting, analyzing, scoring, and monitoring potentially risky Google Chrome extensions** using local static analysis, threat-intelligence enrichment, and SIEM integration.

The project combines **permission analysis, IOC extraction, VirusTotal intelligence, static-code analysis, and multi-factor risk scoring** to produce structured security events that can be monitored in **Wazuh**.

---

## Overview

Browser extensions can request powerful permissions, access sensitive browsing data, communicate with external services, and execute complex JavaScript code. A high permission count alone does not necessarily mean an extension is malicious, so this project evaluates extensions using several independent security signals.

The system analyzes installed Chrome extensions and produces a final risk assessment using:

- Permission-based exposure
- Extracted and normalized Indicators of Compromise (IOCs)
- VirusTotal threat-intelligence results
- Suspicious static-code techniques
- Multi-factor risk scoring
- Wazuh SIEM monitoring

---

## Architecture

```text
Google Chrome
     |
     v
Endpoint Extension Scanner
     |
     v
Permission Risk Scoring
     |
     v
IOC Extraction
     |
     v
IOC Normalization
     |
     v
VirusTotal Threat Intelligence
     |
     v
Threat Intelligence Scoring
     |
     v
Static Code Scoring
     |
     v
Multi-Factor Risk Engine
     |
     v
Security Event Generation
     |
     v
TCP Syslog
     |
     v
Wazuh SIEM / Dashboard
```

---

## Key Features

### Chrome Extension Discovery
- Detects installed Chrome extensions across multiple Chrome profiles
- Extracts extension name, ID, version, manifest version, permissions, and host permissions

### Permission Risk Analysis
- Scores risky permissions such as `tabs`, `cookies`, `downloads`, `nativeMessaging`, `webRequest`, and broad host access such as `<all_urls>`
- Detects risky permission combinations
- Flags deprecated Manifest V2 extensions
- Produces a permission risk score and severity

### IOC Extraction
Statically scans extension files for:

- URLs
- Domains
- IPv4 addresses
- API-style endpoints
- SHA-256 file hashes
- Chrome host match patterns
- Suspicious JavaScript techniques

### IOC Normalization
Filters and cleans extracted indicators before threat-intelligence enrichment.

Examples of excluded values include:

- Wildcard Chrome match patterns
- Local-only addresses
- Invalid URLs
- Template or placeholder strings
- Non-public IP destinations

### VirusTotal Threat Intelligence
Selected indicators are enriched using the VirusTotal API.

The system currently checks a limited number of:

- Domains
- URLs
- File hashes
- Public IP addresses

Results are cached to reduce unnecessary API requests and help respect API rate limits.

> VirusTotal detections are treated as evidence about an extracted indicator, not automatic proof that the entire extension is malicious.

### Static Code Analysis
The analysis engine detects suspicious JavaScript techniques such as:

- `eval()`
- `Function()` constructors
- Base64 decoding
- `String.fromCharCode`
- Long Base64 blobs
- Repeated hexadecimal escapes
- Repeated Unicode escapes
- Legacy `unescape()`

The scorer uses bounded contributions instead of directly scoring raw occurrence counts, reducing false inflation caused by minified or bundled JavaScript.

### Multi-Factor Risk Assessment
The final risk assessment combines:

- Permission risk
- Threat-intelligence evidence
- Static-code findings

The result includes:

- Final risk score
- Final severity
- Recommendation
- Supporting component scores

### Duplicate Analysis Reuse
If the same extension version is installed in multiple Chrome profiles, expensive analysis is reused using:

```text
extension_id:extension_version
```

This avoids duplicate VirusTotal lookups and repeated static analysis.

### Wazuh SIEM Integration
Security events are sent to Wazuh over **TCP Syslog**.

The events can include fields such as:

```text
extension_name
extension_id
extension_version
permission_risk_score
permission_severity
threat_intel_score
static_code_score
final_risk_score
final_severity
final_recommendation
analysis_status
```

The system only updates the latest inventory snapshot after successful Syslog delivery.

If Syslog delivery fails, events are written to a local JSONL fallback spool and the previous snapshot is preserved.

---

## Example Risk Output

```text
Extension: Example Extension

Permission Score : 41
Threat Intel     : 5
Static Code      : 25
Final Score      : 18 / 100
Final Severity   : Low
Recommendation   : Low observed risk; continue monitoring
```

A high permission score does **not** automatically mean an extension is malicious. The final assessment considers multiple sources of evidence.

---

## Project Structure

```text
browser-extension-security-platform/
|
|-- analysis_engine/
|   |-- extension_analyzer.py
|   |-- final_risk_engine.py
|   |-- static_code_scorer.py
|   |-- threat_intel_scorer.py
|   |-- threat_intel_service.py
|   `-- virustotal_client.py
|
|-- endpoint_scanner/
|   |-- browser_scanner.py
|   |-- chrome.py
|   |-- event_writer.py
|   |-- inventory_comparator.py
|   |-- ioc_extractor.py
|   |-- ioc_normalizer.py
|   |-- localization.py
|   |-- manifest.py
|   |-- models.py
|   |-- permission_risk_score.py
|   |-- scanner.py
|   `-- syslog_sender.py
|
|-- logs/
|   |-- threat_intel_cache/
|   `-- wazuh_spool/
|
|-- main.py
|-- requirements.txt
`-- README.md
```

> Some generated folders and files may not exist until the project is executed.

---

## Technologies Used

- **Python**
- **Google Chrome Extension Manifest**
- **VirusTotal API**
- **Wazuh SIEM**
- **TCP Syslog**
- **JSON / JSONL**
- **Windows PowerShell**
- **Git & GitHub**

---

## Prerequisites

Before running the system, ensure you have:

- Python installed
- A Python virtual environment
- Google Chrome installed
- A VirusTotal API key
- A reachable Wazuh server configured to receive TCP Syslog events

---

## Installation

### 1. Clone the Repository

```bash
git clone <your-repository-url>
cd browser-extension-security-platform
```

### 2. Create a Virtual Environment

Windows PowerShell:

```powershell
python -m venv venv
```

Activate it:

```powershell
.\venv\Scripts\Activate.ps1
```

### 3. Install Dependencies

If a `requirements.txt` file is available:

```powershell
pip install -r requirements.txt
```

---

## Environment Variables

### VirusTotal API Key

Set the VirusTotal key for the current PowerShell session:

```powershell
$env:VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
```

To save it as a Windows user environment variable:

```powershell
[System.Environment]::SetEnvironmentVariable(
    "VT_API_KEY",
    "YOUR_VIRUSTOTAL_API_KEY",
    "User"
)
```

Do **not** hardcode or commit your API key to GitHub.

### Wazuh Syslog Configuration

```powershell
$env:WAZUH_SYSLOG_HOST = "YOUR_WAZUH_IP"
$env:WAZUH_SYSLOG_PORT = "5514"
```

Test connectivity:

```powershell
Test-NetConnection $env:WAZUH_SYSLOG_HOST -Port 5514
```

Expected:

```text
TcpTestSucceeded : True
```

---

## Running the Project

With the virtual environment active:

```powershell
python main.py
```

The pipeline performs:

```text
Chrome scan
-> Permission scoring
-> IOC extraction
-> IOC normalization
-> VirusTotal enrichment
-> Threat-intelligence scoring
-> Static-code scoring
-> Final risk scoring
-> Security event generation
-> Wazuh Syslog delivery
```

---

## Generated Output

The system can generate files such as:

```text
logs/latest_chrome_inventory.json
logs/latest_multifactor_analysis.json
logs/threat_intel_cache/
logs/wazuh_spool/
```

These are runtime artifacts and should normally remain excluded from Git.

---

## Security Considerations

This project is designed as a **security-analysis and monitoring prototype**.

Important limitations:

- A high permission score does not prove malicious behavior.
- Static-code techniques such as `eval()` may also appear in legitimate bundled JavaScript.
- VirusTotal detections can contain false positives.
- Extracted URLs may be references embedded in code rather than destinations contacted during runtime.
- The current implementation primarily performs static analysis rather than full dynamic behavioral analysis.
- Final results should be treated as risk indicators that support analyst investigation.

---

## Current Project Status

Implemented:

- [x] Chrome extension discovery
- [x] Multi-profile scanning
- [x] Permission risk scoring
- [x] IOC extraction
- [x] IOC normalization
- [x] VirusTotal enrichment
- [x] Threat-intelligence scoring
- [x] Static-code scoring
- [x] Multi-factor final risk engine
- [x] Unified extension analyzer
- [x] Duplicate analysis reuse
- [x] Inventory comparison
- [x] TCP Syslog integration
- [x] Wazuh event delivery
- [x] Local fallback JSONL spool
- [x] Snapshot preservation on delivery failure

Planned / in progress:

- [ ] Final Wazuh rules based on multi-factor severity
- [ ] Wazuh dashboard validation and visualization
- [ ] Additional IOC filtering improvements
- [ ] Extended testing with controlled malicious-extension samples
- [ ] Final documentation and evaluation

---

## Future Improvements

Possible future enhancements include:

- Dynamic extension behavior monitoring
- JavaScript AST-based analysis
- Additional threat-intelligence providers
- Extension reputation history
- Automated response actions
- Improved IOC prioritization
- Wazuh dashboards and visual risk summaries
- Machine-learning-assisted extension classification

---

## Disclaimer

This project is intended for **academic, defensive-security, and research purposes**. Risk scores should support security investigation and should not be treated as definitive malware verdicts without additional evidence.

---

## License

Add an appropriate license if the project is intended for public reuse or distribution.
