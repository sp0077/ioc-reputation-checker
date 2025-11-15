*IOC Reputation Checker — SOC Automation Tool (Python)
Customized for: Sarvesh Pandekar

Overview
This project is a beginner-friendly security automation tool that checks reputation of URLs, IPs, Domains, and File Hashes using VirusTotal, AlienVault OTX, and AbuseIPDB.

Features
- Detects IOC type (URL, IP, Domain, Hash)
- Adds https:// automatically if missing
- Submits URLs to VirusTotal for actual scanning
- OTX threat pulse lookup
- AbuseIPDB confidence score lookup
- Saves output to report/output.txt
- Beginner-friendly modular Python code

Project Structure
ioc-reputation-checker/
│── main.py
│── README.md
│── modules/
│    ├── vt_checker.py
│    ├── otx_checker.py
│    └── abuse_checker.py
│── report/
│    └── output.txt
│── .gitignore

Requirements
pip install requests colorama python-dotenv
API Keys Setup

Create a .env file:
VT_API=your_virustotal_api_key
OTX_API=your_otx_api_key
ABUSE_API=your_abuseipdb_api_key

Usage
python main.py

Sample Output
VT → Malicious: 2, Suspicious: 1
OTX → Listed in 3 threat intelligence pulses
AbuseIPDB → Confidence Score: 75

Report saved to report/output.txt

Skills Demonstrated
- API Integration
- SOC Automation
- Threat Intelligence
- Python Scripting
- IOC Analysis
- Secure API Key Handling
