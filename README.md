Local Vulnerability Scanner (Network + System Security)

Overview:
This is a lightweight local vulnerability scanner written in Python. It:
- Performs network discovery and port/service scanning using nmap (subprocess or python-nmap).
- Attempts basic service fingerprinting and matches known vulnerable versions from a small local DB.
- Produces HTML and CSV reports with severity categorizations.

WARNING:
- Requires nmap installed on the host (`sudo apt install nmap`) for best results.

Quickstart:
1. Install prerequisites:
   - System: nmap (recommended)
   - Python packages: pip install -r requirements.txt
2. Run scan:
   python3 main.py scan --target 192.168.1.0/24 --ports 22,80,443 --output reports/


- Interate with online CVE databases (requires web.run or internet).
- Add authentication checks, SMB/SSH checks, or OS-specific local checks.
