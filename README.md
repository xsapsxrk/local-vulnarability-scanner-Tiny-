Local Vulnerability Scanner (Network + System Security)

Overview:
This is a lightweight local vulnerability scanner written in Python. It:
- Performs network discovery and port/service scanning using nmap (subprocess or python-nmap).
- Attempts basic service fingerprinting and matches known vulnerable versions from a small local DB.
- Produces HTML and CSV reports with severity categorizations.

WARNING:
- Run this only on systems/networks you own or are authorized to test.
- Requires nmap installed on the host (`sudo apt install nmap`) for best results.

Quickstart:
1. Install prerequisites:
   - System: nmap (recommended)
   - Python packages: pip install -r requirements.txt
2. Run scan:
   python3 main.py scan --target 192.168.1.0/24 --ports 22,80,443 --output reports/

What's included:
- main.py         : CLI entry
- src/scanner.py  : scanning logic (uses nmap subprocess; falls back to python-nmap if available)
- src/cve_db.py   : small sample vulnerability database (editable)
- src/report.py   : reporting utilities (CSV + simple HTML)

Extend:
- Integrate with online CVE databases (requires web.run or internet).
- Add authentication checks, SMB/SSH checks, or OS-specific local checks.
