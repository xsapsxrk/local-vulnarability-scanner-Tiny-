import subprocess
import json
import re
from typing import List, Dict
import shutil
try:
    import nmap  # python-nmap
    _has_pynmap = True
except Exception:
    _has_pynmap = False
from .cve_db import lookup as cve_lookup

def _run_nmap_subprocess(target: str, ports: str = '') -> str:
    cmd = ['nmap', '-sV', '-oX', '-', target]
    if ports:
        cmd = ['nmap', '-sV', '-p', ports, '-oX', '-', target]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"nmap failed: {proc.stderr}")
    return proc.stdout

def _parse_nmap_xml(xml_str: str) -> List[Dict]:
    # Very lightweight XML parsing to extract host/port/service/product/version.
    # For production use, use python-libnmap or xml.etree.ElementTree for robustness.
    import xml.etree.ElementTree as ET
    root = ET.fromstring(xml_str)
    findings = []
    for host in root.findall('host'):
        addr_elem = host.find('address')
        ip = addr_elem.get('addr') if addr_elem is not None else 'unknown'
        ports = host.find('ports')
        if ports is None:
            continue
        for port in ports.findall('port'):
            portid = port.get('portid')
            service = port.find('service')
            svc_name = service.get('name') if service is not None and 'name' in service.attrib else ''
            product = service.get('product') if service is not None and 'product' in service.attrib else ''
            version = service.get('version') if service is not None and 'version' in service.attrib else ''
            findings.append({
                'host': ip,
                'port': portid,
                'service': svc_name,
                'product': product,
                'version': version
            })
    return findings

def scan(target: str, ports: str = '', use_pynmap: bool = False) -> List[Dict]:
    """Scan target and return list of dicts with host/port/service/product/version and matched vulns."""
    xml_out = None
    if use_pynmap and _has_pynmap:
        nm = nmap.PortScanner()
        args = '-sV'
        if ports:
            args += f' -p {ports}'
        nm.scan(hosts=target, arguments=args)
        findings = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    svc = nm[host][proto][port]
                    product = svc.get('product','')
                    version = svc.get('version','')
                    svcname = svc.get('name','')
                    findings.append({'host': host, 'port': str(port), 'service': svcname, 'product': product, 'version': version})
        xml_out = None
    else:
        xml_out = _run_nmap_subprocess(target, ports)
        findings = _parse_nmap_xml(xml_out)
    # match against CVE db
    enriched = []
    for f in findings:
        vulns = cve_lookup(f.get('service',''), f.get('product',''), f.get('version',''))
        highest = 'None'
        sev_order = {'Critical':4,'High':3,'Medium':2,'Low':1,'None':0}
        if vulns:
            highest = sorted([v['severity'] for v in vulns], key=lambda s: sev_order.get(s,0), reverse=True)[0]
        enriched.append({**f, 'vulns': vulns, 'highest_severity': highest})
    return enriched
