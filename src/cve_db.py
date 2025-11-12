# Small sample vulnerability database.
# Mapping: (service_name, product, version_prefix) -> [ { 'cve': 'CVE-XXXX-YYYY', 'severity': 'High', 'description': '...' }, ... ]
# This is intentionally tiny; extend with real CVE data as needed.

SAMPLE_DB = {
    ('ssh', 'OpenSSH', '7.2p2'): [
        {
            'cve': 'CVE-2016-0777',
            'severity': 'Medium',
            'description': 'OpenSSH 7.2p2 weakness example (sample entry).'
        }
    ],
    ('http', 'Apache', '2.4.18'): [
        {
            'cve': 'CVE-2017-7668',
            'severity': 'High',
            'description': 'Sample Apache CVE for demonstration.'
        }
    ],
    ('mysql', 'MySQL', '5.5'): [
        {
            'cve': 'CVE-2012-2122',
            'severity': 'High',
            'description': 'Sample MySQL remote vulnerability.'
        }
    ],
}

def lookup(service_name: str, product: str, version: str):
    """Return list of matching vuln dicts for given service/product/version (simple prefix matching)."""
    results = []
    for (svc, prod, ver_prefix), vulns in SAMPLE_DB.items():
        if svc and svc.lower() in service_name.lower() and prod.lower() in product.lower() and version.startswith(ver_prefix):
            results.extend(vulns)
    return results
