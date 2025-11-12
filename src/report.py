import csv
from jinja2 import Template
from prettytable import PrettyTable
import os

HTML_TEMPLATE = """        <html>
<head><meta charset='utf-8'><title>Scan Report</title></head>
<body>
<h1>Local Vulnerability Scanner - Report</h1>
<h2>Summary</h2>
<p>Total hosts: {{ total_hosts }}</p>
<p>Total vulnerable findings: {{ total_findings }}</p>
<h2>Findings</h2>
<table border='1' cellpadding='6' cellspacing='0'>
<tr><th>Host</th><th>Port</th><th>Service</th><th>Product</th><th>Version</th><th>CVEs</th><th>Severity</th></tr>
{% for f in findings %}
<tr>
  <td>{{ f.host }}</td>
  <td>{{ f.port }}</td>
  <td>{{ f.service }}</td>
  <td>{{ f.product }}</td>
  <td>{{ f.version }}</td>
  <td>
    {% for v in f.vulns %}
      <div>{{ v.cve }} - {{ v.description }}</div>
    {% endfor %}
  </td>
  <td>{{ f.highest_severity }}</td>
</tr>
{% endfor %}
</table>
</body>
</html>
"""

def write_csv(findings, out_path):
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['host','port','service','product','version','cves','highest_severity'])
        for fi in findings:
            cves = ';'.join([v['cve'] for v in fi['vulns']]) if fi['vulns'] else ''
            writer.writerow([fi['host'], fi['port'], fi['service'], fi['product'], fi['version'], cves, fi['highest_severity']])

def write_html(findings, out_path):
    tpl = Template(HTML_TEMPLATE)
    total_hosts = len(set([f['host'] for f in findings]))
    total_findings = len(findings)
    rendered = tpl.render(total_hosts=total_hosts, total_findings=total_findings, findings=findings)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(rendered)

def print_console(findings):
    table = PrettyTable()
    table.field_names = ['Host','Port','Service','Product','Version','CVEs','Severity']
    for fi in findings:
        cves = ','.join([v['cve'] for v in fi['vulns']]) if fi['vulns'] else ''
        table.add_row([fi['host'], fi['port'], fi['service'], fi['product'], fi['version'], cves, fi['highest_severity']])
    print(table)
