import argparse
from src.scanner import scan
from src.report import write_csv, write_html, print_console
import os

def cmd_scan(args):
    findings = scan(args.target, ports=args.ports, use_pynmap=args.pynmap)
    outdir = args.output or 'reports'
    os.makedirs(outdir, exist_ok=True)
    csv_out = os.path.join(outdir, 'findings.csv')
    html_out = os.path.join(outdir, 'report.html')
    write_csv(findings, csv_out)
    write_html(findings, html_out)
    print_console(findings)
    print(f"Reports written to: {csv_out}, {html_out}")

def main():
    parser = argparse.ArgumentParser(description='Local Vulnerability Scanner (lightweight)')
    sub = parser.add_subparsers(dest='cmd')

    p_scan = sub.add_parser('scan')
    p_scan.add_argument('--target', required=True, help='Target host, IP, or CIDR (e.g., 192.168.1.0/24)')
    p_scan.add_argument('--ports', default='', help='Comma-separated ports or ranges (e.g., 22,80,1-1024)')
    p_scan.add_argument('--output', default='reports', help='Output folder for reports')
    p_scan.add_argument('--pynmap', action='store_true', help='Use python-nmap if installed instead of subprocess nmap')
    p_scan.set_defaults(func=cmd_scan)

    args = parser.parse_args()
    if not hasattr(args, 'func'):
        parser.print_help()
        return
    args.func(args)

if __name__ == '__main__':
    main()
