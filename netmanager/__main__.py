import argparse
from .scanner import scan_ip_mac, scan_rdp, scan_all

def main():
    import sys
    parser = argparse.ArgumentParser(description='NetManager CLI Tool')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--ip', action='store_true', help='Show IP and MAC addresses of devices in the LAN')
    group.add_argument('--rdp', action='store_true', help='Scan devices for RDP (port 3389) status')
    group.add_argument('--all', action='store_true', help='Full network scan: IP, MAC, uptime, open ports, RDP status')
    args = parser.parse_args()
    try:
        if args.ip:
            scan_ip_mac()
        elif args.rdp:
            scan_rdp()
        elif args.all:
            scan_all()
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main() 