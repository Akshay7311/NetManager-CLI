from prettytable import PrettyTable
from .utils import get_local_network

def scan_ip_mac():
    from scapy.all import ARP, Ether, srp
    network = get_local_network()
    print(f"\U0001F50E Scanning network: {network} ...\n")
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=2, verbose=0)[0]
    table = PrettyTable(["IP Address", "MAC Address"])
    for sent, received in result:
        table.add_row([received.psrc, received.hwsrc])
    print(table)

def scan_rdp():
    import nmap
    from .utils import get_local_network
    network = get_local_network()
    print(f"\U0001F50E Scanning network: {network} for RDP (port 3389) ...\n")
    nm = nmap.PortScanner()
    scan_result = nm.scan(hosts=network, arguments='-p 3389 --open')
    table = PrettyTable(["IP Address", "RDP"])
    for host in nm.all_hosts():
        state = nm[host]['tcp'][3389]['state'] if 3389 in nm[host].get('tcp', {}) else 'closed'
        table.add_row([host, 'OPEN' if state == 'open' else 'CLOSED'])
    print(table)

def scan_all():
    import nmap
    from scapy.all import ARP, Ether, srp
    from .utils import get_local_network
    network = get_local_network()
    print(f"\U0001F50E Scanning network: {network} ...\n")
    # ARP scan for IP/MAC
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=2, verbose=0)[0]
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    # Nmap scan for open ports and RDP
    nm = nmap.PortScanner()
    scan_result = nm.scan(hosts=network, arguments='-p 22,80,3389 --open')
    table = PrettyTable(["IP Address", "MAC Address", "Uptime", "Open Ports", "RDP"])
    for device in devices:
        ip = device['ip']
        mac = device['mac']
        host_info = nm[ip] if ip in nm.all_hosts() else {}
        # Uptime (if available)
        uptime = host_info.get('uptime', {}).get('lastboot', 'Unknown')
        # Open ports
        open_ports = []
        for port in [22, 80, 3389]:
            if 'tcp' in host_info and port in host_info['tcp'] and host_info['tcp'][port]['state'] == 'open':
                open_ports.append(port)
        # RDP status
        rdp_status = 'OPEN' if 3389 in open_ports else 'CLOSED'
        open_ports_str = ', '.join(str(p) for p in open_ports)
        table.add_row([ip, mac, uptime, open_ports_str, rdp_status])
    print(table) 