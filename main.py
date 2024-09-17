from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSRR
from collections import defaultdict
from threading import Thread, Event
import argparse
import time
from colorama import Fore, Style, init

# TODO: general explanation of the script and implementation details

# Initialize colorama
init()

# Global dictionaries to store flow statistics and DNS resolutions
flow_statistics = defaultdict(lambda: {"packets": 0, "bytes": 0, "protocol": None})
AUTHORIZED_IPS = set()  # Store DNS responses to detect outbound flows without a prior DNS response (not just that)
alerts = []
stop_event = Event()

VOLUME_THRESHOLD = 500000  # Threshold for total bytes in a flow (0.5 MB)
AUTHORIZED_OUTBOUND_PORTS = {80, 443, 53}
AUTHORIZED_INBOUND_PORTS = {22, 80}  # SSH(22) and HTTP(80)
AUTHORIZED_PROTOCOLS = {6, 17}  # TCP(6) and UDP(17)
UNAUTHORIZED_IPS = {"192.168.1.100", "10.0.0.1"}  # Unauthorized IPs (here for example)
INTERNAL_IP_RANGE = None

def check_header(packet, port, protocol_name):
    if protocol_name == 'HTTP' and (port == 80 or port == 443):
        if packet.haslayer(TCP) and packet[TCP].dport in {80, 443}:
            tcp_header_length = packet[TCP].dataofs * 4
            if len(packet[TCP].payload) + tcp_header_length != len(packet):
                return False
            return True
    elif protocol_name == 'HTTPS' and port == 443:
        if packet.haslayer(TCP) and packet[TCP].dport == 443:
            tcp_header_length = packet[TCP].dataofs * 4
            if len(packet[TCP].payload) + tcp_header_length != len(packet):
                return False
            return True
    elif protocol_name == 'FTP' and port == 21:
        if packet.haslayer(TCP) and packet[TCP].dport == 21:
            tcp_header_length = packet[TCP].dataofs * 4
            if len(packet[TCP].payload) + tcp_header_length != len(packet):
                return False
            return True
    elif protocol_name == 'SMTP' and port == 25:
        if packet.haslayer(TCP) and packet[TCP].dport == 25:
            tcp_header_length = packet[TCP].dataofs * 4
            if len(packet[TCP].payload) + tcp_header_length != len(packet):
                return False
            return True
    elif protocol_name == 'SSH' and port == 22:
        if packet.haslayer(TCP) and packet[TCP].dport == 22:
            tcp_header_length = packet[TCP].dataofs * 4
            if len(packet[TCP].payload) + tcp_header_length != len(packet):
                return False
            return True
    elif protocol_name == 'DNS' and port == 53:
        if packet.haslayer(UDP) and packet[UDP].dport == 53:
            return True
    return False

def packet_callback(packet):
    global flow_statistics, AUTHORIZED_IPS, alerts

    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        port_src = packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport
        port_dst = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
        protocol = packet[IP].proto
        protocol_name = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            47: 'GRE',
            50: 'ESP',
            51: 'AH',
            89: 'OSPF',
            132: 'SCTP',
        }.get(protocol, 'Other')

        if protocol == 6:  # TCP protocol
            if port_dst == 22 or port_src == 22:
                protocol_name = 'SSH'
            elif port_dst == 21 or port_src == 21:
                protocol_name = 'FTP'
            elif port_dst == 25 or port_src == 25:
                protocol_name = 'SMTP'
            elif port_dst == 80 or port_src == 80:
                protocol_name = 'HTTP'
            elif port_dst == 443 or port_src == 443:
                protocol_name = 'HTTPS'

        if protocol == 17:
            if port_dst == 53 or port_src == 53:
                protocol_name = 'DNS'

        flow_id = (ip_src, port_src, ip_dst, port_dst, protocol_name)

        stats = flow_statistics[flow_id]
        stats["packets"] += 1
        stats["bytes"] += len(packet)
        stats["protocol"] = protocol_name

        # Check if the header corresponds to the expected protocol
        if not check_header(packet, port_dst, protocol_name):
            alerts.append(f"{Fore.RED}ALERT: Packet header does not match expected protocol for flow {flow_id}{Style.RESET_ALL}")

        if ip_src.startswith(INTERNAL_IP_RANGE) and not ip_dst.startswith(INTERNAL_IP_RANGE):
            if ip_dst in UNAUTHORIZED_IPS:
                alerts.append(f"{Fore.RED}ALERT: Outbound flow to unauthorized IP {ip_dst} - Flow: {flow_id}{Style.RESET_ALL}")

            if port_src not in AUTHORIZED_OUTBOUND_PORTS:
                alerts.append(f"{Fore.RED}ALERT: Outbound flow to unauthorized port {port_src} - Flow: {flow_id}{Style.RESET_ALL}")

            if protocol not in AUTHORIZED_PROTOCOLS:
                alerts.append(f"{Fore.RED}ALERT: Outbound flow using unauthorized protocol {protocol_name} - Flow: {flow_id}{Style.RESET_ALL}")

            if ip_dst not in AUTHORIZED_IPS:
                alerts.append(f"{Fore.RED}ALERT: Outbound flow to {ip_dst} without prior DNS response - Flow: {flow_id}{Style.RESET_ALL}")

            if stats["bytes"] > VOLUME_THRESHOLD:
                alerts.append(f"{Fore.RED}ALERT: High volume detected in outbound flow {flow_id} - Byte Count: {stats['bytes']}{Style.RESET_ALL}")

        else:
            if packet.haslayer(DNS) and packet.haslayer(DNSRR):
                AUTHORIZED_IPS.add(packet[DNSRR].rdata)
                return

            if port_dst not in AUTHORIZED_INBOUND_PORTS:
                alerts.append(f"{Fore.YELLOW}ALERT: Inbound flow to unauthorized port {port_dst} - Flow: {flow_id}{Style.RESET_ALL}")

def start_sniffing(interface):
    sniff(iface=interface, prn=packet_callback, store=0, stop_filter=lambda x: stop_event.is_set())

def print_flow_statistics():
    stats_lines = []
    protocol_count = defaultdict(int)
    for flow, stats in flow_statistics.items():
        line = f"Flow: {flow} - Packet Count: {stats['packets']} - Byte Count: {stats['bytes']} - Protocol: {stats['protocol']}"
        protocol_count[stats['protocol']] += stats['packets']
        stats_lines.append(line)
    for protocol, count in protocol_count.items():
        print(f"{Fore.GREEN}Protocol {protocol} - Number of Packets: {count}{Style.RESET_ALL}")
    return stats_lines

def save_statistics_to_file(filename, stats_lines, alert_lines):
    with open(filename, 'w') as file:
        for line in stats_lines:
            file.write(line + '\n')
        file.write("\nAlerts:\n")
        for alert in alert_lines:
            file.write(alert + '\n')

def main():
    parser = argparse.ArgumentParser(description="Network Traffic Monitor")
    parser.add_argument('--internal-ip-prefix', required=True, help="The prefix of the internal IP range")
    parser.add_argument('--output-file', default="final_statistics.txt", help="The file to save statistics and alerts")

    args = parser.parse_args()
    global INTERNAL_IP_RANGE
    INTERNAL_IP_RANGE = args.internal_ip_prefix
    filename = args.output_file
    interface = "\\Device\\NPF_{7678787C-EFDE-4A68-AC99-5C35A30AE6B9}"  # Define network interface

    sniff_thread = Thread(target=start_sniffing, args=(interface,))
    sniff_thread.start()

    try:
        while not stop_event.is_set():
            time.sleep(10)  # Every 10 seconds, print the statistics and check for alerts
            print_flow_statistics()
            for alert in alerts:
                print(alert)
            alerts.clear()
    except KeyboardInterrupt:
        print("KeyboardInterrupt received, stopping capture...")
    finally:
        stop_event.set()
        sniff_thread.join()
        stats_lines = print_flow_statistics()
        save_statistics_to_file(filename, stats_lines, alerts)
        print(f"Final statistics saved to {filename} \nExiting...")

if __name__ == "__main__":
    main()
