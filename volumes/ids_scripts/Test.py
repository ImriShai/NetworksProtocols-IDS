# This unit test is used to test the IDS in main.py
# The test is done by generating .PCAP files with different types of attacks
# and then running the IDS on the attack as reqested by the user
# The IDS will then output the results of the analysis


from scapy.all import *
import base64
import random
import os


# Function to create a DNS query with "leaked information"
def create_dns_tunnel_packet(secret_data, domain):
    # Encode the information in Base32 to simulate tunneling communication
    encoded_data = base64.b32encode(secret_data.encode()).decode()
    
    # Split the encoded data into smaller chunks and add them as subdomains
    subdomains = [encoded_data[i:i+63] for i in range(0, len(encoded_data), 63)]  # Subdomains up to 63 characters each
    query_name = ".".join(subdomains) + "." + domain

    # Create the DNS packet
    dns_query = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname=query_name, qtype="A"))
    return dns_query

# Function to create multiple DNS packets with encoded data
def create_dns_tunnel_traffic(num_packets, secret_message, domain):
    packets = []
    for i in range(num_packets):
        # Create a sample "data chunk" for each packet
        data_chunk = secret_message + str(i)
        packet = create_dns_tunnel_packet(data_chunk, domain)
        ethernet_packet = Ether()/packet
        packets.append(ethernet_packet)
    # Save the packets to a PCAP file
    wrpcap("../user_pcaps/dns_tunnel_exfiltration.pcap", packets)
    print("PCAP file created with DNS tunneling traffic.")
    
def create_icmp_tunnel_packet(secret_data):
    # Encode the information in Base32 to simulate tunneling communication
    encoded_data = base64.b32encode(secret_data.encode()).decode()
    
    # Create the ICMP packet
    icmp_packet = IP(dst="8.8.8.8")/ICMP()/(encoded_data)
    return icmp_packet

def create_icmp_tunnel_traffic(num_packets, secret_message):
    packets = []
    for i in range(num_packets):
        # Create a sample "data chunk" for each packet
        data_chunk = secret_message + str(i)
        packet = create_icmp_tunnel_packet(data_chunk)
        ethernet_packet = Ether()/packet
        packets.append(ethernet_packet)
    # Save the packets to a PCAP file
    wrpcap("../user_pcaps/icmp_tunnel_exfiltration.pcap", packets)
    print("PCAP file created with ICMP tunneling traffic.")
                     

def create_unauthorized_port_access_packet(port):
    # Create a packet with an unauthorized port access
    packet = IP(dst=f"{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}")/TCP(dport=port) # Destination port is unauthorized, ip address is random
    return packet
def create_unauthorized_port_access_traffic(num_packets, port):
    packets = []
    for i in range(num_packets):
        packet = create_unauthorized_port_access_packet(port)
        ethernet_packet = Ether()/packet
        packets.append(ethernet_packet)
    # Save the packets to a PCAP file
    wrpcap("../user_pcaps/unauthorized_port_access.pcap", packets)
    print("PCAP file created with unauthorized port access.")
    
def create_after_buisness_hours_packet():
    # Create a packet that is sent after buisness hours
    packet = IP(dst=f"{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}")/TCP(dport=80) # Destination port is HTTP, ip address is random
    packet.time = 1610000000 + random.randint(0, 86400)  # Set the packet time to be after buisness hours
    return packet
def create_after_buisness_hours_traffic(num_packets):
    packets = []
    for i in range(num_packets):
        packet = create_after_buisness_hours_packet()
        ethernet_packet = Ether()/packet
        packets.append(ethernet_packet)
    # Save the packets to a PCAP file
    wrpcap("../user_pcaps/after_buisness_hours.pcap", packets)
    print("PCAP file created with traffic sent after buisness hours.")
   
    
def create_large_data_transfer_packet():
    # Create a packet with a large data transfer
    packet = IP(dst=f"10.24.53.63")/TCP(dport=80) # Destination port is HTTP, ip address is an outside IP
    packet.add_payload(b"X"*60000)  # Add a large payload of 1MB
    return packet

def create_large_data_transfer_traffic(num_packets):
    packets = []
    for i in range(num_packets):
        packet = create_large_data_transfer_packet()
        ethernet_packet = Ether()/packet
        packets.append(ethernet_packet)
    # Save the packets to a PCAP file
    wrpcap("../user_pcaps/large_data_transfer.pcap", packets)
    print("PCAP file created with large data transfer.")
    

def create_suspicious_traffic_packet():
    # Create a packet with suspicious traffic
    packet = IP(dst=f"10.0.0.1")/TCP(dport=80) # Destination port is HTTP, ip address is a known malicious IP
    return packet

def create_suspicious_traffic_traffic(num_packets):
    packets = []
    for i in range(num_packets):
        packet = create_suspicious_traffic_packet()
        ethernet_packet = Ether()/packet
        packets.append(ethernet_packet)
    # Save the packets to a PCAP file
    wrpcap("../user_pcaps/suspicious_traffic.pcap", packets)
    print("PCAP file created with suspicious traffic.")


def create_unauthorized_file_transfer_packet():
    # Create a packet with unauthorized file transfer
    packet = IP(dst=f"{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}")/TCP(dport= 21) # Destination port is FTP, ip address is random
    return packet

def create_unauthorized_file_transfer_traffic(num_packets):
    packets = []
    for i in range(num_packets):
        packet = create_unauthorized_file_transfer_packet()
        ethernet_packet = Ether()/packet
        packets.append(ethernet_packet)
    # Save the packets to a PCAP file
    wrpcap("../user_pcaps/unauthorized_file_transfer.pcap", packets)
    print("PCAP file created with unauthorized file transfer.")
    
def create_unusual_traffic_packet():
    # Create a packet with unusual traffic
    packet = IP(dst=f"{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}")/TCP(dport=random.choice([0, 1, 7, 19, 22, 23, 25, 80, 443, 8080])) # Destination port is randomly chosen from a list of common and uncommon ports
    packet.add_payload(b"UNUSUAL_TRAFFIC" * random.randint(1, 100))  # Add a payload with repeated unusual traffic pattern
    packet[TCP].flags = "U"  # Set unusual TCP flags (FIN, PUSH, URG)
    return packet

def create_unusual_traffic_traffic(num_packets):
    packets = []
    for i in range(num_packets):
        packet = create_unusual_traffic_packet()
        ethernet_packet = Ether()/packet
        packets.append(ethernet_packet)
    # Save the packets to a PCAP file
    wrpcap("../user_pcaps/unusual_traffic.pcap", packets)
    print("PCAP file created with unusual traffic.")
    
def create_unusual_user_activity_packet():
    # Create a packet with unusual user activity
    packet = IP(dst=f"{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}")/TCP(dport=80) # Destination port is HTTP, ip address is random
    packet.add_payload(b"UNUSUAL_USER_ACTIVITY" * random.randint(1, 100))  # Add a payload with repeated unusual user activity pattern
    return packet
def create_unusual_user_activity_traffic(num_packets):
    packets = []
    for i in range(num_packets):
        packet = create_unusual_user_activity_packet()
        ethernet_packet = Ether()/packet
        packets.append(ethernet_packet)
    # Save the packets to a PCAP file
    wrpcap("../user_pcaps/unusual_user_activity.pcap", packets)
    print("PCAP file created with unusual user activity.")




if __name__ == '__main__':
    
    type = input("Enter the type of alerts you want to test: \n 1. DNS Tunneling \n 2. ICMP tunneling \n 3. Ports Exploiting(e.g using unautherized ports) \n 4. After buisness hours \n 5. Large data transfer \n 6. Suspicious Traffic \n 7. Unauthorized File Transfer \n 8. Unusual Traffic \n 9. Unusual User Activity \n 11. All of the above \n") 
    type = int(type)
    if type not in [1,2,3,4,5,6,7,8,9,11]:
        print("Invalid input")
        exit()
    else:
        os.makedirs("../user_pcaps", exist_ok=True)
    if type == 1:
        print("DNS Tunneling")
        # Create a PCAP file with DNS tunneling traffic
        create_dns_tunnel_traffic(10, "This sensitive data is being exfiltrated", "example.com")
    elif type == 2:
        print("ICMP Tunneling")
        create_icmp_tunnel_traffic(10, "This sensitive data is being exfiltrated using ICMP")
    elif type == 3:
        print("Ports Exploiting") # Create a PCAP file with unauthorized port access
        create_unauthorized_port_access_traffic(10, 9999)
    elif type == 4:
        print("After buisness hours")
        create_after_buisness_hours_traffic(10)
    elif type == 5:
        print("Large data transfer")
        create_large_data_transfer_traffic(10)

    elif type == 6:
        print("Suspicious Traffic")
        create_suspicious_traffic_traffic(10)
    elif type == 7:
        print("Unauthorized File Transfer")
        create_unauthorized_file_transfer_traffic(10)
    elif type == 8:
        print("Unusual Traffic")
        create_unusual_traffic_traffic(100)
    elif type == 9:
        print("Unusual User Activity")
        create_unusual_user_activity_traffic(1000)
        
    elif type == 11:
        print("All of the above")
        create_dns_tunnel_traffic(10, "This sensitive data is being exfiltrated", "example.com")
        create_icmp_tunnel_traffic(10, "This sensitive data is being exfiltrated using ICMP")
        create_unauthorized_port_access_traffic(10, 9999)
        create_after_buisness_hours_traffic(10)
        create_large_data_transfer_traffic(10)
        create_suspicious_traffic_traffic(10)
        create_unauthorized_file_transfer_traffic(10)
        create_unusual_traffic_traffic(100)
        create_unusual_user_activity_traffic(1000)
    print("All PCAP files created successfully.")
                 
    
    
    
  