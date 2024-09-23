# This unit test is used to test the IDS in main.py
# The test is done by generating .PCAP files with different types of attacks
# and then running the IDS on the attack as reqested by the user
# The IDS will then output the results of the analysis


from scapy.all import *
import base64
import random

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
    print("PCAP file created with DNS tunneling traffic.")
    packets = []
    for i in range(num_packets):
        # Create a sample "data chunk" for each packet
        data_chunk = secret_message + str(i)
        packet = create_dns_tunnel_packet(data_chunk, domain)
        packets.append(packet)
    # Save the packets to a PCAP file
    wrpcap("dns_tunnel_exfiltration.pcap", packets)






if __name__ == '__main__':
    # Create a PCAP file with DNS tunneling traffic
    create_dns_tunnel_traffic(10, "This sensitive data is being exfiltrated", "example.com")
    
    
    
  