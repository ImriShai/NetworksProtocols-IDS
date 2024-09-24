# This unit test is used to test the IDS in main.py
# The test is done by generating .PCAP files with different types of attacks
# and then running the IDS on the attack as reqested by the user
# The IDS will then output the results of the analysis


from scapy.all import *
import base64
import random
import datetime
import dpkt

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

def create_unauthorized_port_access_packet(port):
    # Create a packet with an unauthorized port access
    packet = IP(dst=f"{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}")/TCP(dport=port) # Destination port is unauthorized, ip address is random
    return packet
def create_unauthorized_port_access_traffic(num_packets, port):
    print("PCAP file created with unauthorized port access.")
    packets = []
    for i in range(num_packets):
        packet = create_unauthorized_port_access_packet(port)
        packets.append(packet)
    # Save the packets to a PCAP file
    wrpcap("unauthorized_port_access.pcap", packets)
    
def create_after_buisness_hours_packet():
    # Create a packet that is sent after buisness hours
    packet = IP(dst=f"{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}")/TCP(dport=80) # Destination port is HTTP, ip address is random
    packet.time = 1610000000 + random.randint(0, 86400)  # Set the packet time to be after buisness hours
    return packet
def create_after_buisness_hours_traffic(num_packets):
    print("PCAP file created with traffic sent after buisness hours.")
    packets = []
    for i in range(num_packets):
        packet = create_after_buisness_hours_packet()
        packets.append(packet)
    packets[0].show()   # Display the packet information
    # Save the packets to a PCAP file
    wrpcap("after_buisness_hours.pcap", packets)
    # Define the target time you want (e.g., 2 AM of a specific date)
    target_time = datetime.datetime(2024, 9, 20, 2, 0, 0)

        # Open the original pcap file for reading
    with open('after_buisness_hours.pcap', 'rb') as f:
        pcap_reader = dpkt.pcap.Reader(f)
        
        # Open the same file for writing to modify timestamps
        with open('after_business_hours_modified.pcap', 'wb') as f_out:
            pcap_writer = dpkt.pcap.Writer(f_out)
            
            # Loop through each packet in the original file
            for i, (timestamp, buf) in enumerate(pcap_reader):
                # Adjust the timestamp to the target time
                # Here, you can increment each packet's timestamp by a small delta if desired
                new_timestamp = target_time.timestamp() + i  # Offset by 1 second per packet

                # Write the packet with the new timestamp to the same file
                pcap_writer.writepkt(buf, ts=new_timestamp)

    print("Timestamps updated in 'after_business_hours_modified.pcap'.")
    
def create_large_data_transfer_packet():
    # Create a packet with a large data transfer
    packet = IP(dst=f"10.24.53.63")/TCP(dport=80) # Destination port is HTTP, ip address is an outside IP
    packet.add_payload(b"X"*60000)  # Add a large payload of 1MB
    return packet

def create_large_data_transfer_traffic(num_packets):
    print("PCAP file created with large data transfer.")
    packets = []
    for i in range(num_packets):
        packet = create_large_data_transfer_packet()
        packets.append(packet)
    # Save the packets to a PCAP file
    wrpcap("large_data_transfer.pcap", packets)





if __name__ == '__main__':
    
    type = input("Enter the type of alerts you want to test: \n 1. DNS Tunneling \n 2. Ports Exploiting(e.g using unautherized ports) \n 3. After buisness hours \n 4. Large data transfer \n 5.Suspicious Traffic \n 6. Unauthorized Access \n 7. Unauthorized File Transfer \n 8. Unauthorized Port Access \n 9. Unusual Traffic \n 10. Unusual User Activity \n 12. All of the above \n") 
    type = int(type)
    if type == 1:
        print("DNS Tunneling")
        # Create a PCAP file with DNS tunneling traffic
        create_dns_tunnel_traffic(10, "This sensitive data is being exfiltrated", "example.com")
    elif type == 2:
        print("Ports Exploiting") # Create a PCAP file with unauthorized port access
        create_unauthorized_port_access_traffic(10, 9999)
    elif type == 3:
        print("After buisness hours")
        create_after_buisness_hours_traffic(10)
        
    elif type == 4:
        print("Large data transfer")
        create_large_data_transfer_traffic(10)
        
    elif type == 5:
        print("Suspicious Traffic")
    elif type == 6:
        print("Unauthorized Access")
    elif type == 7:
        print("Unauthorized File Transfer")
    elif type == 8:
        print("Unauthorized Port Access")
    elif type == 9:
        print("Unusual Traffic")
    elif type == 10:
        print("Unusual User Activity")
    elif type == 11:
        print("All of the above")
                 
    
    
    
  