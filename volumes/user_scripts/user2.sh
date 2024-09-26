#!/bin/bash

# Use dig to query www.google.com
dig www.google.com

# Use TCP Replay to replay the traffic from the file dns_tunnel_exfiltration.pcap
tcpreplay -i eth0 ../user_pcaps/dns_tunnel_exfiltration.pcap

