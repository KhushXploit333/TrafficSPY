from scapy.all import sniff, IP, TCP, UDP

# Function to process each packet
def process_packet(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto
        
        # Display relevant information
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}")

        # Check for TCP or UDP and display payload data if available
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"TCP Payload: {bytes(tcp_layer.payload)}")
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"UDP Payload: {bytes(udp_layer.payload)}")

# Start sniffing packets
def start_sniffing(interface=None):
    print("Starting packet sniffing...")
    sniff(iface=interface, prn=process_packet, store=0)

if __name__ == "__main__":
    # You can specify the network interface to sniff on, e.g., 'eth0', 'wlan0', etc.
    start_sniffing(interface=None)  # Use None to sniff on all interfaces