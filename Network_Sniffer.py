import threading
import os
from scapy.all import sniff, Ether, IP, TCP, UDP, wrpcap, rdpcap

capture_running = True
packet_index = 0
packets = []

def packet_callback(packet):
    global packet_index
    packet_index += 1

    # Check if the packet has an Ethernet layer
    if Ether in packet:
        ether_layer = packet[Ether]
        src_mac = ether_layer.src
        dst_mac = ether_layer.dst
    else:
        src_mac = dst_mac = None
    
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
    else:
        src_ip = dst_ip = None
    
    # Check if the packet has a TCP or UDP layer
    if TCP in packet:
        proto_layer = packet[TCP]
        proto = 'TCP'
    elif UDP in packet:
        proto_layer = packet[UDP]
        proto = 'UDP'
    else:
        proto_layer = None
        proto = 'Other'
    
    if proto_layer:
        src_port = proto_layer.sport
        dst_port = proto_layer.dport
    else:
        src_port = dst_port = None

    packets.append(packet)
    print(f"Packet Index: {packet_index}, Src MAC: {src_mac}, Dst MAC: {dst_mac}, Src IP: {src_ip}, Dst IP: {dst_ip}, Proto: {proto}, Src Port: {src_port}, Dst Port: {dst_port}")

def capture_packets():
    global capture_running
    sniff(prn=packet_callback, store=0, stop_filter=lambda x: not capture_running)

def monitor_input():
    global capture_running
    while True:
        user_input = input()
        if user_input.upper() == 'Z':
            capture_running = False
            print("Stopping packet capture...")
            break

def save_packets_to_file(filename):
    wrpcap(filename, packets)
    print(f"Packets saved to {filename}")

def read_packets_from_file(filename):
    global packet_index, packets
    packets = rdpcap(filename)
    packet_index = len(packets)
    for i, packet in enumerate(packets):
        packet_callback(packet)
    print(f"Packets read from {filename}")

def analyze_packet(index):
    if index < 1 or index > len(packets):
        print("Invalid packet index.")
        return
    
    packet = packets[index - 1]

    # Check if the packet has an Ethernet layer
    if Ether in packet:
        ether_layer = packet[Ether]
        src_mac = ether_layer.src
        dst_mac = ether_layer.dst
    else:
        src_mac = dst_mac = None
    
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
    else:
        src_ip = dst_ip = None
    
    # Check if the packet has a TCP or UDP layer
    if TCP in packet:
        proto_layer = packet[TCP]
        proto = 'TCP'
    elif UDP in packet:
        proto_layer = packet[UDP]
        proto = 'UDP'
    else:
        proto_layer = None
        proto = 'Other'
    
    if proto_layer:
        src_port = proto_layer.sport
        dst_port = proto_layer.dport
    else:
        src_port = dst_port = None

    print(f"Analyzed Packet Index: {index}, Src MAC: {src_mac}, Dst MAC: {dst_mac}, Src IP: {src_ip}, Dst IP: {dst_ip}, Proto: {proto}, Src Port: {src_port}, Dst Port: {dst_port}")

def menu():
    while True:
        print("============================================================================")
        print("><><><><><><><><><><><><><>| K-NETWORK SNIFFER |<><><><><><><><><><><><><><>")
        print("============================================================================")
        print("============================================================================")
        print("1. Capture traffic")
        print("2. Save traffic to file")
        print("3. Read traffic from file")
        print("4. Analyze packet by index")
        print("5. Exit")
        
        choice = input("Enter your choice: ")
        
        if choice == '1':
            global capture_running, packet_index, packets
            capture_running = True
            packet_index = 0
            packets = []
            capture_thread = threading.Thread(target=capture_packets)
            capture_thread.start()
            print("Capturing traffic... Press 'Z' to stop.")
            monitor_input()
            capture_thread.join()
            print("Packet capture stopped.")
        elif choice == '2':
            filename = input("Enter filename to save traffic (with .pcap extension): ")
            save_packets_to_file(filename)
        elif choice == '3':
            filename = input("Enter filename to read traffic (with .pcap extension): ")
            if os.path.isfile(filename):
                read_packets_from_file(filename)
            else:
                print(f"File {filename} does not exist.")
        elif choice == '4':
            index = int(input("Enter packet index to analyze: "))
            analyze_packet(index)
        elif choice == '5':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    menu()
