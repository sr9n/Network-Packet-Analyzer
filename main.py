from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        print(f"[+] New Packet: {ip_layer.src} -> {ip_layer.dst}")
        
        if packet.haslayer(TCP):
            print(f"    Protocol: TCP | Port: {packet.sport} -> {packet.dport}")
        elif packet.haslayer(UDP):
            print(f"    Protocol: UDP | Port: {packet.sport} -> {packet.dport}")

def main():
    print("--- SR9N Network Sniffer Starting ---")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
