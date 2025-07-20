from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        proto_num = ip_layer.proto
        proto_name = {
            6: "TCP",
            17: "UDP",
            1: "ICMP"
        }.get(proto_num, str(proto_num))

        print(f"\n[+] Packet:")
        print(f"    Source IP      : {ip_layer.src}")
        print(f"    Destination IP : {ip_layer.dst}")
        print(f"    Protocol       : {proto_name}")

        # Check for payload
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            try:
                payload_str = payload.decode('utf-8', errors='replace')
            except:
                payload_str = str(payload)
            print(f"    Payload        : {payload_str[:100]}")  # Print first 100 chars of payload
        else:
            print("    Payload        : <No Payload>")

# Start sniffing
sniff(prn=packet_callback, count=10)
