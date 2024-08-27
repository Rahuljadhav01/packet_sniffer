Here's a detailed README section for your GitHub repository featuring the Network Packet Analyzer project:

---

# Network Packet Analyzer

**A Python-based tool for capturing and analyzing network packets in real-time. Developed as part of an internship at Prodigy Infotech.**

## Introduction

The **Network Packet Analyzer** is a tool designed to capture and analyze network packets in real-time. Developed using Python and the Scapy library, this tool provides insights into network traffic by displaying source and destination IP addresses, protocol types, and payload data. This project was created as part of my internship at **Prodigy Infotech** with a focus on educational use.

## Features

- **Real-Time Packet Capture**: Monitor network traffic as it happens.
- **Protocol Identification**: Automatically identifies common protocols such as TCP, UDP, and ICMP.
- **Payload Analysis**: Extract and decode payload data from TCP and UDP packets.
- **Modular Design**: Easily extend the tool to support additional protocols or features.

## Installation

To get started with the Network Packet Analyzer, follow these steps:

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/network-packet-analyzer.git
   cd network-packet-analyzer
   ```

2. **Install Dependencies**:
   Ensure you have Python 3.x installed, then install the required Python packages using pip:
   ```bash
   pip install -r requirements.txt
   ```

   Alternatively, if `requirements.txt` is not available, manually install the `scapy` library:
   ```bash
   pip install scapy
   ```

## Usage

### Running the Packet Sniffer

To run the packet sniffer, execute the following command with appropriate permissions (root or administrator):

```bash
sudo python3 packet_sniffer.py
```

This will start capturing and analyzing packets on the network.

### Sample Output

```plaintext
Source: 192.168.1.2 -> Destination: 192.168.1.10 | Protocol: TCP
Payload: GET / HTTP/1.1

--------------------------------------------------
Source: 192.168.1.5 -> Destination: 192.168.1.3 | Protocol: ICMP
--------------------------------------------------
Source: 192.168.1.7 -> Destination: 192.168.1.8 | Protocol: UDP
Payload: \x15\x00\x03...
--------------------------------------------------
```


### Dependencies

- **Python 3.x**
- **Scapy**: A powerful Python library for packet manipulation.

### Packet Callback Function

The core of the tool is the `packet_callback` function, which is invoked for each captured packet. It extracts and prints relevant information, including source and destination IPs, protocol type, and payload data.

Here’s a simplified version of the function:

```python
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        # Determine protocol name
        ...
        # Display packet information
        print(f"Source: {ip_src} -> Destination: {ip_dst} | Protocol: {protocol_name}")
        ...
```

## Ethical Considerations

This tool is intended strictly for educational purposes. **Do not use it on networks without explicit permission**. As a responsible cybersecurity professional, always ensure that your use of this tool aligns with legal and ethical standards.

## Future Enhancements

Planned improvements for the Network Packet Analyzer include:

- **Support for Additional Protocols**: Extend protocol recognition to include HTTP, DNS, etc.
- **GUI Implementation**: Create a user-friendly graphical interface.
- **Packet Filtering**: Implement filters to capture specific packet types or traffic from specific IP addresses.
- **Logging**: Enable logging of captured packets to a file for later analysis.

## Contributing

Contributions are welcome! If you have suggestions, feature requests, or bug reports, please open an issue or submit a pull request. Let’s collaborate to make this tool even better.


## Acknowledgments

- **Prodigy Infotech**: For providing the opportunity and guidance to develop this tool during my internship.
- **Scapy Community**: For their excellent documentation and support.

- # CODE -
- from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        if protocol == 6:  # TCP
            protocol_name = "TCP"
        elif protocol == 17:  # UDP
            protocol_name = "UDP"
        elif protocol == 1:  # ICMP
            protocol_name = "ICMP"
        else:
            protocol_name = str(protocol)
        
        print(f"Source: {ip_src} -> Destination: {ip_dst} | Protocol: {protocol_name}")
        
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = bytes(packet[TCP].payload) if packet.haslayer(TCP) else bytes(packet[UDP].payload)
            print(f"Payload: {payload.decode('utf-8', errors='replace')}")
        print("-" * 50)

# Sniff packets on the network
sniff(prn=packet_callback, store=0)



