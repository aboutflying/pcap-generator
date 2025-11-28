# PCAP Generator

A Node.js application for capturing network packets and exporting them to CSV format.

## Features

- Capture network packets from any network interface
- Support for multiple protocols (TCP, UDP, ICMP, ARP, IPv4, IPv6)
- Export captured packets to CSV format
- BPF (Berkeley Packet Filter) support for filtering packets
- Command-line interface with various options
- Real-time packet display in console
- Configurable packet capture limit

## Prerequisites

- Node.js (v12 or higher)
- npm
- libpcap (packet capture library)

### Installing libpcap

**Ubuntu/Debian:**
```bash
sudo apt-get install libpcap-dev
```

**macOS:**
```bash
brew install libpcap
```

**CentOS/RHEL:**
```bash
sudo yum install libpcap-devel
```

## Installation

1. Clone or download this repository
2. Install dependencies:

```bash
npm install
```

## Usage

The application requires root/administrator privileges to capture network packets.

### Basic Usage

Capture packets on the default network interface:

```bash
sudo node index.js
```

### Command Line Options

- `-i, --interface <name>` - Specify network interface to capture on
- `-f, --filter <filter>` - Apply BPF filter (e.g., "tcp port 80")
- `-o, --output <file>` - Specify output CSV file (default: packets.csv)
- `-n, --count <number>` - Number of packets to capture (default: unlimited)
- `-h, --help` - Show help message

### Examples

**Capture 100 packets on eth0:**
```bash
sudo node index.js -i eth0 -n 100
```

**Capture only HTTPS traffic:**
```bash
sudo node index.js -f "tcp port 443" -o https_packets.csv
```

**Capture traffic from a specific host:**
```bash
sudo node index.js -f "host 192.168.1.1" -n 50
```

**Capture only TCP traffic:**
```bash
sudo node index.js -f "tcp"
```

**Capture HTTP traffic on port 80:**
```bash
sudo node index.js -f "tcp port 80" -o http_traffic.csv
```

## BPF Filter Examples

BPF (Berkeley Packet Filter) allows you to filter packets based on various criteria:

- `tcp` - Capture only TCP packets
- `udp` - Capture only UDP packets
- `icmp` - Capture only ICMP packets
- `port 80` - Capture packets on port 80
- `host 192.168.1.1` - Capture packets to/from specific IP
- `net 192.168.0.0/24` - Capture packets in a subnet
- `tcp and port 443` - Capture TCP packets on port 443
- `not port 22` - Exclude SSH traffic

## CSV Output Format

The application exports packets to CSV with the following columns:

| Column | Description |
|--------|-------------|
| Timestamp | ISO 8601 timestamp of packet capture |
| Protocol | Protocol type (TCP, UDP, ICMP, ARP, etc.) |
| Source IP | Source IP address |
| Source Port | Source port number (if applicable) |
| Destination IP | Destination IP address |
| Destination Port | Destination port number (if applicable) |
| Length | Total packet length in bytes |
| Info | Additional packet information |

### Example CSV Output

```csv
Timestamp,Protocol,Source IP,Source Port,Destination IP,Destination Port,Length,Info
2025-11-28T10:30:45.123Z,TCP,192.168.1.100,52341,172.217.14.206,443,66,Flags: SYN
2025-11-28T10:30:45.156Z,TCP,172.217.14.206,443,192.168.1.100,52341,66,Flags: SYN,ACK
2025-11-28T10:30:45.157Z,TCP,192.168.1.100,52341,172.217.14.206,443,54,Flags: ACK
```

## Stopping Capture

Press `Ctrl+C` to stop capturing packets. The application will gracefully close the CSV file and display statistics.

## Troubleshooting

### Permission Denied Error

If you get a "Permission denied" error, make sure you're running the application with sudo:

```bash
sudo node index.js
```

### No Interfaces Found

Make sure libpcap is properly installed on your system and that you have network interfaces available.

### Module Not Found

If you get module errors, make sure you've installed dependencies:

```bash
npm install
```

## Programmatic Usage

You can also use this as a module in your own Node.js applications:

```javascript
const PacketCapture = require('./index.js');

const capture = new PacketCapture({
  interface: 'eth0',
  filter: 'tcp port 80',
  outputFile: 'my_capture.csv',
  maxPackets: 100
});

capture.start();
```

## Security Considerations

- This application requires elevated privileges to capture network packets
- Be aware of privacy and legal implications when capturing network traffic
- Only capture traffic on networks you own or have permission to monitor
- Captured data may contain sensitive information

## License

MIT
