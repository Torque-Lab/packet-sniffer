# C++ Packet Sniffer

A modular, object-oriented packet sniffer implementation in C++ using libpcap for Linux. This tool captures and analyzes network traffic, displaying detailed information about each packet's headers and payload according to the TCP/IP protocol stack.

## Features

- **Modular Design**: Clean separation of concerns with dedicated classes for each protocol layer
- **Comprehensive Protocol Support**:
  - Ethernet (Layer 2)
  - IPv4 (Layer 3)
  - TCP, UDP, and ICMP (Layer 4)
- **Flexible Filtering**:
  - BPF (Berkeley Packet Filter) expressions
  - Protocol-specific filters (TCP/UDP/ICMP)
  - Port-based filtering
  - Source/Destination IP filtering
- **Detailed Output**:
  - Human-readable header fields
  - Hex/ASCII payload dumps
  - Packet statistics
- **Cross-Platform**: Linux support (libpcap)

## Prerequisites

- Linux operating system
- CMake 3.10 or higher
- C++17 compatible compiler (GCC 8+, Clang 7+)
- libpcap development libraries

### Installing Dependencies

On Debian/Ubuntu:
```bash
sudo apt update
sudo apt install -y build-essential cmake libpcap-dev
```

On RHEL/CentOS:
```bash
sudo yum groupinstall -y "Development Tools"
sudo yum install -y cmake3 libpcap-devel
```

## Building

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/packet-sniffer.git
   cd packet-sniffer
   ```

2. Create a build directory and run CMake:
   ```bash
   mkdir build && cd build
   cmake ..
   ```

3. Build the project:
   ```bash
   make
   ```

4. (Optional) Install system-wide:
   ```bash
   sudo make install
   ```

## Usage

### Basic Usage

```bash
# Run with default settings (requires root privileges)
sudo ./packet_sniffer

# Capture on a specific interface
sudo ./packet_sniffer -i eth0

# Use a BPF filter expression
sudo ./packet_sniffer -i eth0 'tcp port 80'
```

### Command Line Options

```
Usage: packet_sniffer [options] [filter]

Options:
  -i <interface>  Network interface to capture on (default: auto-detect)
  -f <filter>     BPF filter expression (e.g., 'tcp port 80')
  -p <ports>      Comma-separated list of ports to filter (e.g., '80,443,8080')
  -s <ip>         Filter by source IP address
  -d <ip>         Filter by destination IP address
  -t              Toggle TCP packets (default: on)
  -u              Toggle UDP packets (default: on)
  -c              Toggle ICMP packets (default: on)
  -e              Toggle Ethernet frames (default: off)
  -v              Enable verbose output
  -h              Show this help message
```

### Examples

```bash
# Capture only HTTP and HTTPS traffic
sudo ./packet_sniffer -p 80,443

# Capture traffic between specific hosts
sudo ./packet_sniffer -s 192.168.1.100 -d 8.8.8.8

# Show only Ethernet frames (no IP)
sudo ./packet_sniffer -e -tuc

# Combine filters
sudo ./packet_sniffer -i eth0 'tcp port 80' -s 192.168.1.100
```

## Output Format

The sniffer displays detailed information about each captured packet, including:

1. **Packet Metadata**: Timestamp, length, and capture interface
2. **Ethernet Header**: Source/destination MAC addresses, EtherType
3. **IP Header**: Source/destination IPs, protocol, TTL, etc.
4. **Transport Layer**:
   - **TCP**: Ports, sequence numbers, flags, window size
   - **UDP**: Source/destination ports, length, checksum
   - **ICMP**: Type, code, checksum, and other ICMP-specific fields
5. **Payload**: Hex and ASCII representation of packet data

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request
