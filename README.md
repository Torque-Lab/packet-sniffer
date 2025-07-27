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
  - Human-readable string extraction from payloads
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
   git clone https://github.com/Torque-Lab/packet-sniffer.git
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
# Run with default settings (requires Adminstrative privileges)
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
  -t              Toggle TCP packets 
  -u              Toggle UDP packets
  -c              Toggle ICMP packets 
  -e              Toggle Ethernet frames
  -H              Show human-readable strings in payload
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

# Show human-readable strings in HTTP traffic
sudo ./packet_sniffer -H -p 80

# Combine filters with human-readable output
sudo ./packet_sniffer -H -i eth0 'tcp port 80' -s 192.168.1.100
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
5. **Payload**: 
   - Hex and ASCII representation of packet data
   - When using `-H` flag: Additional human-readable string extraction from payloads

### Human-Readable Output

When the `-H` flag is used, the sniffer will display an additional section showing human-readable strings extracted from the packet payload. This is particularly useful for analyzing text-based protocols like HTTP, SMTP, or FTP.

Example output with `-H` flag:
```
Payload (86 bytes):
Hex dump (86 bytes):
    00000000  48 54 54 50 2f 31 2e 31  20 32 30 30 20 4f 4b 0d  |HTTP/1.1 200 OK.|
    00000010  0a 43 6f 6e 74 65 6e 74  2d 54 79 70 65 3a 20 74  |.Content-Type: t|
    00000020  65 78 74 2f 68 74 6d 6c  0d 0a 44 61 74 65 3a 20  |ext/html..Date: |
    00000030  4d 6f 6e 2c 20 32 31 20  4a 75 6c 20 32 30 32 35  |Mon, 21 Jul 2025|
    00000040  20 31 33 3a 32 30 3a 30  30 20 47 4d 54 0d 0a 0d  | 13:20:00 GMT...|
    00000050  0a 3c 68 74 6d 6c 3e 0a  3c 62 6f 64 79 3e 0a 48  |.<html>.<body>.H|
    00000060  65 6c 6c 6f 20 57 6f 72  6c 64 21 0a 3c 2f 62 6f  |ello World!.</bo|
    00000070  64 79 3e 0a 3c 2f 68 74  6d 6c 3e 0a           |dy>.</html>.|

Human-readable string (86 bytes):
    00000000  HTTP/1.1 200 OK
    0000001f  Content-Type: text/html
    0000003e  Date: Mon, 21 Jul 2025 13:20:00 GMT
    00000062  <html><body>Hello World!</body></html>
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request
