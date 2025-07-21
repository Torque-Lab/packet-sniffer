#ifndef PACKET_SNIFFER_SNIFFER_CONFIG_H
#define PACKET_SNIFFER_SNIFFER_CONFIG_H
#include <string>
#include <vector>
#include <cstdint>

namespace packet_sniffer {

struct SnifferConfig {
    std::string interface;          // Network interface to sniff on (empty for default)
    std::string filter;             // BPF filter expression (e.g., "tcp port 80")
    bool promiscuous = true;        // Enable promiscuous mode
    int timeout_ms = 1000;          // Read timeout in milliseconds
    int max_packets = 0;            // Maximum number of packets to capture (0 for unlimited)
    
    // Layer-specific filters
    bool filter_ethernet = true;    // Include Ethernet layer
    bool filter_ip = true;          // Include IP layer
    bool filter_tcp = true;         // Include TCP packets
    bool filter_udp = true;         // Include UDP packets
    bool filter_icmp = true;        // Include ICMP packets
    
    // Port-based filtering
    std::vector<uint16_t> src_ports;  // Filter by source ports
    std::vector<uint16_t> dst_ports;  // Filter by destination ports
    
    // IP-based filtering
    std::string src_ip;             // Filter by source IP
    std::string dst_ip;             // Filter by destination IP
    
    // Output options
    bool verbose = false;           // Show detailed output
    bool show_payload = true;       // Show packet payload
    bool show_hex = true;           // Show hex dump of payload
    bool show_ascii = true;         // Show ASCII representation of payload
    
    // Save captured packets to file
    std::string output_file;        // File to save captured packets (PCAP format)
};

} // namespace packet_sniffer

#endif // PACKET_SNIFFER_SNIFFER_CONFIG_H
