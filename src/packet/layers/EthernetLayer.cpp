#include "packet/layers/EthernetLayer.h"
#include <sstream>
#include <iomanip>
#include <cstring>

namespace packet_sniffer {

void EthernetLayer::parse(const uint8_t* data, uint32_t size) {
    if (size < HEADER_SIZE) {
        throw std::runtime_error("Ethernet packet too small");
    }
    
    const ether_header* eth_hdr = reinterpret_cast<const ether_header*>(data);
    
    // Copy source and destination MAC addresses
    std::memcpy(dest_mac_.data(), eth_hdr->ether_dhost, MAC_ADDR_LEN);
    std::memcpy(source_mac_.data(), eth_hdr->ether_shost, MAC_ADDR_LEN);
    
    // Get the ethernet type (network byte order)
    ether_type_ = ntohs(eth_hdr->ether_type);
    
    // Set payload pointer and size
    payload_ = data + HEADER_SIZE;
    payload_size_ = size - HEADER_SIZE;
}

std::string EthernetLayer::to_string() const {
    std::ostringstream ss;
    
    ss << "Ethernet II, Src: " << mac_to_string(source_mac_)
       << ", Dst: " << mac_to_string(dest_mac_) << "\n";
    
    ss << "  Destination: " << mac_to_string(dest_mac_) << "\n";
    ss << "  Source: " << mac_to_string(source_mac_) << "\n";
    
    // Common ethernet types
    const char* type_str = "";
    switch (ether_type_) {
        case ETHERTYPE_IP:  type_str = "IPv4"; break;
        case ETHERTYPE_IPV6: type_str = "IPv6"; break;
        case ETHERTYPE_ARP: type_str = "ARP"; break;
        case ETHERTYPE_VLAN: type_str = "VLAN"; break;
        default: type_str = "Unknown";
    }
    
    ss << "  Type: 0x" << std::hex << std::setw(4) << std::setfill('0') 
       << ether_type_ << " (" << type_str << ")\n";
    
    return ss.str();
}

std::string EthernetLayer::mac_to_string(const MacAddress& mac) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    
    for (size_t i = 0; i < mac.size(); ++i) {
        if (i > 0) ss << ":";
        ss << std::setw(2) << static_cast<int>(mac[i]);
    }
    
    return ss.str();
}

} // namespace packet_sniffer
