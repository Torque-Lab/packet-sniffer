#include "packet/layers/IPLayer.h"
#include <sstream>
#include <iomanip>
#include <arpa/inet.h>

namespace packet_sniffer {

void IPLayer::parse(const uint8_t* data, uint32_t size) {
    if (size < sizeof(iphdr)) {
        throw std::runtime_error("IP packet too small");
    }
    
    const iphdr* ip_hdr = reinterpret_cast<const iphdr*>(data);
    
    // Parse IP header fields
    version_ = ip_hdr->version;
    ihl_ = ip_hdr->ihl * 4; // IHL is in 32-bit words
    dscp_ = (ip_hdr->tos >> 2) & 0x3F;
    total_length_ = ntohs(ip_hdr->tot_len);
    identification_ = ntohs(ip_hdr->id);
    
    // Flags and fragment offset
    uint16_t frag_and_flags = ntohs(ip_hdr->frag_off);
    flags_ = (frag_and_flags >> 13) & 0x07;
    fragment_offset_ = frag_and_flags & 0x1FFF;
    
    ttl_ = ip_hdr->ttl;
    protocol_ = ip_hdr->protocol;
    checksum_ = ntohs(ip_hdr->check);
    
    // Convert IP addresses to strings
    source_ip_ = ipv4_to_string(ip_hdr->saddr);
    dest_ip_ = ipv4_to_string(ip_hdr->daddr);
    
    // Set payload pointer and sizes
    header_size_ = ihl_;
    payload_ = data + header_size_;
    payload_size_ = total_length_ - header_size_;
}

std::string IPLayer::to_string() const {
    std::ostringstream ss;
    
    ss << "Internet Protocol Version " << static_cast<int>(version_) << ", "
       << "Src: " << source_ip_ << ", Dst: " << dest_ip_ << "\n";
    
    ss << "   " << std::left << std::setw(20) << "0100 .... = Version:" << version_ << "\n";
    ss << "   " << std::left << std::setw(20) << ".... 0101 = Header Length:" << static_cast<int>(ihl_) << " bytes" << "\n";
    ss << "   " << std::left << std::setw(20) << "Differentiated Services:" << "0x" << std::hex << std::setw(2) 
       << std::setfill('0') << static_cast<int>(dscp_) << std::dec << "\n";
    ss << "   " << std::left << std::setw(20) << "Total Length:" << total_length_ << "\n";
    ss << "   " << std::left << std::setw(20) << "Identification:" << "0x" << std::hex << identification_ << std::dec << "\n";
    
    // Flags
    ss << "   " << std::left << std::setw(20) << "Flags:" << "0x" << std::hex << static_cast<int>(flags_) << std::dec;
    if (flags_ & 0x04) ss << " (Don't Fragment)";
    if (flags_ & 0x02) ss << " (More Fragments)";
    ss << "\n";
    
    ss << "   " << std::left << std::setw(20) << "Fragment Offset:" << fragment_offset_ << "\n";
    ss << "   " << std::left << std::setw(20) << "Time to Live:" << static_cast<int>(ttl_) << "\n";
    ss << "   " << std::left << std::setw(20) << "Protocol:" << protocol_to_string(static_cast<Protocol>(protocol_)) 
       << " (" << static_cast<int>(protocol_) << ")\n";
    ss << "   " << std::left << std::setw(20) << "Header Checksum:" << "0x" << std::hex << checksum_ << std::dec << "\n";
    ss << "   " << std::left << std::setw(20) << "Source:" << source_ip_ << "\n";
    ss << "   " << std::left << std::setw(20) << "Destination:" << dest_ip_ << "\n";
    
    return ss.str();
}

std::string IPLayer::protocol_to_string(Protocol protocol) {
    switch (protocol) {
        case Protocol::ICMP: return "ICMP";
        case Protocol::TCP: return "TCP";
        case Protocol::UDP: return "UDP";
        default: return "Unknown";
    }
}

std::string IPLayer::ipv4_to_string(uint32_t ip) const {
    char buf[INET_ADDRSTRLEN];
    struct in_addr addr;
    addr.s_addr = ip;
    
    if (inet_ntop(AF_INET, &addr, buf, INET_ADDRSTRLEN) == nullptr) {
        return "0.0.0.0";
    }
    
    return std::string(buf);
}

} // namespace packet_sniffer
