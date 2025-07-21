#include "packet/layers/UDPLayer.h"
#include <sstream>
#include <iomanip>
#include <netdb.h>

namespace packet_sniffer {

void UDPLayer::parse(const uint8_t* data, uint32_t size) {
    if (size < HEADER_SIZE) {
        throw std::runtime_error("UDP packet too small");
    }
    
    const udphdr* udp_hdr = reinterpret_cast<const udphdr*>(data);
    
    // Parse UDP header fields
    source_port_ = ntohs(udp_hdr->source);
    dest_port_ = ntohs(udp_hdr->dest);
    length_ = ntohs(udp_hdr->len);
    checksum_ = ntohs(udp_hdr->check);
    
    // Set payload pointer
    payload_ = data + HEADER_SIZE;
    
    // Sanity check for length
    if (length_ < HEADER_SIZE) {
        throw std::runtime_error("Invalid UDP length field");
    }
}

std::string UDPLayer::to_string() const {
    std::ostringstream ss;
    
    ss << "User Datagram Protocol, Src Port: " << source_port_
       << ", Dst Port: " << dest_port_ << "\n";
    
    // Source and destination ports with service names
    ss << "   " << std::left << std::setw(20) << "Source Port:" << source_port_;
    std::string service = get_well_known_port(source_port_);
    if (!service.empty()) {
        ss << " (" << service << ")";
    }
    ss << "\n";
    
    ss << "   " << std::left << std::setw(20) << "Destination Port:" << dest_port_;
    service = get_well_known_port(dest_port_);
    if (!service.empty()) {
        ss << " (" << service << ")";
    }
    ss << "\n";
    
    // Length and checksum
    ss << "   " << std::left << std::setw(20) << "Length:" << length_ << "\n";
    ss << "   " << std::left << std::setw(20) << "Checksum:" << "0x" 
       << std::hex << std::setw(4) << std::setfill('0') << checksum_ << std::dec << "\n";
    
    return ss.str();
}

std::string UDPLayer::get_well_known_port(uint16_t port) {
    struct servent* service = getservbyport(htons(port), "udp");
    return service ? service->s_name : "";
}

} // namespace packet_sniffer
