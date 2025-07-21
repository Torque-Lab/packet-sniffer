#include "packet/layers/ICMPLayer.h"
#include <sstream>
#include <iomanip>
#include <arpa/inet.h>

namespace packet_sniffer {

void ICMPLayer::parse(const uint8_t* data, uint32_t size) {
    if (size < sizeof(icmphdr)) {
        throw std::runtime_error("ICMP packet too small");
    }
    
    const icmphdr* icmp_hdr = reinterpret_cast<const icmphdr*>(data);
    
    // Parse ICMP header fields
    type_ = static_cast<Type>(icmp_hdr->type);
    code_ = icmp_hdr->code;
    checksum_ = ntohs(icmp_hdr->checksum);
    
    // Parse type-specific fields
    switch (type_) {
        case Type::ECHO_REPLY:
        case Type::ECHO_REQUEST:
            fields_.echo.id = ntohs(icmp_hdr->un.echo.id);
            fields_.echo.sequence = ntohs(icmp_hdr->un.echo.sequence);
            header_size_ = 8; // ICMP header + echo header
            break;
            
        case Type::DEST_UNREACHABLE:
        case Type::TIME_EXCEEDED:
        case Type::PARAMETER_PROBLEM:
            fields_.frag_needed.unused = 0; // This field is unused in these ICMP types
            fields_.frag_needed.next_hop_mtu = ntohs(icmp_hdr->un.frag.mtu);
            header_size_ = 8; // ICMP header + 4 bytes of unused
            break;
            
        case Type::REDIRECT:
            fields_.gateway = icmp_hdr->un.gateway;
            header_size_ = 8; // ICMP header + gateway address
            break;
            
        default:
            // For other ICMP types, just use the basic header
            header_size_ = 4;
            break;
    }
    
    // Set payload pointer and size
    payload_ = data + header_size_;
    payload_size_ = size - header_size_;
}

std::string ICMPLayer::to_string() const {
    std::ostringstream ss;
    
    ss << "Internet Control Message Protocol\n";
    
    // Type and code
    ss << "   " << std::left << std::setw(20) << "Type:" << static_cast<int>(type_)
       << " (" << type_to_string(type_) << ")\n";
    ss << "   " << std::left << std::setw(20) << "Code:" << static_cast<int>(code_) << "\n";
    ss << "   " << std::left << std::setw(20) << "Checksum:" << "0x" 
       << std::hex << std::setw(4) << std::setfill('0') << checksum_ << std::dec << "\n";
    
    // Type-specific fields
    switch (type_) {
        case Type::ECHO_REPLY:
        case Type::ECHO_REQUEST:
            ss << "   " << std::left << std::setw(20) << "Identifier:" << fields_.echo.id << "\n";
            ss << "   " << std::left << std::setw(20) << "Sequence Number:" << fields_.echo.sequence << "\n";
            break;
            
        case Type::DEST_UNREACHABLE:
            ss << "   " << std::left << std::setw(20) << "Next Hop MTU:" << fields_.frag_needed.next_hop_mtu << "\n";
            break;
            
        case Type::REDIRECT: {
            struct in_addr addr;
            addr.s_addr = fields_.gateway;
            ss << "   " << std::left << std::setw(20) << "Gateway:" 
               << inet_ntoa(addr) << "\n";
            break;
        }
            
        case Type::TIME_EXCEEDED:
            // No specific fields for time exceeded
            break;
            
        case Type::PARAMETER_PROBLEM:
            // The pointer is in the first byte of the ICMP header's data
            if (header_size_ > 4) {
                ss << "   " << std::left << std::setw(20) << "Pointer:" 
                   << static_cast<int>(reinterpret_cast<const uint8_t*>(&fields_)[0]) << "\n";
            }
            break;
            
        default:
            // For other types, just show the raw data
            if (header_size_ > 4) {
                ss << "   " << std::left << std::setw(20) << "Data:" 
                   << "0x" << std::hex << std::setw(8) << std::setfill('0')
                   << *reinterpret_cast<const uint32_t*>(&fields_) << std::dec << "\n";
            }
            break;
    }
    
    return ss.str();
}

std::string ICMPLayer::type_to_string(Type type) {
    switch (type) {
        case Type::ECHO_REPLY: return "Echo Reply";
        case Type::DEST_UNREACHABLE: return "Destination Unreachable";
        case Type::SOURCE_QUENCH: return "Source Quench";
        case Type::REDIRECT: return "Redirect Message";
        case Type::ECHO_REQUEST: return "Echo Request";
        case Type::TIME_EXCEEDED: return "Time Exceeded";
        case Type::PARAMETER_PROBLEM: return "Parameter Problem";
        case Type::TIMESTAMP_REQUEST: return "Timestamp Request";
        case Type::TIMESTAMP_REPLY: return "Timestamp Reply";
        case Type::INFO_REQUEST: return "Information Request";
        case Type::INFO_REPLY: return "Information Reply";
        case Type::ADDRESS_MASK_REQUEST: return "Address Mask Request";
        case Type::ADDRESS_MASK_REPLY: return "Address Mask Reply";
        default: return "Unknown";
    }
}

} // namespace packet_sniffer
