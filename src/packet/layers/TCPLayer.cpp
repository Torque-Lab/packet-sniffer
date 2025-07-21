#include "packet/layers/TCPLayer.h"
#include <sstream>
#include <iomanip>
#include <netdb.h>

// Define TCP flag macros if not already defined
#ifndef TH_ECE
#define TH_ECE 0x40  // ECN-Echo flag
#endif

#ifndef TH_CWR
#define TH_CWR  0x80 // Congestion Window Reduced flag
#endif

namespace packet_sniffer {

void TCPLayer::parse(const uint8_t* data, uint32_t size) {
    if (size < sizeof(tcphdr)) {
        throw std::runtime_error("TCP packet too small");
    }
    
    const tcphdr* tcp_hdr = reinterpret_cast<const tcphdr*>(data);
    
    // Parse TCP header fields
    source_port_ = ntohs(tcp_hdr->source);
    dest_port_ = ntohs(tcp_hdr->dest);
    sequence_ = ntohl(tcp_hdr->seq);
    acknowledgment_ = ntohl(tcp_hdr->ack_seq);
    data_offset_ = tcp_hdr->doff * 4;  // Convert from 32-bit words to bytes
    
    // Parse flags - access flags through th_flags field
    uint16_t flags = ntohs(tcp_hdr->th_flags);
    flags_.fin = (flags & TH_FIN) != 0;
    flags_.syn = (flags & TH_SYN) != 0;
    flags_.rst = (flags & TH_RST) != 0;
    flags_.psh = (flags & TH_PUSH) != 0;
    flags_.ack = (flags & TH_ACK) != 0;
    flags_.urg = (flags & TH_URG) != 0;
    flags_.ece = (flags & TH_ECE) != 0;
    flags_.cwr = (flags & TH_CWR) != 0;
    
    window_size_ = ntohs(tcp_hdr->window);
    checksum_ = ntohs(tcp_hdr->check);
    urgent_pointer_ = ntohs(tcp_hdr->urg_ptr);
    
    // Parse options if header is larger than minimum size
    if (data_offset_ > sizeof(tcphdr)) {
        uint8_t options_length = data_offset_ - sizeof(tcphdr);
        if (size >= data_offset_) {
            const uint8_t* options = data + sizeof(tcphdr);
            parse_options(options, options_length);
        }
    }
    
    // Set payload pointer and size
    header_size_ = data_offset_;
    payload_ = data + header_size_;
    payload_size_ = size - header_size_;
}

void TCPLayer::parse_options([[maybe_unused]] const uint8_t* options, [[maybe_unused]] uint8_t options_length) {
    // TCP options parsing would go here
    // This is a simplified version - actual implementation would parse all option types
}

std::string TCPLayer::to_string() const {
    std::ostringstream ss;
    
    ss << "Transmission Control Protocol, Src Port: " << source_port_ 
       << ", Dst Port: " << dest_port_ << ", Seq: " << sequence_;
    
    if (flags_.ack) {
        ss << ", Ack: " << acknowledgment_;
    }
    
    ss << "\n";
    
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
    
    // Sequence and acknowledgment numbers
    ss << "   " << std::left << std::setw(20) << "Sequence Number:" << sequence_ << "\n";
    
    if (flags_.ack) {
        ss << "   " << std::left << std::setw(20) << "Acknowledgment Number:" << acknowledgment_ << "\n";
    }
    
    // Header length and flags
    ss << "   " << std::left << std::setw(20) << "Header Length:" << static_cast<int>(header_size_) << " bytes\n";
    ss << "   " << std::left << std::setw(20) << "Flags:" << flags_.to_string() << "\n";
    
    // Window size and checksum
    ss << "   " << std::left << std::setw(20) << "Window Size:" << window_size_ << "\n";
    ss << "   " << std::left << std::setw(20) << "Checksum:" << "0x" << std::hex << checksum_ << std::dec << "\n";
    
    if (flags_.urg) {
        ss << "   " << std::left << std::setw(20) << "Urgent Pointer:" << urgent_pointer_ << "\n";
    }
    
    return ss.str();
}

std::string TCPLayer::Flags::to_string() const {
    std::string result;
    
    if (fin) result += "FIN, ";
    if (syn) result += "SYN, ";
    if (rst) result += "RST, ";
    if (psh) result += "PSH, ";
    if (ack) result += "ACK, ";
    if (urg) result += "URG, ";
    if (ece) result += "ECE, ";
    if (cwr) result += "CWR, ";
    
    // Remove trailing comma and space if any flags were set
    if (!result.empty()) {
        result = result.substr(0, result.size() - 2);
    }
    
    return result;
}

std::string TCPLayer::get_well_known_port(uint16_t port) {
    struct servent* service = getservbyport(htons(port), "tcp");
    return service ? service->s_name : "";
}

} // namespace packet_sniffer
