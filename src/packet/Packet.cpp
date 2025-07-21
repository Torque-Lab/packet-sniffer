#include "packet/Packet.h"
#include "packet/layers/EthernetLayer.h"
#include "packet/layers/IPLayer.h"
#include "packet/layers/TCPLayer.h"
#include "packet/layers/UDPLayer.h"
#include "packet/layers/ICMPLayer.h"

#include <sstream>
#include <iomanip>
#include <ctime>

namespace packet_sniffer {

Packet::Packet(const uint8_t* data, uint32_t size, const Timestamp& timestamp)
    : timestamp_(timestamp), size_(size) {
    parse(data, size);
}

void Packet::parse(const uint8_t* data, uint32_t size) {
    if (size < sizeof(ether_header)) {
        return; // Not enough data for even an Ethernet header
    }
    
    // Parse Ethernet layer
    auto eth_layer = std::make_unique<EthernetLayer>();
    eth_layer->parse(data, size);
    
    // Store the layer and move to the next one
    const uint8_t* next_layer = data + eth_layer->get_header_size();
    uint32_t remaining_size = size - eth_layer->get_header_size();
    layers_.push_back(std::move(eth_layer));
    
    // If this is an IP packet, parse the IP layer
    if (auto eth = dynamic_cast<EthernetLayer*>(layers_.back().get())) {
        if (eth->get_ether_type() == 0x0800 && remaining_size >= sizeof(iphdr)) { // IPv4
            auto ip_layer = std::make_unique<IPLayer>();
            ip_layer->parse(next_layer, remaining_size);
            
            next_layer += ip_layer->get_header_size();
            remaining_size = ip_layer->get_payload_size();
            layers_.push_back(std::move(ip_layer));
            
            // Parse transport layer if we have an IP layer
            if (auto ip = dynamic_cast<IPLayer*>(layers_.back().get())) {
                switch (ip->get_protocol()) {
                    case IPLayer::Protocol::TCP:
                        if (remaining_size >= sizeof(tcphdr)) {
                            auto tcp_layer = std::make_unique<TCPLayer>();
                            tcp_layer->parse(next_layer, remaining_size);
                            layers_.push_back(std::move(tcp_layer));
                        }
                        break;
                        
                    case IPLayer::Protocol::UDP:
                        if (remaining_size >= sizeof(udphdr)) {
                            auto udp_layer = std::make_unique<UDPLayer>();
                            udp_layer->parse(next_layer, remaining_size);
                            layers_.push_back(std::move(udp_layer));
                        }
                        break;
                        
                    case IPLayer::Protocol::ICMP:
                        if (remaining_size >= sizeof(icmphdr)) {
                            auto icmp_layer = std::make_unique<ICMPLayer>();
                            icmp_layer->parse(next_layer, remaining_size);
                            layers_.push_back(std::move(icmp_layer));
                        }
                        break;
                        
                    default:
                        // Unsupported protocol
                        break;
                }
            }
        }
    }
}

std::string Packet::to_string() const {
    std::ostringstream ss;
    
    // Format timestamp
    auto time_t = std::chrono::system_clock::to_time_t(timestamp_);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        timestamp_.time_since_epoch()
    ) % 1000;
    
    ss << "[" << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S")
       << "." << std::setfill('0') << std::setw(3) << ms.count() << "] "
       << "Packet (" << size_ << " bytes)" << std::endl;
    
    // Add each layer's string representation
    for (const auto& layer : layers_) {
        ss << layer->to_string() << std::endl;
    }
    
    return ss.str();
}

} // namespace packet_sniffer
