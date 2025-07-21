#ifndef PACKET_SNIFFER_UDP_LAYER_H
#define PACKET_SNIFFER_UDP_LAYER_H

#include "../Packet.h"
#include <string>

namespace packet_sniffer {

class UDPLayer : public Layer {
public:
    static constexpr uint16_t HEADER_SIZE = 8; // UDP header is always 8 bytes
    
    void parse(const uint8_t* data, uint32_t size) override;
    std::string to_string() const override;
    
    uint16_t get_header_size() const override { return HEADER_SIZE; }
    uint16_t get_payload_size() const { return length_ - HEADER_SIZE; }
    const uint8_t* get_payload() const override { return payload_; }
    
    uint16_t get_source_port() const { return source_port_; }
    uint16_t get_dest_port() const { return dest_port_; }
    uint16_t get_length() const { return length_; }
    uint16_t get_checksum() const { return checksum_; }
    
    static std::string get_well_known_port(uint16_t port);
    
private:
    uint16_t source_port_;
    uint16_t dest_port_;
    uint16_t length_;
    uint16_t checksum_;
    
    const uint8_t* payload_;
};

} // namespace packet_sniffer

#endif // PACKET_SNIFFER_UDP_LAYER_H
