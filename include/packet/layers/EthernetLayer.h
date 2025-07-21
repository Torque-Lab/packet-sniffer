#ifndef PACKET_SNIFFER_ETHERNET_LAYER_H
#define PACKET_SNIFFER_ETHERNET_LAYER_H

#include "../Packet.h"
#include <array>

namespace packet_sniffer {

class EthernetLayer : public Layer {
public:
    static constexpr uint16_t HEADER_SIZE = 14; // Ethernet header is always 14 bytes
    static constexpr uint16_t MAC_ADDR_LEN = 6;
    
    using MacAddress = std::array<uint8_t, MAC_ADDR_LEN>;
    
    void parse(const uint8_t* data, uint32_t size) override;
    std::string to_string() const override;
    
    uint16_t get_header_size() const override { return HEADER_SIZE; }
    uint16_t get_payload_size() const { return payload_size_; }
    const uint8_t* get_payload() const override { return payload_; }
    
    const MacAddress& get_source_mac() const { return source_mac_; }
    const MacAddress& get_dest_mac() const { return dest_mac_; }
    uint16_t get_ether_type() const { return ether_type_; }
    
    static std::string mac_to_string(const MacAddress& mac);
    
private:
    MacAddress source_mac_;
    MacAddress dest_mac_;
    uint16_t ether_type_;
    const uint8_t* payload_;
    uint16_t payload_size_;
};

} // namespace packet_sniffer

#endif // PACKET_SNIFFER_ETHERNET_LAYER_H
