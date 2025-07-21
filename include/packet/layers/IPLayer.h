#ifndef PACKET_SNIFFER_IP_LAYER_H
#define PACKET_SNIFFER_IP_LAYER_H

#include "../Packet.h"
#include <string>

namespace packet_sniffer {

class IPLayer : public Layer {
public:
    enum class Protocol : uint8_t {
        ICMP = 1,
        TCP = 6,
        UDP = 17,
        UNKNOWN = 255
    };
    
    void parse(const uint8_t* data, uint32_t size) override;
    std::string to_string() const override;
    
    uint16_t get_header_size() const { return header_size_; }
    uint16_t get_payload_size() const { return payload_size_; }
    const uint8_t* get_payload() const override { return payload_; }
    
    uint8_t get_version() const { return version_; }
    uint8_t get_ihl() const { return ihl_; }
    uint8_t get_dscp() const { return dscp_; }
    uint16_t get_total_length() const { return total_length_; }
    uint16_t get_identification() const { return identification_; }
    bool get_dont_fragment() const { return flags_ & 0x40; }
    bool get_more_fragments() const { return flags_ & 0x20; }
    uint16_t get_fragment_offset() const { return fragment_offset_; }
    uint8_t get_ttl() const { return ttl_; }
    Protocol get_protocol() const { return static_cast<Protocol>(protocol_); }
    uint16_t get_checksum() const { return checksum_; }
    std::string get_source_ip() const { return source_ip_; }
    std::string get_dest_ip() const { return dest_ip_; }
    
    static std::string protocol_to_string(Protocol protocol);
    
private:
    uint8_t version_;
    uint8_t ihl_;
    uint8_t dscp_;
    uint16_t total_length_;
    uint16_t identification_;
    uint8_t flags_;
    uint16_t fragment_offset_;
    uint8_t ttl_;
    uint8_t protocol_;
    uint16_t checksum_;
    std::string source_ip_;
    std::string dest_ip_;
    
    const uint8_t* payload_;
    uint16_t header_size_;
    uint16_t payload_size_;
    
    std::string ipv4_to_string(uint32_t ip) const;
};

} // namespace packet_sniffer

#endif // PACKET_SNIFFER_IP_LAYER_H
