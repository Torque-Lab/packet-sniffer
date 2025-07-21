#ifndef PACKET_SNIFFER_ICMP_LAYER_H
#define PACKET_SNIFFER_ICMP_LAYER_H

#include "../Packet.h"
#include <string>

namespace packet_sniffer {

class ICMPLayer : public Layer {
public:
    enum class Type : uint8_t {
        ECHO_REPLY = 0,
        DEST_UNREACHABLE = 3,
        SOURCE_QUENCH = 4,
        REDIRECT = 5,
        ECHO_REQUEST = 8,
        TIME_EXCEEDED = 11,
        PARAMETER_PROBLEM = 12,
        TIMESTAMP_REQUEST = 13,
        TIMESTAMP_REPLY = 14,
        INFO_REQUEST = 15,
        INFO_REPLY = 16,
        ADDRESS_MASK_REQUEST = 17,
        ADDRESS_MASK_REPLY = 18
    };
    
    void parse(const uint8_t* data, uint32_t size) override;
    std::string to_string() const override;
    
    uint16_t get_header_size() const { return header_size_; }
    uint16_t get_payload_size() const { return payload_size_; }
    const uint8_t* get_payload() const override { return payload_; }
    
    Type get_type() const { return type_; }
    uint8_t get_code() const { return code_; }
    uint16_t get_checksum() const { return checksum_; }
    
    static std::string type_to_string(Type type);
    
private:
    Type type_;
    uint8_t code_;
    uint16_t checksum_;
    
    const uint8_t* payload_;
    uint16_t header_size_;
    uint16_t payload_size_;
    
    // ICMP-specific fields based on type
    union {
        struct {
            uint16_t id;
            uint16_t sequence;
        } echo;
        
        uint32_t gateway;
        
        struct {
            uint16_t unused;
            uint16_t next_hop_mtu;
        } frag_needed;
    } fields_;
};

} // namespace packet_sniffer

#endif // PACKET_SNIFFER_ICMP_LAYER_H
