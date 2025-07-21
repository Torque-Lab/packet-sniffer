#ifndef PACKET_SNIFFER_TCP_LAYER_H
#define PACKET_SNIFFER_TCP_LAYER_H

#include "../Packet.h"
#include <string>

namespace packet_sniffer {

class TCPLayer : public Layer {
public:
    struct Flags {
        bool fin : 1;
        bool syn : 1;
        bool rst : 1;
        bool psh : 1;
        bool ack : 1;
        bool urg : 1;
        bool ece : 1;
        bool cwr : 1;
        
        std::string to_string() const;
    };
    
    void parse(const uint8_t* data, uint32_t size) override;
    std::string to_string() const override;
    
    uint16_t get_header_size() const { return header_size_; }
    uint16_t get_payload_size() const { return payload_size_; }
    const uint8_t* get_payload() const override { return payload_; }
    
    uint16_t get_source_port() const { return source_port_; }
    uint16_t get_dest_port() const { return dest_port_; }
    uint32_t get_sequence() const { return sequence_; }
    uint32_t get_acknowledgment() const { return acknowledgment_; }
    uint8_t get_data_offset() const { return data_offset_; }
    const Flags& get_flags() const { return flags_; }
    uint16_t get_window_size() const { return window_size_; }
    uint16_t get_checksum() const { return checksum_; }
    uint16_t get_urgent_pointer() const { return urgent_pointer_; }
    
    static std::string get_well_known_port(uint16_t port);
    
private:
    uint16_t source_port_;
    uint16_t dest_port_;
    uint32_t sequence_;
    uint32_t acknowledgment_;
    uint8_t data_offset_;
    Flags flags_;
    uint16_t window_size_;
    uint16_t checksum_;
    uint16_t urgent_pointer_;
    
    const uint8_t* payload_;
    uint16_t header_size_;
    uint16_t payload_size_;
    
    void parse_options(const uint8_t* options, uint8_t options_length);
};

} // namespace packet_sniffer

#endif // PACKET_SNIFFER_TCP_LAYER_H
