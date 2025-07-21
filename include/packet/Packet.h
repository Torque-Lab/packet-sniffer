#ifndef PACKET_SNIFFER_PACKET_H
#define PACKET_SNIFFER_PACKET_H

#include <vector>
#include <memory>
#include <string>
#include <chrono>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

namespace packet_sniffer {

class Layer {
public:
    virtual ~Layer() = default;
    virtual void parse(const uint8_t* data, uint32_t size) = 0;
    virtual std::string to_string() const = 0;
    virtual uint16_t get_header_size() const = 0;
    virtual uint16_t get_payload_size() const = 0;
    virtual const uint8_t* get_payload() const = 0;
};

class Packet {
public:
    using Timestamp = std::chrono::system_clock::time_point;
    
    Packet() = default;
    explicit Packet(const uint8_t* data, uint32_t size, const Timestamp& timestamp);
    
    void parse(const uint8_t* data, uint32_t size);
    std::string to_string() const;
    
    const Timestamp& get_timestamp() const { return timestamp_; }
    uint32_t get_size() const { return size_; }
    
    template<typename T>
    const T* get_layer() const {
        for (const auto& layer : layers_) {
            if (auto ptr = dynamic_cast<const T*>(layer.get())) {
                return ptr;
            }
        }
        return nullptr;
    }
    
    const std::vector<std::unique_ptr<Layer>>& get_layers() const { return layers_; }
    
private:
    std::vector<std::unique_ptr<Layer>> layers_;
    Timestamp timestamp_;
    uint32_t size_;
};

} // namespace packet_sniffer

#endif // PACKET_SNIFFER_PACKET_H
