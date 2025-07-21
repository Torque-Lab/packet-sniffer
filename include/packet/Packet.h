#ifndef PACKET_SNIFFER_PACKET_H
#define PACKET_SNIFFER_PACKET_H

#include <vector>
#include <memory> //provide smart pointer functionality
#include <string>
#include <chrono>//provide time related functionality
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h> //provide icmp header functionality

namespace packet_sniffer {
class Layer {
public:
    virtual ~Layer() = default;
    virtual void parse(const uint8_t* data, uint32_t size) = 0; //parse the layer
    virtual std::string to_string() const = 0; //return the layer as a string
    virtual uint16_t get_header_size() const = 0; //return the header size
    virtual uint16_t get_payload_size() const = 0; //return the payload size
    virtual const uint8_t* get_payload() const = 0; //return the payload
};

class Packet {
public:
    using Timestamp = std::chrono::system_clock::time_point;
    
    Packet() = default;
    explicit Packet(const uint8_t* data, uint32_t size, const Timestamp& timestamp);
    
    void parse(const uint8_t* data, uint32_t size); //parse the packet
    std::string to_string() const; //return the packet as a string
    
    const Timestamp& get_timestamp() const { return timestamp_; }
    uint32_t get_size() const { return size_; }
    
    template<typename T> //T is the type of the our tcp/ip layer
    const T* get_layer() const {
        for (const auto& layer : layers_) {
            /*layer	A reference to a unique_ptr<Layer>
            layer.get()	give Raw Layer* pointer from smart pointer
            dynamic_cast<const T*> safely tries to convert that Layer* into a pointer to a more specific derived type like TCPLayer*.
            If the cast succeeds, ptr is non-null and returned.
            If the cast fails, ptr is null. */
            if (auto ptr = dynamic_cast<const T*>(layer.get())) {
                return ptr;
            }
        }
        return nullptr;
    }
    
    const std::vector<std::unique_ptr<Layer>>& get_layers() const { return layers_; } //return the layers
    
private:
    std::vector<std::unique_ptr<Layer>> layers_;
    Timestamp timestamp_;
    uint32_t size_;
};

} // namespace packet_sniffer

#endif // PACKET_SNIFFER_PACKET_H
