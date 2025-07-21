#ifndef PACKET_SNIFFER_PACKET_SNIFFER_H
#define PACKET_SNIFFER_PACKET_SNIFFER_H

#include "SnifferConfig.h"
#include "../packet/Packet.h"
#include <pcap.h>
#include <functional>
#include <string>
#include <memory>
#include <vector>
#include <mutex>
#include <thread>

namespace packet_sniffer {

class PacketSniffer {
public:
    using PacketCallback = std::function<void(const Packet&)>;
    
    explicit PacketSniffer(const SnifferConfig& config);
    ~PacketSniffer();
    
    // Disable copy and move
    PacketSniffer(const PacketSniffer&) = delete;
    PacketSniffer& operator=(const PacketSniffer&) = delete;
    PacketSniffer(PacketSniffer&&) = delete;
    PacketSniffer& operator=(PacketSniffer&&) = delete;
    
    // Start capturing packets
    bool start();
    
    // Stop capturing packets
    void stop();
    
    // Set callback for captured packets
    void set_packet_callback(PacketCallback callback) { packet_callback_ = std::move(callback); }
    
    // Get available network interfaces
    static std::vector<std::string> list_interfaces();
    
    // Apply a new filter
    bool set_filter(const std::string& filter);
    
    // Get current statistics
    struct Stats {
        uint64_t packets_received{0};
        uint64_t packets_dropped{0};
        uint64_t packets_if_dropped{0};
    };
    
    Stats get_stats() const;
    
private:
    bool initialize();
    void cleanup();
    void process_packet(const struct pcap_pkthdr* header, const u_char* packet);
    static void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet);
    void display_payload(const uint8_t* payload, uint32_t payload_size) const;
    SnifferConfig config_;
    pcap_t* handle_{nullptr};
    char errbuf_[PCAP_ERRBUF_SIZE];
    std::string device_name_;  
    volatile bool is_running_{false};
    Stats stats_;
    PacketCallback packet_callback_;
    std::thread capture_thread_;
    mutable std::mutex mutex_;
};

} // namespace packet_sniffer

#endif // PACKET_SNIFFER_PACKET_SNIFFER_H
