#include "sniffer/PacketSniffer.h"
#include "packet/Packet.h"
#include "packet/layers/IPLayer.h"
#include "packet/layers/TCPLayer.h"
#include "packet/layers/UDPLayer.h"
#include "packet/layers/ICMPLayer.h"
#include <iomanip>
#include <pcap.h>
#include <cstring>
#include <stdexcept>
#include <iostream>  // Added for std::cerr and std::endl
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <unistd.h>
#include <memory>
#include <thread>
#include <chrono>

namespace packet_sniffer {

PacketSniffer::PacketSniffer(const SnifferConfig& config)
    : config_(config), 
      handle_(nullptr), 
      errbuf_(),
      device_name_(""),
      is_running_(false),
      stats_{},
      packet_callback_(),
      capture_thread_() {
    std::memset(errbuf_, 0, PCAP_ERRBUF_SIZE);
}

PacketSniffer::~PacketSniffer() {
    stop();
    cleanup();
}

bool PacketSniffer::start() {
    if (is_running_) {
        return true; // Already running
    }
    
    if (!initialize()) {
        return false;
    }
    
    // Set non-blocking mode
    if (pcap_setnonblock(handle_, 1, errbuf_) == -1) {
        return false;
    }
    
    // Start a new thread for packet capture
    capture_thread_ = std::thread([this]() {
        struct pcap_pkthdr header;
        const u_char* packet;
        
        while (is_running_) {
            // Process all available packets
            while ((packet = pcap_next(handle_, &header)) != nullptr) {
                process_packet(&header, packet);
            }
            
            // Small sleep to prevent busy waiting
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    });
    
    is_running_ = true;
    return true;
}

void PacketSniffer::stop() {
    is_running_ = false;
    if (capture_thread_.joinable()) {
        capture_thread_.join();
    }
}

bool PacketSniffer::initialize() {
    const char* device = nullptr;
    std::string device_name;  // Store the device name if we need to allocate it
    
    if (config_.interface.empty()) {
        // Use pcap_findalldevs instead of deprecated pcap_lookupdev
        pcap_if_t* alldevs;
        if (pcap_findalldevs(&alldevs, errbuf_) == -1) {
            std::cerr << "Could not find any network devices: " << errbuf_ << std::endl;
            return false;
        }
        if (alldevs == nullptr) {
            std::cerr << "No network devices found" << std::endl;
            return false;
        }
        device_name = alldevs->name;  // Store the device name
        device = device_name.c_str();
        pcap_freealldevs(alldevs);
    } else {
        device = config_.interface.c_str();
    }
    
    // Store the device name in the class member for later use
    if (device) {
        device_name_ = device;
    }
    
    // Open the capture device
    handle_ = pcap_open_live(device, BUFSIZ, config_.promiscuous ? 1 : 0, 
                            config_.timeout_ms, errbuf_);
    if (!handle_) {
        return false;
    }
    
    // Set the data link type to Ethernet
    if (pcap_datalink(handle_) != DLT_EN10MB) {
        std::strcpy(errbuf_, "Only Ethernet is supported");
        cleanup();
        return false;
    }
    
    // Apply the BPF filter if specified
    if (!config_.filter.empty() && !set_filter(config_.filter)) {
        cleanup();
        return false;
    }
    
    return true;
}

void PacketSniffer::cleanup() {
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

bool PacketSniffer::set_filter(const std::string& filter) {
    if (!handle_) return false;
    
    struct bpf_program fp;
    bpf_u_int32 netmask = 0xffffff00; // Default netmask
    
    // Get network mask from the device
    bpf_u_int32 netp;
    if (pcap_lookupnet(device_name_.c_str(), &netp, &netmask, errbuf_) == -1) {
        std::cerr << "Couldn't get netmask for device " << device_name_ 
                 << ": " << errbuf_ << std::endl;
        netmask = 0xffffff00; // Use default if can't get netmask
    }
    
    // Compile the filter
    std::string full_filter = filter;
    if (pcap_compile(handle_, &fp, full_filter.c_str(), 0, netmask) == -1) {
        std::cerr << "Couldn't parse filter " << full_filter 
                 << ": " << pcap_geterr(handle_) << std::endl;
        return false;
    }
    
    // Apply the filter
    if (pcap_setfilter(handle_, &fp) == -1) {
        std::cerr << "Couldn't install filter " << full_filter 
                 << ": " << pcap_geterr(handle_) << std::endl;
        pcap_freecode(&fp);
        return false;
    }
    
    pcap_freecode(&fp);
    return true;
}

std::vector<std::string> PacketSniffer::list_interfaces() {
    std::vector<std::string> interfaces;
    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        return interfaces;
    }
    
    for (d = alldevs; d != nullptr; d = d->next) {
        if (d->name) {
            interfaces.push_back(d->name);
        }
    }
    
    pcap_freealldevs(alldevs);
    return interfaces;
}
void PacketSniffer::display_payload_hex_ascii(const uint8_t* payload, uint32_t payload_size) const {
    if (!payload || payload_size == 0) {
        std::cout << "No payload data to display.\n";
        return;
    }

    const int bytes_per_line = 16;
    uint32_t offset = 0;
    
    while (offset < payload_size) {
        // Print offset
        std::cout << std::hex << std::setw(8) << std::setfill('0') << offset << "  ";
        
        // Print hex bytes
        for (int i = 0; i < bytes_per_line; ++i) {
            if (i == 8) std::cout << " ";  // Extra space after 8 bytes
            if (offset + i < payload_size) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') 
                         << static_cast<int>(payload[offset + i]) << " ";
            } else {
                std::cout << "   ";  // Pad with spaces if needed
            }
        }
        
        std::cout << " ";
        
        // Print ASCII representation
        for (int i = 0; i < bytes_per_line; ++i) {
            if (offset + i >= payload_size) break;
            
            uint8_t byte = payload[offset + i];
            if (byte >= 32 && byte <= 126) {
                std::cout << static_cast<char>(byte);
            } else {
                std::cout << ".";
            }
        }
        
        std::cout << "\n";
        offset += bytes_per_line;
    }
    std::cout << std::dec;  // Reset to decimal output
}

void PacketSniffer::process_packet(const struct pcap_pkthdr* header, const u_char* packet) {
    if (!is_running_ || !packet_callback_) {
        std::cerr << "DEBUG: Not processing packet - " 
                 << (!is_running_ ? "not running" : "no callback") << std::endl;
        return;
    }
    
    try {
       
        // Create a timestamp for the packet
        auto timestamp = std::chrono::system_clock::time_point(
            std::chrono::seconds(header->ts.tv_sec) + 
            std::chrono::microseconds(header->ts.tv_usec)
        );
        
        // Create and parse the packet
        Packet pkt(packet, header->caplen, timestamp);
        
        // Apply filters based on configuration
        bool should_process = true;
        
        // Filter by protocol
        if (auto ip = pkt.get_layer<IPLayer>()) {
            
            
            // Check if the protocol is enabled in the configuration
            bool protocol_enabled = true;
            
            switch (ip->get_protocol()) {
                case IPLayer::Protocol::TCP:
                    protocol_enabled = config_.filter_tcp;
                    std::cout << " TCP protocol " << (protocol_enabled ? "enabled" : "disabled") << std::endl;
                    break;
                case IPLayer::Protocol::UDP:
                    protocol_enabled = config_.filter_udp;
                    std::cout << " UDP protocol " << (protocol_enabled ? "enabled" : "disabled") << std::endl;
                    break;
                case IPLayer::Protocol::ICMP:
                    protocol_enabled = config_.filter_icmp;
                    std::cout << " ICMP protocol " << (protocol_enabled ? "enabled" : "disabled") << std::endl;
                    break;
                default:
                    protocol_enabled = false;
                    std::cout << " Unknown protocol " << static_cast<int>(ip->get_protocol()) << std::endl;
                    break;
            }
            
            if (!protocol_enabled) {
                std::cout << " Packet filtered out by protocol" << std::endl;
                should_process = false;
            }
            
            // Filter by source/destination IP
            if (!config_.src_ip.empty() && ip->get_source_ip() != config_.src_ip) {
                std::cout << " Packet filtered out by source IP" << std::endl;
                should_process = false;
            }
            
            if (!config_.dst_ip.empty() && ip->get_dest_ip() != config_.dst_ip) {
                std::cout << " Packet filtered out by destination IP" << std::endl;
                should_process = false;
            }
            
            // Filter by port for TCP/UDP
            if (ip->get_protocol() == IPLayer::Protocol::TCP) {
                if (auto tcp = pkt.get_layer<TCPLayer>()) {
                    std::cout << " TCP Layer - Src Port: " << tcp->get_source_port() 
                             << ", Dst Port: " << tcp->get_dest_port() << std::endl;
                    
                    if ((!config_.src_ports.empty() && 
                         std::find(config_.src_ports.begin(), config_.src_ports.end(), 
                                 tcp->get_source_port()) == config_.src_ports.end()) ||
                        (!config_.dst_ports.empty() && 
                         std::find(config_.dst_ports.begin(), config_.dst_ports.end(), 
                                 tcp->get_dest_port()) == config_.dst_ports.end())) {
                        std::cout << " Packet filtered out by port filter" << std::endl;
                        should_process = false;
                    }
                }
            } else if (ip->get_protocol() == IPLayer::Protocol::UDP) {
                if (auto udp = pkt.get_layer<UDPLayer>()) {
                    std::cout << " UDP Layer - Src Port: " << udp->get_source_port() 
                             << ", Dst Port: " << udp->get_dest_port() << std::endl;
                    
                    if ((!config_.src_ports.empty() && 
                         std::find(config_.src_ports.begin(), config_.src_ports.end(), 
                                 udp->get_source_port()) == config_.src_ports.end()) ||
                        (!config_.dst_ports.empty() && 
                         std::find(config_.dst_ports.begin(), config_.dst_ports.end(), 
                                 udp->get_dest_port()) == config_.dst_ports.end())) {
                        std::cout << " Packet filtered out by port filter" << std::endl;
                        should_process = false;
                    }
                }
            }
        } else if (!config_.filter_ethernet) {
            std::cout << " Non-IP packet and ethernet filter is off" << std::endl;
            should_process = false;
        }
        // If the packet passes all filters, process it
if (should_process) {
    std::cout << "Calling packet callback" << std::endl;
    
    // Display payload in hex and ASCII
    if (auto ip = pkt.get_layer<IPLayer>()) {
        std::cout<<"*==============================*\n";
        std::cout << "\n=== Payload (Hex and ASCII) ===\n";
        display_payload_hex_ascii(ip->get_payload(), ip->get_payload_size());
        std::cout << "Displaying payload in hex and ASCII completed\n";
        std::cout<<"*==============================*\n";
    }
    
    if (packet_callback_) {
        std::cout<<"*==============================*\n";
        std::cout << "Displaying packet bytes completed\n";
        packet_callback_(pkt);
    }
    std::cout << "Packet byte display completed\n";
    std::cout<<"*==============================*\n";
}
        

    } catch (const std::exception& e) {
        std::cerr << "Error processing packet: " << e.what() << std::endl;
    }
}

void PacketSniffer::packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    auto sniffer = reinterpret_cast<PacketSniffer*>(user);
    if (sniffer) {
        sniffer->process_packet(header, packet);
    }
}

PacketSniffer::Stats PacketSniffer::get_stats() const {
    Stats stats = {};
    
    if (handle_) {
        pcap_stat ps;
        if (pcap_stats(handle_, &ps) == 0) {
            stats.packets_received = ps.ps_recv;
            stats.packets_dropped = ps.ps_drop;
            stats.packets_if_dropped = ps.ps_ifdrop;
        }
    }
    
    return stats;
}

} // namespace packet_sniffer
