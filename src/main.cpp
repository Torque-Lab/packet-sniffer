#include <iostream>
#include <string>
#include <vector>
#include <csignal>
#include <getopt.h>
#include <unistd.h>  // for usleep
#include <cstdint>   // for uint16_t
#include <sstream>   // for stringstream
#include <algorithm> // for min
#include <iomanip>   // for put_time
#include <ctime>     // for time_t, localtime
#include <chrono>    // for system_clock

#include "sniffer/PacketSniffer.h"
#include "utils/HexDump.h"

using namespace packet_sniffer;

// Global flag for signal handling
volatile sig_atomic_t g_running = 1;

// Signal handler for graceful shutdown
void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        g_running = 0;
    }
}

// Print usage information
void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [options] [filter]\n"
              << "Options:\n"
              << "  -i <interface>  Network interface to capture on (default: auto-detect)\n"
              << "  -f <filter>     BPF filter expression (e.g., 'tcp port 80')\n"
              << "  -p <ports>      Comma-separated list of ports to filter (e.g., '80,443,8080')\n"
              << "  -s <ip>         Filter by source IP address\n"
              << "  -d <ip>         Filter by destination IP address\n"
              << "  -t              Toggle TCP packets (default: on)\n"
              << "  -u              Toggle UDP packets (default: on)\n"
              << "  -c              Toggle ICMP packets (default: on)\n"
              << "  -e              Toggle Ethernet frames (default: off)\n"
              << "  -H              Show human-readable strings in payload\n"
              << "  -v              Verbose output\n"
              << "  -h              Show this help message\n"
              << "\nExamples:\n"
              << "  " << program_name << " -i eth0 'tcp port 80'\n"
              << "  " << program_name << " -p 22,80,443\n"
              << "  " << program_name << " -s 192.168.1.1 -d 8.8.8.8\n"
              << "  " << program_name << " -H -p 80     # Show human-readable strings in HTTP traffic\n"
              << std::endl;
}

// Parse comma-separated list of ports
std::vector<uint16_t> parse_ports(const std::string& port_str) {
    std::vector<uint16_t> ports;
    std::stringstream ss(port_str);
    std::string port;
    
    while (std::getline(ss, port, ',')) {
        try {
            int p = std::stoi(port);
            if (p > 0 && p <= 65535) {
                ports.push_back(static_cast<uint16_t>(p));
            }
        } catch (const std::exception&) {
            // Ignore invalid ports
        }
    }
    
    return ports;
}

int main(int argc, char* argv[]) {
    SnifferConfig config;
    std::string filter_expr;
    std::string port_str;
    int opt;
    
    // Set default protocol filters - all off by default
    config.filter_tcp = false;
    config.filter_udp = false;
    config.filter_icmp = false;
    config.filter_ethernet = false;
    config.human_readable = false;  // Default to off
    
    // Parse command line options
    while ((opt = getopt(argc, argv, "i:f:p:s:d:tucevhH")) != -1) {
        switch (opt) {
            case 'i':
                config.interface = optarg;
                break;
            case 'f':
                filter_expr = optarg;
                break;
            case 'p':
                port_str = optarg;
                break;
            case 's':
                config.src_ip = optarg;
                break;
            case 'd':
                config.dst_ip = optarg;
                break;
            case 't':
                config.filter_tcp = true;  // Enable TCP filtering when -t is used
                break;
            case 'u':
                config.filter_udp = true;  // Enable UDP filtering when -u is used
                break;
            case 'c':
                config.filter_icmp = true;  // Enable ICMP filtering when -c is used
                break;
            case 'e':
                config.filter_ethernet = true;  // Enable Ethernet filtering when -e is used
                break;
            case 'v':
                config.verbose = true;
                break;
            case 'H':
                config.human_readable = true;  // Enable human-readable output
                break;
            case 'h':
            case '?':
                print_usage(argv[0]);
                return 0;
            default:
                std::cerr << "Unknown option: " << static_cast<char>(opt) << std::endl;
                return 1;
        }
    }
    
    // Any remaining arguments are treated as a filter expression
    if (optind < argc) {
        filter_expr = argv[optind];
    }
    
    // If ports are specified, update the filter expression
    if (!port_str.empty()) {
        auto ports = parse_ports(port_str);
        if (!ports.empty()) {
            std::string port_filter;
            for (size_t i = 0; i < ports.size(); ++i) {
                if (i > 0) port_filter += " or ";
                port_filter += "port " + std::to_string(ports[i]);
            }
            
            if (filter_expr.empty()) {
                filter_expr = port_filter;
            } else {
                filter_expr = "(" + filter_expr + ") and (" + port_filter + ")";
            }
        }
    }
    
    // Set the filter expression
    if (!filter_expr.empty()) {
        config.filter = filter_expr;
    }
    
    // Debug output for configuration
    std::cout << " Configuration ===" << std::endl;
    std::cout << "Verbose mode: " << (config.verbose ? "ON" : "OFF") << std::endl;
    std::cout << "Interface: " << (config.interface.empty() ? "[auto-detect]" : config.interface) << std::endl;
    std::cout << "Filter: " << (config.filter.empty() ? "[none]" : config.filter) << std::endl;
    std::cout << "===========================" << std::endl;
    
    // Set up signal handlers
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
    
    try {
        // Create and configure the packet sniffer
        PacketSniffer sniffer(config);
        
        // Set up packet callback to print packet details
        sniffer.set_packet_callback([&](const packet_sniffer::Packet& packet) {
            if (!config.verbose) {
                std::cout << packet.to_string() << std::endl;
                return;
            }

            std::cout << "\n=== New Packet ===" << std::endl;
            auto time = std::chrono::system_clock::to_time_t(packet.get_timestamp());
            std::cout << "Timestamp: " << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S") << std::endl;
            std::cout << "Size: " << packet.get_size() << " bytes" << std::endl;
            
            const auto& layers = packet.get_layers();
            std::cout << "Number of layers: " << layers.size() << std::endl;
            
            // Only show layers that match the enabled protocols
            bool has_enabled_layer = false;
            
            for (size_t i = 0; i < layers.size(); ++i) {
                bool show_layer = false;
                std::string layer_type = typeid(*layers[i]).name();
                
                // Check if this layer type should be shown based on enabled protocols
                if (layer_type.find("TCPLayer") != std::string::npos && config.filter_tcp) {
                    show_layer = true;
                } else if (layer_type.find("UDP") != std::string::npos && config.filter_udp) {
                    show_layer = true;
                } else if (layer_type.find("ICMP") != std::string::npos && config.filter_icmp) {
                    show_layer = true;
                } else if (layer_type.find("IPLayer") != std::string::npos && 
                          (config.filter_tcp || config.filter_udp || config.filter_icmp)) {
                    // Always show IP layer if any IP-based protocol is enabled
                    show_layer = true;
                } else if (layer_type.find("Ethernet") != std::string::npos && config.filter_ethernet) {
                    show_layer = true;
                }
                
                if (show_layer) {
                    has_enabled_layer = true;
                    std::cout << "\nLayer " << (i + 1) << ":\n";
                    std::cout << layers[i]->to_string() << std::endl;
                    
                    // Print payload if available
                    if (layers[i]->get_payload_size() > 0) {
                        std::cout << "Payload (" << layers[i]->get_payload_size() << " bytes):" << std::endl;
                        try {
                            if (config.human_readable) {
                                std::cout << packet_sniffer::HexDump::format_human(
                                    layers[i]->get_payload(),
                                    std::min<size_t>(layers[i]->get_payload_size(), 1024)  // Increased limit for human-readable output
                                ) << std::endl;
                            } else {
                                std::cout << packet_sniffer::HexDump::format(
                                    layers[i]->get_payload(),
                                    std::min<size_t>(layers[i]->get_payload_size(), 128),
                                    true
                                ) << std::endl;
                            }
                        } catch (const std::exception& e) {
                            std::cerr << "Error formatting payload: " << e.what() << std::endl;
                        }
                    } else {
                        std::cout << "No payload in this layer" << std::endl;
                    }
                }
            }
            
            if (!has_enabled_layer) {
                std::cout << "\n[No layers match the enabled protocol filters]" << std::endl;
            }
            
            std::cout << std::string(50, '=') << "\n" << std::endl;
        });
        
        // Start capturing packets
        if (!sniffer.start()) {
            std::cerr << "Failed to start packet capture" << std::endl;
            return 1;
        }
        
        std::cout << "Capturing packets (press Ctrl+C to stop)..." << std::endl;
        
        // Main capture loop
        while (g_running) {
            // Process packets (non-blocking)
            // The actual capture happens in a separate thread
            usleep(100000); // Sleep for 100ms
            
            // Periodically print statistics
            static int counter = 0;
            if (++counter % 10 == 0 && config.verbose) {
                auto stats = sniffer.get_stats();
                std::cout << "\rPackets: " << stats.packets_received
                          << " (dropped: " << stats.packets_dropped << ")"
                          << std::flush;
            }
        }
        
        // Stop capturing
        sniffer.stop();
        
        // Print final statistics
        auto stats = sniffer.get_stats();
        std::cout << "\nCapture complete. " 
                  << stats.packets_received << " packets received, "
                  << stats.packets_dropped << " packets dropped" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
