#ifndef PACKET_SNIFFER_HEX_DUMP_H
#define PACKET_SNIFFER_HEX_DUMP_H

#include <string>
#include <iomanip>
#include <sstream>
#include <vector>
#include <cstdint>
#include <cctype>

namespace packet_sniffer {

class HexDump {
public:
    // Format binary data as a hex dump
    static std::string format(const uint8_t* data, size_t size, bool show_ascii = true);
    
    // Format binary data with human-readable output
    static std::string format_human(const uint8_t* data, size_t size);
    
    // Format a single byte as two hex characters
    static std::string byte_to_hex(uint8_t byte);
    
    // Convert a byte to a printable character (or '.' if not printable)
    static char byte_to_ascii(uint8_t byte);
    
    // Format a vector of bytes as a hex string
    template<typename T>
    static std::string to_hex(const T& container) {
        std::ostringstream ss;
        ss << std::hex << std::setfill('0');
        for (const auto& byte : container) {
            ss << std::setw(2) << static_cast<int>(byte) << " ";
        }
        return ss.str();
    }
};

} // namespace packet_sniffer

#endif // PACKET_SNIFFER_HEX_DUMP_H
