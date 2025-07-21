#include "utils/HexDump.h"
#include <iomanip>
#include <sstream>
#include <cstdint>

namespace packet_sniffer {

std::string HexDump::format(const uint8_t* data, size_t size, bool show_ascii) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    
    // Process each byte in the data
    for (size_t i = 0; i < size; i += 16) {
        // Offset
        ss << "    " << std::setw(8) << i << "  ";
        
        // Hex bytes
        size_t j;
        for (j = 0; j < 16; ++j) {
            if (i + j < size) {
                ss << std::setw(2) << static_cast<int>(data[i + j]) << " ";
            } else {
                ss << "   "; // Pad with spaces for partial lines
            }
            
            // Extra space after 8 bytes
            if (j == 7) ss << " ";
        }
        
        // ASCII representation
        if (show_ascii) {
            ss << " |";
            for (j = 0; j < 16 && (i + j) < size; ++j) {
                ss << byte_to_ascii(data[i + j]);
            }
            ss << "|";
        }
        
        ss << "\n";
    }
    
    return ss.str();
}

std::string HexDump::byte_to_hex(uint8_t byte) {
    std::ostringstream ss;
    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    return ss.str();
}

char HexDump::byte_to_ascii(uint8_t byte) {
    // Return printable characters as-is, others as a dot
    return (byte >= 32 && byte <= 126) ? static_cast<char>(byte) : '.';
}

} // namespace packet_sniffer
