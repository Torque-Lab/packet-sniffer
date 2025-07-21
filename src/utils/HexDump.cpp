#include "utils/HexDump.h"
#include <iomanip>
#include <sstream>
#include <cstdint>
#include <cctype>
#include <algorithm>

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

std::string HexDump::format_human(const uint8_t* data, size_t size) {
    std::ostringstream ss;
    
    // First, show the regular hex dump
    ss << "Hex dump (" << size << " bytes):\n";
    ss << format(data, size, true) << "\n";
    
    // Then show the human-readable string
    ss << "Human-readable string (" << size << " bytes):\n";
    
    // Process the data to extract human-readable strings
    std::string current_line;
    bool in_string = false;
    
    for (size_t i = 0; i < size; i++) {
        uint8_t c = data[i];
        
        if (std::isprint(c) && !std::iscntrl(c)) {
            // Printable character
            if (!in_string) {
                // Start of a new string
                ss << "    " << std::setw(8) << std::hex << i << "  ";
                in_string = true;
            }
            ss << static_cast<char>(c);
        } else {
            // Non-printable character
            if (in_string) {
                // End of a string
                ss << "\n";
                in_string = false;
            }
        }
    }
    
    // Add a newline if we ended in the middle of a string
    if (in_string) {
        ss << "\n";
    }
    
    ss << "\n";
    return ss.str();
}

std::string HexDump::byte_to_hex(uint8_t byte) {
    std::ostringstream ss;
    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    return ss.str();
}

char HexDump::byte_to_ascii(uint8_t byte) {
    return (byte >= 32 && byte <= 126) ? static_cast<char>(byte) : '.';
}

} // namespace packet_sniffer
