#ifndef _HEXDUMP_HPP_
#define _HEXDUMP_HPP_

#include <cctype>
#include <cstring>
#include <iostream>
#include <string>
using std::string;

// clang-format off
static const char* HEX = "0123456789ABCDEF";
static string to_hex_str(size_t number) {
    char buf[9];
    buf[8] = 0;
    buf[7] = *(HEX+(number%16)); number /= 16;
    buf[6] = *(HEX+(number%16)); number /= 16;
    buf[5] = *(HEX+(number%16)); number /= 16;
    buf[4] = *(HEX+(number%16)); number /= 16;
    buf[3] = *(HEX+(number%16)); number /= 16;
    buf[2] = *(HEX+(number%16)); number /= 16;
    buf[1] = *(HEX+(number%16)); number /= 16;
    buf[0] = *(HEX+(number%16));
    return string(buf);
}
static string to_hex_byte(uint8_t number) {
    char buf[3];
    buf[2] = 0;
    buf[1] = *(HEX+(number%16)); number /= 16;
    buf[0] = *(HEX+(number%16));
    return string(buf);
}
// clang-format on

template <typename T>
void hexdump(const T &data, std::ostream &printer, bool print_header = true) {
    size_t len = data.size();
    if (len <= 0) {
        printer << "hexdump: empty string" << std::endl;
        return;
    }
    if (print_header) {
        printer << "          +0 +1 +2 +3 +4 +5 +6 +7  +8 +9 +A +B +C +D +E +F"
                << std::endl;
    }

    size_t pos = 0;
    while (pos < len) {
        size_t data_len = len - pos;
        if (data_len > 16)
            data_len = 16;
        printer << to_hex_str(pos) << "  ";
        for (size_t offset = 0; offset < 16; offset++) {
            if (offset >= data_len) {
                printer << "   ";
            } else {
                printer << to_hex_byte((uint8_t)data[pos + offset]) << ' ';
            }
            if (offset == 7)
                printer << " ";
        }
        printer << " |";
        for (size_t offset = 0; offset < 16; offset++) {
            if (offset >= data_len) {
                printer << " ";
            } else {
                char ch = data[pos + offset];
                if (isgraph(ch)) {
                    printer << ch;
                } else {
                    printer << ".";
                }
            }
        }
        printer << "|" << std::endl;
        pos += 16;
    }
}
//           +0 +1 +2 +3 +4 +5 +6 +7  +8 +9 +A +B +C  D  E  F
// 00000000  00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  |0123456789ABCDEF|
// 00000000                                                    ||

void hexdump(const uint8_t *data, size_t len, std::ostream &printer,
             bool print_header = true) {
    // if (data == nullptr || len <= 0) throw std::invalid_argument();
    hexdump(string((const char *)data, len), printer, print_header);
}

#endif