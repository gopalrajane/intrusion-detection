#include "LogEntry.h"
#include <sstream>
#include <vector>

uint32_t ipToInt(const std::string& ip) {
    uint32_t result = 0;
    std::stringstream ss(ip);
    std::string octet;

    while (std::getline(ss, octet, '.')) {
        result = (result << 8) | static_cast<uint32_t>(std::stoi(octet));
    }
    return result;
}

std::string intToIp(uint32_t ipNum) {
    int a = (ipNum >> 24) & 0xFF;
    int b = (ipNum >> 16) & 0xFF;
    int c = (ipNum >> 8) & 0xFF;
    int d = ipNum & 0xFF;
    return std::to_string(a) + "." + std::to_string(b) + "." +
           std::to_string(c) + "." + std::to_string(d);
}

int timeToSeconds(const std::string& hhmmss) {
    int h = 0, m = 0, s = 0;
    char colon;
    std::stringstream ss(hhmmss);
    ss >> h >> colon >> m >> colon >> s;
    return h * 3600 + m * 60 + s;
}
