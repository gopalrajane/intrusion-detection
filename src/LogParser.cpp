#include "LogParser.h"
#include <fstream>
#include <sstream>
#include <iostream>

int LogParser::skippedCount = 0;

std::vector<LogEntry> LogParser::parseFile(const std::string& filename) {
    std::vector<LogEntry> entries;
    skippedCount = 0;

    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "[LogParser] ERROR: Could not open file: " << filename << "\n";
        return entries;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) continue;

        std::stringstream ss(line);
        std::string timestamp, eventType, ip, account;

        if (!(ss >> timestamp >> eventType >> ip >> account)) {
            skippedCount++;
            continue;
        }

        int secs = timeToSeconds(timestamp);
        entries.emplace_back(timestamp, secs, eventType, ip, account);
    }

    file.close();
    return entries;
}

int LogParser::lastSkippedCount() {
    return skippedCount;
}
