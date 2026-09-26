#ifndef LOG_ENTRY_H
#define LOG_ENTRY_H

#include <string>
#include <cstdint>

// One parsed line from a log file.
// Example raw line: "10:05:12 FAILED_LOGIN 192.168.1.10 admin"
struct LogEntry {
    std::string timestamp;   // "HH:MM:SS" as read from file
    int timeInSeconds;       // timestamp converted to seconds-since-midnight, for math/sorting
    std::string eventType;   // "FAILED_LOGIN" or "SUCCESS_LOGIN"
    std::string ip;          // "192.168.1.10"
    std::string account;     // "admin"

    LogEntry() : timeInSeconds(0) {}

    LogEntry(std::string ts, int secs, std::string evt, std::string ipAddr, std::string acct)
        : timestamp(std::move(ts)), timeInSeconds(secs),
          eventType(std::move(evt)), ip(std::move(ipAddr)), account(std::move(acct)) {}

    bool isFailedLogin() const {
        return eventType == "FAILED_LOGIN";
    }
};

// Converts "192.168.1.10" -> a single 32-bit number.
// This lets the BST compare/order IPs numerically (needed for range queries),
// instead of comparing them as plain strings (which sorts wrong: "192.168.1.9" > "192.168.1.10" alphabetically).
uint32_t ipToInt(const std::string& ip);

// Converts a 32-bit number back to "a.b.c.d" form, for printing.
std::string intToIp(uint32_t ipNum);

// Converts "HH:MM:SS" -> total seconds since midnight (for sorting/window math).
int timeToSeconds(const std::string& hhmmss);

#endif
