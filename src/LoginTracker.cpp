#include "LoginTracker.h"

void LoginTracker::process(const std::vector<LogEntry>& entries) {
    for (const auto& entry : entries) {
        if (entry.isFailedLogin()) {
            failedCounts[entry.ip]++;
        }
    }
}

int LoginTracker::getFailedCount(const std::string& ip) const {
    auto it = failedCounts.find(ip);
    if (it == failedCounts.end()) return 0;
    return it->second;
}

const std::unordered_map<std::string, int>& LoginTracker::getAllCounts() const {
    return failedCounts;
}
