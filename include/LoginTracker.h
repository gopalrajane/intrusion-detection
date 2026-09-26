#ifndef LOGIN_TRACKER_H
#define LOGIN_TRACKER_H

#include <unordered_map>
#include <string>
#include <vector>
#include "LogEntry.h"

class LoginTracker {
public:
    void process(const std::vector<LogEntry>& entries);
    int getFailedCount(const std::string& ip) const;
    const std::unordered_map<std::string, int>& getAllCounts() const;

private:
    std::unordered_map<std::string, int> failedCounts;
};

#endif
