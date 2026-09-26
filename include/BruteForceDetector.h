#ifndef BRUTE_FORCE_DETECTOR_H
#define BRUTE_FORCE_DETECTOR_H

#include <unordered_map>
#include <queue>
#include <string>
#include <vector>
#include "LogEntry.h"

class BruteForceDetector {
public:
    BruteForceDetector(int windowSeconds = 60, int threshold = 5);
    void process(const std::vector<LogEntry>& sortedEntries);
    bool isBruteForce(const std::string& ip) const;
    int getTriggerCount(const std::string& ip) const;

private:
    int windowSeconds;
    int threshold;
    std::unordered_map<std::string, std::queue<int>> recentFailures;
    std::unordered_map<std::string, bool> flaggedBruteForce;
    std::unordered_map<std::string, int> triggerCounts;
};

#endif
