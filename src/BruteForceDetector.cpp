#include "BruteForceDetector.h"

BruteForceDetector::BruteForceDetector(int windowSeconds, int threshold)
    : windowSeconds(windowSeconds), threshold(threshold) {}

void BruteForceDetector::process(const std::vector<LogEntry>& sortedEntries) {
    for (const auto& entry : sortedEntries) {
        if (!entry.isFailedLogin()) continue;

        auto& q = recentFailures[entry.ip];
        q.push(entry.timeInSeconds);

        while (!q.empty() && (entry.timeInSeconds - q.front()) > windowSeconds) {
            q.pop();
        }

        if (static_cast<int>(q.size()) >= threshold) {
            flaggedBruteForce[entry.ip] = true;
            triggerCounts[entry.ip] = static_cast<int>(q.size());
        }
    }
}

bool BruteForceDetector::isBruteForce(const std::string& ip) const {
    auto it = flaggedBruteForce.find(ip);
    return it != flaggedBruteForce.end() && it->second;
}

int BruteForceDetector::getTriggerCount(const std::string& ip) const {
    auto it = triggerCounts.find(ip);
    if (it == triggerCounts.end()) return 0;
    return it->second;
}
