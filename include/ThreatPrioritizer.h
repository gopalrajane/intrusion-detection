#ifndef THREAT_PRIORITIZER_H
#define THREAT_PRIORITIZER_H

#include <string>
#include <vector>
#include <queue>

// Threat levels, ordered low -> high so we can compare them as numbers.
enum class ThreatLevel {
    LOW = 0,
    MEDIUM = 1,
    HIGH = 2
};

std::string threatLevelToString(ThreatLevel level);

// One IP's threat info, ready to be ranked.
struct ThreatEntry {
    std::string ip;
    int failedAttempts;
    ThreatLevel level;

    ThreatEntry(std::string ipAddr, int attempts, ThreatLevel lvl)
        : ip(std::move(ipAddr)), failedAttempts(attempts), level(lvl) {}
};

// Comparator so priority_queue puts the HIGHEST threat at the top.
// std::priority_queue is a max-heap by default using operator<, but for
// a struct we must supply our own comparison — "a is lower priority than b"
// if a's level is smaller, or (same level) a has fewer failed attempts.
struct ThreatComparator {
    bool operator()(const ThreatEntry& a, const ThreatEntry& b) const {
        if (a.level != b.level) {
            return a.level < b.level; // higher level = higher priority
        }
        return a.failedAttempts < b.failedAttempts; // tie-break: more attempts = worse
    }
};

// Wraps a max-heap (priority_queue) of ThreatEntry so the highest-risk
// IP is always available in O(1), and inserting/removing is O(log n) --
// far cheaper than re-sorting the whole list every time new data comes in.
class ThreatPrioritizer {
public:
    void addThreat(const std::string& ip, int failedAttempts, ThreatLevel level);

    bool empty() const;

    // Returns and removes the current highest-priority threat. O(log n).
    ThreatEntry extractHighestThreat();

    // Returns the top N threats without needing to fully drain the heap
    // (used to print a "top threats" list for the report).
    std::vector<ThreatEntry> getTopN(int n) const;

    // Simple helper: classify a raw failed-attempt count into a ThreatLevel.
    // (Used when a caller hasn't already computed one, e.g. from BruteForceDetector.)
    static ThreatLevel classify(int failedAttempts, bool isBruteForce, bool isInCluster);

private:
    std::priority_queue<ThreatEntry, std::vector<ThreatEntry>, ThreatComparator> heap;
};

#endif
