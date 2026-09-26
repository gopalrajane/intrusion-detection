#include "ThreatPrioritizer.h"

std::string threatLevelToString(ThreatLevel level) {
    switch (level) {
        case ThreatLevel::HIGH:   return "HIGH";
        case ThreatLevel::MEDIUM: return "MEDIUM";
        default:                 return "LOW";
    }
}

void ThreatPrioritizer::addThreat(const std::string& ip, int failedAttempts, ThreatLevel level) {
    heap.emplace(ip, failedAttempts, level); // O(log n) — heap re-balances on insert
}

bool ThreatPrioritizer::empty() const {
    return heap.empty();
}

ThreatEntry ThreatPrioritizer::extractHighestThreat() {
    ThreatEntry top = heap.top(); // O(1) peek
    heap.pop();                  // O(log n) removal + re-balance
    return top;
}

std::vector<ThreatEntry> ThreatPrioritizer::getTopN(int n) const {
    // Copy the heap so we don't destroy the original while peeking at the top N.
    // (priority_queue has no "peek without removing several" operation, so
    // this is the standard workaround — still O(n log n) worst case for the copy+drain,
    // but n is small in practice, e.g. top 5 threats for a report.)
    auto heapCopy = heap;
    std::vector<ThreatEntry> result;
    int count = 0;
    while (!heapCopy.empty() && count < n) {
        result.push_back(heapCopy.top());
        heapCopy.pop();
        count++;
    }
    return result;
}

ThreatLevel ThreatPrioritizer::classify(int failedAttempts, bool isBruteForce, bool isInCluster) {
    // Simple, explainable rule set (easy to justify in a viva):
    // - Brute force (many fast failures) OR part of a coordinated cluster -> HIGH
    // - Some failures but not fast/coordinated -> MEDIUM
    // - Very few failures -> LOW
    if (isBruteForce || isInCluster) {
        return ThreatLevel::HIGH;
    }
    if (failedAttempts >= 3) {
        return ThreatLevel::MEDIUM;
    }
    return ThreatLevel::LOW;
}
