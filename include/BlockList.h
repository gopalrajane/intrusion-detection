#ifndef BLOCK_LIST_H
#define BLOCK_LIST_H

#include <unordered_set>
#include <unordered_map>
#include <string>

// Simulated automatic response: once an IP is added here, it's "blocked" --
// any further attempts from it get rejected instantly, without re-checking
// its full history. Uses unordered_set for O(1) average membership checks,
// which matters because every incoming attempt needs a fast "already blocked?"
// check before anything else happens.
class BlockList {
public:
    // Add an IP to the blocklist, with a human-readable reason (for the action log).
    void block(const std::string& ip, const std::string& reason);

    // O(1) average -- is this IP currently blocked?
    bool isBlocked(const std::string& ip) const;

    // Reason the IP was blocked, if it is blocked.
    std::string getBlockReason(const std::string& ip) const;

    int size() const;

private:
    std::unordered_set<std::string> blocked;
    std::unordered_map<std::string, std::string> reasons;
};

#endif
