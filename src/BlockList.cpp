#include "BlockList.h"

void BlockList::block(const std::string& ip, const std::string& reason) {
    blocked.insert(ip);   // O(1) average
    reasons[ip] = reason;
}

bool BlockList::isBlocked(const std::string& ip) const {
    return blocked.find(ip) != blocked.end(); // O(1) average
}

std::string BlockList::getBlockReason(const std::string& ip) const {
    auto it = reasons.find(ip);
    if (it == reasons.end()) return "";
    return it->second;
}

int BlockList::size() const {
    return static_cast<int>(blocked.size());
}
