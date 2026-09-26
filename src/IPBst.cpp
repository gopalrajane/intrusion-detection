#include "IPBst.h"

IPBst::IPBst() : root(nullptr) {}

IPBst::~IPBst() {
    destroyTree(root);
}

void IPBst::destroyTree(Node* node) {
    if (!node) return;
    destroyTree(node->left);
    destroyTree(node->right);
    delete node;
}

void IPBst::insert(uint32_t ipNum) {
    root = insertHelper(root, ipNum);
}

IPBst::Node* IPBst::insertHelper(Node* node, uint32_t ipNum) {
    if (!node) return new Node(ipNum);

    if (ipNum < node->ipValue) {
        node->left = insertHelper(node->left, ipNum);
    } else if (ipNum > node->ipValue) {
        node->right = insertHelper(node->right, ipNum);
    }

    return node;
}

bool IPBst::contains(uint32_t ipNum) const {
    return containsHelper(root, ipNum);
}

bool IPBst::containsHelper(Node* node, uint32_t ipNum) const {
    if (!node) return false;
    if (node->ipValue == ipNum) return true;
    if (ipNum < node->ipValue) return containsHelper(node->left, ipNum);
    return containsHelper(node->right, ipNum);
}

std::vector<uint32_t> IPBst::inOrderTraversal() const {
    std::vector<uint32_t> result;
    inOrderHelper(root, result);
    return result;
}

void IPBst::inOrderHelper(Node* node, std::vector<uint32_t>& result) const {
    if (!node) return;
    inOrderHelper(node->left, result);
    result.push_back(node->ipValue);
    inOrderHelper(node->right, result);
}

std::vector<uint32_t> IPBst::rangeQuery(uint32_t lowIp, uint32_t highIp) const {
    std::vector<uint32_t> result;
    rangeQueryHelper(root, lowIp, highIp, result);
    return result;
}

void IPBst::rangeQueryHelper(Node* node, uint32_t low, uint32_t high, std::vector<uint32_t>& result) const {
    if (!node) return;

    if (node->ipValue > low) {
        rangeQueryHelper(node->left, low, high, result);
    }

    if (node->ipValue >= low && node->ipValue <= high) {
        result.push_back(node->ipValue);
    }

    if (node->ipValue < high) {
        rangeQueryHelper(node->right, low, high, result);
    }
}
