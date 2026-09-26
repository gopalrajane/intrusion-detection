#ifndef IP_BST_H
#define IP_BST_H

#include <cstdint>
#include <string>
#include <vector>

class IPBst {
public:
    IPBst();
    ~IPBst();

    void insert(uint32_t ipNum);
    bool contains(uint32_t ipNum) const;
    std::vector<uint32_t> inOrderTraversal() const;
    std::vector<uint32_t> rangeQuery(uint32_t lowIp, uint32_t highIp) const;

private:
    struct Node {
        uint32_t ipValue;
        Node* left;
        Node* right;
        explicit Node(uint32_t val) : ipValue(val), left(nullptr), right(nullptr) {}
    };

    Node* root;

    Node* insertHelper(Node* node, uint32_t ipNum);
    bool containsHelper(Node* node, uint32_t ipNum) const;
    void inOrderHelper(Node* node, std::vector<uint32_t>& result) const;
    void rangeQueryHelper(Node* node, uint32_t low, uint32_t high, std::vector<uint32_t>& result) const;
    void destroyTree(Node* node);
};

#endif
